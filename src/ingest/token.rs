//! Presubmit tokens.
//!
//! The server answers a presubmit with a token; the Accelerator echoes it back
//! as `PresubmitToken` on every later upload. The token carries the decision
//! (full upload or metadata only) and the crash fingerprint, signed with
//! HMAC-SHA256 so a client can neither forge a "metadata only" pass nor
//! upgrade one.
//!
//! Format: `<kind>.<signature>.<issued_at hex>.<mac>`; no `|`, which is the
//! protocol's field separator.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, bail};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const MAC_BYTES: usize = 16;
const TTL_SECS: i64 = 6 * 3600;
const CLOCK_SKEW_SECS: i64 = 300;

pub struct Secret(Vec<u8>);

impl Secret {
    #[cfg(test)]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Read the key at `path`, creating a random 256-bit one (mode 0600) on first start.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        match Self::read(path) {
            Ok(Some(secret)) => return Ok(secret),
            Ok(None) => {}
            Err(e) => return Err(e),
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let key: [u8; 32] = rand::random();

        use std::os::unix::fs::OpenOptionsExt;
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);
        match created {
            Ok(mut file) => {
                file.write_all(&key)?;
                file.sync_all()?;
                Ok(Self(key.to_vec()))
            }
            // Another process won the race: use its key.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::read(path)?.context("secret key vanished")
            }
            Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
        }
    }

    fn read(path: &Path) -> anyhow::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) if bytes.len() >= 32 => Ok(Some(Self(bytes))),
            Ok(_) => bail!(
                "{} is shorter than 32 bytes; delete it to regenerate",
                path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// HMAC for other signed values (web sessions). Callers must prefix `body`
    /// with their own domain string so tokens can't be swapped between uses.
    pub fn sign(&self, body: &str) -> String {
        self.mac(body)
    }

    fn mac(&self, body: &str) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0)
            .expect("HMAC accepts keys of any length");
        mac.update(body.as_bytes());
        hex::encode(&mac.finalize().into_bytes()[..MAC_BYTES])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Upload the dump and the metadata.
    Full,
    /// Upload only the metadata (the server is saving space).
    MetadataOnly,
}

impl Kind {
    /// The first byte of the presubmit response.
    pub fn letter(self) -> char {
        match self {
            Kind::Full => 'Y',
            Kind::MetadataOnly => 'M',
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Claims {
    pub kind: Kind,
    pub signature: String,
    pub issued_at: i64,
}

pub fn mint(secret: &Secret, kind: Kind, signature: &str, now: i64) -> String {
    let body = format!("{}.{signature}.{now:x}", kind.letter());
    format!("{body}.{}", secret.mac(&body))
}

/// Constant-time comparison.
pub fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

pub fn verify(secret: &Secret, token: &str, now: i64) -> Option<Claims> {
    let mut parts = token.split('.');
    let (kind, signature, issued, mac) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }

    let body = format!("{kind}.{signature}.{issued}");
    if !same(&secret.mac(&body), mac) {
        return None;
    }

    let kind = match kind {
        "Y" => Kind::Full,
        "M" => Kind::MetadataOnly,
        _ => return None,
    };
    let issued_at = i64::from_str_radix(issued, 16).ok()?;
    if issued_at > now + CLOCK_SKEW_SECS || now - issued_at > TTL_SECS {
        return None;
    }
    Some(Claims {
        kind,
        signature: signature.to_string(),
        issued_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> Secret {
        Secret::from_bytes(vec![byte; 32])
    }

    #[test]
    fn roundtrip() {
        let s = secret(1);
        let token = mint(&s, Kind::MetadataOnly, "0123456789abcdef", 1000);
        assert!(!token.contains('|'));
        let claims = verify(&s, &token, 1000).unwrap();
        assert_eq!(claims.kind, Kind::MetadataOnly);
        assert_eq!(claims.signature, "0123456789abcdef");
    }

    #[test]
    fn tampering_is_detected() {
        let s = secret(1);
        let token = mint(&s, Kind::MetadataOnly, "0123456789abcdef", 1000);
        // Upgrade M to Y without re-signing.
        let forged = format!("Y{}", &token[1..]);
        assert_eq!(verify(&s, &forged, 1000), None);
        // Different key.
        assert_eq!(verify(&secret(2), &token, 1000), None);
        // Garbage.
        for bad in ["", "x", "Y.a.b", "Y.a.b.c.d", "Y.0123456789abcdef.3e8.00"] {
            assert_eq!(verify(&s, bad, 1000), None, "{bad}");
        }
    }

    #[test]
    fn tokens_expire() {
        let s = secret(1);
        let token = mint(&s, Kind::Full, "0123456789abcdef", 1000);
        assert!(verify(&s, &token, 1000 + TTL_SECS).is_some());
        assert!(verify(&s, &token, 1000 + TTL_SECS + 1).is_none());
        // Issued in the future beyond clock skew.
        assert!(verify(&s, &token, 1000 - CLOCK_SKEW_SECS - 1).is_none());
    }

    #[test]
    fn secret_is_created_once_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/secret.key");
        let a = Secret::load_or_create(&path).unwrap();
        let b = Secret::load_or_create(&path).unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(a.0.len(), 32);

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        std::fs::write(&path, b"short").unwrap();
        assert!(Secret::load_or_create(&path).is_err());
    }
}
