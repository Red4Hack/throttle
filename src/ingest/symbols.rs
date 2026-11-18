//! `POST /symbols/submit`: Breakpad `.sym` uploads.
//!
//! Policy: first upload wins. A given (name, build id) is one specific binary,
//! so a second upload can only be a duplicate or an attempt to replace good
//! symbols with bad ones.

use std::path::Path;

use axum::body::to_bytes;
use axum::extract::{FromRequest, Multipart, Request, State};
use axum::response::Response;

use super::form::{content_type, multipart_error, read_capped};
use super::{Reject, store, text};
use crate::app::AppState;
use crate::config::Config;
use crate::stats;
use sqlx::SqlitePool;

const MAX_NAME_LEN: usize = 255;
const MAX_ID_LEN: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    pub os: String,
    pub arch: String,
    /// Upper-case hex.
    pub id: String,
    pub name: String,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
}

fn token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `MODULE <os> <arch> <id> <name>`; the name may contain spaces.
pub fn parse_header(line: &str) -> Option<Header> {
    let rest = line.strip_prefix("MODULE ")?;
    let mut parts = rest.splitn(4, ' ');
    let (os, arch, id, name) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if !token_ok(os) || !token_ok(arch) || !valid_name(name) {
        return None;
    }
    if id.is_empty() || id.len() > MAX_ID_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(Header {
        os: os.to_string(),
        arch: arch.to_string(),
        id: id.to_ascii_uppercase(),
        name: name.to_string(),
    })
}

/// Linux symbol files need at least one FUNC record (Accelerator < 2.4.3
/// produced PUBLIC-only files that can't be walked reliably).
fn has_func_records(data: &[u8]) -> bool {
    for line in data.split(|&b| b == b'\n') {
        if line.starts_with(b"FUNC ") {
            return true;
        }
        if line.starts_with(b"STACK ") {
            return false;
        }
    }
    false
}

/// `foo.pdb` is stored as `foo.sym.gz`, anything else as `<name>.sym.gz`.
pub fn file_stem(name: &str) -> &str {
    match name.len().checked_sub(4) {
        Some(cut) if name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(".pdb") => {
            &name[..cut]
        }
        _ => name,
    }
}

async fn read_body(req: Request, max: u64) -> Result<Vec<u8>, Reject> {
    let ct = content_type(&req);
    let max = max as usize;

    if ct.starts_with("multipart/form-data") {
        let mut mp = Multipart::from_request(req, &())
            .await
            .map_err(|_| Reject::BadRequest("malformed multipart body"))?;
        while let Some(field) = mp.next_field().await.map_err(multipart_error)? {
            if field.name() == Some("symbol_file") {
                return read_capped(field, max).await;
            }
        }
        Err(Reject::BadRequest("missing symbol_file"))
    } else if ct.starts_with("application/x-www-form-urlencoded") {
        // Percent-encoding can triple the size.
        let bytes = to_bytes(req.into_body(), max.saturating_mul(3))
            .await
            .map_err(|_| Reject::TooLarge)?;
        form_urlencoded::parse(&bytes)
            .find(|(k, _)| k == "symbol_file")
            .map(|(_, v)| v.into_owned().into_bytes())
            .ok_or(Reject::BadRequest("missing symbol_file"))
    } else {
        // Raw body (what the Accelerator CI and curl send).
        to_bytes(req.into_body(), max)
            .await
            .map(|b| b.to_vec())
            .map_err(|_| Reject::TooLarge)
    }
}

async fn invalid(state: &AppState, reason: &'static str) -> Result<Response, Reject> {
    stats::bump(&state.db, "symbols:rejected:invalid", 1).await;
    Err(Reject::BadRequest(reason))
}

pub async fn submit(State(state): State<AppState>, req: Request) -> Result<Response, Reject> {
    // Large uploads are the one thing that can exhaust memory; cap concurrency.
    let _permit = state
        .symbol_uploads
        .clone()
        .try_acquire_owned()
        .map_err(|_| Reject::Busy)?;

    if crate::retention::low_disk(&state.config) {
        return Err(Reject::NoSpace);
    }

    let max = state.config.limits.max_symbol_bytes;
    let data = read_body(req, max).await?;
    if data.len() as u64 > max {
        return Err(Reject::TooLarge);
    }

    stats::bump(&state.db, "symbols:submitted", 1).await;
    stats::bump(&state.db, "symbols:submitted:bytes", data.len() as i64).await;

    let first_line = data.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let Ok(first_line) = std::str::from_utf8(first_line) else {
        return invalid(&state, "Invalid symbol file").await;
    };
    let Some(header) = parse_header(first_line.trim_end_matches('\r')) else {
        tracing::warn!("rejected symbol file with a bad MODULE line");
        return invalid(&state, "Invalid symbol file").await;
    };

    if header.os.eq_ignore_ascii_case("linux") && !has_func_records(&data) {
        stats::bump(&state.db, "symbols:rejected:no-functions", 1).await;
        return Err(Reject::BadRequest(
            "Symbol file had no FUNC records, please update to Accelerator 2.4.3 or later",
        ));
    }

    if file_stem(&header.name).is_empty() {
        return invalid(&state, "Invalid symbol file").await;
    }

    let outcome = store_file(&state.config, &state.db, "public", &header, data).await?;

    if outcome == Written::Created {
        stats::bump(&state.db, "symbols:accepted", 1).await;
        Ok(text(format!(
            "Stored symbols for {}/{}/{}/{}\n",
            header.name, header.id, header.os, header.arch
        )))
    } else {
        Ok(text(format!(
            "Already have symbols for {}/{}/{}/{}\n",
            header.name, header.id, header.os, header.arch
        )))
    }
}

/// Compress `data` and keep it as the symbols of `header` in `store_name`.
/// The first file for a (name, build id) wins. Used by uploads and by the
/// symbol fetcher; the caller has validated the header.
pub async fn store_file(
    config: &Config,
    db: &SqlitePool,
    store_name: &str,
    header: &Header,
    data: Vec<u8>,
) -> Result<Written, Reject> {
    let stem = file_stem(&header.name);
    if stem.is_empty() {
        return Err(Reject::BadRequest("Invalid symbol file"));
    }
    let dir = config
        .symbols_dir()
        .join(store_name)
        .join(&header.name)
        .join(&header.id);
    let final_path = dir.join(format!("{stem}.sym.gz"));
    tokio::fs::create_dir_all(&dir).await?;

    let uncompressed = data.len() as i64;
    let compressed = tokio::task::spawn_blocking(move || store::gzip(&data, 3))
        .await
        .map_err(|_| Reject::Internal)??;

    let outcome = write_new(&dir, &final_path, &compressed).await?;

    sqlx::query("INSERT OR IGNORE INTO symbol (name, identifier, store, bytes, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&header.name)
        .bind(&header.id)
        .bind(store_name)
        .bind(uncompressed)
        .bind(stats::now())
        .execute(db)
        .await?;
    Ok(outcome)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Written {
    Created,
    AlreadyThere,
}

/// Write via a temp file and a hard link, so readers never see a partial file
/// and an existing file is never replaced.
async fn write_new(dir: &Path, final_path: &Path, bytes: &[u8]) -> Result<Written, Reject> {
    let tmp = dir.join(format!("{}.part", hex::encode(rand::random::<[u8; 8]>())));
    tokio::fs::write(&tmp, bytes).await?;
    let linked = tokio::fs::hard_link(&tmp, final_path).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    match linked {
        Ok(()) => Ok(Written::Created),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(Written::AlreadyThere),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parsing() {
        let h = parse_header("MODULE Linux x86_64 aaaabbbb server_srv.so").unwrap();
        assert_eq!(
            h,
            Header {
                os: "Linux".into(),
                arch: "x86_64".into(),
                id: "AAAABBBB".into(),
                name: "server_srv.so".into()
            }
        );

        let h = parse_header("MODULE windows x86 5A9832E5287241C1838ED98914E9B7FF1 my lib.pdb")
            .unwrap();
        assert_eq!(h.name, "my lib.pdb");
    }

    #[test]
    fn header_rejects_bad_input() {
        for bad in [
            "",
            "MODULE",
            "MODULE Linux x86_64 ABCD",
            "MODULE Linux x86_64 XYZ name.so",
            "MODULE Linux x86_64 ABCD ../evil.so",
            "MODULE Linux x86_64 ABCD a/b.so",
            "MODULE Linux x86_64 ABCD a\\b.so",
            "MODULE Linux x86_64 ABCD ..",
            "MODULE Linux x86_64 ABCD a\u{0}b",
            "MODULE Li/nux x86_64 ABCD name.so",
            "module Linux x86_64 ABCD name.so",
        ] {
            assert_eq!(parse_header(bad), None, "{bad:?}");
        }
        let long = format!("MODULE Linux x86_64 {} n.so", "A".repeat(65));
        assert_eq!(parse_header(&long), None);
    }

    #[test]
    fn func_detection_stops_at_stack() {
        assert!(has_func_records(b"MODULE\nFILE 0 a\nFUNC 10 4 0 main\n"));
        assert!(!has_func_records(b"MODULE\nPUBLIC 10 0 main\n"));
        assert!(!has_func_records(
            b"MODULE\nSTACK CFI INIT 1 2 x\nFUNC 10 4 0 main\n"
        ));
    }

    #[test]
    fn stems() {
        assert_eq!(file_stem("foo.pdb"), "foo");
        assert_eq!(file_stem("FOO.PDB"), "FOO");
        assert_eq!(file_stem("server_srv.so"), "server_srv.so");
        assert_eq!(file_stem(".pdb"), "");
        assert_eq!(file_stem("é"), "é");
    }
}
