//! Crash IDs: 12 symbols of base32 (`a-z2-7`), i.e. 60 random bits.
//!
//! Also the reversible mapping to the UUIDs used by the standard Breakpad
//! uploader (`prod=1`), kept compatible with the PHP version so old links work:
//! `bee0cafe-0000-4000-` + 64 bits made of the variant nibble `1000` followed
//! by the 60 ID bits (see docs/protocol.md).

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const ID_LEN: usize = 12;
const ID_BITS_MASK: u64 = (1 << 60) - 1;
const UUID_PREFIX: &str = "bee0cafe-0000-4000-";

fn encode(mut bits: u64) -> String {
    let mut out = [0u8; ID_LEN];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(bits & 31) as usize];
        bits >>= 5;
    }
    // ALPHABET is ASCII.
    String::from_utf8(out.to_vec()).expect("ascii alphabet")
}

fn decode(id: &str) -> Option<u64> {
    if id.len() != ID_LEN {
        return None;
    }
    let mut bits = 0u64;
    for b in id.bytes() {
        let idx = ALPHABET.iter().position(|&c| c == b)? as u64;
        bits = (bits << 5) | idx;
    }
    Some(bits)
}

/// A fresh random ID. The caller must still handle a (1 in 2^60) collision by
/// retrying on a unique-constraint error.
pub fn generate() -> String {
    encode(rand::random::<u64>() & ID_BITS_MASK)
}

/// Accepts user input (`ABCD-EFGH-IJKL`, any case, with or without dashes) and
/// returns the canonical lowercase form, or `None` if it isn't a valid ID.
pub fn normalize(input: &str) -> Option<String> {
    let id: String = input
        .chars()
        .filter(|&c| c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    decode(&id).map(|_| id)
}

/// `abcdefghijkl` -> `ABCD-EFGH-IJKL`.
pub fn display(id: &str) -> String {
    id.to_ascii_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

pub fn to_uuid(id: &str) -> Option<String> {
    let bits = decode(id)?;
    let value = (0b1000u64 << 60) | bits;
    let hex = format!("{value:016x}");
    Some(format!("{UUID_PREFIX}{}-{}", &hex[..4], &hex[4..]))
}

/// Inverse of [`to_uuid`]. Only the 60 payload bits are read, like the PHP
/// version, so the fixed prefix is not enforced.
pub fn from_uuid(uuid: &str) -> Option<String> {
    let b = uuid.as_bytes();
    if b.len() != 36 || ![8, 13, 18, 23].iter().all(|&i| b[i] == b'-') {
        return None;
    }
    if !uuid
        .bytes()
        .enumerate()
        .all(|(i, c)| [8, 13, 18, 23].contains(&i) || c.is_ascii_hexdigit())
    {
        return None;
    }
    // Chars 20..23 and 24..36: three nibbles of byte 0/1 plus six more bytes.
    let payload = format!("{}{}", &uuid[20..23], &uuid[24..]);
    let bits = u64::from_str_radix(&payload, 16).ok()?;
    Some(encode(bits & ID_BITS_MASK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_valid_and_roundtrip() {
        for _ in 0..1000 {
            let id = generate();
            assert_eq!(id.len(), 12);
            assert_eq!(normalize(&id).as_deref(), Some(id.as_str()));
            assert_eq!(
                from_uuid(&to_uuid(&id).unwrap()).as_deref(),
                Some(id.as_str())
            );
        }
    }

    #[test]
    fn normalize_accepts_display_form() {
        assert_eq!(normalize("ABCD-EFGH-IJKL").as_deref(), Some("abcdefghijkl"));
        assert_eq!(display("abcdefghijkl"), "ABCD-EFGH-IJKL");
    }

    #[test]
    fn normalize_rejects_garbage() {
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("abcdefghijk"), None); // 11
        assert_eq!(normalize("abcdefghijklm"), None); // 13
        assert_eq!(normalize("abcdefghij01"), None); // 0 and 1 are not in the alphabet
        assert_eq!(normalize("../../../etc"), None);
    }

    /// Hand-computed against the PHP algorithm (pack 4 bits `1000` + 12x5 bits,
    /// split into bytes, dash after the 2nd byte).
    #[test]
    fn uuid_matches_legacy_encoding() {
        // "aaaaaaaaaaaa" = 60 zero bits -> 0x8000000000000000
        assert_eq!(
            to_uuid("aaaaaaaaaaaa").as_deref(),
            Some("bee0cafe-0000-4000-8000-000000000000")
        );
        // "777777777777" = 60 one bits -> 0x8fffffffffffffff
        assert_eq!(
            to_uuid("777777777777").as_deref(),
            Some("bee0cafe-0000-4000-8fff-ffffffffffff")
        );
        // "baaaaaaaaaaa": first symbol = 1 -> bits 00001 ... -> 0x8080000000000000
        assert_eq!(
            to_uuid("baaaaaaaaaaa").as_deref(),
            Some("bee0cafe-0000-4000-8080-000000000000")
        );
    }

    #[test]
    fn from_uuid_rejects_malformed() {
        assert_eq!(from_uuid("not-a-uuid"), None);
        assert_eq!(from_uuid("bee0cafe-0000-4000-8000-00000000000g"), None);
        assert_eq!(from_uuid("bee0cafe00004000800000000000000000"), None);
    }
}
