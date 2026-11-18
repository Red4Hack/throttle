//! The Accelerator metadata file (`.dmp.txt`): a CONFIG block of `Key=Value`
//! lines and an optional CONSOLE HISTORY block. See docs/protocol.md.

const CONFIG_BEGIN: &[u8] = b"-------- CONFIG BEGIN --------";
const CONFIG_END: &[u8] = b"-------- CONFIG END --------";
const CONSOLE_BEGIN: &[u8] = b"-------- CONSOLE HISTORY BEGIN --------";
const CONSOLE_END: &[u8] = b"-------- CONSOLE HISTORY END --------";

const MAX_KEY_LEN: usize = 64;
const MAX_VALUE_CHARS: usize = 4096;
const MAX_PAIRS: usize = 128;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub config: Vec<(String, String)>,
    pub has_console: bool,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The bytes between the first `begin` and the first `end` after it. The raw
/// file can contain arbitrary bytes, so this works on `&[u8]`; like the old
/// regex (`[^\x00]+`) the block ends at the first NUL.
fn between<'a>(raw: &'a [u8], begin: &[u8], end: &[u8]) -> Option<&'a [u8]> {
    let start = find(raw, begin)? + begin.len();
    let rest = &raw[start..];
    let rest = &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())];
    let stop = find(rest, end)?;
    Some(&rest[..stop])
}

/// The text of the CONSOLE HISTORY block, if the file has one.
pub fn console(raw: &[u8]) -> Option<String> {
    between(raw, CONSOLE_BEGIN, CONSOLE_END).map(|b| String::from_utf8_lossy(b).into_owned())
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

pub fn parse(raw: &[u8]) -> Parsed {
    let mut parsed = Parsed::default();

    if let Some(block) = between(raw, CONFIG_BEGIN, CONFIG_END) {
        let text = String::from_utf8_lossy(block);
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            // Empty values never overwrite (same as the PHP version).
            if value.is_empty() || !valid_key(key) {
                continue;
            }
            if parsed.config.len() >= MAX_PAIRS {
                break;
            }
            parsed.config.push((
                key.to_string(),
                value.chars().take(MAX_VALUE_CHARS).collect(),
            ));
        }
    }

    if let Some(block) = between(raw, CONSOLE_BEGIN, CONSOLE_END) {
        parsed.has_console = !String::from_utf8_lossy(block).trim().is_empty();
    }

    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config_and_console() {
        let raw = b"-------- CONFIG BEGIN --------\nMap=de_dust2\r\nSteam_PatchVersion = 1.2.3\nEmpty=\nbad key=1\nNoEquals\n-------- CONFIG END --------\n-------- CONSOLE HISTORY BEGIN --------\nhello\n-------- CONSOLE HISTORY END --------\n";
        let p = parse(raw);
        assert_eq!(
            p.config,
            vec![
                ("Map".to_string(), "de_dust2".to_string()),
                ("Steam_PatchVersion".to_string(), "1.2.3".to_string()),
            ]
        );
        assert!(p.has_console);
    }

    #[test]
    fn empty_console_is_not_a_console() {
        let raw =
            b"-------- CONSOLE HISTORY BEGIN --------\n  \n-------- CONSOLE HISTORY END --------";
        assert!(!parse(raw).has_console);
    }

    #[test]
    fn tolerates_binary_garbage_and_missing_markers() {
        assert_eq!(parse(b"\xff\xfe\x00\x01"), Parsed::default());
        assert_eq!(parse(b""), Parsed::default());
        // Unterminated block is ignored.
        assert_eq!(
            parse(b"-------- CONFIG BEGIN --------\nMap=x\n"),
            Parsed::default()
        );
    }

    #[test]
    fn invalid_utf8_in_values_is_replaced() {
        let raw =
            b"-------- CONFIG BEGIN --------\nCommandLine=ab\xffcd\n-------- CONFIG END --------";
        assert_eq!(parse(raw).config[0].1, "ab\u{fffd}cd");
    }

    #[test]
    fn caps_pairs_and_value_length() {
        let mut raw = b"-------- CONFIG BEGIN --------\n".to_vec();
        for i in 0..200 {
            raw.extend(format!("K{i}=v\n").bytes());
        }
        raw.extend(b"-------- CONFIG END --------");
        assert_eq!(parse(&raw).config.len(), MAX_PAIRS);

        let long = format!(
            "-------- CONFIG BEGIN --------\nK={}\n-------- CONFIG END --------",
            "x".repeat(10_000)
        );
        assert_eq!(parse(long.as_bytes()).config[0].1.len(), MAX_VALUE_CHARS);
    }
}
