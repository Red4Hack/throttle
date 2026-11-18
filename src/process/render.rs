//! Frame rendering, ported from the PHP `CrashProcessCommand` so that rendered
//! strings, and therefore stack hashes, stay comparable with old reports.

use sha2::{Digest, Sha256};

const MAX_FUNCTION_BYTES: usize = 512;
const PLACEHOLDER: &[u8] = b"[...]";

/// Breakpad's machine-readable output drops these from every field.
pub fn strip_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '|' | '\n' | '\r'))
        .collect()
}

/// Last path component, accepting both `/` and `\`.
pub fn basename(path: &str) -> &str {
    path.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
}

/// Template-heavy C++ names can be kilobytes long. Repeatedly replace the
/// contents of the deepest `<...>` level with a placeholder until the name fits.
/// Same algorithm (and same quirks) as the PHP version.
pub fn shorten(name: &str) -> String {
    let mut data = name.as_bytes().to_vec();

    while data.len() > MAX_FUNCTION_BYTES {
        let mut depth: i32 = 0;
        let mut watermark: i32 = 0;
        for &c in &data {
            match c {
                b'<' => {
                    depth += 1;
                    watermark = watermark.max(depth);
                }
                b'>' => depth -= 1,
                _ => {}
            }
        }

        // `depth` deliberately carries over from the first pass, as in PHP.
        let mut out = Vec::with_capacity(data.len());
        let mut cursor = 0;
        for (i, &c) in data.iter().enumerate() {
            match c {
                b'<' => {
                    depth += 1;
                    out.extend_from_slice(&data[cursor..i]);
                    cursor = i;
                }
                b'>' => {
                    if depth >= watermark {
                        out.extend_from_slice(PLACEHOLDER);
                        cursor = i + 1;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        out.extend_from_slice(&data[cursor..]);

        if out == data {
            // Nothing left to cut.
            data = PLACEHOLDER.to_vec();
            break;
        }
        data = out;
    }

    let text = String::from_utf8_lossy(&data).into_owned();
    if data == PLACEHOLDER {
        text
    } else {
        // Put the angle brackets back around the placeholders.
        text.replace("[...]", "<[...]>")
    }
}

pub struct FrameParts<'a> {
    pub module: &'a str,
    pub function: &'a str,
    /// Full source path as recorded in the symbol file.
    pub file: &'a str,
    pub line: u32,
    /// `0x...`
    pub offset: &'a str,
}

/// `module!function [file.cc:42 + 0x1f]`, falling back to less detail when
/// symbols are missing.
pub fn render(p: &FrameParts) -> String {
    if !p.file.is_empty() {
        let file = basename(p.file);
        format!(
            "{}!{} [{}:{} + {}]",
            p.module, p.function, file, p.line, p.offset
        )
    } else if !p.function.is_empty() {
        format!("{}!{} + {}", p.module, p.function, p.offset)
    } else if !p.module.is_empty() {
        format!("{} + {}", p.module, p.offset)
    } else {
        p.offset.to_string()
    }
}

/// First 8 hex chars of SHA-256 for each of the given rendered frames,
/// concatenated. `None` when there are no frames to hash.
pub fn stackhash<'a>(rendered: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut out = String::new();
    for r in rendered {
        let digest = Sha256::digest(r.as_bytes());
        out.push_str(&hex::encode(&digest[..4]));
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_handles_both_separators() {
        assert_eq!(basename("c:\\src\\test_app.cc"), "test_app.cc");
        assert_eq!(basename("/a/b/c.cpp"), "c.cpp");
        assert_eq!(basename("plain"), "plain");
        assert_eq!(basename("dir/"), "dir");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn short_names_are_untouched() {
        assert_eq!(
            shorten("std::vector<int>::push_back"),
            "std::vector<int>::push_back"
        );
    }

    #[test]
    fn long_names_lose_their_deepest_template_arguments() {
        let name = format!("f<{}<{}>>", "x".repeat(300), "y".repeat(300));
        assert!(name.len() > MAX_FUNCTION_BYTES);
        assert_eq!(shorten(&name), format!("f<{}<[...]>>", "x".repeat(300)));
    }

    #[test]
    fn long_names_that_cannot_be_cut_become_a_placeholder() {
        assert_eq!(shorten(&"a".repeat(600)), "[...]");
    }

    #[test]
    fn shortening_terminates_on_unbalanced_brackets() {
        for name in [
            format!("<{}", "<".repeat(600)),
            format!("{}>", ">".repeat(600)),
            "<>".repeat(400),
        ] {
            assert!(
                shorten(&name).len() <= MAX_FUNCTION_BYTES + 64,
                "{}",
                name.len()
            );
        }
    }

    #[test]
    fn rendering_degrades_with_missing_symbols() {
        let p = |module, function, file, offset| FrameParts {
            module,
            function,
            file,
            line: 42,
            offset,
        };
        assert_eq!(
            render(&p("engine.so", "Sys_Error", "/src/sys.cpp", "0x1f")),
            "engine.so!Sys_Error [sys.cpp:42 + 0x1f]"
        );
        assert_eq!(
            render(&p("engine.so", "Sys_Error", "", "0x1f")),
            "engine.so!Sys_Error + 0x1f"
        );
        assert_eq!(render(&p("engine.so", "", "", "0x1f")), "engine.so + 0x1f");
        assert_eq!(render(&p("", "", "", "0x400000")), "0x400000");
    }

    #[test]
    fn stackhash_is_8_hex_chars_per_frame() {
        // SHA-256("abc") = ba7816bf 8f01cfea ...
        assert_eq!(stackhash(["abc"]).as_deref(), Some("ba7816bf"));
        assert_eq!(
            stackhash(["abc", "abc"]).as_deref(),
            Some("ba7816bfba7816bf")
        );
        assert_eq!(stackhash([] as [&str; 0]), None);
    }

    #[test]
    fn separators_are_stripped() {
        assert_eq!(strip_separators("operator|(a\nb)"), "operator(ab)");
    }
}
