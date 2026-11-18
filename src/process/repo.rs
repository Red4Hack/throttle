//! `INFO REPO <rev> <url> <prefix>` records in SourceMod/Accelerator symbol
//! files, and the GitHub links built from them.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    /// Source path prefix this repository covers.
    pub prefix: String,
    pub url: String,
    pub rev: String,
}

/// All repos in a symbol file, most specific (longest/greatest) prefix first,
/// so submodules win over their parent repository.
pub fn parse(sym: &[u8]) -> Vec<Repo> {
    let mut repos = BTreeMap::new();
    for line in sym.split(|&b| b == b'\n') {
        if !line.starts_with(b"INFO REPO ") {
            continue;
        }
        let line = String::from_utf8_lossy(line);
        let parts: Vec<&str> = line.trim().splitn(5, ' ').collect();
        if parts.len() < 5 || parts[4].is_empty() {
            continue;
        }
        repos.insert(
            parts[4].to_string(),
            Repo {
                prefix: parts[4].to_string(),
                url: parts[3].to_string(),
                rev: parts[2].to_string(),
            },
        );
    }
    repos.into_values().rev().collect()
}

fn safe_rev(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() <= 64
        && rev
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

fn safe_url(url: &str) -> bool {
    url.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.' | b'_' | b'~' | b'/' | b':' | b'%' | b'@' | b'+'
            )
    })
}

fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 1);
    if !path.starts_with('/') {
        out.push('/');
    }
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A GitHub permalink for `file:line`, if one of the repos covers the file.
/// The symbol file is attacker-supplied, so only plain github.com URLs and
/// conservative revisions are accepted and the path is percent-encoded.
pub fn source_url(repos: &[Repo], file: &str, line: u32) -> Option<String> {
    for repo in repos {
        if !file.starts_with(&repo.prefix) {
            continue;
        }
        let mut url = repo.url.replace("git@github.com:", "https://github.com/");
        if !url.starts_with("https://github.com/") {
            continue;
        }
        if let Some(stripped) = url.strip_suffix(".git") {
            url = stripped.to_string();
        }
        if !safe_url(&url) || !safe_rev(&repo.rev) {
            continue;
        }
        let path = file[repo.prefix.len()..].replace('\\', "/");
        return Some(format!(
            "{url}/blob/{}{}#L{line}",
            repo.rev,
            encode_path(&path)
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYM: &[u8] = b"MODULE Linux x86_64 AB x.so\n\
        INFO REPO aaaa1111 git@github.com:alliedmodders/sourcemod.git /home/build/sourcemod\n\
        INFO REPO bbbb2222 https://github.com/alliedmodders/sourcemod.git /home/build/sourcemod/sourcepawn\n\
        INFO REPO cccc3333 https://gitlab.com/evil/repo.git /home/build/other\n\
        INFO REPO short\n\
        FUNC 1000 10 0 main\n";

    #[test]
    fn parses_and_orders_most_specific_first() {
        let repos = parse(SYM);
        assert_eq!(repos.len(), 3);
        assert_eq!(repos[0].prefix, "/home/build/sourcemod/sourcepawn");
        assert_eq!(repos[1].prefix, "/home/build/sourcemod");
    }

    #[test]
    fn builds_github_permalinks() {
        let repos = parse(SYM);
        assert_eq!(
            source_url(&repos, "/home/build/sourcemod/core/smn.cpp", 12).as_deref(),
            Some("https://github.com/alliedmodders/sourcemod/blob/aaaa1111/core/smn.cpp#L12")
        );
        // The submodule wins over the parent.
        assert_eq!(
            source_url(&repos, "/home/build/sourcemod/sourcepawn/vm/a b.cpp", 3).as_deref(),
            Some("https://github.com/alliedmodders/sourcemod/blob/bbbb2222/vm/a%20b.cpp#L3")
        );
    }

    #[test]
    fn refuses_other_hosts_and_unsafe_values() {
        let repos = parse(SYM);
        assert_eq!(source_url(&repos, "/home/build/other/x.cpp", 1), None);
        assert_eq!(source_url(&repos, "/elsewhere/x.cpp", 1), None);

        let evil = parse(b"INFO REPO a\"onclick=x https://github.com/a/b /p\n");
        assert_eq!(source_url(&evil, "/p/x.cpp", 1), None);
        let evil = parse(b"INFO REPO abc https://github.com/a/b\"x /p\n");
        assert_eq!(source_url(&evil, "/p/x.cpp", 1), None);
    }
}
