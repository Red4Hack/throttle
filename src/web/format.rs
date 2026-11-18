//! Small formatting helpers shared by templates and handlers.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Command-line arguments whose value is a secret.
const SENSITIVE: &[&str] = &["sv_password", "rcon_password", "sv_setsteamaccount"];
const ACRONYMS: &[&str] = &["url", "lsb", "pid", "guid", "id", "mvp"];

/// `2023-11-14 22:13:20 UTC`, without a date library.
pub fn utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn plural(n: i64, unit: &str) -> String {
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

/// "just now", "5 minutes ago", ..., then the plain date.
pub fn reldate(ts: i64, now: i64) -> String {
    let diff = now - ts;
    match diff {
        d if d < 60 => "just now".into(),
        d if d < 3600 => plural(d / 60, "minute"),
        d if d < 86_400 => plural(d / 3600, "hour"),
        d if d < 30 * 86_400 => plural(d / 86_400, "day"),
        _ => utc(ts)[..10].to_string(),
    }
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// The raw 4 or 16 bytes stored in `crash.ip`, as text.
pub fn ip_string(bytes: &[u8]) -> String {
    if let Ok(v4) = <[u8; 4]>::try_from(bytes) {
        Ipv4Addr::from(v4).to_string()
    } else if let Ok(v6) = <[u8; 16]>::try_from(bytes) {
        Ipv6Addr::from(v6).to_string()
    } else {
        String::new()
    }
}

fn word(w: &str) -> String {
    let lower = w.to_lowercase();
    if ACRONYMS.contains(&lower.as_str()) {
        return lower.to_uppercase();
    }
    let mut chars = lower.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// `SourceModVersion` -> `SourceMod Version`, `Steam_PatchVersion` -> `Steam Patch Version`.
pub fn label(key: &str) -> String {
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in key.chars() {
        if matches!(c, '_' | '-' | '.') || c.is_whitespace() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower && !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_lowercase();
        cur.push(c);
    }
    if !cur.is_empty() {
        words.push(cur);
    }

    let label = words.iter().map(|w| word(w)).collect::<Vec<_>>().join(" ");
    let fixed = match label.as_str() {
        "Prod" => Some("Host Product"),
        "Ver" => Some("Host Version"),
        "Rept" => Some("Reporter"),
        "Ptime" => Some("Process Time"),
        "Source Mod Path" => Some("SourceMod Path"),
        "Source Mod Version" => Some("SourceMod Version"),
        _ => None,
    };
    fixed.map_or(label, str::to_string)
}

/// Hide the value of password-like launch arguments. Whatever follows one is
/// masked even if it looks like another flag: better too much than a leak.
pub fn mask_cmdline(cmd: &str) -> String {
    let mut out = Vec::new();
    let mut mask_next = false;
    for token in cmd.split_whitespace() {
        if mask_next {
            out.push("*****".to_string());
            mask_next = false;
            continue;
        }
        out.push(token.to_string());
        let name = token.trim_start_matches(['+', '-']).to_ascii_lowercase();
        mask_next = SENSITIVE.contains(&name.as_str());
    }
    out.join(" ")
}

fn version_parts(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|p| {
            p.trim()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .unwrap_or(0)
        })
        .collect()
}

/// A frame of the SourcePawn JIT calling into a plugin, as rendered by the
/// processor: `sourcepawn.jit.x86!sp::PluginContext::Invoke [...]`.
pub fn is_sourcepawn_invoke(rendered: &str) -> bool {
    let Some(rest) = rendered.strip_prefix("sourcepawn.jit.") else {
        return false;
    };
    let Some((module, function)) = rest.split_once('!') else {
        return false;
    };
    let Some(function) = function.strip_prefix("sp::") else {
        return false;
    };
    match function.split_once("::") {
        Some((class, tail)) => {
            !module.is_empty()
                && !class.is_empty()
                && !class.contains(':')
                && tail.starts_with("Invoke")
        }
        None => false,
    }
}

/// Is dotted version `have` older than `latest`?
pub fn version_older(have: &str, latest: &str) -> bool {
    let (mut a, mut b) = (version_parts(have), version_parts(latest));
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    a < b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(-1), "1969-12-31 23:59:59 UTC");
    }

    #[test]
    fn relative_dates() {
        let now = 1_700_000_000;
        assert_eq!(reldate(now - 30, now), "just now");
        assert_eq!(reldate(now + 500, now), "just now");
        assert_eq!(reldate(now - 60, now), "1 minute ago");
        assert_eq!(reldate(now - 120, now), "2 minutes ago");
        assert_eq!(reldate(now - 7200, now), "2 hours ago");
        assert_eq!(reldate(now - 3 * 86_400, now), "3 days ago");
        assert_eq!(reldate(now - 40 * 86_400, now), "2023-10-05");
    }

    #[test]
    fn sizes_and_addresses() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(ip_string(&[203, 0, 113, 9]), "203.0.113.9");
        assert_eq!(ip_string(&[0; 16]), "::");
        assert_eq!(ip_string(&[1, 2, 3]), "");
    }

    #[test]
    fn labels() {
        assert_eq!(label("Map"), "Map");
        assert_eq!(label("SourceModVersion"), "SourceMod Version");
        assert_eq!(label("Steam_PatchVersion"), "Steam Patch Version");
        assert_eq!(label("MapID"), "Map ID");
        assert_eq!(label("ServerURL"), "Server URL");
        assert_eq!(label("Prod"), "Host Product");
        assert_eq!(label("Rept"), "Reporter");
        assert_eq!(label(""), "");
    }

    #[test]
    fn passwords_are_masked() {
        assert_eq!(
            mask_cmdline(
                "./srcds +map de_dust2 +sv_password hunter2 -rcon_password x  +sv_setsteamaccount ABC"
            ),
            "./srcds +map de_dust2 +sv_password ***** -rcon_password ***** +sv_setsteamaccount *****"
        );
        assert_eq!(mask_cmdline("+sv_password"), "+sv_password");
        assert_eq!(mask_cmdline(""), "");
    }

    #[test]
    fn versions() {
        assert!(version_older("2.4.2", "2.4.3"));
        assert!(!version_older("2.4.3", "2.4.3"));
        assert!(!version_older("2.10", "2.9"));
        assert!(version_older("2.4", "2.4.1"));
        assert!(!version_older("garbage", "0"));
    }
}

#[cfg(test)]
mod sourcepawn_tests {
    use super::*;

    #[test]
    fn sourcepawn_invoke_frames() {
        for (frame, expected) in [
            ("sourcepawn.jit.x86!sp::PluginContext::Invoke + 0x1f", true),
            (
                "sourcepawn.jit.x64!sp::Environment::Invoke(int) [env.cpp:9 + 0x4]",
                true,
            ),
            ("sourcepawn.jit.x86!sp::PluginContext::Other + 0x1f", false),
            ("sourcepawn.jit.x86!sp::Invoke + 0x1f", false),
            ("sourcepawn.jit.x86!sp:::Invoke", false),
            ("sourcepawn.jit.!sp::A::Invoke", false),
            ("server.so!sp::PluginContext::Invoke", false),
            ("sourcepawn.jit.x86 + 0x10", false),
            ("", false),
        ] {
            assert_eq!(is_sourcepawn_invoke(frame), expected, "{frame}");
        }
    }
}
