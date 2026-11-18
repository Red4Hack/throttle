//! Notices: banners attached to a crash while it is processed ("known engine
//! bug", "outdated server", ...), chosen by declarative rules.
//!
//! The PHP version stored a raw SQL `SELECT` per notice and glued them together
//! with `UNION ALL`. Here a rule is data (TOML in the config, JSON in the
//! database) and is evaluated in Rust: nothing a rule contains is ever executed
//! as SQL.
//!
//! A notice whose id starts with `nosteam-` has one more effect: the owner+IP
//! it was attached to is turned away for [`NOSTEAM_DAYS`] days (see ingest).

use std::collections::{BTreeMap, HashSet};

use anyhow::bail;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::SqlitePool;

pub const NOSTEAM_PREFIX: &str = "nosteam-";
pub const NOSTEAM_DAYS: i64 = 30;

const SEVERITIES: &[&str] = &["info", "warning", "danger"];
const MAX_WITHIN: u32 = 64;
const MAX_PATTERN_CHARS: usize = 200;
const MAX_METADATA_KEYS: usize = 16;

/// A notice as written in the configuration.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NoticeDef {
    pub id: String,
    /// `info`, `warning` or `danger`.
    pub severity: String,
    pub text: String,
    pub rule: Rule,
}

/// Every condition that is present must hold. Patterns use `*` (any run of
/// characters) and `?` (one character).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    /// One of the top frames of the crashing thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameRule>,
    /// Metadata values (`Map`, `GameDirectory`, `SourceModVersion`, ...) by key.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// The server's command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    /// Some loaded module (case-insensitive) matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_loaded: Option<String>,
    /// No loaded module matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_missing: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct FrameRule {
    /// Module name, case-insensitive (`engine*.so`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Function name, case-sensitive (`Sys_Error*`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// How many frames from the top to look at (default 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub within: Option<u32>,
}

impl Rule {
    fn is_empty(&self) -> bool {
        self.frame.is_none()
            && self.metadata.is_empty()
            && self.cmdline.is_none()
            && self.module_loaded.is_none()
            && self.module_missing.is_none()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.is_empty() {
            bail!("a rule needs at least one condition");
        }
        if let Some(f) = &self.frame {
            if f.module.is_none() && f.function.is_none() {
                bail!("frame needs a module or a function");
            }
            if !(1..=MAX_WITHIN).contains(&f.within.unwrap_or(1)) {
                bail!("frame.within must be between 1 and {MAX_WITHIN}");
            }
        }
        if self.metadata.len() > MAX_METADATA_KEYS {
            bail!("at most {MAX_METADATA_KEYS} metadata conditions");
        }
        let patterns = self
            .frame
            .iter()
            .flat_map(|f| [&f.module, &f.function])
            .flatten()
            .chain(self.metadata.values())
            .chain(self.cmdline.iter())
            .chain(self.module_loaded.iter())
            .chain(self.module_missing.iter());
        for p in patterns {
            if p.is_empty() || p.chars().count() > MAX_PATTERN_CHARS {
                bail!("patterns must be 1 to {MAX_PATTERN_CHARS} characters");
            }
        }
        Ok(())
    }
}

impl NoticeDef {
    pub fn validate(&self) -> anyhow::Result<()> {
        let id_ok = !self.id.is_empty()
            && self.id.len() <= 100
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !id_ok {
            bail!(
                "notice id {:?} must be 1-100 characters of a-z, 0-9, '-', '_' or '.'",
                self.id
            );
        }
        if !SEVERITIES.contains(&self.severity.as_str()) {
            bail!("notice {}: severity must be one of {SEVERITIES:?}", self.id);
        }
        if self.text.trim().is_empty() || self.text.chars().count() > 1000 {
            bail!("notice {}: text must be 1 to 1000 characters", self.id);
        }
        self.rule
            .validate()
            .map_err(|e| anyhow::anyhow!("notice {}: {e}", self.id))
    }
}

/// Validate a whole list: each notice, and ids must be unique.
pub fn validate_all(defs: &[NoticeDef]) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for d in defs {
        d.validate()?;
        if !seen.insert(d.id.as_str()) {
            bail!("notice id {:?} is used twice", d.id);
        }
    }
    Ok(())
}

/// Glob match with `*` and `?`; linear-ish (no exponential backtracking).
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn glob_ci(pattern: &str, text: &str) -> bool {
    glob(&pattern.to_lowercase(), &text.to_lowercase())
}

/// What a rule is checked against: one processed crash.
pub struct Subject<'a> {
    /// `(module, function)` of the crashing thread's frames, top first.
    pub frames: &'a [(&'a str, &'a str)],
    pub modules: &'a [&'a str],
    pub metadata: &'a Map<String, Value>,
    pub cmdline: Option<&'a str>,
}

pub fn matches(rule: &Rule, s: &Subject) -> bool {
    if let Some(f) = &rule.frame {
        let within = f.within.unwrap_or(1) as usize;
        let hit = s.frames.iter().take(within).any(|(module, function)| {
            f.module.as_deref().is_none_or(|p| glob_ci(p, module))
                && f.function.as_deref().is_none_or(|p| glob(p, function))
        });
        if !hit {
            return false;
        }
    }
    for (key, pattern) in &rule.metadata {
        let value = match s.metadata.get(key) {
            Some(Value::String(v)) => v.clone(),
            Some(other) => other.to_string(),
            None => return false,
        };
        if !glob(pattern, &value) {
            return false;
        }
    }
    if let Some(p) = &rule.cmdline
        && !s.cmdline.is_some_and(|c| glob(p, c))
    {
        return false;
    }
    if let Some(p) = &rule.module_loaded
        && !s.modules.iter().any(|m| glob_ci(p, m))
    {
        return false;
    }
    if let Some(p) = &rule.module_missing
        && s.modules.iter().any(|m| glob_ci(p, m))
    {
        return false;
    }
    true
}

/// Ids of the rules that match.
pub fn matching(rules: &[(String, Rule)], s: &Subject) -> Vec<String> {
    rules
        .iter()
        .filter(|(_, r)| matches(r, s))
        .map(|(id, _)| id.clone())
        .collect()
}

/// Make the `notice` table equal to the configuration: new and changed
/// notices are written, notices no longer configured are deleted (their
/// `crashnotice` rows go with them).
pub async fn sync(db: &SqlitePool, defs: &[NoticeDef]) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    for d in defs {
        let rule = serde_json::to_string(&d.rule).unwrap_or_else(|_| "{}".into());
        sqlx::query(
            "INSERT INTO notice (id, severity, text, rule) VALUES (?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET severity = excluded.severity, text = excluded.text, rule = excluded.rule",
        )
        .bind(&d.id)
        .bind(&d.severity)
        .bind(&d.text)
        .bind(rule)
        .execute(&mut *tx)
        .await?;
    }
    let existing: Vec<String> = sqlx::query_scalar("SELECT id FROM notice")
        .fetch_all(&mut *tx)
        .await?;
    for id in existing
        .iter()
        .filter(|id| !defs.iter().any(|d| &d.id == *id))
    {
        sqlx::query("DELETE FROM notice WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

/// The rules in the database. Broken ones are skipped (and logged), never fatal.
pub async fn load(db: &SqlitePool) -> sqlx::Result<Vec<(String, Rule)>> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT id, rule FROM notice ORDER BY id")
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, json)| match serde_json::from_str::<Rule>(&json) {
            Ok(rule) if rule.validate().is_ok() => Some((id, rule)),
            _ => {
                tracing::warn!(%id, "ignoring a notice whose rule is invalid");
                None
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use serde_json::json;

    fn subject<'a>(
        frames: &'a [(&'a str, &'a str)],
        modules: &'a [&'a str],
        metadata: &'a Map<String, Value>,
        cmdline: Option<&'a str>,
    ) -> Subject<'a> {
        Subject {
            frames,
            modules,
            metadata,
            cmdline,
        }
    }

    fn rule(toml: &str) -> Rule {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn globs() {
        for (p, t, expected) in [
            ("*", "", true),
            ("*", "anything", true),
            ("engine*.so", "engine_srv.so", true),
            ("engine*.so", "engine.so", true),
            ("engine*.so", "engine.dll", false),
            ("Sys_Error*", "Sys_Error_Internal", true),
            ("Sys_Error", "Sys_Error_Internal", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("*a*b*c*", "xxaxxbxxcxx", true),
            ("*a*b*c*", "xxaxxcxxbxx", false),
            ("", "", true),
            ("", "x", false),
            ("é*", "éclair", true),
        ] {
            assert_eq!(glob(p, t), expected, "{p:?} vs {t:?}");
        }
        // No exponential blow-up: this has to fail fast, not after 2^100 steps.
        assert!(!glob(&format!("{}b", "a*".repeat(100)), &"a".repeat(1000)));
        assert!(glob(&"a*".repeat(100), &"a".repeat(100)));
    }

    #[test]
    fn frame_rules_look_at_the_top_frames_only() {
        let frames = [
            ("engine_srv.so", "Sys_Error_Internal"),
            ("server.so", "Think"),
            ("tier0.so", "x"),
        ];
        let meta = Map::new();
        let s = subject(&frames, &[], &meta, None);

        assert!(matches(
            &rule("frame = { module = \"ENGINE*.so\", function = \"Sys_Error*\" }"),
            &s
        ));
        assert!(
            !matches(&rule("frame = { function = \"Think\" }"), &s),
            "within defaults to 1"
        );
        assert!(matches(
            &rule("frame = { function = \"Think\", within = 2 }"),
            &s
        ));
        assert!(!matches(
            &rule("frame = { function = \"x\", within = 2 }"),
            &s
        ));
        assert!(
            !matches(&rule("frame = { function = \"sys_error*\" }"), &s),
            "functions are case-sensitive"
        );
    }

    #[test]
    fn all_conditions_must_hold() {
        let meta =
            json!({ "Map": "de_dust2", "SourceModVersion": "1.9.0.6000", "HasConsoleLog": true });
        let meta = meta.as_object().unwrap();
        let s = subject(
            &[],
            &["engine_srv.so", "Server.so"],
            meta,
            Some("./srcds +map de_dust2 -nomaster"),
        );

        assert!(matches(&rule("metadata = { Map = \"de_*\" }"), &s));
        assert!(
            matches(&rule("metadata = { HasConsoleLog = \"true\" }"), &s),
            "non-strings are compared as text"
        );
        assert!(!matches(&rule("metadata = { Map = \"cs_*\" }"), &s));
        assert!(!matches(&rule("metadata = { Missing = \"*\" }"), &s));
        assert!(matches(&rule("cmdline = \"*-nomaster*\""), &s));
        assert!(!matches(
            &rule("cmdline = \"*-nomaster*\""),
            &subject(&[], &[], meta, None)
        ));
        assert!(matches(&rule("module_loaded = \"server.so\""), &s));
        assert!(matches(&rule("module_missing = \"metamod*\""), &s));
        assert!(!matches(&rule("module_missing = \"server.so\""), &s));

        assert!(matches(
            &rule("module_loaded = \"server.so\"\nmetadata = { Map = \"de_*\" }"),
            &s
        ));
        assert!(!matches(
            &rule("module_loaded = \"server.so\"\nmetadata = { Map = \"cs_*\" }"),
            &s
        ));
    }

    #[test]
    fn invalid_rules_and_notices_are_rejected() {
        for bad in [
            "",
            "frame = {}",
            "frame = { function = \"x\", within = 0 }",
            "frame = { function = \"x\", within = 65 }",
            "cmdline = \"\"",
        ] {
            assert!(rule(bad).validate().is_err(), "{bad:?}");
        }
        let long = format!("cmdline = \"{}\"", "x".repeat(201));
        assert!(rule(&long).validate().is_err());
        assert!(toml::from_str::<Rule>("unknown = 1").is_err());

        let def = |id: &str, severity: &str, text: &str| NoticeDef {
            id: id.into(),
            severity: severity.into(),
            text: text.into(),
            rule: rule("cmdline = \"*\""),
        };
        assert!(def("ok-1", "warning", "text").validate().is_ok());
        for (id, sev, text) in [
            ("", "info", "t"),
            ("a b", "info", "t"),
            ("a/b", "info", "t"),
            ("a", "fatal", "t"),
            ("a", "info", "  "),
        ] {
            assert!(
                def(id, sev, text).validate().is_err(),
                "{id:?} {sev:?} {text:?}"
            );
        }
        assert!(validate_all(&[def("a", "info", "t"), def("a", "info", "t")]).is_err());
    }

    #[tokio::test]
    async fn sync_makes_the_table_equal_to_the_config() {
        let db = db::open_memory().await.unwrap();
        let def = |id: &str, text: &str| NoticeDef {
            id: id.into(),
            severity: "info".into(),
            text: text.into(),
            rule: rule("cmdline = \"*\""),
        };

        sync(&db, &[def("a", "first"), def("b", "x")])
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO crash (id, created_at, ip) VALUES ('abcdefghijkl', 1, x'01020304')",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO crashnotice (crash, notice) VALUES ('abcdefghijkl', 'b')")
            .execute(&db)
            .await
            .unwrap();

        sync(&db, &[def("a", "changed")]).await.unwrap();
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT id, text FROM notice")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(rows, [("a".to_string(), "changed".to_string())]);
        let attached: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crashnotice")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(attached, 0, "removing a notice detaches it");

        let loaded = load(&db).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1.cmdline.as_deref(), Some("*"));
    }

    #[tokio::test]
    async fn broken_rules_in_the_database_are_skipped() {
        let db = db::open_memory().await.unwrap();
        for (id, rule) in [
            ("empty", "{}"),
            ("junk", "not json"),
            ("unknown", "{\"sql\":\"SELECT 1\"}"),
            ("fine", "{\"cmdline\":\"*\"}"),
        ] {
            sqlx::query("INSERT INTO notice (id, severity, text, rule) VALUES (?, 'info', 't', ?)")
                .bind(id)
                .bind(rule)
                .execute(&db)
                .await
                .unwrap();
        }
        let loaded = load(&db).await.unwrap();
        assert_eq!(
            loaded.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            ["fine"]
        );
    }
}
