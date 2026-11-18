//! Runtime configuration (TOML). Every key has a default, so a missing file
//! means "run with defaults"; unknown keys are rejected so typos fail loudly.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    /// The public host name (`throttle.example.com`, optionally with a port). When
    /// unset, the Steam login and the CSRF check use the `Host` the browser
    /// connected to, so `localhost`, `0.0.0.0` or a LAN address all work. Pin it
    /// in production (and behind a reverse proxy) so only that name is trusted.
    pub hostname: Option<String>,
    /// The site is served over HTTPS (directly or behind a TLS proxy): Secure
    /// cookies and https:// Steam login URLs.
    pub https: bool,
    /// Everything mutable lives here: database, dumps, symbols, secret key.
    pub data_dir: PathBuf,
    /// Only requests coming from these addresses may set X-Forwarded-For.
    pub trusted_proxies: Vec<IpAddr>,
    pub maintenance_message: Option<String>,
    pub show_version: bool,
    /// Latest Accelerator version; older reports get an "outdated" warning.
    pub accelerator_version: Option<String>,
    pub steam_api_key: Option<String>,
    /// Enables `GET /metrics` for `Authorization: Bearer <token>` (min. 16 chars). Off when unset.
    pub metrics_token: Option<String>,
    /// SteamID64 lists.
    pub admins: Vec<u64>,
    pub developers: Vec<u64>,
    pub limits: Limits,
    pub retention: Retention,
    pub processing: Processing,
    /// Banners attached to crashes by declarative rules (`[[notices]]`).
    pub notices: Vec<crate::notice::NoticeDef>,
    /// Download missing symbols from HTTP symbol servers (off without servers).
    pub symbol_fetch: SymbolFetch,
    /// Optional deep analysis page (off without `carburetor.path`).
    pub carburetor: Carburetor,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Largest minidump accepted.
    pub max_dump_bytes: u64,
    /// Largest metadata file accepted.
    pub max_metadata_bytes: u64,
    /// Largest (uncompressed) symbol file accepted.
    pub max_symbol_bytes: u64,
    /// Crashes accepted per owner+IP inside `rate_window_secs`.
    pub rate_limit: u32,
    pub rate_window_secs: u64,
    /// Above this many unprocessed crashes, presubmit asks for metadata only.
    pub queue_watermark: u32,
    /// A stackhash seen this many times in the last 24h is metadata-only.
    /// 0 disables the check.
    pub dedupe_threshold: u32,
    /// The same crash (same owner, or same address when anonymous, same fingerprint)
    /// within this many days is counted on the crash already stored, not stored again.
    /// 0 disables the check.
    pub repeat_window_days: u32,
    /// Total size of stored dumps. Past this, the oldest unviewed ones are evicted.
    pub disk_quota_bytes: u64,
    /// Below this much free disk, uploads get HTTP 503.
    pub disk_min_free_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Retention {
    /// Crashes older than this (since last view, or creation) are deleted.
    pub max_age_days: u32,
    /// Keep at most this many unviewed crashes per Steam owner + IP.
    pub keep_per_owner: u32,
    /// Same, for anonymous uploads (per IP).
    pub keep_per_anonymous_ip: u32,
    /// Deletions per cleanup batch (bounds lock time; cleanup loops until done).
    pub batch_size: u32,
    /// Seconds between retention passes (age, per-owner caps, disk quota).
    pub interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            hostname: None,
            https: false,
            data_dir: PathBuf::from("data"),
            trusted_proxies: Vec::new(),
            maintenance_message: None,
            show_version: true,
            accelerator_version: None,
            steam_api_key: None,
            metrics_token: None,
            admins: Vec::new(),
            developers: Vec::new(),
            limits: Limits::default(),
            retention: Retention::default(),
            processing: Processing::default(),
            notices: Vec::new(),
            symbol_fetch: SymbolFetch::default(),
            carburetor: Carburetor::default(),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_dump_bytes: 64 * MIB,
            max_metadata_bytes: 2 * MIB,
            max_symbol_bytes: 512 * MIB,
            rate_limit: 12,
            rate_window_secs: 3600,
            queue_watermark: 5000,
            dedupe_threshold: 50,
            repeat_window_days: 30,
            disk_quota_bytes: 50 * GIB,
            disk_min_free_bytes: GIB,
        }
    }
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            max_age_days: 90,
            keep_per_owner: 100,
            keep_per_anonymous_ip: 50,
            batch_size: 500,
            interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Processing {
    /// Parallel crash processors; 0 = half of the CPU cores.
    pub workers: usize,
    /// A crash that keeps failing (or killing the server) is given up on after this many tries.
    pub max_attempts: u32,
    pub timeout_secs: u64,
    /// Directories under `data_dir/symbols`, searched in order. Put trusted
    /// stores before `public`: anything anyone uploads lands in `public`.
    pub symbol_stores: Vec<String>,
    /// Memory for parsed symbol files shared between dumps, in MiB (an
    /// estimate: a parsed file takes about 4x the size of its text). 0 = off.
    pub symbol_cache_mib: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SymbolFetch {
    /// Asked in order; the first one that has a file wins.
    pub servers: Vec<SymbolServer>,
    pub interval_secs: u64,
    /// Modules looked up per pass.
    pub batch_size: u32,
    /// A module no server has is asked for again after this many days.
    pub retry_days: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolServer {
    /// Where downloads are stored; must be listed in `processing.symbol_stores`.
    pub store: String,
    /// Base URL; files live at `<url>/<name>/<build id>/<stem>.sym`.
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Carburetor {
    /// The `carburetor` executable (github.com/asherkin/carburetor), an absolute path.
    pub path: Option<PathBuf>,
    pub timeout_secs: u64,
    /// Analyses running at once; more are told to try again later.
    pub max_concurrent: usize,
    /// A run printing more than this is killed.
    pub max_output_bytes: u64,
}

impl Default for Carburetor {
    fn default() -> Self {
        Self {
            path: None,
            timeout_secs: 120,
            max_concurrent: 2,
            max_output_bytes: 64 * MIB,
        }
    }
}

impl Carburetor {
    fn validate(&self) -> anyhow::Result<()> {
        if self.path.as_ref().is_some_and(|p| !p.is_absolute()) {
            bail!("carburetor.path must be an absolute path");
        }
        if self.timeout_secs == 0 || self.max_output_bytes == 0 {
            bail!(
                "carburetor.timeout_secs and carburetor.max_output_bytes must be greater than zero"
            );
        }
        if !(1..=16).contains(&self.max_concurrent) {
            bail!("carburetor.max_concurrent must be between 1 and 16");
        }
        Ok(())
    }
}

impl Default for SymbolFetch {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            interval_secs: 600,
            batch_size: 20,
            retry_days: 7,
        }
    }
}

impl SymbolFetch {
    fn validate(&self, stores: &[String]) -> anyhow::Result<()> {
        if self.interval_secs == 0 || self.batch_size == 0 || self.retry_days == 0 {
            bail!(
                "symbol_fetch.interval_secs, batch_size and retry_days must be greater than zero"
            );
        }
        for s in &self.servers {
            let http = s.url.starts_with("https://") || s.url.starts_with("http://");
            if !http || s.url.contains(char::is_whitespace) {
                bail!(
                    "symbol_fetch.servers: url must be an http(s) URL without spaces, got {:?}",
                    s.url
                );
            }
            if !stores.contains(&s.store) {
                bail!(
                    "symbol_fetch.servers: store {:?} must also be listed in processing.symbol_stores, \
                     otherwise its symbols would never be used",
                    s.store
                );
            }
        }
        Ok(())
    }
}

impl Default for Processing {
    fn default() -> Self {
        Self {
            workers: 0,
            max_attempts: 3,
            timeout_secs: 120,
            symbol_stores: vec!["public".into()],
            symbol_cache_mib: 256,
        }
    }
}

/// Something a browser puts in a `Host` header: a name or address, with an
/// optional port (`example.com`, `192.168.1.5:8080`, `[::1]:8080`). No path,
/// credentials, spaces or non-ASCII.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
}

impl Config {
    /// Load the configuration file at `path`, which has to exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the configuration file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(host) = &self.hostname
            && !valid_host(host)
        {
            bail!(
                "hostname must be a host name or address with an optional port, like \"throttle.example.com\" or \"192.168.1.5:8080\", got {host:?}"
            );
        }
        let l = &self.limits;
        if l.max_dump_bytes == 0 || l.max_metadata_bytes == 0 || l.max_symbol_bytes == 0 {
            bail!("limits.max_*_bytes must be greater than zero");
        }
        if l.rate_limit == 0 || l.rate_window_secs == 0 {
            bail!("limits.rate_limit and limits.rate_window_secs must be greater than zero");
        }
        if self.retention.batch_size == 0 || self.retention.interval_secs == 0 {
            bail!("retention.batch_size and retention.interval_secs must be greater than zero");
        }
        if self.metrics_token.as_ref().is_some_and(|t| t.len() < 16) {
            bail!("metrics_token must be at least 16 characters");
        }
        crate::notice::validate_all(&self.notices)?;
        self.symbol_fetch.validate(&self.processing.symbol_stores)?;
        self.carburetor.validate()?;
        let p = &self.processing;
        if p.max_attempts == 0 || p.timeout_secs == 0 {
            bail!("processing.max_attempts and processing.timeout_secs must be greater than zero");
        }
        for store in &p.symbol_stores {
            if store.is_empty()
                || store == "."
                || store == ".."
                || store.contains(['/', '\\', '\0'])
            {
                bail!(
                    "processing.symbol_stores entries must be plain directory names, got {store:?}"
                );
            }
        }
        Ok(())
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("throttle.sqlite")
    }

    pub fn dumps_dir(&self) -> PathBuf {
        self.data_dir.join("dumps")
    }

    pub fn symbols_dir(&self) -> PathBuf {
        self.data_dir.join("symbols")
    }

    pub fn secret_path(&self) -> PathBuf {
        self.data_dir.join("secret.key")
    }

    /// `dumps/<first two chars>/<id>.dmp`. `id` must already be a valid crash ID.
    pub fn dump_path(&self, id: &str) -> PathBuf {
        let bucket = id.get(..2).unwrap_or(id);
        self.dumps_dir().join(bucket).join(format!("{id}.dmp"))
    }

    pub fn meta_path(&self, id: &str) -> PathBuf {
        let bucket = id.get(..2).unwrap_or(id);
        self.dumps_dir()
            .join(bucket)
            .join(format!("{id}.meta.txt.gz"))
    }

    /// `http(s)://host`, no trailing slash: the address the site is reached at.
    /// The pinned `hostname` wins; otherwise the request's `Host` header, if it
    /// looks like a host (it is attacker-controlled input, so anything else is
    /// ignored); otherwise the address we listen on.
    pub fn origin(&self, host_header: Option<&str>) -> String {
        let scheme = if self.https { "https" } else { "http" };
        let host = match &self.hostname {
            Some(pinned) => pinned.clone(),
            None => host_header
                .filter(|h| valid_host(h))
                .map_or_else(|| self.listen.to_string(), str::to_string),
        };
        format!("{scheme}://{host}")
    }

    pub fn symbol_store_dirs(&self) -> Vec<PathBuf> {
        self.processing
            .symbol_stores
            .iter()
            .map(|s| self.symbols_dir().join(s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn empty_file_is_defaults() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg.limits.rate_limit, 12);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::parse("listn = \"0.0.0.0:80\"").is_err());
        assert!(Config::parse("[limits]\nrate_limt = 3").is_err());
    }

    #[test]
    fn zero_limits_are_rejected() {
        assert!(Config::parse("[limits]\nrate_limit = 0").is_err());
    }

    #[test]
    fn unsafe_symbol_stores_are_rejected() {
        for bad in ["\"..\"", "\"a/b\"", "\"\"", "\"/etc\"", "\"a\\\\b\""] {
            let toml = format!("[processing]\nsymbol_stores = [{bad}]");
            assert!(Config::parse(&toml).is_err(), "{bad}");
        }
        assert!(Config::parse("[processing]\nsymbol_stores = [\"official\", \"public\"]").is_ok());
    }

    /// Keeps deploy/config.example.toml in sync with the real schema.
    #[test]
    fn example_config_parses() {
        Config::parse(include_str!("../deploy/config.example.toml")).unwrap();
    }
}

#[cfg(test)]
mod deploy_tests {
    use super::*;

    #[test]
    fn container_config_parses() {
        let cfg = Config::parse(include_str!("../deploy/config.container.toml")).unwrap();
        assert_eq!(cfg.listen.port(), 8080);
    }

    #[test]
    fn metrics_token_and_interval_are_validated() {
        assert!(Config::parse("metrics_token = \"short\"").is_err());
        assert!(Config::parse("metrics_token = \"0123456789abcdef\"").is_ok());
        assert!(Config::parse("[retention]\ninterval_secs = 0").is_err());
    }
}

#[cfg(test)]
mod notice_config_tests {
    use super::*;

    #[test]
    fn notices_are_read_from_the_config() {
        let cfg = Config::parse(
            r#"
[[notices]]
id = "sys-error"
severity = "info"
text = "The engine aborted with an error message."
[notices.rule]
frame = { module = "engine*.so", function = "Sys_Error*", within = 3 }

[[notices]]
id = "nosteam-cracked"
severity = "danger"
text = "Unsupported server."
[notices.rule]
metadata = { SteamPatchVersion = "*" }
cmdline = "*-insecure*"
"#,
        )
        .unwrap();
        assert_eq!(cfg.notices.len(), 2);
        assert_eq!(
            cfg.notices[0].rule.frame.as_ref().and_then(|f| f.within),
            Some(3)
        );
    }

    #[test]
    fn bad_notices_fail_at_startup() {
        for bad in [
            "[[notices]]\nid = \"a\"\nseverity = \"info\"\ntext = \"t\"\n[notices.rule]\n",
            "[[notices]]\nid = \"a\"\nseverity = \"loud\"\ntext = \"t\"\n[notices.rule]\ncmdline = \"*\"\n",
            "[[notices]]\nid = \"a\"\nseverity = \"info\"\ntext = \"t\"\nsql = \"SELECT 1\"\n[notices.rule]\ncmdline = \"*\"\n",
            "[[notices]]\nid = \"a\"\nseverity = \"info\"\ntext = \"t\"\n[notices.rule]\ncmdline = \"*\"\n[[notices]]\nid = \"a\"\nseverity = \"info\"\ntext = \"t\"\n[notices.rule]\ncmdline = \"*\"\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod symbol_fetch_config_tests {
    use super::*;

    const OK: &str = r#"
[processing]
symbol_stores = ["mozilla", "public"]

[symbol_fetch]
retry_days = 3

[[symbol_fetch.servers]]
store = "mozilla"
url = "https://symbols.example.org"
"#;

    #[test]
    fn servers_are_read() {
        let cfg = Config::parse(OK).unwrap();
        assert_eq!(cfg.symbol_fetch.servers.len(), 1);
        assert_eq!(cfg.symbol_fetch.retry_days, 3);
        assert_eq!(
            cfg.symbol_fetch.batch_size, 20,
            "the rest keeps its defaults"
        );
        assert!(
            Config::default().symbol_fetch.servers.is_empty(),
            "off unless configured"
        );
    }

    #[test]
    fn bad_servers_fail_at_startup() {
        for bad in [
            OK.replace("store = \"mozilla\"", "store = \"unlisted\""),
            OK.replace("https://symbols.example.org", "ftp://symbols.example.org"),
            OK.replace("https://symbols.example.org", "https://a b"),
            OK.replace("retry_days = 3", "retry_days = 0"),
            OK.replace("retry_days = 3", "retries = 3"),
        ] {
            assert!(Config::parse(&bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod carburetor_config_tests {
    use super::*;

    #[test]
    fn off_by_default_and_read_when_set() {
        assert!(Config::default().carburetor.path.is_none());
        let cfg =
            Config::parse("[carburetor]\npath = \"/usr/local/bin/carburetor\"\nmax_concurrent = 4")
                .unwrap();
        assert_eq!(
            cfg.carburetor.path.as_deref(),
            Some(std::path::Path::new("/usr/local/bin/carburetor"))
        );
        assert_eq!(
            (cfg.carburetor.max_concurrent, cfg.carburetor.timeout_secs),
            (4, 120)
        );
    }

    #[test]
    fn unsafe_settings_fail_at_startup() {
        for bad in [
            "[carburetor]\npath = \"carburetor\"",
            "[carburetor]\npath = \"./carburetor\"",
            "[carburetor]\ntimeout_secs = 0",
            "[carburetor]\nmax_output_bytes = 0",
            "[carburetor]\nmax_concurrent = 0",
            "[carburetor]\nmax_concurrent = 99",
            "[carburetor]\nargs = \"--evil\"",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod symbol_cache_config_tests {
    use super::*;

    #[test]
    fn a_budget_is_on_by_default_and_zero_turns_it_off() {
        assert_eq!(Config::default().processing.symbol_cache_mib, 256);
        let cfg = Config::parse("[processing]\nsymbol_cache_mib = 0").unwrap();
        assert_eq!(cfg.processing.symbol_cache_mib, 0);
        assert!(Config::parse("[processing]\nsymbol_cache_mib = -1").is_err());
    }
}

#[cfg(test)]
mod origin_tests {
    use super::*;

    #[test]
    fn unpinned_follows_the_host_the_browser_used() {
        let cfg = Config::default();
        assert_eq!(cfg.origin(Some("0.0.0.0:8080")), "http://0.0.0.0:8080");
        assert_eq!(cfg.origin(Some("localhost:8080")), "http://localhost:8080");
        assert_eq!(cfg.origin(Some("localhost")), "http://localhost");
        assert_eq!(
            cfg.origin(Some("192.168.1.5:9000")),
            "http://192.168.1.5:9000"
        );
        assert_eq!(cfg.origin(Some("[::1]:8080")), "http://[::1]:8080");
        assert_eq!(cfg.origin(Some("my_box.lan")), "http://my_box.lan");
    }

    #[test]
    fn odd_hosts_fall_back_to_the_listen_address() {
        let cfg = Config::default();
        let long = "a".repeat(300);
        for bad in [
            "",
            "a b",
            "evil.com/x",
            "u@evil.com",
            "a?b",
            "a#b",
            "é.com",
            "a\\b",
            long.as_str(),
        ] {
            assert_eq!(cfg.origin(Some(bad)), "http://127.0.0.1:8080", "{bad:?}");
        }
        assert_eq!(cfg.origin(None), "http://127.0.0.1:8080");
        assert_eq!(
            Config::parse("listen = \"0.0.0.0:9000\"")
                .unwrap()
                .origin(None),
            "http://0.0.0.0:9000"
        );
    }

    #[test]
    fn a_pinned_hostname_always_wins_and_https_sets_the_scheme() {
        let cfg = Config::parse("hostname = \"throttle.example.com\"\nhttps = true").unwrap();
        assert_eq!(
            cfg.origin(Some("evil.example")),
            "https://throttle.example.com"
        );
        assert_eq!(cfg.origin(None), "https://throttle.example.com");
        let plain = Config::parse("https = true").unwrap();
        assert_eq!(
            plain.origin(Some("localhost:8080")),
            "https://localhost:8080"
        );
    }

    #[test]
    fn bad_hostnames_fail_at_startup() {
        for bad in [
            "\"\"",
            "\"a b\"",
            "\"http://x.com\"",
            "\"x.com/\"",
            "\"u@x.com\"",
        ] {
            assert!(
                Config::parse(&format!("hostname = {bad}")).is_err(),
                "{bad}"
            );
        }
        for good in [
            "\"throttle.example.com\"",
            "\"192.168.1.5:8080\"",
            "\"localhost:8080\"",
        ] {
            assert!(
                Config::parse(&format!("hostname = {good}")).is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn a_missing_config_file_is_an_error_not_silently_the_defaults() {
        let err = Config::load(Path::new("/nonexistent/throttle.toml")).unwrap_err();
        assert!(
            format!("{err:#}").contains("/nonexistent/throttle.toml"),
            "{err:#}"
        );
    }
}
