//! Downloading symbol files we are missing from HTTP symbol servers that use
//! the Breakpad layout: `<base>/<name>/<build id>/<stem>.sym` (Mozilla's
//! symbol server does, and serves Windows system DLLs).
//!
//! Only `*.pdb` modules are asked for: that is what such servers have, and
//! Linux modules of a game server only ever have symbols if the Accelerator
//! uploaded them. The Microsoft Symbol Server is not supported: it serves
//! PDBs, not `.sym` files, and converting them needs `dump_syms`.
//!
//! Module names and build IDs come from untrusted dumps. They only reach a
//! URL after a strict character check, a downloaded file must be about
//! exactly the module that was asked for, and everything is size-capped.
//! Modules nobody has are remembered (`symbol_miss`) so they are not asked
//! for on every pass.

use std::time::Duration;

use sqlx::SqlitePool;

use crate::app::AppState;
use crate::config::Config;
use crate::ingest::symbols::{self, Header};
use crate::stats;

const DAY: i64 = 86_400;
/// Give up on a pass after this many modules in a row hit only dead servers.
const MAX_UNREACHABLE_IN_A_ROW: u32 = 3;

/// Modules of processed crashes that still lack symbols, that we hold no
/// symbols for in any store, and that were not asked for recently.
const CANDIDATES: &str = "SELECT DISTINCT m.name, m.identifier FROM module m \
    WHERE m.present = 0 AND lower(m.name) LIKE '%.pdb' \
      AND NOT EXISTS (SELECT 1 FROM symbol s WHERE s.name = m.name AND s.identifier = m.identifier) \
      AND NOT EXISTS (SELECT 1 FROM symbol_miss x \
                      WHERE x.name = m.name AND x.identifier = m.identifier AND x.tried_at > ?) \
    LIMIT ?";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub fetched: u64,
    /// No server had it (or what they had was not acceptable).
    pub missed: u64,
    /// Servers could not be reached; nothing was recorded.
    pub errors: u64,
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The URL of the symbol file for `name` / `id` on the server at `base`, or
/// `None` if either contains anything unusual.
pub fn symbol_url(base: &str, name: &str, id: &str) -> Option<String> {
    if !safe_name(name)
        || id.is_empty()
        || id.len() > 64
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let stem = symbols::file_stem(name);
    if stem.is_empty() {
        return None;
    }
    Some(format!(
        "{}/{name}/{}/{stem}.sym",
        base.trim_end_matches('/'),
        id.to_ascii_uppercase()
    ))
}

enum Fetched {
    Found(Vec<u8>),
    /// 4xx, or too large: nothing usable there.
    Missing,
    /// Network error or 5xx: try again later.
    Unreachable,
}

async fn download(http: &reqwest::Client, url: &str, max: u64) -> Fetched {
    let Ok(mut res) = http.get(url).send().await else {
        return Fetched::Unreachable;
    };
    let status = res.status();
    if status.is_client_error() {
        return Fetched::Missing;
    }
    if !status.is_success() {
        return Fetched::Unreachable;
    }
    if res.content_length().is_some_and(|n| n > max) {
        return Fetched::Missing;
    }
    let mut data = Vec::new();
    loop {
        match res.chunk().await {
            Ok(Some(chunk)) => {
                if (data.len() + chunk.len()) as u64 > max {
                    return Fetched::Missing;
                }
                data.extend_from_slice(&chunk);
            }
            Ok(None) => return Fetched::Found(data),
            Err(_) => return Fetched::Unreachable,
        }
    }
}

/// The header of a downloaded file, if the file is about the module we asked for.
fn accept(name: &str, id: &str, data: &[u8]) -> Option<Header> {
    let line = data.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let header = symbols::parse_header(line)?;
    let about_it = header.name == name
        && header.id.eq_ignore_ascii_case(id)
        && !symbols::file_stem(&header.name).is_empty();
    about_it.then_some(header)
}

/// One pass over (at most `batch_size`) modules we are missing symbols for.
pub async fn run_once(
    db: &SqlitePool,
    config: &Config,
    http: &reqwest::Client,
) -> sqlx::Result<Report> {
    let cfg = &config.symbol_fetch;
    let retry_before = stats::now() - i64::from(cfg.retry_days) * DAY;
    let max = config.limits.max_symbol_bytes;

    let wanted: Vec<(String, String)> = sqlx::query_as(CANDIDATES)
        .bind(retry_before)
        .bind(i64::from(cfg.batch_size))
        .fetch_all(db)
        .await?;

    let mut report = Report::default();
    let mut unreachable_in_a_row = 0;
    for (name, id) in wanted {
        let mut found = None;
        let mut transient = false;
        for server in &cfg.servers {
            // Depends only on the module, so no server can do better.
            let Some(url) = symbol_url(&server.url, &name, &id) else {
                break;
            };
            match download(http, &url, max).await {
                Fetched::Found(data) => {
                    if let Some(header) = accept(&name, &id, &data) {
                        found = Some((server.store.as_str(), header, data));
                        break;
                    }
                }
                Fetched::Missing => {}
                Fetched::Unreachable => {
                    transient = true;
                    tracing::warn!(store = %server.store, "symbol server unreachable");
                }
            }
        }

        match found {
            Some((store, header, data)) => {
                unreachable_in_a_row = 0;
                match symbols::store_file(config, db, store, &header, data).await {
                    Ok(_) => {
                        report.fetched += 1;
                        stats::bump(db, "symbols:fetched", 1).await;
                    }
                    Err(e) => tracing::warn!(?e, %name, "could not store a downloaded symbol file"),
                }
            }
            None if transient => {
                report.errors += 1;
                unreachable_in_a_row += 1;
                if unreachable_in_a_row >= MAX_UNREACHABLE_IN_A_ROW {
                    break;
                }
            }
            None => {
                unreachable_in_a_row = 0;
                report.missed += 1;
                sqlx::query(
                    "INSERT INTO symbol_miss (name, identifier, tried_at) VALUES (?, ?, ?) \
                     ON CONFLICT (name, identifier) DO UPDATE SET tried_at = excluded.tried_at",
                )
                .bind(&name)
                .bind(&id)
                .bind(stats::now())
                .execute(db)
                .await?;
            }
        }
    }
    Ok(report)
}

/// Starts the periodic pass; does nothing without configured servers.
pub fn spawn(state: &AppState) {
    if state.config.symbol_fetch.servers.is_empty() {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent(concat!("throttle/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client");
        let every = Duration::from_secs(state.config.symbol_fetch.interval_secs);
        loop {
            if !crate::retention::low_disk(&state.config) {
                match run_once(&state.db, &state.config, &http).await {
                    Ok(r) if r == Report::default() => {}
                    Ok(r) => tracing::info!(
                        fetched = r.fetched,
                        missed = r.missed,
                        errors = r.errors,
                        "symbol fetch pass"
                    ),
                    Err(e) => tracing::error!(error = %e, "symbol fetch failed"),
                }
            }
            tokio::time::sleep(every).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::extract::{Path as UrlPath, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use tempfile::TempDir;

    use super::*;
    use crate::config::SymbolServer;
    use crate::db;

    const TEST_APP_ID: &str = "5A9832E5287241C1838ED98914E9B7FF1";

    struct Fake {
        hits: AtomicUsize,
        test_app: String,
    }

    async fn handler(
        State(fake): State<Arc<Fake>>,
        UrlPath((name, id, file)): UrlPath<(String, String, String)>,
    ) -> axum::response::Response {
        fake.hits.fetch_add(1, Ordering::SeqCst);
        match (name.as_str(), file.as_str()) {
            ("test_app.pdb", "test_app.sym") if id == TEST_APP_ID => {
                fake.test_app.clone().into_response()
            }
            // A file about some other module than the one asked for.
            ("evil.pdb", _) => {
                format!("MODULE windows x86 {id} other.pdb\nFUNC 1 1 0 f\n").into_response()
            }
            ("big.pdb", _) => {
                format!("MODULE windows x86 {id} big.pdb\n{}", "x".repeat(5000)).into_response()
            }
            ("broken.pdb", _) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }

    /// Base URL of a local symbol server, and its request counter.
    async fn serve() -> (String, Arc<Fake>) {
        let test_app = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/symbols/test_app.pdb")
                .join(TEST_APP_ID)
                .join("test_app.sym"),
        )
        .unwrap();
        let fake = Arc::new(Fake {
            hits: AtomicUsize::new(0),
            test_app,
        });
        let app = Router::new()
            .route("/syms/{name}/{id}/{file}", get(handler))
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/syms"), fake)
    }

    struct Env {
        db: SqlitePool,
        config: Config,
        http: reqwest::Client,
        _dir: TempDir,
    }

    async fn new_env(url: &str, tweak: impl FnOnce(&mut Config)) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        config.processing.symbol_stores = vec!["public".into(), "mozilla".into()];
        config.symbol_fetch.servers = vec![SymbolServer {
            store: "mozilla".into(),
            url: url.into(),
        }];
        tweak(&mut config);
        Env {
            db: db::open_memory().await.unwrap(),
            config,
            http: reqwest::Client::new(),
            _dir: dir,
        }
    }

    impl Env {
        /// A processed crash whose module has no symbols.
        async fn add_module(&self, n: u8, name: &str, id: &str) {
            let crash = char::from(b'a' + n).to_string().repeat(12);
            sqlx::query(
                "INSERT INTO crash (id, created_at, ip, status) VALUES (?, 1, x'7f000001', 2)",
            )
            .bind(&crash)
            .execute(&self.db)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO module (crash, name, identifier, present) VALUES (?, ?, ?, 0)",
            )
            .bind(crash)
            .bind(name)
            .bind(id)
            .execute(&self.db)
            .await
            .unwrap();
        }

        async fn run(&self) -> Report {
            run_once(&self.db, &self.config, &self.http).await.unwrap()
        }

        async fn count(&self, sql: &'static str) -> i64 {
            sqlx::query_scalar(sql).fetch_one(&self.db).await.unwrap()
        }
    }

    #[test]
    fn urls_are_built_only_from_boring_names() {
        let id = "5a9832e5287241c1838ed98914e9b7ff1";
        assert_eq!(
            symbol_url("https://sym.example/", "ntdll.pdb", id).as_deref(),
            Some("https://sym.example/ntdll.pdb/5A9832E5287241C1838ED98914E9B7FF1/ntdll.sym")
        );
        assert_eq!(
            symbol_url("http://h/p", "libfoo-1_2.so", "AB").as_deref(),
            Some("http://h/p/libfoo-1_2.so/AB/libfoo-1_2.so.sym")
        );
        for bad in [
            "",
            ".",
            "..",
            "a/b.pdb",
            "a\\b.pdb",
            "we ird.pdb",
            "a?b.pdb",
            "a#b.pdb",
            "é.pdb",
            ".pdb",
        ] {
            assert_eq!(symbol_url("http://h", bad, "AB"), None, "{bad:?}");
        }
        for bad in ["", "XYZ", "AB/CD", "AB..", &"A".repeat(65)] {
            assert_eq!(symbol_url("http://h", "a.pdb", bad), None, "{bad:?}");
        }
    }

    #[test]
    fn only_a_file_about_the_requested_module_is_accepted() {
        let good =
            b"MODULE windows x86 5A9832E5287241C1838ED98914E9B7FF1 test_app.pdb\nFUNC 1 1 0 f\n";
        assert!(accept("test_app.pdb", "5a9832e5287241c1838ed98914e9b7ff1", good).is_some());
        assert!(accept("other.pdb", TEST_APP_ID, good).is_none());
        assert!(accept("test_app.pdb", "AAAA", good).is_none());
        assert!(accept("test_app.pdb", TEST_APP_ID, b"<html>not found</html>").is_none());
        assert!(accept("test_app.pdb", TEST_APP_ID, b"").is_none());
        assert!(accept("test_app.pdb", TEST_APP_ID, &[0xff, 0xfe]).is_none());
    }

    #[tokio::test]
    async fn a_missing_module_is_downloaded_stored_and_not_asked_for_again() {
        let (url, fake) = serve().await;
        let env = new_env(&url, |_| {}).await;
        env.add_module(0, "test_app.pdb", TEST_APP_ID).await;

        assert_eq!(
            env.run().await,
            Report {
                fetched: 1,
                ..Report::default()
            }
        );
        let stored = env
            .config
            .symbols_dir()
            .join("mozilla/test_app.pdb")
            .join(TEST_APP_ID)
            .join("test_app.sym.gz");
        assert!(stored.is_file());
        let store: String =
            sqlx::query_scalar("SELECT store FROM symbol WHERE name = 'test_app.pdb'")
                .fetch_one(&env.db)
                .await
                .unwrap();
        assert_eq!(store, "mozilla");

        // Now we have it: the next pass has nothing to do.
        assert_eq!(env.run().await, Report::default());
        assert_eq!(fake.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn modules_nobody_has_are_remembered_for_a_while() {
        let (url, fake) = serve().await;
        let env = new_env(&url, |_| {}).await;
        env.add_module(0, "nope.pdb", "ABCD").await;

        assert_eq!(
            env.run().await,
            Report {
                missed: 1,
                ..Report::default()
            }
        );
        assert_eq!(env.run().await, Report::default());
        assert_eq!(
            fake.hits.load(Ordering::SeqCst),
            1,
            "not asked again within the retry window"
        );
        assert_eq!(env.count("SELECT COUNT(*) FROM symbol").await, 0);

        // Once the retry window has passed it is asked for again.
        sqlx::query("UPDATE symbol_miss SET tried_at = tried_at - ?")
            .bind(8 * DAY)
            .execute(&env.db)
            .await
            .unwrap();
        assert_eq!(
            env.run().await,
            Report {
                missed: 1,
                ..Report::default()
            }
        );
        assert_eq!(fake.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_file_about_another_module_or_too_big_is_refused() {
        let (url, _) = serve().await;
        let env = new_env(&url, |c| c.limits.max_symbol_bytes = 1000).await;
        env.add_module(0, "evil.pdb", "ABCD").await;
        env.add_module(1, "big.pdb", "ABCD").await;

        assert_eq!(
            env.run().await,
            Report {
                missed: 2,
                ..Report::default()
            }
        );
        assert_eq!(env.count("SELECT COUNT(*) FROM symbol").await, 0);
        assert!(!env.config.symbols_dir().join("mozilla").exists());
    }

    #[tokio::test]
    async fn only_pdb_modules_with_boring_names_are_requested() {
        let (url, fake) = serve().await;
        let env = new_env(&url, |_| {}).await;
        env.add_module(0, "libc.so.6", "ABCD").await; // not a candidate at all
        env.add_module(1, "we ird.pdb", "ABCD").await; // a candidate we refuse to put in a URL
        env.add_module(2, "../x.pdb", "ABCD").await;

        assert_eq!(
            env.run().await,
            Report {
                missed: 2,
                ..Report::default()
            }
        );
        assert_eq!(fake.hits.load(Ordering::SeqCst), 0, "no request was made");
        assert_eq!(env.count("SELECT COUNT(*) FROM symbol_miss").await, 2);
        // They no longer take up space in the next batch.
        assert_eq!(env.run().await, Report::default());
    }

    #[tokio::test]
    async fn dead_servers_and_server_errors_are_not_held_against_the_module() {
        let (url, _) = serve().await;
        let env = new_env(&url, |_| {}).await;
        env.add_module(0, "broken.pdb", "ABCD").await;
        assert_eq!(
            env.run().await,
            Report {
                errors: 1,
                ..Report::default()
            }
        );
        assert_eq!(env.count("SELECT COUNT(*) FROM symbol_miss").await, 0);

        let dead = new_env("http://127.0.0.1:1/syms", |_| {}).await;
        for n in 0..5 {
            dead.add_module(n, &format!("m{n}.pdb"), "ABCD").await;
        }
        let report = dead.run().await;
        assert_eq!(
            report,
            Report {
                errors: 3,
                ..Report::default()
            },
            "gives up after a few"
        );
        assert_eq!(dead.count("SELECT COUNT(*) FROM symbol_miss").await, 0);
    }

    #[tokio::test]
    async fn later_servers_are_tried_when_an_earlier_one_lacks_the_file() {
        let (url, _) = serve().await;
        let env = new_env(&url, |c| {
            c.processing.symbol_stores = vec!["public".into(), "first".into(), "mozilla".into()];
            let second = c.symbol_fetch.servers.remove(0);
            c.symbol_fetch.servers = vec![
                SymbolServer {
                    store: "first".into(),
                    url: format!("{}/empty", second.url.trim_end_matches("/syms")),
                },
                second,
            ];
        })
        .await;
        env.add_module(0, "test_app.pdb", TEST_APP_ID).await;
        assert_eq!(
            env.run().await,
            Report {
                fetched: 1,
                ..Report::default()
            }
        );
        let store: String = sqlx::query_scalar("SELECT store FROM symbol")
            .fetch_one(&env.db)
            .await
            .unwrap();
        assert_eq!(store, "mozilla");
    }
}
