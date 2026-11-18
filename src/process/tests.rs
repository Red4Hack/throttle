//! Oracle test: the rewrite must agree with the legacy `minidump_stackwalk -m`
//! output stored in tests/fixtures/golden (regenerate with tools/oracle/golden.sh),
//! plus end-to-end tests of the worker.

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::analyze::analyze;
use super::supplier::SymbolStores;
use super::{drain, requeue_new_symbols};
use crate::app::AppState;
use crate::config::Config;
use crate::ingest::token::Secret;
use crate::notice::{self, NoticeDef};
use crate::{db, stats};

const TEST_APP_ID: &str = "5A9832E5287241C1838ED98914E9B7FF1";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

// ---- golden comparison -------------------------------------------------------

type FrameKey = (i64, i64, String, String, String, String, String);

struct Golden {
    failed: bool,
    crash_thread: i64,
    modules: BTreeSet<(String, String)>,
    frames: BTreeSet<FrameKey>,
}

fn parse_golden(text: &str) -> Golden {
    let mut g = Golden {
        failed: false,
        crash_thread: -1,
        modules: BTreeSet::new(),
        frames: BTreeSet::new(),
    };
    let mut in_frames = false;
    for line in text.lines() {
        if let Some(code) = line.strip_prefix("exit=") {
            g.failed = code != "0";
            continue;
        }
        if line.is_empty() {
            in_frames = true;
            continue;
        }
        let p: Vec<&str> = line.split('|').collect();
        if !in_frames {
            match p[0] {
                "Crash" => g.crash_thread = p.get(3).and_then(|t| t.parse().ok()).unwrap_or(-1),
                "Module" if p.len() >= 5 && !p[3].is_empty() && !p[4].is_empty() => {
                    g.modules.insert((p[3].to_string(), p[4].to_string()));
                }
                _ => {}
            }
        } else if p.len() == 7 {
            g.frames.insert((
                p[0].parse().unwrap_or(-1),
                p[1].parse().unwrap_or(-1),
                p[2].into(),
                p[3].into(),
                p[4].into(),
                p[5].into(),
                p[6].into(),
            ));
        }
    }
    // Like the PHP version: only the crashing thread (or thread 0) and thread 0 are kept.
    let keep = g.crash_thread.max(0);
    g.frames.retain(|f| f.0 == keep || f.0 == 0);
    g
}

fn diff<T: Ord + Debug>(
    what: &str,
    name: &str,
    legacy: &BTreeSet<T>,
    ours: &BTreeSet<T>,
    out: &mut Vec<String>,
) {
    for x in legacy.difference(ours) {
        out.push(format!("{name}: {what} only in legacy:  {x:?}"));
    }
    for x in ours.difference(legacy) {
        out.push(format!("{name}: {what} only in rewrite: {x:?}"));
    }
}

/// Frames are compared strictly, except for two fixtures whose legacy output
/// is known to be worse or arbitrary (not a defect of the rewrite):
///
/// * `linux-mini` has no symbols, so both sides fall back to stack scanning.
///   Breakpad's old heuristic also emits module-less junk frames (addresses
///   that are module bases); rust-minidump drops them. Everything with a module
///   is identical and in the same order, only the frame numbers shift. Stack
///   hashes of scan-only stacks therefore differ from the legacy ones.
/// * `pipeline-inlines-macos-segv` has a `.sym` with INLINE records that the old
///   Breakpad cannot read, so legacy resolved no functions at all. Only the
///   module of each frame can be compared.
fn compare_frames(
    name: &str,
    legacy: &BTreeSet<FrameKey>,
    ours: &BTreeSet<FrameKey>,
    out: &mut Vec<String>,
) {
    match name {
        "linux-mini" => {
            let with_module =
                |s: &BTreeSet<FrameKey>| -> Vec<(String, String, String, String, String)> {
                    s.iter()
                        .filter(|f| !f.2.is_empty())
                        .map(|f| {
                            (
                                f.2.clone(),
                                f.3.clone(),
                                f.4.clone(),
                                f.5.clone(),
                                f.6.clone(),
                            )
                        })
                        .collect()
                };
            let (l, o) = (with_module(legacy), with_module(ours));
            if l != o {
                out.push(format!(
                    "{name}: frames with a module differ\n  legacy:  {l:?}\n  rewrite: {o:?}"
                ));
            }
        }
        "pipeline-inlines-macos-segv" => {
            let modules = |s: &BTreeSet<FrameKey>| -> BTreeSet<(i64, i64, String)> {
                s.iter().map(|f| (f.0, f.1, f.2.clone())).collect()
            };
            diff("frame module", name, &modules(legacy), &modules(ours), out);
        }
        _ => diff("frame", name, legacy, ours, out),
    }
}

#[tokio::test]
async fn analysis_matches_the_legacy_minidump_stackwalk() {
    let fx = fixtures();
    let stores = SymbolStores::new(vec![fx.join("symbols")], 512 << 20);
    let mut problems = Vec::new();
    let mut checked = 0;

    let mut dumps: Vec<_> = std::fs::read_dir(fx.join("dumps"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    dumps.sort();
    for path in dumps {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let golden = parse_golden(
            &std::fs::read_to_string(fx.join("golden").join(format!("{name}.txt"))).unwrap(),
        );

        match (analyze(&path, &stores).await, golden.failed) {
            (Err(e), false) => problems.push(format!(
                "{name}: rewrite failed ({e:#}) but legacy succeeded"
            )),
            (Ok(_), true) => {
                eprintln!("note: {name}: legacy rejected this dump, the rewrite accepts it")
            }
            (Err(_), true) => checked += 1,
            (Ok(a), false) => {
                checked += 1;
                let thread = golden.crash_thread.max(0);
                if a.thread != thread {
                    problems.push(format!(
                        "{name}: crash thread {} (legacy {thread})",
                        a.thread
                    ));
                }
                let modules = a
                    .modules
                    .iter()
                    .map(|m| (m.name.clone(), m.identifier.clone()))
                    .collect();
                diff("module", &name, &golden.modules, &modules, &mut problems);

                let frames: BTreeSet<FrameKey> = a
                    .frames
                    .iter()
                    .map(|f| {
                        let line = if f.file.is_empty() {
                            String::new()
                        } else {
                            f.line.to_string()
                        };
                        (
                            f.thread,
                            f.frame,
                            f.module.clone(),
                            f.function.clone(),
                            f.file.clone(),
                            line,
                            f.offset.clone(),
                        )
                    })
                    .collect();
                compare_frames(&name, &golden.frames, &frames, &mut problems);
            }
        }
    }

    assert!(checked >= 5, "only {checked} fixtures were compared");
    assert!(
        problems.is_empty(),
        "differences from the legacy output:\n{}",
        problems.join("\n")
    );
}

/// Real server dumps carry passwords, paths and addresses, so they are not committed:
/// drop them in `tests/local/` (git-ignored) and they are checked here. Each one must
/// analyze to something sane, and when the legacy stackwalker is installed
/// (tools/oracle/fetch.sh) the modules, the crashing thread and every frame that has a
/// module must agree with it.
#[tokio::test]
async fn local_dumps_are_analyzed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Ok(entries) = std::fs::read_dir(root.join("tests/local")) else {
        eprintln!("note: no tests/local, nothing to check");
        return;
    };
    let mut dumps: Vec<PathBuf> = entries
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "dmp"))
        .collect();
    dumps.sort();
    let oracle = root.join("tools/oracle/bin/minidump_stackwalk");
    let stores = SymbolStores::new(vec![fixtures().join("symbols")], 512 << 20);

    let mut problems = Vec::new();
    for path in &dumps {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let a = match analyze(path, &stores).await {
            Ok(a) => a,
            Err(e) => {
                problems.push(format!("{name}: {e:#}"));
                continue;
            }
        };
        if a.modules.is_empty() {
            problems.push(format!("{name}: no modules"));
        }
        if !a.frames.iter().any(|f| f.thread == a.thread) {
            problems.push(format!("{name}: no frames for thread {}", a.thread));
        }
        if !oracle.exists() {
            continue;
        }

        let out = std::process::Command::new(&oracle)
            .arg("-m")
            .arg(path)
            .arg(fixtures().join("symbols"))
            .output()
            .unwrap();
        let golden = parse_golden(&String::from_utf8_lossy(&out.stdout));
        let thread = golden.crash_thread.max(0);
        if a.thread != thread {
            problems.push(format!(
                "{name}: crash thread {} (legacy {thread})",
                a.thread
            ));
        }
        let modules = a
            .modules
            .iter()
            .map(|m| (m.name.clone(), m.identifier.clone()))
            .collect();
        diff("module", &name, &golden.modules, &modules, &mut problems);

        // Frames without a module come from stack scanning, where the old Breakpad
        // and rust-minidump are known to differ (see compare_frames).
        let legacy: BTreeSet<(i64, String, String, String)> = golden
            .frames
            .iter()
            .filter(|f| !f.2.is_empty())
            .map(|f| (f.0, f.2.clone(), f.3.clone(), f.6.clone()))
            .collect();
        let ours: BTreeSet<(i64, String, String, String)> = a
            .frames
            .iter()
            .filter(|f| !f.module.is_empty())
            .map(|f| {
                (
                    f.thread,
                    f.module.clone(),
                    f.function.clone(),
                    f.offset.clone(),
                )
            })
            .collect();
        if a.bad_jump {
            // The legacy walker followed the frame pointer into junk; we restart from the
            // return address on the stack, so we may have more frames, never fewer.
            for x in legacy.difference(&ours) {
                problems.push(format!(
                    "{name}: frame with a module only in legacy:  {x:?}"
                ));
            }
        } else {
            diff("frame with a module", &name, &legacy, &ours, &mut problems);
        }
    }
    assert!(problems.is_empty(), "local dumps:\n{}", problems.join("\n"));
}

// ---- worker ------------------------------------------------------------------

struct Env {
    state: AppState,
    _dir: TempDir,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: dir.path().to_path_buf(),
        ..Config::default()
    };
    let state = AppState::new(
        config,
        db::open_memory().await.unwrap(),
        Secret::from_bytes(vec![1; 32]),
    );
    Env { state, _dir: dir }
}

async fn add_crash(env: &Env, id: &str, dump: &[u8]) {
    let path = env.state.config.dump_path(id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, dump).unwrap();
    sqlx::query("INSERT INTO crash (id, created_at, ip, status) VALUES (?, ?, x'7f000001', 0)")
        .bind(id)
        .bind(stats::now())
        .execute(&env.state.db)
        .await
        .unwrap();
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn install_test_app_symbols(env: &Env) {
    copy_dir(
        &fixtures().join("symbols/test_app.pdb"),
        &env.state.config.symbols_dir().join("public/test_app.pdb"),
    );
}

fn test_dump() -> Vec<u8> {
    std::fs::read(fixtures().join("dumps/test.dmp")).unwrap()
}

async fn present(env: &Env, id: &str, module: &str) -> i64 {
    sqlx::query_scalar("SELECT present FROM module WHERE crash = ? AND name = ?")
        .bind(id)
        .bind(module)
        .fetch_one(&env.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_pending_crash_is_processed_with_symbols() {
    let env = env().await;
    add_crash(&env, "aaaaaaaaaaaa", &test_dump()).await;
    install_test_app_symbols(&env);

    assert_eq!(drain(&env.state).await.unwrap(), 1);

    type Row = (
        i64,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Row = sqlx::query_as(
        "SELECT status, thread, stackhash, crash_module, crash_function, error FROM crash WHERE id = 'aaaaaaaaaaaa'",
    )
    .fetch_one(&env.state.db)
    .await
    .unwrap();
    assert_eq!(row.0, 2);
    assert_eq!(row.1, Some(0));
    let hash = row.2.unwrap();
    assert!(!hash.is_empty() && hash.len().is_multiple_of(8), "{hash}");
    assert_eq!(row.3.as_deref(), Some("test_app.exe"));
    assert_eq!(
        row.4.as_deref(),
        Some("`anonymous namespace'::CrashFunction")
    );
    assert_eq!(row.5, None);

    let rendered: String = sqlx::query_scalar(
        "SELECT rendered FROM frame WHERE crash = 'aaaaaaaaaaaa' AND thread = 0 AND frame = 0",
    )
    .fetch_one(&env.state.db)
    .await
    .unwrap();
    assert_eq!(
        rendered,
        "test_app.exe!`anonymous namespace'::CrashFunction [test_app.cc:58 + 0x3]"
    );

    assert_eq!(present(&env, "aaaaaaaaaaaa", "test_app.pdb").await, 1);
    assert_eq!(present(&env, "aaaaaaaaaaaa", "dbghelp.pdb").await, 0);

    // Nothing left to do.
    assert_eq!(drain(&env.state).await.unwrap(), 0);
}

#[tokio::test]
async fn an_unusable_dump_is_marked_failed_with_a_reason() {
    let env = env().await;
    add_crash(&env, "bbbbbbbbbbbb", b"this is not a minidump").await;
    // And one whose file is gone entirely.
    sqlx::query(
        "INSERT INTO crash (id, created_at, ip, status) VALUES ('cccccccccccc', ?, x'7f000001', 0)",
    )
    .bind(stats::now() + 1)
    .execute(&env.state.db)
    .await
    .unwrap();

    assert_eq!(drain(&env.state).await.unwrap(), 2);

    for id in ["bbbbbbbbbbbb", "cccccccccccc"] {
        let (status, error): (i64, Option<String>) =
            sqlx::query_as("SELECT status, error FROM crash WHERE id = ?")
                .bind(id)
                .fetch_one(&env.state.db)
                .await
                .unwrap();
        assert_eq!(status, 3, "{id}");
        assert!(error.is_some_and(|e| !e.is_empty()), "{id}");
    }
}

#[tokio::test]
async fn crashes_are_processed_oldest_first() {
    let env = env().await;
    for (id, created) in [
        ("dddddddddddd", 300),
        ("eeeeeeeeeeee", 100),
        ("ffffffffffff", 200),
    ] {
        sqlx::query("INSERT INTO crash (id, created_at, ip, status) VALUES (?, ?, x'7f000001', 0)")
            .bind(id)
            .bind(created)
            .execute(&env.state.db)
            .await
            .unwrap();
    }
    let order: Vec<String> = {
        let mut order = Vec::new();
        while let Some(id) = super::claim(&env.state.db).await.unwrap() {
            order.push(id);
        }
        order
    };
    assert_eq!(order, ["eeeeeeeeeeee", "ffffffffffff", "dddddddddddd"]);
}

#[tokio::test]
async fn interrupted_crashes_are_recovered_or_given_up_on() {
    let env = env().await;
    for (id, attempts) in [("gggggggggggg", 1), ("hhhhhhhhhhhh", 3)] {
        sqlx::query("INSERT INTO crash (id, created_at, ip, status, attempts) VALUES (?, 1, x'7f000001', 1, ?)")
            .bind(id)
            .bind(attempts)
            .execute(&env.state.db)
            .await
            .unwrap();
    }
    super::recover(&env.state.db, 3).await.unwrap();

    let status = |id: &'static str| {
        let db = env.state.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT status FROM crash WHERE id = ?")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };
    assert_eq!(status("gggggggggggg").await, 0);
    assert_eq!(status("hhhhhhhhhhhh").await, 3);
}

#[tokio::test]
async fn crashes_are_reprocessed_when_their_symbols_arrive() {
    let env = env().await;
    add_crash(&env, "aaaaaaaaaaaa", &test_dump()).await;
    drain(&env.state).await.unwrap();
    assert_eq!(present(&env, "aaaaaaaaaaaa", "test_app.pdb").await, 0);

    let processed_at: i64 =
        sqlx::query_scalar("SELECT processed_at FROM crash WHERE id = 'aaaaaaaaaaaa'")
            .fetch_one(&env.state.db)
            .await
            .unwrap();
    let add_symbol = |store: &'static str, created_at: i64| {
        let db = env.state.db.clone();
        async move {
            sqlx::query("INSERT OR REPLACE INTO symbol (name, identifier, store, created_at) VALUES ('test_app.pdb', ?, ?, ?)")
                .bind(TEST_APP_ID)
                .bind(store)
                .bind(created_at)
                .execute(&db)
                .await
                .unwrap();
        }
    };

    // A symbol that is older than the last processing changes nothing...
    add_symbol("public", processed_at - 10).await;
    assert_eq!(requeue_new_symbols(&env.state).await.unwrap(), 0);
    // ...and neither does one in a store we don't read.
    add_symbol("untrusted", processed_at + 10).await;
    assert_eq!(requeue_new_symbols(&env.state).await.unwrap(), 0);

    // A new symbol file in a configured store does.
    install_test_app_symbols(&env);
    add_symbol("public", processed_at + 10).await;
    assert_eq!(requeue_new_symbols(&env.state).await.unwrap(), 1);

    assert_eq!(drain(&env.state).await.unwrap(), 1);
    assert_eq!(present(&env, "aaaaaaaaaaaa", "test_app.pdb").await, 1);

    // Resolved, so it is not requeued again.
    assert_eq!(requeue_new_symbols(&env.state).await.unwrap(), 0);
}

// ---- notices -----------------------------------------------------------------

fn notice_def(id: &str, rule: &str) -> NoticeDef {
    NoticeDef {
        id: id.into(),
        severity: "warning".into(),
        text: format!("text of {id}"),
        rule: toml::from_str(rule).unwrap(),
    }
}

async fn notices_of(env: &Env, id: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT notice FROM crashnotice WHERE crash = ? ORDER BY notice")
        .bind(id)
        .fetch_all(&env.state.db)
        .await
        .unwrap()
}

async fn reprocess(env: &Env, id: &str) {
    sqlx::query("UPDATE crash SET status = 0 WHERE id = ?")
        .bind(id)
        .execute(&env.state.db)
        .await
        .unwrap();
    assert_eq!(drain(&env.state).await.unwrap(), 1);
}

#[tokio::test]
async fn matching_notices_are_attached_and_reprocessing_refreshes_them() {
    let env = env().await;
    install_test_app_symbols(&env);
    add_crash(&env, "aaaaaaaaaaaa", &test_dump()).await;
    sqlx::query("UPDATE crash SET metadata = '{\"Map\":\"de_dust2\"}', cmdline = './srcds +map de_dust2' WHERE id = 'aaaaaaaaaaaa'")
        .execute(&env.state.db)
        .await
        .unwrap();

    let defs = vec![
        notice_def(
            "hit",
            "frame = { module = \"TEST_APP.exe\", function = \"*CrashFunction\" }",
        ),
        notice_def(
            "wrong-function",
            "frame = { module = \"test_app.exe\", function = \"Nope\" }",
        ),
        notice_def("module-rule", "module_loaded = \"test_app.pdb\""),
        notice_def("missing-rule", "module_missing = \"test_app.pdb\""),
        notice_def("metadata-rule", "metadata = { Map = \"de_*\" }"),
        notice_def("cmdline-rule", "cmdline = \"*+map*\""),
    ];
    notice::sync(&env.state.db, &defs).await.unwrap();

    assert_eq!(drain(&env.state).await.unwrap(), 1);
    assert_eq!(
        notices_of(&env, "aaaaaaaaaaaa").await,
        ["cmdline-rule", "hit", "metadata-rule", "module-rule"]
    );

    // Change the rules, reprocess: the old matches are replaced, not accumulated.
    let defs = vec![
        notice_def("hit", "frame = { function = \"Nope\" }"),
        notice_def("module-rule", "module_loaded = \"test_app.pdb\""),
    ];
    notice::sync(&env.state.db, &defs).await.unwrap();
    // Notices that left the config detach at once; the rest stay until reprocessing.
    assert_eq!(
        notices_of(&env, "aaaaaaaaaaaa").await,
        ["hit", "module-rule"]
    );
    reprocess(&env, "aaaaaaaaaaaa").await;
    assert_eq!(notices_of(&env, "aaaaaaaaaaaa").await, ["module-rule"]);
}

#[tokio::test]
async fn processing_without_notices_attaches_nothing() {
    let env = env().await;
    add_crash(&env, "aaaaaaaaaaaa", &test_dump()).await;
    assert_eq!(drain(&env.state).await.unwrap(), 1);
    assert!(notices_of(&env, "aaaaaaaaaaaa").await.is_empty());
}

// ---- symbol cache ------------------------------------------------------------

async fn crash_function_of(env: &Env, id: &str) -> String {
    sqlx::query_scalar("SELECT crash_function FROM crash WHERE id = ?")
        .bind(id)
        .fetch_one(&env.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn parsed_symbols_are_reused_between_crashes() {
    let env = env().await;
    install_test_app_symbols(&env);
    add_crash(&env, "aaaaaaaaaaaa", &test_dump()).await;
    add_crash(&env, "bbbbbbbbbbbb", &test_dump()).await;
    assert_eq!(drain(&env.state).await.unwrap(), 2);

    // One file was loaded; modules without symbols never reach the cache.
    let cache = &env.state.symbol_cache;
    assert_eq!((cache.misses(), cache.hits()), (1, 1));
    assert!(cache.bytes() > 0);

    let frames = |id: &'static str| {
        let db = env.state.db.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT rendered FROM frame WHERE crash = ? ORDER BY thread, frame",
            )
            .bind(id)
            .fetch_all(&db)
            .await
            .unwrap()
        }
    };
    let (first, second) = (frames("aaaaaaaaaaaa").await, frames("bbbbbbbbbbbb").await);
    assert!(!first.is_empty());
    assert_eq!(
        first, second,
        "a cached file gives the same stack as a freshly read one"
    );
}

#[tokio::test]
async fn a_replaced_symbol_file_is_not_served_from_the_cache() {
    let env = env().await;
    install_test_app_symbols(&env);
    add_crash(&env, "aaaaaaaaaaaa", &test_dump()).await;
    assert_eq!(drain(&env.state).await.unwrap(), 1);
    assert!(
        crash_function_of(&env, "aaaaaaaaaaaa")
            .await
            .contains("CrashFunction")
    );

    let path = env
        .state
        .config
        .symbols_dir()
        .join("public/test_app.pdb")
        .join(TEST_APP_ID)
        .join("test_app.sym");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("CrashFunction"));
    std::fs::write(&path, text.replace("CrashFunction", "ReplacedFunc")).unwrap();

    add_crash(&env, "bbbbbbbbbbbb", &test_dump()).await;
    assert_eq!(drain(&env.state).await.unwrap(), 1);
    assert!(
        crash_function_of(&env, "bbbbbbbbbbbb")
            .await
            .contains("ReplacedFunc")
    );
    assert_eq!(env.state.symbol_cache.misses(), 2, "the new file was read");
}
