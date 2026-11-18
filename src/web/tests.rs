//! End-to-end tests of the website: real router, in-memory database, temp data dir.

use std::io::Write;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use tempfile::TempDir;
use tower::ServiceExt;

use super::session;
use crate::app::{AppState, router};
use crate::config::Config;
use crate::ingest::token::Secret;
use crate::{db, ids, stats};

const BASE: i64 = 76_561_197_960_265_728;
const ALICE: i64 = BASE + 101;
const BOB: i64 = BASE + 102;
const ROOT: i64 = BASE + 103;
const CAROL: i64 = BASE + 104;
const ORIGIN: &str = "http://throttle.test";

const ALICE_CRASH: &str = "aaaaaaaaaaaa";
const BOB_CRASH: &str = "bbbbbbbbbbbb";
const ANON_CRASH: &str = "cccccccccccc";

struct Env {
    app: Router,
    state: AppState,
    _dir: TempDir,
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Res {
    fn location(&self) -> &str {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

async fn env() -> Env {
    env_with(|_| {}).await
}

async fn env_with(tweak: impl FnOnce(&mut Config)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        data_dir: dir.path().to_path_buf(),
        hostname: Some("throttle.test".into()),
        admins: vec![ROOT as u64],
        accelerator_version: Some("2.4.3".into()),
        ..Config::default()
    };
    tweak(&mut config);
    let state = AppState::new(
        config,
        db::open_memory().await.unwrap(),
        Secret::from_bytes(vec![5; 32]),
    );
    for (id, name) in [
        (ALICE, "Alice"),
        (BOB, "Bob"),
        (ROOT, "Root"),
        (CAROL, "Carol"),
    ] {
        sqlx::query("INSERT INTO user (id, name) VALUES (?, ?)")
            .bind(id)
            .bind(name)
            .execute(&state.db)
            .await
            .unwrap();
    }
    Env {
        app: router(state.clone()),
        state,
        _dir: dir,
    }
}

impl Env {
    fn cookie(&self, id: i64) -> String {
        format!(
            "{}={}",
            session::cookie_name(false),
            session::mint(&self.state.secret, id, stats::now())
        )
    }

    async fn send(&self, req: Request<Body>) -> Res {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let bytes = to_bytes(body, 1 << 22).await.unwrap();
        Res {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn get(&self, path: &str, who: Option<i64>) -> Res {
        let mut req = Request::builder().method(Method::GET).uri(path);
        if let Some(id) = who {
            req = req.header(header::COOKIE, self.cookie(id));
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }

    async fn post(&self, path: &str, who: Option<i64>, origin: Option<&str>, form: &str) -> Res {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(id) = who {
            req = req.header(header::COOKIE, self.cookie(id));
        }
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        self.send(req.body(Body::from(form.to_string())).unwrap())
            .await
    }

    /// A processed crash with one stack frame, uploaded from 203.0.113.9.
    async fn seed(&self, id: &str, owner: Option<i64>, module: &str) {
        let metadata = r#"{"Map":"<script>alert(1)</script>","GamePath":"hidden-path-xyz","ExtensionBuild":"build-xyz","ExtensionVersion":"2.4.0","HasConsoleLog":true}"#;
        sqlx::query(
            "INSERT INTO crash (id, created_at, ip, owner, metadata, cmdline, status, has_dump, thread, stackhash, \
             crash_module, crash_function) VALUES (?, ?, x'cb007109', ?, ?, './srcds +map x +sv_password hunter2', \
             2, 1, 0, 'abcd1234', ?, 'Crashy')",
        )
        .bind(id)
        .bind(stats::now() - 120)
        .bind(owner)
        .bind(metadata)
        .bind(module)
        .execute(&self.state.db)
        .await
        .unwrap();
        for (frame, rendered, url) in [
            (
                0,
                "engine.so!Sys_Error + 0x10",
                "https://github.com/a/b/blob/abc/x.cpp#L1",
            ),
            (1, "server.so!Other + 0x20", "javascript:alert(1)"),
        ] {
            sqlx::query(
                "INSERT INTO frame (crash, thread, frame, module, function, file, line, offset, rendered, url) \
                 VALUES (?, 0, ?, 'engine.so', 'f', '', 0, '0x10', ?, ?)",
            )
            .bind(id)
            .bind(frame)
            .bind(rendered)
            .bind(url)
            .execute(&self.state.db)
            .await
            .unwrap();
        }
    }

    fn put_files(&self, id: &str) {
        let dump = self.state.config.dump_path(id);
        std::fs::create_dir_all(dump.parent().unwrap()).unwrap();
        std::fs::write(&dump, b"MDMP-bytes").unwrap();

        let meta = "-------- CONFIG BEGIN --------\nMap=x\n-------- CONFIG END --------\n-------- CONSOLE HISTORY BEGIN --------\nhello console\n-------- CONSOLE HISTORY END --------\n";
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(meta.as_bytes()).unwrap();
        std::fs::write(self.state.config.meta_path(id), gz.finish().unwrap()).unwrap();
    }

    async fn share(&self, owner: i64, user: i64, accepted: bool) {
        sqlx::query("INSERT INTO share (owner, user, invited_at, accepted_at) VALUES (?, ?, 1, ?)")
            .bind(owner)
            .bind(user)
            .bind(accepted.then_some(2))
            .execute(&self.state.db)
            .await
            .unwrap();
    }

    async fn count(&self, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.state.db)
            .await
            .unwrap()
    }
}

// ---- crash page --------------------------------------------------------------

#[tokio::test]
async fn the_page_says_why_it_crashed_and_when_symbols_are_missing() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    let path = format!("/{ALICE_CRASH}");

    // Nothing stored about the reason, no module list: the page claims nothing.
    let body = env.get(&path, None).await.body;
    assert!(!body.contains("Crash reason"), "{body}");
    assert!(!body.contains("is not code"), "{body}");
    assert!(!body.contains("None of the modules"), "{body}");

    sqlx::query(
        "UPDATE crash SET crash_reason = 'SIGSEGV / SEGV_MAPERR', crash_address = '0x2800001', bad_jump = 1 WHERE id = ?",
    )
    .bind(ALICE_CRASH)
    .execute(&env.state.db)
    .await
    .unwrap();
    for name in ["a.so", "b.so"] {
        sqlx::query(
            "INSERT INTO module (crash, name, identifier, base, present) VALUES (?, ?, 'AAAA', '0x1000', 0)",
        )
        .bind(ALICE_CRASH)
        .bind(name)
        .execute(&env.state.db)
        .await
        .unwrap();
    }

    let body = env.get(&path, None).await.body;
    assert!(body.contains("Crash reason"), "{body}");
    assert!(body.contains("SEGV_MAPERR at 0x2800001"), "{body}");
    assert!(
        body.contains("jumped to an address that is not code (0x2800001)"),
        "{body}"
    );
    assert!(
        body.contains("None of the modules of this crash have symbols"),
        "{body}"
    );

    // One module with symbols is enough to drop the hint; the rest stays.
    sqlx::query("UPDATE module SET present = 1 WHERE name = 'b.so'")
        .execute(&env.state.db)
        .await
        .unwrap();
    let body = env.get(&path, None).await.body;
    assert!(!body.contains("None of the modules"), "{body}");
    assert!(body.contains("SEGV_MAPERR at 0x2800001"), "{body}");
}

#[tokio::test]
async fn anonymous_visitors_see_the_stack_but_not_private_data() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;

    let res = env.get(&format!("/{ALICE_CRASH}"), None).await;
    assert_eq!(res.status, StatusCode::OK);
    let body = &res.body;

    assert!(body.contains("engine.so!Sys_Error + 0x10"));
    assert!(body.contains("rel=\"noreferrer noopener\""));
    assert!(body.contains("outdated Accelerator (2.4.0)"));
    // Metadata is shown, escaped.
    assert!(!body.contains("<script>alert"), "{body}");
    assert!(body.contains("&lt;script&gt;"));
    // Links that are not https are dropped.
    assert!(!body.contains("javascript:"));

    for secret in [
        "203.0.113.9",
        "hunter2",
        "sv_password",
        "hidden-path-xyz",
        "build-xyz",
        "/download",
        "/delete",
    ] {
        assert!(!body.contains(secret), "leaked {secret}");
    }
}

#[tokio::test]
async fn managers_see_the_uploader_and_a_masked_command_line() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    env.put_files(ALICE_CRASH);

    let res = env.get(&format!("/{ALICE_CRASH}"), Some(ALICE)).await;
    assert_eq!(res.status, StatusCode::OK);
    let body = &res.body;
    assert!(body.contains("203.0.113.9"));
    assert!(body.contains("hidden-path-xyz"));
    assert!(body.contains("+sv_password *****"));
    assert!(!body.contains("hunter2"));
    assert!(!body.contains("build-xyz"));
    for link in ["/download", "/metadata", "/console", "/delete"] {
        assert!(
            body.contains(&format!("/{ALICE_CRASH}{link}")),
            "missing {link}"
        );
    }
    assert!(!body.contains("/reprocess"), "only admins reprocess");

    // Someone else, even logged in, gets the public view.
    let other = env.get(&format!("/{ALICE_CRASH}"), Some(BOB)).await;
    assert!(!other.body.contains("203.0.113.9"));
}

#[tokio::test]
async fn ids_are_normalized_and_unknown_ones_404() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;

    let res = env.get("/AAAA-AAAA-AAAA", None).await;
    assert_eq!(
        (res.status, res.location()),
        (StatusCode::PERMANENT_REDIRECT, "/aaaaaaaaaaaa")
    );

    let uuid = ids::to_uuid(ALICE_CRASH).unwrap();
    let res = env.get(&format!("/{uuid}"), None).await;
    assert_eq!(
        (res.status, res.location()),
        (StatusCode::PERMANENT_REDIRECT, "/aaaaaaaaaaaa")
    );

    for path in ["/zzzzzzzzzzzz", "/..%2f..%2fetc", "/aaaaaaaaaaaa/nope"] {
        assert_eq!(
            env.get(path, None).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

#[tokio::test]
async fn the_index_looks_crashes_up() {
    let env = env().await;
    assert_eq!(env.get("/", None).await.status, StatusCode::OK);

    let res = env.get("/?id=ABCD-EFGH-IJKL", None).await;
    assert_eq!(
        (res.status, res.location()),
        (StatusCode::SEE_OTHER, "/abcdefghijkl")
    );

    let res = env.get("/?id=nonsense", None).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.body.contains("look like a crash ID"));
}

// ---- files and actions ---------------------------------------------------------

#[tokio::test]
async fn raw_files_need_permission() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    env.put_files(ALICE_CRASH);
    let path = format!("/{ALICE_CRASH}/download");

    let anon = env.get(&path, None).await;
    assert_eq!(
        (anon.status, anon.location()),
        (StatusCode::SEE_OTHER, "/login")
    );
    assert_eq!(
        env.get(&path, Some(BOB)).await.status,
        StatusCode::FORBIDDEN
    );

    for who in [ALICE, ROOT] {
        let res = env.get(&path, Some(who)).await;
        assert_eq!(res.status, StatusCode::OK);
        assert_eq!(res.body, "MDMP-bytes");
        assert_eq!(
            res.headers[header::CONTENT_DISPOSITION],
            format!("attachment; filename=\"crash_{ALICE_CRASH}.dmp\"")
        );
    }

    let meta = env
        .get(&format!("/{ALICE_CRASH}/metadata"), Some(ALICE))
        .await;
    assert!(meta.body.contains("Map=x"));
    assert!(
        meta.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let console = env
        .get(&format!("/{ALICE_CRASH}/console"), Some(ALICE))
        .await;
    assert!(console.body.contains("hello console"));
    assert_eq!(
        env.get(&format!("/{ALICE_CRASH}/console"), Some(BOB))
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    // Anonymous uploads can only be managed by admins.
    env.seed(ANON_CRASH, None, "mod_anon").await;
    env.put_files(ANON_CRASH);
    let path = format!("/{ANON_CRASH}/download");
    assert_eq!(
        env.get(&path, Some(ALICE)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(env.get(&path, Some(ROOT)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn deleting_needs_permission_and_a_same_site_origin() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    env.put_files(ALICE_CRASH);
    let path = format!("/{ALICE_CRASH}/delete");

    // CSRF: right cookie, missing or foreign origin.
    assert_eq!(
        env.post(&path, Some(ALICE), None, "").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        env.post(&path, Some(ALICE), Some("https://evil.example"), "")
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    // Right origin, wrong person; and nobody.
    assert_eq!(
        env.post(&path, Some(BOB), Some(ORIGIN), "").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        env.post(&path, None, Some(ORIGIN), "").await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(env.count("SELECT COUNT(*) FROM crash").await, 1);

    let res = env.post(&path, Some(ALICE), Some(ORIGIN), "").await;
    assert_eq!(
        (res.status, res.location()),
        (StatusCode::SEE_OTHER, "/dashboard")
    );
    assert_eq!(env.count("SELECT COUNT(*) FROM crash").await, 0);
    assert_eq!(
        env.count("SELECT COUNT(*) FROM frame").await,
        0,
        "frames cascade"
    );
    assert!(!env.state.config.dump_path(ALICE_CRASH).exists());
    assert!(!env.state.config.meta_path(ALICE_CRASH).exists());

    assert_eq!(
        env.post(&path, Some(ALICE), Some(ORIGIN), "").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn only_admins_reprocess() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    let path = format!("/{ALICE_CRASH}/reprocess");

    assert_eq!(
        env.post(&path, Some(ALICE), Some(ORIGIN), "").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        env.post(&path, Some(ROOT), None, "").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(env.count("SELECT status FROM crash").await, 2);

    let res = env.post(&path, Some(ROOT), Some(ORIGIN), "").await;
    assert_eq!(
        (res.status, res.location()),
        (StatusCode::SEE_OTHER, "/aaaaaaaaaaaa")
    );
    assert_eq!(
        env.count("SELECT status FROM crash").await,
        0,
        "back in the queue"
    );

    // Already queued: nothing to redo.
    assert_eq!(
        env.post(&path, Some(ROOT), Some(ORIGIN), "").await.status,
        StatusCode::BAD_REQUEST
    );
}

// ---- dashboard and sharing -------------------------------------------------------

#[tokio::test]
async fn the_dashboard_shows_own_and_accepted_shared_reports() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    env.seed(BOB_CRASH, Some(BOB), "mod_bob").await;
    env.seed(ANON_CRASH, Some(CAROL), "mod_carol").await;

    assert_eq!(env.get("/dashboard", None).await.location(), "/login");

    // Bob invited Alice, who has not accepted yet.
    env.share(BOB, ALICE, false).await;
    let body = env.get("/dashboard", Some(ALICE)).await.body;
    assert!(body.contains("mod_alice") && !body.contains("mod_bob") && !body.contains("mod_carol"));

    let res = env
        .post(
            "/settings/share/accept",
            Some(ALICE),
            Some(ORIGIN),
            &format!("owner={BOB}"),
        )
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    let body = env.get("/dashboard", Some(ALICE)).await.body;
    assert!(body.contains("mod_alice") && body.contains("mod_bob") && !body.contains("mod_carol"));
    assert_eq!(
        env.get(&format!("/{BOB_CRASH}/console"), Some(ALICE))
            .await
            .status,
        StatusCode::NOT_FOUND,
        "no meta file, but allowed"
    );

    let filtered = env
        .get(&format!("/dashboard?user={BOB}"), Some(ALICE))
        .await
        .body;
    assert!(filtered.contains("mod_bob") && !filtered.contains("mod_alice"));
    // Filtering by someone you cannot see shows nothing rather than leaking.
    let nothing = env
        .get(&format!("/dashboard?user={CAROL}"), Some(ALICE))
        .await
        .body;
    assert!(!nothing.contains("mod_carol"));
    assert_eq!(
        env.get("/dashboard?user=abc", Some(ALICE)).await.status,
        StatusCode::BAD_REQUEST
    );

    let admin = env.get("/dashboard", Some(ROOT)).await.body;
    assert!(
        admin.contains("mod_alice") && admin.contains("mod_bob") && admin.contains("mod_carol")
    );
}

#[tokio::test]
async fn the_dashboard_pages() {
    let env = env().await;
    for i in 0..25 {
        sqlx::query("INSERT INTO crash (id, created_at, ip, owner, status, crash_module) VALUES (?, ?, x'01020304', ?, 2, 'bulk')")
            .bind(ids::generate())
            .bind(stats::now() - i)
            .bind(CAROL)
            .execute(&env.state.db)
            .await
            .unwrap();
    }
    let page1 = env.get("/dashboard", Some(CAROL)).await.body;
    assert_eq!(page1.matches("class=\"crash-link\"").count(), 20);
    assert!(page1.contains("page=2") && !page1.contains("Newer"));

    let page2 = env.get("/dashboard?page=2", Some(CAROL)).await.body;
    assert_eq!(page2.matches("class=\"crash-link\"").count(), 5);
    assert!(page2.contains("Newer") && !page2.contains("Older"));

    // Absurd pages are clamped, not an error or a huge OFFSET scan.
    assert_eq!(
        env.get("/dashboard?page=0", Some(CAROL)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        env.get("/dashboard?page=4000000000", Some(CAROL))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        env.get("/dashboard?page=x", Some(CAROL)).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn the_sharing_flow() {
    let env = env().await;
    let invite = |user: String, origin: Option<&'static str>| {
        let env = &env;
        async move {
            env.post(
                "/settings/share/invite",
                Some(ALICE),
                origin,
                &format!("user={user}"),
            )
            .await
        }
    };

    assert_eq!(
        invite(BOB.to_string(), None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        env.post("/settings/share/invite", None, Some(ORIGIN), "user=1")
            .await
            .location(),
        "/login"
    );

    for (user, error) in [
        (String::new(), "missing"),
        ("abc".into(), "invalid"),
        (ALICE.to_string(), "self"),
    ] {
        let res = invite(user.clone(), Some(ORIGIN)).await;
        assert_eq!(
            res.location(),
            format!("/settings/share?error={error}"),
            "{user:?}"
        );
    }

    let res = invite(BOB.to_string(), Some(ORIGIN)).await;
    assert_eq!(
        (res.status, res.location()),
        (StatusCode::SEE_OTHER, "/settings/share")
    );
    assert_eq!(
        env.count("SELECT COUNT(*) FROM share WHERE accepted_at IS NULL")
            .await,
        1
    );
    assert_eq!(
        invite(BOB.to_string(), Some(ORIGIN)).await.location(),
        "/settings/share?error=pending"
    );

    // Someone who wasn't invited cannot accept; the owner cannot accept for Bob.
    env.post(
        "/settings/share/accept",
        Some(CAROL),
        Some(ORIGIN),
        &format!("owner={ALICE}"),
    )
    .await;
    env.post(
        "/settings/share/accept",
        Some(ALICE),
        Some(ORIGIN),
        &format!("owner={ALICE}"),
    )
    .await;
    assert_eq!(
        env.count("SELECT COUNT(*) FROM share WHERE accepted_at IS NOT NULL")
            .await,
        0
    );

    env.post(
        "/settings/share/accept",
        Some(BOB),
        Some(ORIGIN),
        &format!("owner={ALICE}"),
    )
    .await;
    assert_eq!(
        env.count("SELECT COUNT(*) FROM share WHERE accepted_at IS NOT NULL")
            .await,
        1
    );
    assert_eq!(
        invite(BOB.to_string(), Some(ORIGIN)).await.location(),
        "/settings/share?error=exists"
    );

    let page = env.get("/settings/share?error=exists", Some(ALICE)).await;
    assert!(page.body.contains("That user already has access."));
    assert!(page.body.contains("Bob"));
    // Unknown error codes are ignored, never echoed.
    assert!(
        !env.get("/settings/share?error=%3Cb%3E", Some(ALICE))
            .await
            .body
            .contains("<b>")
    );

    // Revoking: exactly one of user/owner, and only your own side.
    let both = env
        .post(
            "/settings/share/revoke",
            Some(ALICE),
            Some(ORIGIN),
            &format!("user={BOB}&owner={BOB}"),
        )
        .await;
    assert_eq!(both.status, StatusCode::BAD_REQUEST);
    env.post(
        "/settings/share/revoke",
        Some(CAROL),
        Some(ORIGIN),
        &format!("user={BOB}"),
    )
    .await;
    assert_eq!(env.count("SELECT COUNT(*) FROM share").await, 1);
    env.post(
        "/settings/share/revoke",
        Some(ALICE),
        Some(ORIGIN),
        &format!("user={BOB}"),
    )
    .await;
    assert_eq!(env.count("SELECT COUNT(*) FROM share").await, 0);
}

#[tokio::test]
async fn either_side_can_end_a_share() {
    let env = env().await;
    env.share(ALICE, BOB, true).await;
    env.post(
        "/settings/share/revoke",
        Some(BOB),
        Some(ORIGIN),
        &format!("owner={ALICE}"),
    )
    .await;
    assert_eq!(env.count("SELECT COUNT(*) FROM share").await, 0);
}

// ---- login, sessions, headers -------------------------------------------------------

#[tokio::test]
async fn login_redirects_to_steam() {
    let env = env().await;
    let res = env.get("/login", None).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert!(
        res.location()
            .starts_with("https://steamcommunity.com/openid/login?")
    );
    assert!(
        res.location()
            .contains("openid.return_to=http%3A%2F%2Fthrottle.test%2Flogin%2Fcallback")
    );

    // Already logged in: straight to the dashboard.
    assert_eq!(
        env.get("/login", Some(ALICE)).await.location(),
        "/dashboard"
    );
}

#[tokio::test]
async fn forged_callbacks_are_rejected_before_any_network_call() {
    let env = env().await;
    for query in [
        "",
        "?openid.mode=cancel",
        "?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=id_res",
    ] {
        let res = env.get(&format!("/login/callback{query}"), None).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{query}");
        assert!(!res.headers.contains_key(header::SET_COOKIE));
    }
}

#[tokio::test]
async fn bad_sessions_mean_logged_out() {
    let env = env().await;
    let good = env.cookie(ALICE);

    let tampered = good.replacen(&ALICE.to_string(), &BOB.to_string(), 1);
    let expired = format!(
        "{}={}",
        session::cookie_name(false),
        session::mint(&env.state.secret, ALICE, stats::now() - 31 * 86_400)
    );
    let foreign = format!(
        "{}={}",
        session::cookie_name(false),
        session::mint(&Secret::from_bytes(vec![9; 32]), ALICE, stats::now())
    );
    for cookie in [
        tampered,
        expired,
        foreign,
        "throttle_session=garbage".into(),
    ] {
        let req = Request::get("/dashboard")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let res = env.send(req).await;
        assert_eq!(
            (res.status, res.location()),
            (StatusCode::SEE_OTHER, "/login"),
            "{cookie}"
        );
    }

    let req = Request::get("/dashboard")
        .header(header::COOKIE, &good)
        .body(Body::empty())
        .unwrap();
    assert_eq!(env.send(req).await.status, StatusCode::OK);
}

#[tokio::test]
async fn logout_clears_the_cookie_and_checks_the_origin() {
    let env = env().await;
    assert_eq!(
        env.post("/logout", Some(ALICE), None, "").await.status,
        StatusCode::FORBIDDEN
    );

    let res = env.post("/logout", Some(ALICE), Some(ORIGIN), "").await;
    assert_eq!((res.status, res.location()), (StatusCode::SEE_OTHER, "/"));
    let cookie = res.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("Max-Age=0") && cookie.contains("HttpOnly"));

    // GET /logout does not log anyone out (it would be CSRF-able).
    assert_ne!(env.get("/logout", Some(ALICE)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn every_response_carries_security_headers() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    for path in [
        "/",
        "/aaaaaaaaaaaa",
        "/nope",
        "/healthz",
        "/static/app.css",
        "/robots.txt",
    ] {
        let res = env.get(path, None).await;
        let h = &res.headers;
        assert!(
            h[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("default-src 'none'"),
            "{path}"
        );
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{path}");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY", "{path}");
        assert!(h.contains_key(header::CACHE_CONTROL), "{path}");
    }
    let css = env.get("/static/app.css", None).await;
    assert!(
        css.headers[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("max-age")
    );
    assert_eq!(
        env.get("/robots.txt", None).await.body,
        "User-agent: *\nDisallow: /\n"
    );
}

#[tokio::test]
async fn ingest_routes_still_win_over_crash_ids() {
    let env = env().await;
    // POST-only routes answer 405 to GET instead of being swallowed by /{id}.
    assert_eq!(
        env.get("/submit", None).await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(env.get("/healthz", None).await.status, StatusCode::OK);
}

// ---- statistics ---------------------------------------------------------------------

impl Env {
    /// A processed crash `age_secs` old, from address 10.0.0.`ip`.
    async fn stat_crash(
        &self,
        id: &str,
        age_secs: i64,
        module: &str,
        hash: &str,
        owner: Option<i64>,
        ip: u8,
    ) {
        sqlx::query(
            "INSERT INTO crash (id, created_at, ip, owner, status, has_dump, stackhash, crash_module, crash_function) \
             VALUES (?, ?, ?, ?, 2, 1, ?, ?, 'Crashy')",
        )
        .bind(id)
        .bind(stats::now() - age_secs)
        .bind(vec![10, 0, 0, ip])
        .bind(owner)
        .bind(hash)
        .bind(module)
        .execute(&self.state.db)
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn the_stats_page_is_public_aggregate_and_ordered_by_crash_count() {
    let env = env().await;
    env.stat_crash("aaaaaaaaaaaa", 60, "mod_a", "h1", Some(ALICE), 1)
        .await;
    env.stat_crash("bbbbbbbbbbbb", 70, "mod_a", "h1", Some(BOB), 2)
        .await;
    env.stat_crash("cccccccccccc", 80, "mod_b", "h2", None, 3)
        .await;
    env.stat_crash("dddddddddddd", 20 * 86_400, "mod_old", "h3", None, 4)
        .await;

    let res = env.get("/stats", None).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.headers[header::CACHE_CONTROL], "private, max-age=60");
    let body = &res.body;

    // 90 daily and 168 hourly bars, however the clock falls; the performance charts are
    // line/area paths with a legend.
    assert_eq!(body.matches("class=\"bar\"").count(), 90 + 168);
    assert_eq!(body.matches("<figure class=\"perf\"").count(), 8);
    assert!(body.contains("mod_a!Crashy") && body.contains("mod_b!Crashy"));
    assert!(
        body.find("mod_a").unwrap() < body.find("mod_b").unwrap(),
        "most crashes first"
    );
    assert!(
        body.contains("<td>2</td>"),
        "two crashes share the first stack"
    );
    // The default period is all time, as the old site's.
    assert!(body.contains("mod_old"));
    // Nobody's identity is on this page.
    assert!(!body.contains("Alice") && !body.contains("Bob"));

    for (scope, shows_old) in [
        ("day", false),
        ("week", false),
        ("month", true),
        ("all", true),
        ("bogus", true),
    ] {
        let body = env.get(&format!("/stats?scope={scope}"), None).await.body;
        assert_eq!(body.contains("mod_old"), shows_old, "{scope}");
        assert!(body.contains("mod_a"), "{scope}");
    }
}

#[tokio::test]
async fn the_stats_page_works_when_empty_and_escapes_what_it_shows() {
    let env = env().await;
    let res = env.get("/stats", None).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("No processed crashes in this period."));

    env.stat_crash("aaaaaaaaaaaa", 60, "<b>x</b>", "h1", None, 1)
        .await;
    let body = env.get("/stats", None).await.body;
    assert!(!body.contains("<b>x</b>"));
    assert!(body.contains("&lt;b&gt;"));

    // The navigation links to it, for everybody.
    assert!(env.get("/", None).await.body.contains("href=\"/stats\""));
}

#[tokio::test]
async fn the_stats_page_reports_the_last_days_counters() {
    let env = env().await;
    stats::bump(&env.state.db, "crashes:accepted", 7).await;
    stats::bump(&env.state.db, "processing:count", 2).await;
    stats::bump(&env.state.db, "processing:millis", 500).await;
    let body = env.get("/stats", None).await.body;
    assert!(body.contains("Processing Performance"), "{body}");
    assert!(body.contains("Crashes submitted - by day"));
    assert!(body.contains("<td>accepted</td>"));
}

// ---- deep analysis (carburetor) ---------------------------------------------------------

async fn with_analysis() -> Env {
    let env =
        env_with(|c| c.carburetor.path = Some(crate::carburetor::tests::fake().to_path_buf()))
            .await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    env.put_files(ALICE_CRASH);
    env
}

/// The fake program prints a different fixture depending on the dump's first line.
fn set_mode(env: &Env, mode: &str) {
    std::fs::write(env.state.config.dump_path(ALICE_CRASH), format!("{mode}\n")).unwrap();
}

#[tokio::test]
async fn the_analysis_does_not_exist_without_a_configured_program() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    env.put_files(ALICE_CRASH);
    for path in [
        format!("/{ALICE_CRASH}/carburetor"),
        format!("/{ALICE_CRASH}/carburetor/data"),
    ] {
        for who in [None, Some(ALICE), Some(ROOT)] {
            assert_eq!(
                env.get(&path, who).await.status,
                StatusCode::NOT_FOUND,
                "{path} {who:?}"
            );
        }
    }
    // Without the program, "View Raw" opens the plain text report instead.
    let body = env.get(&format!("/{ALICE_CRASH}"), Some(ALICE)).await.body;
    assert!(!body.contains("/carburetor"), "{body}");
    assert!(body.contains("View Raw") && body.contains(&format!("/{ALICE_CRASH}/raw")));
}

#[tokio::test]
async fn only_people_who_manage_the_crash_get_the_analysis() {
    let env = with_analysis().await;
    set_mode(&env, "real");
    let page = format!("/{ALICE_CRASH}/carburetor");
    let data = format!("{page}/data");

    for path in [&page, &data] {
        let anon = env.get(path, None).await;
        assert_eq!(
            (anon.status, anon.location()),
            (StatusCode::SEE_OTHER, "/login"),
            "{path}"
        );
        assert_eq!(
            env.get(path, Some(BOB)).await.status,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }

    let res = env.get(&page, Some(ALICE)).await;
    assert_eq!(res.status, StatusCode::OK);
    for part in [
        "CrashFunction",
        "Thread 0 (crashed):",
        "eip: 0x",
        "Found via instruction pointer in context",
    ] {
        assert!(res.body.contains(part), "{part} missing in {}", res.body);
    }
    // The three tabs of the old viewer.
    for tab in ["Stack", "Memory", "Raw"] {
        assert!(res.body.contains(&format!(">{tab}</label>")), "{tab}");
    }
    assert!(
        res.body.contains("kernel32.pdb"),
        "modules without symbols are in the Raw tab"
    );

    let raw = env.get(&data, Some(ROOT)).await;
    assert_eq!(raw.status, StatusCode::OK);
    assert_eq!(raw.headers[header::CONTENT_TYPE], "application/json");
    assert!(serde_json::from_str::<serde_json::Value>(&raw.body).is_ok());

    // The button is only offered to those who can use it.
    let details = format!("/{ALICE_CRASH}");
    assert!(
        env.get(&details, Some(ALICE))
            .await
            .body
            .contains(&format!("/{ALICE_CRASH}/carburetor"))
    );
    assert!(
        env.get(&details, Some(ALICE))
            .await
            .body
            .contains("View Raw")
    );
    assert!(!env.get(&details, Some(BOB)).await.body.contains("View Raw"));
    assert!(!env.get(&details, None).await.body.contains("View Raw"));
}

#[tokio::test]
async fn analysis_output_is_escaped_and_failures_become_error_pages() {
    let env = with_analysis().await;
    let page = format!("/{ALICE_CRASH}/carburetor");

    set_mode(&env, "plugin");
    let body = env.get(&page, Some(ALICE)).await.body;
    assert!(!body.contains("<script>alert"), "{body}");
    assert!(body.contains("&lt;script&gt;"));
    assert!(body.contains("plugin.smx: OnPluginStart"));

    set_mode(&env, "fail");
    assert_eq!(
        env.get(&page, Some(ALICE)).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    set_mode(&env, "garbage");
    assert_eq!(
        env.get(&page, Some(ALICE)).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );

    // A crash without a dump has nothing to analyze.
    std::fs::remove_file(env.state.config.dump_path(ALICE_CRASH)).unwrap();
    assert_eq!(
        env.get(&page, Some(ALICE)).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_busy_analyzer_asks_to_try_again() {
    let env = with_analysis().await;
    set_mode(&env, "real");
    let slots = env.state.config.carburetor.max_concurrent;
    let held: Vec<_> = (0..slots)
        .map(|_| env.state.carburetor_runs.try_acquire().unwrap())
        .collect();

    let res = env
        .get(&format!("/{ALICE_CRASH}/carburetor"), Some(ALICE))
        .await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(res.body.contains("Try again"));
    drop(held);
    assert_eq!(
        env.get(&format!("/{ALICE_CRASH}/carburetor"), Some(ALICE))
            .await
            .status,
        StatusCode::OK
    );
}

// ---- the address the site is reached at ----------------------------------------------

impl Env {
    /// A request that names its host the way a browser does.
    async fn call(&self, method: Method, path: &str, host: &str, origin: Option<&str>) -> Res {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }
}

fn form_encoded(host: &str) -> String {
    host.replace(':', "%3A")
        .replace('[', "%5B")
        .replace(']', "%5D")
}

#[tokio::test]
async fn without_a_pinned_hostname_login_returns_to_the_address_it_was_opened_on() {
    let env = env_with(|c| c.hostname = None).await;
    for host in [
        "0.0.0.0:8080",
        "localhost:8080",
        "192.168.1.5:9000",
        "[::1]:8080",
        "throttle.example.com",
    ] {
        let res = env.call(Method::GET, "/login", host, None).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{host}");
        let encoded = form_encoded(host);
        assert!(
            res.location().contains(&format!(
                "openid.return_to=http%3A%2F%2F{encoded}%2Flogin%2Fcallback&"
            )),
            "{host}: {}",
            res.location()
        );
        assert!(
            res.location()
                .contains(&format!("openid.realm=http%3A%2F%2F{encoded}&")),
            "{host}"
        );
    }

    // A Host header that is not a host is not believed: we use where we listen.
    for bad in ["", "a b", "evil.com/path", "user@evil.com", "x?y"] {
        let res = env.call(Method::GET, "/login", bad, None).await;
        assert!(
            res.location()
                .contains("openid.return_to=http%3A%2F%2F127.0.0.1%3A8080%2Flogin%2Fcallback&"),
            "{bad:?}: {}",
            res.location()
        );
    }

    // And the page title does not print a missing hostname.
    let home = env.call(Method::GET, "/", "0.0.0.0:8080", None).await;
    assert!(
        home.body.contains("<title>Throttle</title>"),
        "{}",
        home.body
    );
}

#[tokio::test]
async fn without_a_pinned_hostname_posts_are_accepted_from_the_same_site_only() {
    let env = env_with(|c| c.hostname = None).await;
    for host in ["0.0.0.0:8080", "localhost:8080", "192.168.1.5:9000"] {
        let own = format!("http://{host}");
        let ok = env.call(Method::POST, "/logout", host, Some(&own)).await;
        assert_eq!(
            (ok.status, ok.location()),
            (StatusCode::SEE_OTHER, "/"),
            "{host}"
        );

        let wrong_scheme = format!("https://{host}");
        let subdomain = format!("http://{host}.evil.example");
        for foreign in [
            "http://evil.example",
            "null",
            wrong_scheme.as_str(),
            subdomain.as_str(),
        ] {
            let res = env.call(Method::POST, "/logout", host, Some(foreign)).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{host} from {foreign}");
        }
        let no_origin = env.call(Method::POST, "/logout", host, None).await;
        assert_eq!(
            no_origin.status,
            StatusCode::FORBIDDEN,
            "{host} without Origin"
        );
    }
}

#[tokio::test]
async fn a_pinned_hostname_is_not_overridden_by_the_host_header() {
    let env = env().await; // pinned to throttle.test
    let res = env.call(Method::GET, "/login", "evil.example", None).await;
    assert!(
        res.location()
            .contains("openid.return_to=http%3A%2F%2Fthrottle.test%2Flogin%2Fcallback&")
    );
    assert!(!res.location().contains("evil"));

    // An Origin that matches the Host header but not the pinned name is refused.
    let forged = env
        .call(
            Method::POST,
            "/logout",
            "evil.example",
            Some("http://evil.example"),
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let own = env
        .call(Method::POST, "/logout", "evil.example", Some(ORIGIN))
        .await;
    assert_eq!(own.status, StatusCode::SEE_OTHER);

    let home = env.call(Method::GET, "/", "evil.example", None).await;
    assert!(
        home.body
            .contains("<title>Throttle · throttle.test</title>"),
        "{}",
        home.body
    );
}

// ---- repeats, bulk delete, raw view ---------------------------------------

async fn crashes_left(env: &Env) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM crash")
        .fetch_one(&env.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn ticked_reports_are_deleted_together_or_not_at_all() {
    let env = env().await;
    let (a, b, c) = (ALICE_CRASH, "dddddddddddd", BOB_CRASH);
    env.seed(a, Some(ALICE), "m").await;
    env.seed(b, Some(ALICE), "m").await;
    env.seed(c, Some(BOB), "m").await;
    for id in [a, b, c] {
        env.put_files(id);
    }
    let all = format!("id={a}&id={b}&id={c}");

    let evil = env
        .post(
            "/dashboard/delete",
            Some(ALICE),
            Some("https://evil.example"),
            &all,
        )
        .await;
    assert_eq!(evil.status, StatusCode::FORBIDDEN);
    let anonymous = env
        .post("/dashboard/delete", None, Some(ORIGIN), &all)
        .await;
    assert_eq!(anonymous.location(), "/login");

    // Bob's report among them: nothing is deleted.
    let res = env
        .post("/dashboard/delete", Some(ALICE), Some(ORIGIN), &all)
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(crashes_left(&env).await, 3);

    // Her own, one twice, an unknown id and a malformed one.
    let own = format!("id={a}&id={b}&id=zzzzzzzzzzzz&id=not-an-id&id={a}");
    let res = env
        .post("/dashboard/delete", Some(ALICE), Some(ORIGIN), &own)
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.location(), "/dashboard?deleted=2");
    assert_eq!(crashes_left(&env).await, 1);
    assert!(!env.state.config.dump_path(a).exists());
    assert!(!env.state.config.dump_path(b).exists());
    assert!(env.state.config.dump_path(c).exists(), "Bob's files stay");

    // Nothing ticked; and an admin may delete anybody's, keeping the filter.
    let res = env
        .post("/dashboard/delete", Some(ALICE), Some(ORIGIN), "")
        .await;
    assert_eq!(res.location(), "/dashboard?deleted=0");
    let form = format!("id={c}&user={BOB}");
    let res = env
        .post("/dashboard/delete", Some(ROOT), Some(ORIGIN), &form)
        .await;
    assert_eq!(res.location(), format!("/dashboard?deleted=1&user={BOB}"));
    assert_eq!(crashes_left(&env).await, 0);
}

#[tokio::test]
async fn the_dashboard_offers_checkboxes_and_says_how_many_were_deleted() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "m").await;

    let body = env.get("/dashboard", Some(ALICE)).await.body;
    assert!(body.contains(r#"name="id" value="aaaaaaaaaaaa""#), "{body}");
    assert!(body.contains("Delete the selected reports?"));
    assert!(
        !body.contains(" checked aria-label"),
        "nothing is ticked by default"
    );
    assert!(!body.contains("Deleted "));

    let body = env.get("/dashboard?select=all", Some(ALICE)).await.body;
    assert!(body.contains(" checked aria-label"), "{body}");

    assert!(
        env.get("/dashboard?deleted=2", Some(ALICE))
            .await
            .body
            .contains("Deleted 2 reports.")
    );
    assert!(
        env.get("/dashboard?deleted=1", Some(ALICE))
            .await
            .body
            .contains("Deleted 1 report.")
    );

    // Nothing to select, nothing to offer.
    let body = env.get("/dashboard", Some(CAROL)).await.body;
    assert!(!body.contains("Delete selected"), "{body}");
}

#[tokio::test]
async fn repeats_show_on_the_dashboard_the_crash_page_and_the_stats() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "m").await;
    sqlx::query("UPDATE crash SET repeats = 4, last_repeat_at = ?")
        .bind(stats::now() - 3600)
        .execute(&env.state.db)
        .await
        .unwrap();

    let body = env.get("/dashboard", Some(ALICE)).await.body;
    assert!(
        body.contains("&times;5") && body.contains("Reported 5 times"),
        "{body}"
    );

    let body = env.get(&format!("/{ALICE_CRASH}"), None).await.body;
    assert!(body.contains("reported again 4 times"), "{body}");
    assert!(
        body.contains("5 reports share this crash signature"),
        "{body}"
    );

    // A crash that never repeated says nothing of the kind.
    env.seed(BOB_CRASH, Some(BOB), "m").await;
    let body = env.get(&format!("/{BOB_CRASH}"), None).await.body;
    assert!(!body.contains("reported again"), "{body}");

    env.stat_crash("eeeeeeeeeeee", 60, "mod_r", "h9", Some(ALICE), 1)
        .await;
    sqlx::query("UPDATE crash SET repeats = 2 WHERE id = 'eeeeeeeeeeee'")
        .execute(&env.state.db)
        .await
        .unwrap();
    let body = env.get("/stats", None).await.body;
    assert!(
        body.contains("mod_r") && body.contains("<td>3</td>"),
        "{body}"
    );
}

#[tokio::test]
async fn the_raw_view_prints_the_whole_dump_for_whoever_manages_the_crash() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "m").await;
    let dump = env.state.config.dump_path(ALICE_CRASH);
    std::fs::create_dir_all(dump.parent().unwrap()).unwrap();
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dumps/test.dmp"),
        &dump,
    )
    .unwrap();
    let path = format!("/{ALICE_CRASH}/raw");

    let res = env.get(&path, Some(ALICE)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    for part in [
        "Operating system:",
        "Crash reason:",
        "Thread 0",
        "Loaded modules:",
    ] {
        assert!(res.body.contains(part), "{part} missing in {}", res.body);
    }
    // The report comes from the dump alone, not from what the database holds.
    assert!(!res.body.contains("hunter2"));

    // Only people who manage the crash, and the page only offers it to them.
    assert_eq!(env.get(&path, None).await.location(), "/login");
    assert_eq!(
        env.get(&path, Some(BOB)).await.status,
        StatusCode::FORBIDDEN
    );
    assert!(
        env.get(&format!("/{ALICE_CRASH}"), Some(ALICE))
            .await
            .body
            .contains(&path)
    );
    assert!(
        !env.get(&format!("/{ALICE_CRASH}"), None)
            .await
            .body
            .contains("/raw")
    );

    // The dump is gone (evicted), or is not a dump.
    env.seed(BOB_CRASH, Some(ALICE), "m").await;
    assert_eq!(
        env.get(&format!("/{BOB_CRASH}/raw"), Some(ALICE))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    env.seed("dddddddddddd", Some(ALICE), "m").await;
    env.put_files("dddddddddddd");
    let res = env.get("/dddddddddddd/raw", Some(ALICE)).await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
}

// ---- the stats drill-down -------------------------------------------------------------

/// The first frame of the crash's thread, as the crash page shows it.
async fn top_frame(env: &Env, id: &str, rendered: &str) {
    sqlx::query("UPDATE crash SET thread = 0 WHERE id = ?")
        .bind(id)
        .execute(&env.state.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO frame (crash, thread, frame, rendered) VALUES (?, 0, 0, ?)")
        .bind(id)
        .bind(rendered)
        .execute(&env.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_stats_drill_down_goes_from_the_module_to_the_function_to_the_stack() {
    let env = env().await;
    env.stat_crash("aaaaaaaaaaaa", 60, "mod_a", "abcd1234", Some(ALICE), 1)
        .await;
    env.stat_crash("bbbbbbbbbbbb", 70, "mod_a", "abcd1234", Some(BOB), 2)
        .await;
    env.stat_crash("cccccccccccc", 80, "mod_b", "ef567890", None, 3)
        .await;
    top_frame(&env, "aaaaaaaaaaaa", "mod_a!Crashy + 0x10").await;
    top_frame(&env, "bbbbbbbbbbbb", "mod_a!Crashy + 0x10").await;
    top_frame(&env, "cccccccccccc", "mod_b!Crashy + 0x20").await;

    // The site-wide page links each row down to its function, and has the counters.
    let root = env.get("/stats", None).await.body;
    assert!(
        root.contains("&#x2f;stats&#x2f;mod_a&#x2f;Crashy"),
        "{root}"
    );
    assert!(root.contains("Unique servers") && root.contains("Latest Crash Reports"));

    // A module: its functions and its crashes, and none of the site-wide numbers.
    let res = env.get("/stats/mod_a", None).await;
    assert_eq!(res.status, StatusCode::OK);
    let body = &res.body;
    assert!(
        body.contains("mod_a!Crashy") && body.contains("<td>2</td>"),
        "{body}"
    );
    assert!(
        body.contains("AAAA-AAAA-AAAA") && body.contains("BBBB-BBBB-BBBB"),
        "{body}"
    );
    assert!(
        !body.contains("mod_b") && !body.contains("CCCC-CCCC-CCCC"),
        "{body}"
    );
    assert!(!body.contains("Unique servers"));
    assert_eq!(body.matches("class=\"bar\"").count(), 90 + 168);

    // A function: its frames, offsets included.
    let body = env.get("/stats/mod_a/Crashy", None).await.body;
    assert!(
        body.contains("mod_a!Crashy + 0x10") && body.contains("<td>2</td>"),
        "{body}"
    );
    assert!(!body.contains("mod_b"));

    // A stack: the crashes that share it.
    let body = env.get("/stats/abcd1234", None).await.body;
    assert!(
        body.contains("AAAA-AAAA-AAAA") && body.contains("BBBB-BBBB-BBBB"),
        "{body}"
    );
    assert!(!body.contains("CCCC-CCCC-CCCC"));

    // Nothing known about a name; and not a name at all.
    let body = env.get("/stats/nothing_here", None).await.body;
    assert!(body.contains("No processed crashes in this period."));
    assert_eq!(
        env.get("/stats/%00", None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn names_with_odd_characters_survive_the_round_trip_through_a_link() {
    let env = env().await;
    env.stat_crash("aaaaaaaaaaaa", 60, "mod_x", "abcd1234", None, 1)
        .await;
    sqlx::query("UPDATE crash SET crash_function = 'Foo::bar(int/char*) 100%'")
        .execute(&env.state.db)
        .await
        .unwrap();

    let root = env.get("/stats", None).await.body;
    let link = "&#x2f;stats&#x2f;mod_x&#x2f;Foo%3A%3Abar%28int%2Fchar%2A%29%20100%25";
    assert!(root.contains(link), "{root}");

    let res = env
        .get(
            "/stats/mod_x/Foo%3A%3Abar%28int%2Fchar%2A%29%20100%25",
            None,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        res.body.contains("Foo::bar(int&#x2f;char*) 100%"),
        "{}",
        res.body
    );
}

#[tokio::test]
async fn the_site_charts_come_from_the_counters_with_repeats_included() {
    let env = env().await;
    stats::bump(&env.state.db, "crashes:accepted", 5).await;
    stats::bump(&env.state.db, "crashes:repeated", 3).await;
    let body = env.get("/stats", None).await.body;
    // The current hour, in the hourly chart and in the daily one.
    assert_eq!(body.matches(": 8</title>").count(), 2, "{body}");
    assert!(body.contains("<span>8</span>"), "the last 24 hours");
}

#[tokio::test]
async fn the_crash_page_links_its_signature_to_the_stats_of_that_stack() {
    let env = env().await;
    env.seed(ALICE_CRASH, Some(ALICE), "mod_alice").await;
    let body = env.get(&format!("/{ALICE_CRASH}"), None).await.body;
    // The link is template text, not a value: its slashes are not escaped.
    assert!(body.contains("href=\"/stats/abcd1234\""), "{body}");
    assert_eq!(
        env.get("/stats/abcd1234", None).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_crash_id_that_starts_with_stats_is_still_a_crash() {
    let env = env().await;
    env.seed("statsaaaaaaa", Some(ALICE), "m").await;
    assert_eq!(env.get("/statsaaaaaaa", None).await.status, StatusCode::OK);
}
