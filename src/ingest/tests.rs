//! End-to-end tests: real router, in-memory database, temp data directory.

use std::io::Read;
use std::net::SocketAddr;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use super::token::{self, Kind, Secret};
use crate::app::{AppState, router};
use crate::config::Config;
use crate::{db, ids, stats};

const IP: [u8; 4] = [203, 0, 113, 9];
const BOUNDARY: &str = "----throttletest";

const SIG: &str = "2|1700000000|linux|amd64|1|SIGSEGV /0x00000000|0|0\
    |M|server_srv.so|AAAABBBBCCCCDDDDEEEEFFFF000011112\
    |M|libc.so.6|0123456789ABCDEF0123456789ABCDEF0\
    |F|0|1d72|F|1|f302e|F|-1|400000";

const SYM: &str = "MODULE Linux x86_64 AAAABBBBCCCCDDDDEEEEFFFF000011112 server_srv.so\n\
    FILE 0 /src/a.cpp\n\
    FUNC 1000 20 0 main\n\
    1000 20 10 0\n\
    STACK CFI INIT 1000 20 .cfa: $rsp 8 + .ra: .cfa 8 - ^\n";

const META: &str = "-------- CONFIG BEGIN --------\nMap=de_dust2\nCommandLine=./srcds_run +map x\nSourceModVersion=1.12\nEmpty=\n-------- CONFIG END --------\n-------- CONSOLE HISTORY BEGIN --------\nhello\n-------- CONSOLE HISTORY END --------\n";

struct Harness {
    app: Router,
    state: AppState,
    _dir: TempDir,
}

async fn harness(tweak: impl FnOnce(&mut Config)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        data_dir: dir.path().to_path_buf(),
        ..Config::default()
    };
    // Test machines may be short on disk; the low-disk test sets this itself.
    config.limits.disk_min_free_bytes = 0;
    tweak(&mut config);
    std::fs::create_dir_all(config.dumps_dir()).unwrap();
    std::fs::create_dir_all(config.symbols_dir()).unwrap();

    let state = AppState::new(
        config,
        db::open_memory().await.unwrap(),
        Secret::from_bytes(vec![7; 32]),
    );
    let app = router(state.clone()).layer(MockConnectInfo(SocketAddr::from((IP, 4000))));
    Harness {
        app,
        state,
        _dir: dir,
    }
}

async fn post(h: &Harness, path: &str, content_type: &str, body: Vec<u8>) -> (StatusCode, String) {
    let req = Request::post(path)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap();
    let res = h.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Default)]
struct Form(Vec<u8>);

impl Form {
    fn text(mut self, key: &str, value: &str) -> Self {
        self.0.extend(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"
            )
            .bytes(),
        );
        self
    }

    fn file(mut self, key: &str, data: &[u8]) -> Self {
        self.0.extend(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{key}\"; filename=\"{key}.bin\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .bytes(),
        );
        self.0.extend_from_slice(data);
        self.0.extend_from_slice(b"\r\n");
        self
    }

    async fn send(mut self, h: &Harness, path: &str) -> (StatusCode, String) {
        self.0.extend(format!("--{BOUNDARY}--\r\n").bytes());
        post(
            h,
            path,
            &format!("multipart/form-data; boundary={BOUNDARY}"),
            self.0,
        )
        .await
    }
}

async fn insert_crash(h: &Harness, id: &str, status: i64) {
    sqlx::query("INSERT INTO crash (id, created_at, ip, status) VALUES (?, ?, ?, ?)")
        .bind(id)
        .bind(stats::now())
        .bind(IP.to_vec())
        .bind(status)
        .execute(&h.state.db)
        .await
        .unwrap();
}

fn crash_id(body: &str) -> String {
    ids::normalize(
        body.strip_prefix("Crash ID: ")
            .expect("a Crash ID response"),
    )
    .unwrap()
}

fn tmp_is_empty(h: &Harness) -> bool {
    match std::fs::read_dir(h.state.config.dumps_dir().join(".tmp")) {
        Ok(mut d) => d.next().is_none(),
        Err(_) => true,
    }
}

// ---- presubmit ------------------------------------------------------------

#[tokio::test]
async fn presubmit_asks_for_unknown_symbols_and_gives_a_token() {
    let h = harness(|_| {}).await;
    let (status, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert_eq!(status, StatusCode::OK);

    let parts: Vec<&str> = body.split('|').collect();
    assert_eq!(parts.len(), 3, "{body}");
    assert_eq!(parts[0], "Y");
    assert_eq!(parts[1], "YY"); // exactly one flag per module
    let claims = token::verify(&h.state.secret, parts[2], stats::now()).unwrap();
    assert_eq!(claims.kind, Kind::Full);
    assert_eq!(claims.signature.len(), 16);
}

#[tokio::test]
async fn presubmit_does_not_ask_for_symbols_we_have() {
    let h = harness(|_| {}).await;
    sqlx::query("INSERT INTO symbol (name, identifier, created_at) VALUES ('server_srv.so', 'AAAABBBBCCCCDDDDEEEEFFFF000011112', 1)")
        .execute(&h.state.db)
        .await
        .unwrap();
    let (_, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("Y|NY|"), "{body}");
}

#[tokio::test]
async fn presubmit_reports_bad_signatures_as_errors() {
    let h = harness(|_| {}).await;
    let (status, body) = Form::default()
        .text("CrashSignature", "9|garbage")
        .send(&h, "/submit")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "E|bad version");
}

#[tokio::test]
async fn presubmit_applies_the_rate_limit() {
    let h = harness(|c| c.limits.rate_limit = 1).await;
    insert_crash(&h, "aaaaaaaaaaaa", 2).await;
    let (_, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert_eq!(body, "N|NN|Rate limit exceeded.");
}

#[tokio::test]
async fn presubmit_asks_for_metadata_only_when_the_queue_is_full() {
    let h = harness(|c| c.limits.queue_watermark = 2).await;
    insert_crash(&h, "aaaaaaaaaaaa", 0).await;
    let (_, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("Y|"), "queue below the watermark: {body}");

    insert_crash(&h, "bbbbbbbbbbbb", 0).await;
    let (_, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("M|YY|"), "{body}");
}

#[tokio::test]
async fn presubmit_dedupes_known_signatures() {
    let h = harness(|c| c.limits.dedupe_threshold = 1).await;
    let fingerprint = super::signature::parse(SIG).unwrap().hash();
    sqlx::query("INSERT INTO crash (id, created_at, ip, status, signature) VALUES ('aaaaaaaaaaaa', ?, x'01020304', 2, ?)")
        .bind(stats::now())
        .bind(&fingerprint)
        .execute(&h.state.db)
        .await
        .unwrap();
    let (_, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("M|"), "{body}");
}

// ---- upload ---------------------------------------------------------------

#[tokio::test]
async fn upload_stores_dump_metadata_and_row() {
    let h = harness(|_| {}).await;
    let (status, body) = Form::default()
        .text("UserID", "STEAM_0:1:1234")
        .text("ServerID", "0b1c2d3e-aaaa-4bbb-8ccc-0123456789ab")
        .text("GameDirectory", "csgo")
        .file("upload_file_minidump", b"MDMP-not-really")
        .file("upload_file_metadata", META.as_bytes())
        .send(&h, "/submit")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.starts_with("Crash ID: ") && body.len() == "Crash ID: ".len() + 14,
        "{body}"
    );
    assert!(!body.ends_with('\n'));
    let id = crash_id(&body);

    let dir = h.state.config.dumps_dir().join(&id[..2]);
    assert_eq!(
        std::fs::read(dir.join(format!("{id}.dmp"))).unwrap(),
        b"MDMP-not-really"
    );

    let mut gz = flate2::read::GzDecoder::new(
        std::fs::File::open(dir.join(format!("{id}.meta.txt.gz"))).unwrap(),
    );
    let mut raw = String::new();
    gz.read_to_string(&mut raw).unwrap();
    assert_eq!(raw, META);

    type Row = (
        Option<i64>,
        Vec<u8>,
        i64,
        i64,
        i64,
        Option<String>,
        Option<String>,
        String,
    );
    let row: Row = sqlx::query_as(
        "SELECT owner, ip, status, has_dump, dump_bytes, cmdline, server_id, metadata FROM crash WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&h.state.db)
    .await
    .unwrap();
    assert_eq!(row.0, Some(76_561_197_960_265_728 + 2469));
    assert_eq!(row.1, IP.to_vec());
    assert_eq!((row.2, row.3, row.4), (0, 1, 15)); // pending, has dump, 15 bytes
    assert_eq!(row.5.as_deref(), Some("./srcds_run +map x"));
    assert_eq!(
        row.6.as_deref(),
        Some("0b1c2d3e-aaaa-4bbb-8ccc-0123456789ab")
    );

    let meta: Value = serde_json::from_str(&row.7).unwrap();
    assert_eq!(meta["Map"], "de_dust2");
    assert_eq!(meta["GameDirectory"], "csgo");
    assert_eq!(meta["HasConsoleLog"], true);
    assert!(meta.get("CommandLine").is_none());
    assert!(meta.get("UserID").is_none());
    assert!(meta.get("Empty").is_none());

    assert!(tmp_is_empty(&h));
}

#[tokio::test]
async fn upload_without_a_dump_is_refused_with_the_legacy_text() {
    let h = harness(|_| {}).await;
    let (status, body) = Form::default()
        .file("upload_file_metadata", META.as_bytes())
        .send(&h, "/submit")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        "A problem with your host is preventing crash reports from being generated.\n"
    );

    // An empty dump is the same as none.
    let (_, body) = Form::default()
        .file("upload_file_minidump", b"")
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("A problem with your host"));
}

#[tokio::test]
async fn upload_rate_limit_answers_200_with_the_legacy_text() {
    let h = harness(|c| c.limits.rate_limit = 1).await;
    let (_, first) = Form::default()
        .file("upload_file_minidump", b"x")
        .send(&h, "/submit")
        .await;
    assert!(first.starts_with("Crash ID: "));

    let (status, second) = Form::default()
        .file("upload_file_minidump", b"x")
        .send(&h, "/submit")
        .await;
    assert_eq!(
        (status, second.as_str()),
        (StatusCode::OK, "Rate limit exceeded.")
    );
    assert!(tmp_is_empty(&h));
}

#[tokio::test]
async fn metadata_only_upload_needs_a_valid_token() {
    let h = harness(|_| {}).await;
    let now = stats::now();

    // Forged: right shape, wrong key.
    let forged = token::mint(
        &Secret::from_bytes(vec![9; 32]),
        Kind::MetadataOnly,
        "0123456789abcdef",
        now,
    );
    let (_, body) = Form::default()
        .text("PresubmitToken", &forged)
        .file("upload_file_metadata", META.as_bytes())
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("A problem with your host"), "{body}");

    // A "full" token doesn't allow skipping the dump either.
    let full = token::mint(&h.state.secret, Kind::Full, "0123456789abcdef", now);
    let (_, body) = Form::default()
        .text("PresubmitToken", &full)
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("A problem with your host"), "{body}");

    // The real thing.
    let good = token::mint(&h.state.secret, Kind::MetadataOnly, "0123456789abcdef", now);
    let (_, body) = Form::default()
        .text("PresubmitToken", &good)
        .file("upload_file_metadata", META.as_bytes())
        .send(&h, "/submit")
        .await;
    let id = crash_id(&body);

    let row: (i64, i64, String, Option<i64>) = sqlx::query_as(
        "SELECT status, has_dump, COALESCE(signature, ''), processed_at FROM crash WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&h.state.db)
    .await
    .unwrap();
    assert_eq!((row.0, row.1, row.2.as_str()), (2, 0, "0123456789abcdef")); // done, no dump
    assert!(row.3.is_some());
    assert!(
        !h.state
            .config
            .dumps_dir()
            .join(&id[..2])
            .join(format!("{id}.dmp"))
            .exists()
    );
}

#[tokio::test]
async fn oversized_dumps_get_413_and_leave_nothing_behind() {
    let h = harness(|c| c.limits.max_dump_bytes = 10).await;
    let (status, _) = Form::default()
        .file("upload_file_minidump", &[0u8; 100])
        .send(&h, "/submit")
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(tmp_is_empty(&h));

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crash")
        .fetch_one(&h.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn prod_uploads_get_a_uuid_that_maps_back() {
    let h = harness(|_| {}).await;
    let (_, uuid) = Form::default()
        .text("prod", "1")
        .file("upload_file_minidump", b"x")
        .send(&h, "/submit")
        .await;
    assert_eq!(uuid.len(), 36, "{uuid}");
    assert!(uuid.starts_with("bee0cafe-0000-4000-"));

    let id = ids::from_uuid(&uuid).unwrap();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crash WHERE id = ?")
        .bind(id)
        .fetch_one(&h.state.db)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn a_bad_user_id_is_anonymous_and_non_forms_are_rejected() {
    let h = harness(|_| {}).await;
    let (_, body) = Form::default()
        .text("UserID", "not-a-steam-id")
        .file("upload_file_minidump", b"x")
        .send(&h, "/submit")
        .await;
    let owner: Option<i64> = sqlx::query_scalar("SELECT owner FROM crash WHERE id = ?")
        .bind(crash_id(&body))
        .fetch_one(&h.state.db)
        .await
        .unwrap();
    assert_eq!(owner, None);

    let (status, _) = post(&h, "/submit", "application/json", b"{}".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn urlencoded_presubmit_works_too() {
    let h = harness(|_| {}).await;
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("CrashSignature", SIG)
        .finish();
    let (status, resp) = post(
        &h,
        "/submit",
        "application/x-www-form-urlencoded",
        body.into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(resp.starts_with("Y|YY|"), "{resp}");
}

// ---- symbols --------------------------------------------------------------

#[tokio::test]
async fn symbols_are_stored_once_and_change_the_presubmit_answer() {
    let h = harness(|_| {}).await;

    let (status, body) = post(&h, "/symbols/submit", "text/plain", SYM.as_bytes().to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        "Stored symbols for server_srv.so/AAAABBBBCCCCDDDDEEEEFFFF000011112/Linux/x86_64\n"
    );

    let path = h
        .state
        .config
        .symbols_dir()
        .join("public/server_srv.so/AAAABBBBCCCCDDDDEEEEFFFF000011112/server_srv.so.sym.gz");
    let mut gz = flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap());
    let mut stored = String::new();
    gz.read_to_string(&mut stored).unwrap();
    assert_eq!(stored, SYM);

    // Second upload is a no-op, not an overwrite.
    let (status, body) = post(
        &h,
        "/symbols/submit",
        "text/plain",
        SYM.replace("main", "evil").into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("Already have symbols"), "{body}");
    let mut gz = flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap());
    let mut still = String::new();
    gz.read_to_string(&mut still).unwrap();
    assert_eq!(still, SYM);

    let (_, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("Y|NY|"), "{body}");
}

#[tokio::test]
async fn symbols_accept_multipart_and_urlencoded_forms() {
    let h = harness(|_| {}).await;
    let (status, body) = Form::default()
        .text("symbol_file", SYM)
        .send(&h, "/symbols/submit")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.starts_with("Stored symbols for server_srv.so"),
        "{body}"
    );

    let other = SYM.replace("AAAABBBB", "11112222");
    let form = form_urlencoded::Serializer::new(String::new())
        .append_pair("symbol_file", &other)
        .finish();
    let (status, body) = post(
        &h,
        "/symbols/submit",
        "application/x-www-form-urlencoded",
        form.into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.starts_with("Stored symbols for server_srv.so/11112222"),
        "{body}"
    );
}

#[tokio::test]
async fn bad_symbol_files_are_rejected() {
    let h = harness(|_| {}).await;
    let cases = [
        ("not a symbol file\n".to_string(), "Invalid symbol file"),
        (
            "MODULE Linux x86_64 ABCDEF ../../evil.so\nFUNC 1 1 0 f\n".to_string(),
            "Invalid symbol file",
        ),
        (
            "MODULE Linux x86_64 ABCDEF a\\b.so\nFUNC 1 1 0 f\n".to_string(),
            "Invalid symbol file",
        ),
        (
            "MODULE Linux x86_64 NOTHEX x.so\nFUNC 1 1 0 f\n".to_string(),
            "Invalid symbol file",
        ),
        (
            "MODULE Linux x86_64 ABCDEF x.so\nPUBLIC 1000 0 main\n".to_string(),
            "Symbol file had no FUNC records, please update to Accelerator 2.4.3 or later",
        ),
    ];
    for (data, expected) in cases {
        let (status, body) = post(
            &h,
            "/symbols/submit",
            "text/plain",
            data.clone().into_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{data:?}");
        assert_eq!(body, expected, "{data:?}");
    }

    // Nothing was written, nothing escaped the store.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM symbol")
        .fetch_one(&h.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(!h.state.config.symbols_dir().join("public").exists());
    assert!(
        !h.state
            .config
            .symbols_dir()
            .parent()
            .unwrap()
            .join("evil.so")
            .exists()
    );
}

#[tokio::test]
async fn windows_symbols_dont_need_func_records_and_pdb_is_stripped() {
    let h = harness(|_| {}).await;
    let data =
        "MODULE windows x86 5A9832E5287241C1838ED98914E9B7FF1 test_app.pdb\nPUBLIC 1000 0 main\n";
    let (status, body) = post(
        &h,
        "/symbols/submit",
        "text/plain",
        data.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.starts_with("Stored symbols for test_app.pdb"),
        "{body}"
    );
    assert!(
        h.state
            .config
            .symbols_dir()
            .join("public/test_app.pdb/5A9832E5287241C1838ED98914E9B7FF1/test_app.sym.gz")
            .exists()
    );
}

#[tokio::test]
async fn oversized_symbols_get_413() {
    let h = harness(|c| c.limits.max_symbol_bytes = 64).await;
    let big = format!("{SYM}{}", "x".repeat(200));
    let (status, _) = post(&h, "/symbols/submit", "text/plain", big.into_bytes()).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn uploads_are_refused_with_503_only_when_the_disk_is_nearly_full() {
    let h = harness(|c| c.limits.disk_min_free_bytes = u64::MAX).await;

    let (status, _) = Form::default()
        .file("upload_file_minidump", b"x")
        .send(&h, "/submit")
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = post(&h, "/symbols/submit", "text/plain", SYM.as_bytes().to_vec()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crash")
        .fetch_one(&h.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(tmp_is_empty(&h));

    // Presubmit costs no disk, so it keeps answering.
    let (_, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("Y|"), "{body}");
}

#[tokio::test]
async fn servers_with_a_nosteam_notice_are_turned_away_for_a_month() {
    let h = harness(|_| {}).await;
    sqlx::query("INSERT INTO notice (id, severity, text, rule) VALUES ('nosteam-test', 'danger', 't', '{\"cmdline\":\"*\"}')")
        .execute(&h.state.db)
        .await
        .unwrap();
    insert_crash(&h, "aaaaaaaaaaaa", 2).await;
    sqlx::query("INSERT INTO crashnotice (crash, notice) VALUES ('aaaaaaaaaaaa', 'nosteam-test')")
        .execute(&h.state.db)
        .await
        .unwrap();

    let refusal = "Servers that support piracy are not welcome.";
    let (_, body) = Form::default()
        .text("CrashSignature", SIG)
        .send(&h, "/submit")
        .await;
    assert_eq!(body, format!("N|NN|{refusal}"));

    let (status, body) = Form::default()
        .file("upload_file_minidump", b"x")
        .send(&h, "/submit")
        .await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, refusal));
    assert!(tmp_is_empty(&h));

    // The same address with a different Steam account is a different server.
    let (_, body) = Form::default()
        .text("UserID", "STEAM_0:1:1234")
        .file("upload_file_minidump", b"x")
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("Crash ID: "), "{body}");

    // Other notices don't count, and the ban expires.
    sqlx::query(
        "UPDATE crashnotice SET notice = (SELECT 'nosteam-test') WHERE crash = 'aaaaaaaaaaaa'",
    )
    .execute(&h.state.db)
    .await
    .unwrap();
    sqlx::query("UPDATE crash SET created_at = ? WHERE id = 'aaaaaaaaaaaa'")
        .bind(stats::now() - 31 * 86_400)
        .execute(&h.state.db)
        .await
        .unwrap();
    let (_, body) = Form::default()
        .file("upload_file_minidump", b"x")
        .send(&h, "/submit")
        .await;
    assert!(body.starts_with("Crash ID: "), "{body}");
}

// ---- repeats --------------------------------------------------------------

const ALICE_ID: &str = "STEAM_0:1:1234";
const ALICE_STEAM: i64 = 76_561_197_960_265_728 + 2469;
const BOB_ID: &str = "STEAM_0:0:1234";

/// Presubmit as `user`: the answer and the token in it.
async fn ask(h: &Harness, user: Option<&str>) -> (String, String) {
    let mut form = Form::default();
    if let Some(user) = user {
        form = form.text("UserID", user);
    }
    let (_, body) = form.text("CrashSignature", SIG).send(h, "/submit").await;
    let token = body.rsplit('|').next().unwrap().to_owned();
    (body, token)
}

/// Upload as `user` with `token`, with the dump or with the metadata only. The reply.
async fn send_crash(h: &Harness, user: &str, token: &str, dump: bool) -> String {
    let form = Form::default()
        .text("UserID", user)
        .text("PresubmitToken", token);
    let form = if dump {
        form.file("upload_file_minidump", b"MDMP-x")
    } else {
        form.file("upload_file_metadata", META.as_bytes())
    };
    let (status, body) = form.send(h, "/submit").await;
    assert_eq!(status, StatusCode::OK);
    body
}

async fn insert_signed(h: &Harness, id: &str, owner: Option<i64>, ip: [u8; 4], days_ago: i64) {
    sqlx::query(
        "INSERT INTO crash (id, created_at, ip, owner, status, signature) VALUES (?, ?, ?, ?, 2, ?)",
    )
    .bind(id)
    .bind(stats::now() - days_ago * 86_400)
    .bind(ip.to_vec())
    .bind(owner)
    .bind(super::signature::parse(SIG).unwrap().hash())
    .execute(&h.state.db)
    .await
    .unwrap();
}

#[tokio::test]
async fn the_same_crash_again_is_counted_not_stored_again() {
    let h = harness(|_| {}).await;

    let (answer, token) = ask(&h, Some(ALICE_ID)).await;
    assert!(answer.starts_with("Y|"), "{answer}");
    let first = crash_id(&send_crash(&h, ALICE_ID, &token, true).await);

    // Now the server knows it: only the (small) metadata is asked for.
    let (answer, token_again) = ask(&h, Some(ALICE_ID)).await;
    assert!(answer.starts_with("M|"), "{answer}");
    let body = send_crash(&h, ALICE_ID, &token_again, false).await;
    assert_eq!(
        crash_id(&body),
        first,
        "the reply names the crash already stored"
    );

    // A client that still sends the whole dump (an older token) is counted the same way.
    let body = send_crash(&h, ALICE_ID, &token, true).await;
    assert_eq!(crash_id(&body), first);

    let (crashes, repeats, last): (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(repeats), 0), MAX(last_repeat_at) FROM crash",
    )
    .fetch_one(&h.state.db)
    .await
    .unwrap();
    assert_eq!((crashes, repeats), (1, 2));
    assert!(last.is_some());

    let dumps = std::fs::read_dir(h.state.config.dumps_dir().join(&first[..2]))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "dmp")
        })
        .count();
    assert_eq!(dumps, 1, "no second dump on disk");
    assert!(tmp_is_empty(&h));
}

#[tokio::test]
async fn a_repeat_needs_the_same_owner_or_the_same_address_when_anonymous() {
    let h = harness(|_| {}).await;
    insert_signed(&h, "aaaaaaaaaaaa", Some(ALICE_STEAM), [1, 2, 3, 4], 1).await;

    // The owner counts, wherever the crash came from; somebody else does not.
    assert!(ask(&h, Some(ALICE_ID)).await.0.starts_with("M|"));
    assert!(ask(&h, Some(BOB_ID)).await.0.starts_with("Y|"));
    assert!(ask(&h, None).await.0.starts_with("Y|"));

    // Anonymous crashes are told apart by address.
    insert_signed(&h, "bbbbbbbbbbbb", None, [9, 9, 9, 9], 1).await;
    assert!(ask(&h, None).await.0.starts_with("Y|"));
    insert_signed(&h, "cccccccccccc", None, IP, 1).await;
    assert!(ask(&h, None).await.0.starts_with("M|"));
    assert!(ask(&h, Some(BOB_ID)).await.0.starts_with("Y|"));
}

#[tokio::test]
async fn a_repeat_must_be_recent_and_the_window_slides() {
    let h = harness(|_| {}).await;
    insert_signed(&h, "aaaaaaaaaaaa", Some(ALICE_STEAM), IP, 31).await;
    assert!(
        ask(&h, Some(ALICE_ID)).await.0.starts_with("Y|"),
        "31 days is out of the window"
    );

    // It came again yesterday: the window starts from then.
    sqlx::query("UPDATE crash SET last_repeat_at = ?")
        .bind(stats::now() - 86_400)
        .execute(&h.state.db)
        .await
        .unwrap();
    assert!(ask(&h, Some(ALICE_ID)).await.0.starts_with("M|"));

    let off = harness(|c| c.limits.repeat_window_days = 0).await;
    insert_signed(&off, "aaaaaaaaaaaa", Some(ALICE_STEAM), IP, 0).await;
    assert!(
        ask(&off, Some(ALICE_ID)).await.0.starts_with("Y|"),
        "0 turns it off"
    );
}

#[tokio::test]
async fn a_repeat_whose_original_is_gone_is_stored_as_a_new_crash() {
    let h = harness(|_| {}).await;
    let (_, token) = ask(&h, Some(ALICE_ID)).await;
    let first = crash_id(&send_crash(&h, ALICE_ID, &token, true).await);

    let (answer, token_again) = ask(&h, Some(ALICE_ID)).await;
    assert!(answer.starts_with("M|"), "{answer}");
    sqlx::query("DELETE FROM crash")
        .execute(&h.state.db)
        .await
        .unwrap();

    let second = crash_id(&send_crash(&h, ALICE_ID, &token_again, false).await);
    assert_ne!(first, second);
    let (crashes, has_dump): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), MAX(has_dump) FROM crash")
            .fetch_one(&h.state.db)
            .await
            .unwrap();
    assert_eq!((crashes, has_dump), (1, 0));
}
