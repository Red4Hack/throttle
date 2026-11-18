//! `GET /metrics`, Prometheus text format. Off unless `metrics_token` is set,
//! and then only for `Authorization: Bearer <token>`.

use std::fmt::Write;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::app::AppState;
use crate::ingest::token::same;
use crate::retention;

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: i64) {
    let _ = write!(
        out,
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
    );
}

async fn scalar(state: &AppState, sql: &'static str) -> sqlx::Result<i64> {
    sqlx::query_scalar(sql).fetch_one(&state.db).await
}

async fn collect(state: &AppState) -> sqlx::Result<String> {
    let mut out = String::new();

    let by_status: Vec<(i64, i64)> =
        sqlx::query_as("SELECT status, COUNT(*) FROM crash GROUP BY status")
            .fetch_all(&state.db)
            .await?;
    out.push_str("# HELP throttle_crashes Crash reports by processing status.\n# TYPE throttle_crashes gauge\n");
    for (code, name) in [
        (0, "pending"),
        (1, "processing"),
        (2, "done"),
        (3, "failed"),
    ] {
        let n = by_status
            .iter()
            .find(|(s, _)| *s == code)
            .map_or(0, |(_, n)| *n);
        let _ = writeln!(out, "throttle_crashes{{status=\"{name}\"}} {n}");
    }

    let dump_bytes = scalar(
        state,
        "SELECT COALESCE(SUM(dump_bytes), 0) FROM crash WHERE has_dump = 1",
    )
    .await?;
    metric(
        &mut out,
        "throttle_dump_bytes",
        "gauge",
        "Size of the stored dumps.",
        dump_bytes,
    );
    let symbols = scalar(state, "SELECT COUNT(*) FROM symbol").await?;
    metric(
        &mut out,
        "throttle_symbol_files",
        "gauge",
        "Stored symbol files.",
        symbols,
    );
    let users = scalar(state, "SELECT COUNT(*) FROM user").await?;
    metric(
        &mut out,
        "throttle_users",
        "gauge",
        "Known Steam users.",
        users,
    );
    if let Some(free) = retention::free_bytes(&state.config.data_dir) {
        let free = i64::try_from(free).unwrap_or(i64::MAX);
        metric(
            &mut out,
            "throttle_disk_free_bytes",
            "gauge",
            "Free space where the data lives.",
            free,
        );
    }

    let cache = &state.symbol_cache;
    metric(
        &mut out,
        "throttle_symbol_cache_bytes",
        "gauge",
        "Estimated memory held by parsed symbol files.",
        i64::try_from(cache.bytes()).unwrap_or(i64::MAX),
    );
    metric(
        &mut out,
        "throttle_symbol_cache_hits_total",
        "counter",
        "Symbol files served from the cache since start.",
        i64::try_from(cache.hits()).unwrap_or(i64::MAX),
    );
    metric(
        &mut out,
        "throttle_symbol_cache_misses_total",
        "counter",
        "Symbol files loaded from disk since start.",
        i64::try_from(cache.misses()).unwrap_or(i64::MAX),
    );

    let events: Vec<(String, i64)> =
        sqlx::query_as("SELECT name, SUM(value) FROM counter GROUP BY name ORDER BY name")
            .fetch_all(&state.db)
            .await?;
    out.push_str(
        "# HELP throttle_events_total Counted events (uploads, rejections, processing...).\n",
    );
    out.push_str("# TYPE throttle_events_total counter\n");
    for (name, value) in events {
        let _ = writeln!(
            out,
            "throttle_events_total{{event=\"{}\"}} {value}",
            escape(&name)
        );
    }
    Ok(out)
}

pub async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = state.config.metrics_token.as_deref() else {
        return crate::web::WebError::NotFound.into_response();
    };
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !same(given, token) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    }
    match collect(&state).await {
        Ok(body) => (
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "could not collect metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    use crate::app::{AppState, router};
    use crate::config::Config;
    use crate::db;
    use crate::ingest::token::Secret;

    const TOKEN: &str = "0123456789abcdef0123456789";

    async fn get(configured: Option<&str>, auth: Option<&str>) -> (StatusCode, String) {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: dir.path().to_path_buf(),
            metrics_token: configured.map(String::from),
            ..Config::default()
        };
        let state = AppState::new(
            config,
            db::open_memory().await.unwrap(),
            Secret::from_bytes(vec![1; 32]),
        );
        sqlx::query(
            "INSERT INTO crash (id, created_at, ip, status, has_dump, dump_bytes) VALUES \
             ('aaaaaaaaaaaa', 1, x'01020304', 0, 1, 500), ('bbbbbbbbbbbb', 1, x'01020304', 3, 1, 250)",
        )
        .execute(&state.db)
        .await
        .unwrap();
        crate::stats::bump(&state.db, "crashes:accepted", 2).await;

        let mut req = Request::get("/metrics");
        if let Some(auth) = auth {
            req = req.header(header::AUTHORIZATION, auth);
        }
        let res = router(state)
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let body = to_bytes(res.into_body(), 1 << 20).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn disabled_without_a_token() {
        assert_eq!(get(None, None).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            get(None, Some(&format!("Bearer {TOKEN}"))).await.0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn requires_the_bearer_token() {
        for auth in [
            None,
            Some("Bearer nope"),
            Some(TOKEN),
            Some("Basic abc"),
            Some("Bearer "),
        ] {
            assert_eq!(
                get(Some(TOKEN), auth).await.0,
                StatusCode::UNAUTHORIZED,
                "{auth:?}"
            );
        }
    }

    #[tokio::test]
    async fn exposes_queue_storage_and_event_counters() {
        let (status, body) = get(Some(TOKEN), Some(&format!("Bearer {TOKEN}"))).await;
        assert_eq!(status, StatusCode::OK);
        for line in [
            "throttle_crashes{status=\"pending\"} 1",
            "throttle_crashes{status=\"done\"} 0",
            "throttle_crashes{status=\"failed\"} 1",
            "throttle_dump_bytes 750",
            "throttle_events_total{event=\"crashes:accepted\"} 2",
        ] {
            assert!(
                body.lines().any(|l| l == line),
                "missing {line:?} in\n{body}"
            );
        }
        assert!(body.contains("# TYPE throttle_events_total counter"));
        assert!(body.contains("throttle_disk_free_bytes "));
        for line in [
            "throttle_symbol_cache_bytes 0",
            "throttle_symbol_cache_hits_total 0",
            "throttle_symbol_cache_misses_total 0",
        ] {
            assert!(body.lines().any(|l| l == line), "missing {line:?}");
        }
    }
}
