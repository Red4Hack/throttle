//! Shared state and the HTTP router.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use sqlx::SqlitePool;
use tokio::sync::{Notify, Semaphore};
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::ingest::token::Secret;
use crate::{db, ingest, process, web};

/// Symbol files can be hundreds of MiB; only this many are in flight at once.
const CONCURRENT_SYMBOL_UPLOADS: usize = 2;
/// Reading a dump for the raw view walks every thread; only this many at once.
const CONCURRENT_RAW_VIEWS: usize = 2;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: SqlitePool,
    /// Signs presubmit tokens.
    pub secret: Arc<Secret>,
    pub symbol_uploads: Arc<Semaphore>,
    /// Poked when a crash is queued, so a worker picks it up without waiting for its poll.
    pub wake: Arc<Notify>,
    pub views: Arc<web::Views>,
    /// For Steam (OpenID check, profile lookups).
    pub http: reqwest::Client,
    /// Limits parallel carburetor runs.
    pub carburetor_runs: Arc<Semaphore>,
    /// Limits parallel raw views of a dump.
    pub raw_views: Arc<Semaphore>,
    /// Parsed symbol files shared by the crash processors.
    pub symbol_cache: Arc<crate::process::cache::SymbolCache>,
    /// POST /submit hits per client IP in the current minute (see `ingest::too_many_requests`).
    pub submit_hits: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (i64, u32)>>>,
}

impl AppState {
    pub fn new(config: Config, db: SqlitePool, secret: Secret) -> Self {
        let carburetor_slots = config.carburetor.max_concurrent;
        let symbol_cache_bytes = config
            .processing
            .symbol_cache_mib
            .saturating_mul(1024 * 1024);
        Self {
            config: Arc::new(config),
            db,
            secret: Arc::new(secret),
            symbol_uploads: Arc::new(Semaphore::new(CONCURRENT_SYMBOL_UPLOADS)),
            wake: Arc::new(Notify::new()),
            carburetor_runs: Arc::new(Semaphore::new(carburetor_slots)),
            raw_views: Arc::new(Semaphore::new(CONCURRENT_RAW_VIEWS)),
            symbol_cache: Arc::new(crate::process::cache::SymbolCache::new(symbol_cache_bytes)),
            submit_hits: Arc::default(),
            views: Arc::new(web::build_views()),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent(concat!("throttle/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("HTTP client"),
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(crate::metrics::metrics))
        .merge(ingest::routes(&state.config.limits))
        .merge(web::routes())
        .fallback(|| async { web::WebError::NotFound })
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::map_response(web::security_headers))
        .with_state(state)
}

/// Liveness + database check, for load balancers and container healthchecks.
async fn healthz(State(state): State<AppState>) -> StatusCode {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db)
        .await
    {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            tracing::error!(error = %e, "healthcheck failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

/// Creates a directory under `data_dir`. The usual way this fails is a host
/// directory mounted into a container: it belongs to the host user, and the
/// image runs as an unprivileged one. Say so instead of a bare "Permission denied".
fn create_data_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| {
        format!(
            "cannot create {}: data_dir must be writable by the user running throttle \
             (in a container, mount a volume, or add `:U` to a host directory: -v ./data:/data:U)",
            dir.display()
        )
    })
}

/// Ctrl-C, and SIGTERM, which is what `podman stop`, `docker stop` and systemd send.
/// As PID 1 of a container the process gets no default action for SIGTERM, so without
/// a handler it only stops when the runtime gives up waiting and kills it.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    create_data_dir(&config.dumps_dir())?;
    create_data_dir(&config.symbols_dir())?;
    let db = db::open(&config.db_path()).await?;
    let secret = Secret::load_or_create(&config.secret_path())?;

    let listen = config.listen;
    let state = AppState::new(config, db, secret);
    crate::notice::sync(&state.db, &state.config.notices).await?;
    process::recover(&state.db, state.config.processing.max_attempts).await?;
    process::spawn(&state);
    crate::retention::spawn(&state);
    crate::symfetch::spawn(&state);
    web::spawn_profile_refresh(&state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "listening");

    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn a_data_dir_that_cannot_be_created_says_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let err = create_data_dir(&file.join("dumps")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("file/dumps") && msg.contains(":U"), "{msg}");
    }

    #[tokio::test]
    async fn healthz_reports_ok() {
        let state = AppState::new(
            Config::default(),
            db::open_memory().await.unwrap(),
            Secret::from_bytes(vec![0; 32]),
        );
        let res = router(state)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
