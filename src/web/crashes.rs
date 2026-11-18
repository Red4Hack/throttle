//! A crash's page and the actions on it.
//!
//! Anyone with the (unguessable, 60-bit) crash ID can open the page. What the
//! owner, people the owner shares with, and admins additionally get is the
//! raw material: dump, metadata, console, uploader address, command line.

use std::io::Read;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Redirect, Response};
use flate2::read::GzDecoder;
use minijinja::context;
use serde::Serialize;
use serde_json::{Map, Value};
use tokio_util::io::ReaderStream;

use super::session::{MaybeUser, User};
use super::{WebError, check_origin, format, render};
use crate::app::AppState;
use crate::ingest::metadata;
use crate::{ids, stats};

/// SourceMod before this cannot walk SourcePawn frames reliably.
const SOURCEPAWN_STACKS_FIXED_IN: &str = "1.10.0.6431";
/// Metadata keys that are internal to the server.
const HIDDEN_KEYS: &[&str] = &["ExtensionBuild", "HasConsoleLog"];
/// Metadata keys that reveal the server's file system layout.
const PRIVATE_KEYS: &[&str] = &["GamePath", "SourceModPath"];

/// The canonical ID for user input: an ID in any case (with or without dashes),
/// or a UUID from the standard Breakpad uploader.
pub fn canonical(raw: &str) -> Option<String> {
    ids::normalize(raw).or_else(|| ids::from_uuid(raw))
}

/// Admins, the owner, and people the owner has shared with (accepted).
pub async fn can_manage(state: &AppState, user: &User, owner: Option<i64>) -> sqlx::Result<bool> {
    if user.admin {
        return Ok(true);
    }
    let Some(owner) = owner else {
        return Ok(false);
    };
    if owner == user.id {
        return Ok(true);
    }
    let shared: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM share WHERE owner = ? AND user = ? AND accepted_at IS NOT NULL",
    )
    .bind(owner)
    .bind(user.id)
    .fetch_optional(&state.db)
    .await?;
    Ok(shared.is_some())
}

/// Resolve `raw` to an existing crash the user may manage.
pub(super) async fn managed(
    state: &AppState,
    user: Option<&User>,
    raw: &str,
) -> Result<String, WebError> {
    let id = ids::normalize(raw).ok_or(WebError::NotFound)?;
    let owner: Option<Option<i64>> = sqlx::query_scalar("SELECT owner FROM crash WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;
    let owner = owner.ok_or(WebError::NotFound)?;
    let user = user.ok_or(WebError::LoginRequired)?;
    if can_manage(state, user, owner).await? {
        Ok(id)
    } else {
        Err(WebError::Forbidden)
    }
}

#[derive(sqlx::FromRow)]
struct CrashRow {
    id: String,
    created_at: i64,
    ip: Vec<u8>,
    owner: Option<i64>,
    owner_name: Option<String>,
    metadata: String,
    cmdline: Option<String>,
    status: i64,
    has_dump: i64,
    thread: Option<i64>,
    stackhash: Option<String>,
    error: Option<String>,
    sys_error: Option<String>,
    crash_reason: Option<String>,
    crash_address: Option<String>,
    bad_jump: i64,
    repeats: i64,
    last_repeat_at: Option<i64>,
}

#[derive(sqlx::FromRow, Serialize)]
struct FrameView {
    frame: i64,
    rendered: String,
    url: Option<String>,
}

#[derive(sqlx::FromRow, Serialize)]
struct ModuleView {
    name: String,
    identifier: String,
    base: Option<String>,
    present: i64,
}

#[derive(sqlx::FromRow, Serialize)]
struct NoticeView {
    severity: String,
    text: String,
}

#[derive(Serialize)]
struct Pair {
    label: String,
    value: String,
}

#[derive(Serialize)]
struct StackStats {
    owners: i64,
    servers: i64,
    total: i64,
    /// The stack hash, which `/stats/{hash}` is about.
    hash: String,
}

fn metadata_rows(meta: &Map<String, Value>, manage: bool) -> Vec<Pair> {
    meta.iter()
        .filter(|(k, _)| {
            !HIDDEN_KEYS.contains(&k.as_str()) && (manage || !PRIVATE_KEYS.contains(&k.as_str()))
        })
        .filter_map(|(k, v)| {
            let value = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (!value.is_empty()).then(|| Pair {
                label: format::label(k),
                value,
            })
        })
        .collect()
}

pub async fn details(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(raw): Path<String>,
) -> Result<Response, WebError> {
    let id = canonical(&raw).ok_or(WebError::NotFound)?;
    if raw != id {
        // Upper case, dashes, or a legacy UUID: send them to the canonical URL.
        return Ok(Redirect::permanent(&format!("/{id}")).into_response());
    }

    let crash: CrashRow = sqlx::query_as(
        "SELECT c.id, c.created_at, c.ip, c.owner, u.name AS owner_name, c.metadata, c.cmdline, \
         c.status, c.has_dump, c.thread, c.stackhash, c.error, c.sys_error, \
         c.crash_reason, c.crash_address, c.bad_jump, c.repeats, c.last_repeat_at \
         FROM crash c LEFT JOIN user u ON u.id = c.owner WHERE c.id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(WebError::NotFound)?;

    let manage = match &user {
        Some(u) => can_manage(&state, u, crash.owner).await?,
        None => false,
    };

    // "Last viewed" keeps looked-at reports from being cleaned up; once a day is plenty.
    let now = stats::now();
    sqlx::query(
        "UPDATE crash SET last_view = ? WHERE id = ? AND (last_view IS NULL OR last_view < ?)",
    )
    .bind(now)
    .bind(&id)
    .bind(now - 86_400)
    .execute(&state.db)
    .await?;

    let mut frames: Vec<FrameView> = sqlx::query_as(
        "SELECT frame, rendered, url FROM frame WHERE crash = ? AND thread = ? ORDER BY frame",
    )
    .bind(&id)
    .bind(crash.thread.unwrap_or(0))
    .fetch_all(&state.db)
    .await?;
    for f in &mut frames {
        // Links come from our own URL builder, but never emit anything but https.
        f.url = f.url.take().filter(|u| u.starts_with("https://"));
    }

    let modules: Vec<ModuleView> = sqlx::query_as(
        "SELECT name, identifier, base, present FROM module WHERE crash = ? ORDER BY name",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;

    let notices: Vec<NoticeView> = sqlx::query_as(
        "SELECT n.severity, n.text FROM crashnotice cn JOIN notice n ON n.id = cn.notice WHERE cn.crash = ?",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;

    let stack_stats = match &crash.stackhash {
        Some(hash) => {
            let (owners, servers, total): (i64, i64, i64) =
                sqlx::query_as("SELECT COUNT(DISTINCT owner), COUNT(DISTINCT ip), COUNT(*) + COALESCE(SUM(repeats), 0) FROM crash WHERE stackhash = ?")
                    .bind(hash)
                    .fetch_one(&state.db)
                    .await?;
            Some(StackStats {
                owners,
                servers,
                total,
                hash: hash.clone(),
            })
        }
        None => None,
    };

    let meta: Map<String, Value> = serde_json::from_str(&crash.metadata).unwrap_or_default();
    let outdated = state
        .config
        .accelerator_version
        .as_deref()
        .and_then(|latest| {
            let have = meta.get("ExtensionVersion")?.as_str()?;
            format::version_older(have, latest).then(|| have.to_string())
        });

    let has_meta = manage
        && tokio::fs::try_exists(state.config.meta_path(&id))
            .await
            .unwrap_or(false);
    let has_console = has_meta && meta.get("HasConsoleLog") == Some(&Value::Bool(true));
    let cmdline = if manage {
        crash.cmdline.as_deref().map(format::mask_cmdline)
    } else {
        None
    };
    let ip = Some(format::ip_string(&crash.ip)).filter(|s| manage && !s.is_empty());

    // The message may name paths and map names: for people who manage the crash only.
    let sys_error = crash.sys_error.clone().filter(|_| manage);
    let sourcepawn_warning = meta
        .get("SourceModVersion")
        .and_then(Value::as_str)
        .is_some_and(|v| format::version_older(v, SOURCEPAWN_STACKS_FIXED_IN))
        && frames
            .iter()
            .any(|f| format::is_sourcepawn_invoke(&f.rendered));

    // Every module without symbols: the frames are bare addresses until some are uploaded.
    let no_symbols = !modules.is_empty() && modules.iter().all(|m| m.present == 0);

    let crash_ctx = context! {
        id => &crash.id,
        created_at => crash.created_at,
        status => crash.status,
        has_dump => crash.has_dump != 0,
        thread => crash.thread,
        owner_id => crash.owner.map(|o| o.to_string()),
        owner_name => &crash.owner_name,
        ip => ip,
        error => &crash.error,
        reason => &crash.crash_reason,
        address => &crash.crash_address,
        bad_jump => crash.bad_jump != 0,
        repeats => crash.repeats,
        last_repeat_at => crash.last_repeat_at,
    };

    let html = render(
        &state,
        "details.html",
        user.as_ref(),
        context! {
            crash => crash_ctx,
            frames => frames,
            modules => modules,
            notices => notices,
            metadata => metadata_rows(&meta, manage),
            stats => stack_stats,
            outdated => outdated,
            cmdline => cmdline,
            can_manage => manage,
            is_admin => user.as_ref().is_some_and(|u| u.admin),
            has_meta => has_meta,
            has_console => has_console,
            carburetor => state.config.carburetor.path.is_some() && crash.has_dump != 0 && crash.status == 2,
            sys_error => sys_error,
            sourcepawn_warning => sourcepawn_warning,
            no_symbols => no_symbols,
        },
    )?;
    Ok(html.into_response())
}

fn not_found_or(e: std::io::Error) -> WebError {
    if e.kind() == std::io::ErrorKind::NotFound {
        WebError::NotFound
    } else {
        e.into()
    }
}

pub async fn download(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(raw): Path<String>,
) -> Result<Response, WebError> {
    let id = managed(&state, user.as_ref(), &raw).await?;
    let file = tokio::fs::File::open(state.config.dump_path(&id))
        .await
        .map_err(not_found_or)?;
    let len = file.metadata().await?.len();
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"crash_{id}.dmp\""),
            ),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        Body::from_stream(ReaderStream::new(file)),
    )
        .into_response())
}

/// The uploaded metadata file, decompressed (bounded by the upload limit).
async fn read_meta(state: &AppState, id: &str) -> Result<Vec<u8>, WebError> {
    let path = state.config.meta_path(id);
    let cap = state.config.limits.max_metadata_bytes;
    let read = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        GzDecoder::new(std::fs::File::open(path)?)
            .take(cap)
            .read_to_end(&mut out)?;
        Ok(out)
    })
    .await
    .map_err(|_| WebError::Internal)?;
    read.map_err(not_found_or)
}

fn plain_text(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

pub async fn metadata_file(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(raw): Path<String>,
) -> Result<Response, WebError> {
    let id = managed(&state, user.as_ref(), &raw).await?;
    let raw = read_meta(&state, &id).await?;
    Ok(plain_text(String::from_utf8_lossy(&raw).into_owned()))
}

pub async fn console(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(raw): Path<String>,
) -> Result<Response, WebError> {
    let id = managed(&state, user.as_ref(), &raw).await?;
    let raw = read_meta(&state, &id).await?;
    let text = metadata::console(&raw).ok_or(WebError::NotFound)?;
    Ok(plain_text(text))
}

/// Reading a dump walks every thread; one that takes longer than this is not worth waiting for.
const RAW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The whole dump as text (crash reason, system, every thread's stack, the modules), for
/// people who manage the crash. It is what `minidump_stackwalk` prints, and needs no carburetor.
pub async fn raw(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(id_raw): Path<String>,
) -> Result<Response, WebError> {
    let id = managed(&state, user.as_ref(), &id_raw).await?;
    if !tokio::fs::try_exists(state.config.dump_path(&id))
        .await
        .unwrap_or(false)
    {
        return Err(WebError::NotFound);
    }
    // Walking every thread takes real CPU: only a few at a time.
    let _slot = state.raw_views.try_acquire().map_err(|_| {
        WebError::Unavailable("Other dumps are being read right now. Try again in a moment.")
    })?;
    match tokio::time::timeout(RAW_TIMEOUT, crate::process::raw_report(&state, &id)).await {
        Ok(Ok(text)) => Ok(plain_text(text)),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, id = %id, "raw view failed");
            Err(WebError::Unavailable("This dump could not be read."))
        }
        Err(_) => Err(WebError::Unavailable("Reading the dump took too long.")),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    MaybeUser(user): MaybeUser,
    Path(raw): Path<String>,
) -> Result<Response, WebError> {
    check_origin(&state, &headers)?;
    let id = managed(&state, user.as_ref(), &raw).await?;

    // Frames, modules and notices go with the row (ON DELETE CASCADE).
    sqlx::query("DELETE FROM crash WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    crate::retention::remove_files(&state.config, &id).await;
    Ok(Redirect::to("/dashboard").into_response())
}

pub async fn reprocess(
    State(state): State<AppState>,
    headers: HeaderMap,
    MaybeUser(user): MaybeUser,
    Path(raw): Path<String>,
) -> Result<Response, WebError> {
    check_origin(&state, &headers)?;
    let user = MaybeUser(user).required()?;
    if !user.admin {
        return Err(WebError::Forbidden);
    }
    let id = ids::normalize(&raw).ok_or(WebError::NotFound)?;

    let queued = sqlx::query(
        "UPDATE crash SET status = 0, attempts = 0, error = NULL \
         WHERE id = ? AND has_dump = 1 AND status IN (2, 3)",
    )
    .bind(&id)
    .execute(&state.db)
    .await?
    .rows_affected();
    if queued == 0 {
        return Err(WebError::BadRequest(
            "This crash cannot be reprocessed right now.",
        ));
    }
    state.wake.notify_one();
    Ok(Redirect::to(&format!("/{id}")).into_response())
}
