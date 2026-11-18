//! Crash and symbol ingestion, wire-compatible with the Accelerator extension
//! (see docs/protocol.md).
//!
//! Design rule: the client never retries and deletes its dump whatever we
//! answer, so every refusal loses a crash for good. We therefore accept
//! cheaply and shed load later (queue + quota eviction); the only soft knob
//! the protocol offers is `M` (metadata only).

mod clientip;
mod form;
pub mod metadata;
mod queries;
mod signature;
pub mod steam;
mod store;
pub mod symbols;
pub mod token;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::{Map, Value};

use crate::app::AppState;
use crate::config::Limits;
use crate::{ids, stats};
use form::Submission;
use token::Kind;

const MIB: u64 = 1024 * 1024;
/// Texts the Accelerator logs verbatim; kept identical to the PHP version.
const MSG_NO_DUMP: &str =
    "A problem with your host is preventing crash reports from being generated.\n";
const MSG_RATE_LIMIT: &str = "Rate limit exceeded.";
const MSG_NO_STEAM: &str = "Servers that support piracy are not welcome.";

const META_BUDGET: usize = 64 * 1024;
const MAX_VALUE_CHARS: usize = 4096;
const MAX_KEY_LEN: usize = 64;
/// Keys the server consumes itself; they never reach the stored metadata.
const RESERVED_FIELDS: &[&str] = &[
    "UserID",
    "ServerID",
    "PresubmitToken",
    "CrashSignature",
    "prod",
];

/// Why a request was refused with a non-2xx status.
#[derive(Debug)]
pub enum Reject {
    TooLarge,
    BadRequest(&'static str),
    Busy,
    /// The disk is nearly full (and eviction can't keep up).
    NoSpace,
    Internal,
}

impl IntoResponse for Reject {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Reject::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "Upload too large"),
            Reject::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Reject::Busy => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Server busy, try again later",
            ),
            Reject::NoSpace => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Server is out of disk space",
            ),
            Reject::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };
        tracing::warn!(status = status.as_u16(), message, "upload rejected");
        (
            status,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            message,
        )
            .into_response()
    }
}

impl From<std::io::Error> for Reject {
    fn from(e: std::io::Error) -> Self {
        tracing::error!(error = %e, "io error while ingesting");
        Reject::Internal
    }
}

impl From<sqlx::Error> for Reject {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error while ingesting");
        Reject::Internal
    }
}

pub(crate) fn text(body: impl Into<String>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body.into(),
    )
        .into_response()
}

pub fn routes(limits: &Limits) -> Router<AppState> {
    let submit_cap = (limits.max_dump_bytes + limits.max_metadata_bytes + MIB) as usize;
    let symbols_cap = (limits.max_symbol_bytes + MIB) as usize;
    Router::new()
        .route(
            "/submit",
            post(submit).layer(DefaultBodyLimit::max(submit_cap)),
        )
        .route(
            "/symbols/submit",
            post(symbols::submit).layer(DefaultBodyLimit::max(symbols_cap)),
        )
}

/// Cheap per-IP cap on /submit (presubmits cost DB work but add no crash row, so
/// `rate_limit` never sees them). The client then uploads anyway, so nothing is lost.
/// shortcut: fixed one-minute window, in memory; upgrade if it needs to survive restarts.
fn too_many_requests(state: &AppState, ip: IpAddr) -> bool {
    const PER_MINUTE: u32 = 120;
    let minute = stats::now() / 60;
    let mut hits = state.submit_hits.lock().unwrap_or_else(|e| e.into_inner());
    if hits.len() > 10_000 {
        hits.retain(|_, (m, _)| *m == minute);
    }
    let entry = hits.entry(ip).or_insert((minute, 0));
    if entry.0 != minute {
        *entry = (minute, 0);
    }
    entry.1 += 1;
    entry.1 > PER_MINUTE
}

async fn submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Reject> {
    let ip = clientip::client_ip(peer.ip(), req.headers(), &state.config.trusted_proxies);
    if too_many_requests(&state, ip) {
        return Err(Reject::Busy);
    }
    let tmp_dir = state.config.dumps_dir().join(".tmp");
    let sub = form::read(req, &state.config.limits, &tmp_dir).await?;

    let owner = match sub.field("UserID").map(steam::parse_owner) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(id))) => Some(id),
        Some(Err(_)) => {
            tracing::warn!(%ip, "bad UserID in submit, treating as anonymous");
            None
        }
    };

    match sub.field("CrashSignature").map(str::to_owned) {
        Some(signature) => presubmit(&state, &signature, owner, ip).await,
        None => upload(&state, sub, owner, ip).await,
    }
}

/// Has this owner+IP used up its quota for the current window?
async fn rate_limited(state: &AppState, owner: Option<i64>, ip: IpAddr) -> Result<bool, Reject> {
    let limits = &state.config.limits;
    let since = stats::now() - limits.rate_window_secs as i64;
    let recent = queries::count_recent(&state.db, owner, &store::ip_bytes(ip), since).await?;
    Ok(recent >= i64::from(limits.rate_limit))
}

/// Was this owner+IP flagged by a `nosteam-*` notice recently?
async fn nosteam_blocked(state: &AppState, owner: Option<i64>, ip: IpAddr) -> Result<bool, Reject> {
    let since = stats::now() - crate::notice::NOSTEAM_DAYS * 86_400;
    let blocked =
        queries::has_recent_nosteam(&state.db, owner, &store::ip_bytes(ip), since).await?;
    Ok(blocked)
}

async fn wants_symbols(state: &AppState, module: &signature::Module) -> Result<bool, Reject> {
    let id = &module.identifier;
    // All-zero ids mean "no build id"; there is nothing to look symbols up by.
    if id.is_empty()
        || id.len() > 64
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
        || id.bytes().all(|b| b == b'0')
    {
        return Ok(false);
    }
    let have = queries::has_symbol(&state.db, &module.file, &id.to_ascii_uppercase()).await?;
    Ok(!have)
}

/// The crash this one repeats, if the feature is on and there is one.
async fn repeat_of(
    state: &AppState,
    fingerprint: &str,
    owner: Option<i64>,
    ip: IpAddr,
    now: i64,
) -> Result<Option<String>, Reject> {
    let days = state.config.limits.repeat_window_days;
    if days == 0 {
        return Ok(None);
    }
    let since = now - i64::from(days) * 86_400;
    let found =
        queries::find_repeat(&state.db, fingerprint, owner, &store::ip_bytes(ip), since).await?;
    Ok(found)
}

/// What the client is told after an upload. Plain Breakpad uploaders (`prod=1`) expect a UUID.
fn crash_reply(id: &str, want_uuid: bool) -> String {
    match want_uuid.then(|| ids::to_uuid(id)).flatten() {
        Some(uuid) => uuid,
        None => format!("Crash ID: {}", ids::display(id)),
    }
}

/// `<Y|M|N>|<one flag per module>|<token or message>`
async fn presubmit(
    state: &AppState,
    raw: &str,
    owner: Option<i64>,
    ip: IpAddr,
) -> Result<Response, Reject> {
    stats::bump(&state.db, "crashes:presubmitted", 1).await;

    let sig = match signature::parse(raw) {
        Ok(sig) => sig,
        Err(why) => {
            tracing::warn!(%ip, why, "bad presubmit signature");
            return Ok(text(format!("E|{why}")));
        }
    };

    if nosteam_blocked(state, owner, ip).await? {
        stats::bump(&state.db, "crashes:rejected:no-steam", 1).await;
        let flags = "N".repeat(sig.modules.len());
        return Ok(text(format!("N|{flags}|{MSG_NO_STEAM}")));
    }

    if rate_limited(state, owner, ip).await? {
        stats::bump(&state.db, "crashes:rejected:rate-limit", 1).await;
        let flags = "N".repeat(sig.modules.len());
        return Ok(text(format!("N|{flags}|{MSG_RATE_LIMIT}")));
    }

    let mut flags = String::with_capacity(sig.modules.len());
    for module in &sig.modules {
        flags.push(if wants_symbols(state, module).await? {
            'Y'
        } else {
            'N'
        });
    }

    let limits = &state.config.limits;
    let now = stats::now();
    let fingerprint = sig.hash();

    let mut kind = Kind::Full;
    // A crash we already have: the client only sends the (small) metadata, which is
    // enough to count it.
    let repeated = repeat_of(state, &fingerprint, owner, ip, now)
        .await?
        .is_some();
    if repeated
        || (limits.queue_watermark > 0
            && queries::pending_at_least(&state.db, limits.queue_watermark).await?)
    {
        kind = Kind::MetadataOnly;
    } else if limits.dedupe_threshold > 0 {
        let seen = queries::count_signature(&state.db, &fingerprint, now - 86_400).await?;
        if seen >= i64::from(limits.dedupe_threshold) {
            kind = Kind::MetadataOnly;
        }
    }

    let token = token::mint(&state.secret, kind, &fingerprint, now);
    Ok(text(format!("{}|{flags}|{token}", kind.letter())))
}

fn clip(value: &str) -> String {
    value.chars().take(MAX_VALUE_CHARS).collect()
}

/// Merge form fields and the metadata file's CONFIG block (the file wins, as
/// before) into the stored JSON object. Returns it plus the command line,
/// which is kept in its own column.
fn build_metadata(fields: &[(String, String)], raw: Option<&[u8]>) -> (String, Option<String>) {
    let parsed = raw.map(metadata::parse).unwrap_or_default();

    let from_form = fields
        .iter()
        .filter(|(k, _)| {
            !RESERVED_FIELDS.contains(&k.as_str()) && !k.is_empty() && k.len() <= MAX_KEY_LEN
        })
        .map(|(k, v)| (k.clone(), clip(v)));

    let mut map = Map::new();
    let mut budget = META_BUDGET;
    for (key, value) in from_form.chain(parsed.config) {
        let cost = key.len() + value.len();
        if cost <= budget {
            budget -= cost;
            map.insert(key, Value::String(value));
        }
    }
    if parsed.has_console {
        map.insert("HasConsoleLog".into(), Value::Bool(true));
    }

    let cmdline = match map.remove("CommandLine") {
        Some(Value::String(s)) if !s.is_empty() => Some(s),
        _ => None,
    };
    (Value::Object(map).to_string(), cmdline)
}

fn valid_server_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

async fn upload(
    state: &AppState,
    sub: Submission,
    owner: Option<i64>,
    ip: IpAddr,
) -> Result<Response, Reject> {
    stats::bump(&state.db, "crashes:submitted", 1).await;

    let now = stats::now();
    let claims = sub
        .field("PresubmitToken")
        .and_then(|t| token::verify(&state.secret, t, now));

    let Submission {
        fields,
        dump,
        metadata: raw_metadata,
    } = sub;
    let dump = dump.filter(|d| d.size > 0);

    // No dump is only legitimate when the server itself asked for metadata only.
    let metadata_only = dump.is_none()
        && claims
            .as_ref()
            .is_some_and(|c| c.kind == Kind::MetadataOnly);
    if dump.is_none() && !metadata_only {
        stats::bump(&state.db, "crashes:rejected:no-minidump", 1).await;
        return Ok(text(MSG_NO_DUMP));
    }

    if nosteam_blocked(state, owner, ip).await? {
        stats::bump(&state.db, "crashes:rejected:no-steam", 1).await;
        // 200 on purpose, like every other refusal that is not about capacity.
        return Ok(text(MSG_NO_STEAM));
    }

    let want_uuid = fields
        .iter()
        .any(|(k, v)| k == "prod" && !v.is_empty() && v != "0");

    // The same crash again (same owner, same fingerprint): count it on the crash already
    // stored instead of storing another dump. The fingerprint comes from the signed
    // presubmit token, so it cannot be made up, and the reply carries the stored crash's
    // ID, so a plugin asking for the uploaded crash still gets a real one. It adds no
    // row, so it does not count against the rate limit either.
    if let Some(claims) = &claims
        && let Some(target) = repeat_of(state, &claims.signature, owner, ip, now).await?
        && queries::bump_repeat(&state.db, &target, now).await?
    {
        stats::bump(&state.db, "crashes:repeated", 1).await;
        return Ok(text(crash_reply(&target, want_uuid)));
    }

    if rate_limited(state, owner, ip).await? {
        stats::bump(&state.db, "crashes:rejected:rate-limit", 1).await;
        // 200 on purpose: the client treats any non-2xx as a failed upload.
        return Ok(text(MSG_RATE_LIMIT));
    }

    // The only case where we refuse a dump for capacity: the disk is really full.
    if dump.is_some() && crate::retention::low_disk(&state.config) {
        stats::bump(&state.db, "crashes:rejected:no-space", 1).await;
        return Err(Reject::NoSpace);
    }

    if let Some(dump) = &dump {
        stats::bump(&state.db, "crashes:submitted:bytes", dump.size as i64).await;
    }

    let server_id = fields
        .iter()
        .find(|(k, _)| k == "ServerID")
        .map(|(_, v)| v.as_str())
        .filter(|v| valid_server_id(v))
        .map(str::to_owned);
    let (metadata, cmdline) = build_metadata(&fields, raw_metadata.as_deref());

    let id = store::persist(
        state,
        store::NewCrash {
            ip,
            owner,
            server_id,
            metadata,
            cmdline,
            signature: claims.map(|c| c.signature),
            dump,
            raw_metadata,
        },
    )
    .await?;

    stats::bump(&state.db, "crashes:accepted", 1).await;

    Ok(text(crash_reply(&id, want_uuid)))
}
