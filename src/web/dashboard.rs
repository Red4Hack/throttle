//! The crash list: your own reports, those of people who shared with you
//! (accepted shares only), or everything for admins.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use minijinja::context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::crashes::managed;
use super::session::MaybeUser;
use super::{WebError, check_origin, render};
use crate::app::AppState;
use crate::ingest::steam::parse_owner;

const PAGE_SIZE: i64 = 20;
const MAX_PAGE: u32 = 100_000;

#[derive(Deserialize)]
pub struct Params {
    /// 1-based.
    page: Option<u32>,
    /// Only show this owner's reports (a SteamID64).
    user: Option<String>,
    /// How many reports were just deleted (set by the redirect after a bulk delete).
    deleted: Option<u32>,
    /// `all`: every report on the page starts out ticked.
    select: Option<String>,
}

#[derive(sqlx::FromRow)]
struct RawRow {
    id: String,
    created_at: i64,
    owner: Option<i64>,
    owner_name: Option<String>,
    owner_avatar: Option<String>,
    status: i64,
    has_dump: i64,
    crash_module: Option<String>,
    crash_function: Option<String>,
    notices: i64,
    cmdline: Option<String>,
    repeats: i64,
    last_repeat_at: Option<i64>,
}

#[derive(Serialize)]
struct Row {
    id: String,
    created_at: i64,
    owner: Option<i64>,
    owner_name: Option<String>,
    owner_avatar: Option<String>,
    status: i64,
    has_dump: bool,
    crash_module: Option<String>,
    crash_function: Option<String>,
    notices: i64,
    /// How many times the same crash came again (see `limits.repeat_window_days`).
    repeats: i64,
    last_repeat_at: Option<i64>,
    /// A short hash of the server's command line. It seeds the identicon that
    /// tells servers apart; the command line itself never leaves the database.
    server: Option<String>,
}

impl From<RawRow> for Row {
    fn from(r: RawRow) -> Self {
        let server = r
            .cmdline
            .filter(|c| !c.trim().is_empty())
            .map(|c| hex::encode(&Sha256::digest(c.as_bytes())[..8]));
        Row {
            id: r.id,
            created_at: r.created_at,
            owner: r.owner,
            owner_name: r.owner_name,
            owner_avatar: r.owner_avatar,
            status: r.status,
            has_dump: r.has_dump != 0,
            crash_module: r.crash_module,
            crash_function: r.crash_function,
            notices: r.notices,
            repeats: r.repeats,
            last_repeat_at: r.last_repeat_at,
            server,
        }
    }
}

/// One tab above the list: you, or somebody who shares their reports with you.
#[derive(Serialize)]
struct Person {
    id: i64,
    name: Option<String>,
    avatar: Option<String>,
    active: bool,
}

pub async fn dashboard(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Query(params): Query<Params>,
) -> Result<Response, WebError> {
    let user = MaybeUser(user).required()?;
    let page = i64::from(params.page.unwrap_or(1).clamp(1, MAX_PAGE));

    let filter = match params
        .user
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(raw) => match parse_owner(raw) {
            Ok(Some(id)) => Some(id),
            _ => return Err(WebError::BadRequest("That is not a valid Steam ID.")),
        },
    };

    // One extra row tells us whether there is a next page.
    let raw: Vec<RawRow> = sqlx::query_as(
        "SELECT c.id, c.created_at, c.owner, u.name AS owner_name, u.avatar AS owner_avatar, c.status, \
                c.has_dump, c.crash_module, c.crash_function, c.cmdline, c.repeats, c.last_repeat_at, \
                (SELECT COUNT(*) FROM crashnotice cn WHERE cn.crash = c.id) AS notices \
         FROM crash c LEFT JOIN user u ON u.id = c.owner \
         WHERE (? = 1 OR c.owner = ? OR c.owner IN \
                 (SELECT owner FROM share WHERE user = ? AND accepted_at IS NOT NULL)) \
           AND (? IS NULL OR c.owner = ?) \
         ORDER BY c.created_at DESC, c.id DESC LIMIT ? OFFSET ?",
    )
    .bind(i64::from(user.admin))
    .bind(user.id)
    .bind(user.id)
    .bind(filter)
    .bind(filter)
    .bind(PAGE_SIZE + 1)
    .bind((page - 1) * PAGE_SIZE)
    .fetch_all(&state.db)
    .await?;

    let has_next = raw.len() as i64 > PAGE_SIZE;
    let rows: Vec<Row> = raw
        .into_iter()
        .take(PAGE_SIZE as usize)
        .map(Row::from)
        .collect();

    // Tabs: you first, then everybody who shares with you.
    let shared: Vec<(i64, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT u.id, u.name, u.avatar FROM share s JOIN user u ON u.id = s.owner \
         WHERE s.user = ? AND s.accepted_at IS NOT NULL ORDER BY u.name, u.id",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    let people: Vec<Person> = std::iter::once((user.id, user.name.clone(), user.avatar.clone()))
        .chain(shared)
        .map(|(id, name, avatar)| Person {
            id,
            name,
            avatar,
            active: filter == Some(id),
        })
        .collect();

    let tabs = people.len() > 1 || user.admin;
    let filter_in_tabs = tabs && people.iter().any(|p| p.active);

    let html = render(
        &state,
        "dashboard.html",
        Some(&user),
        context! {
            rows => rows,
            prev => (page > 1).then(|| page - 1),
            next => has_next.then(|| page + 1),
            filter_id => filter.map(|f| f.to_string()),
            filter_in_tabs => filter_in_tabs,
            people => people,
            tabs => tabs,
            // Whose crash each row is only matters when several people's show up.
            show_owner => tabs && filter.is_none(),
            page => page,
            select_all => params.select.as_deref() == Some("all"),
            deleted => params.deleted,
        },
    )?;
    Ok(html.into_response())
}

/// Most reports one request may delete; a page has 20, so this is generous.
const MAX_BULK_DELETE: usize = 200;

/// Delete the ticked reports (one `id` field each). Permission is all or nothing: a report
/// the user may not manage refuses the whole request. One that is already gone is skipped.
pub async fn delete_many(
    State(state): State<AppState>,
    headers: HeaderMap,
    MaybeUser(user): MaybeUser,
    body: Bytes,
) -> Result<Response, WebError> {
    check_origin(&state, &headers)?;
    let user = MaybeUser(user).required()?;

    let mut raw_ids = Vec::new();
    let mut filter = None;
    for (key, value) in form_urlencoded::parse(&body) {
        match &*key {
            "id" => raw_ids.push(value.into_owned()),
            "user" => filter = parse_owner(value.trim()).ok().flatten(),
            _ => {}
        }
    }
    if raw_ids.len() > MAX_BULK_DELETE {
        return Err(WebError::BadRequest("Too many reports selected at once."));
    }

    let mut ids: Vec<String> = Vec::new();
    for raw in &raw_ids {
        match managed(&state, Some(&user), raw).await {
            Ok(id) => {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            Err(WebError::NotFound) => {}
            Err(e) => return Err(e),
        }
    }

    let mut deleted = 0;
    if !ids.is_empty() {
        // Frames, modules and notices go with the rows (ON DELETE CASCADE).
        let mut tx = state.db.begin().await?;
        let mut gone = Vec::new();
        for id in &ids {
            // Like the retention pass, skip crashes a worker is processing right now.
            let n = sqlx::query("DELETE FROM crash WHERE id = ? AND status != 1")
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            if n > 0 {
                gone.push(id);
            }
            deleted += n;
        }
        tx.commit().await?;
        for id in gone {
            crate::retention::remove_files(&state.config, id).await;
        }
    }

    let mut to = format!("/dashboard?deleted={deleted}");
    if let Some(owner) = filter {
        to.push_str(&format!("&user={owner}"));
    }
    Ok(Redirect::to(&to).into_response())
}
