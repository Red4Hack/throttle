//! Sharing: an owner invites another Steam user, who must accept before they
//! can see the owner's reports. Either side can revoke at any time.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use minijinja::context;
use serde::{Deserialize, Serialize};

use super::session::MaybeUser;
use super::{WebError, check_origin, render};
use crate::app::AppState;
use crate::ingest::steam::parse_owner;
use crate::stats;

const MAX_SHARES_PER_OWNER: i64 = 100;
const PAGE: &str = "/settings/share";

#[derive(sqlx::FromRow, Serialize)]
struct Person {
    id: i64,
    name: Option<String>,
    avatar: Option<String>,
    accepted_at: Option<i64>,
}

#[derive(Deserialize)]
pub struct PageQuery {
    error: Option<String>,
}

fn error_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "missing" => "Enter a Steam ID.",
        "invalid" => "That is not a valid Steam ID.",
        "self" => "You already have access to your own reports.",
        "exists" => "That user already has access.",
        "pending" => "You already invited that user; they haven't accepted yet.",
        "limit" => "You have reached the sharing limit.",
        _ => return None,
    })
}

pub async fn page(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Query(query): Query<PageQuery>,
) -> Result<Response, WebError> {
    let user = MaybeUser(user).required()?;

    let sharing: Vec<Person> = sqlx::query_as(
        "SELECT s.user AS id, u.name, u.avatar, s.accepted_at FROM share s LEFT JOIN user u ON u.id = s.user \
         WHERE s.owner = ? ORDER BY s.accepted_at IS NULL DESC, s.accepted_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    let shared: Vec<Person> = sqlx::query_as(
        "SELECT s.owner AS id, u.name, u.avatar, s.accepted_at FROM share s LEFT JOIN user u ON u.id = s.owner \
         WHERE s.user = ? ORDER BY s.accepted_at IS NULL DESC, s.accepted_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;

    let error = query.error.as_deref().and_then(error_text);
    let html = render(
        &state,
        "share.html",
        Some(&user),
        context! { sharing => sharing, shared => shared, error => error },
    )?;
    Ok(html.into_response())
}

#[derive(Deserialize)]
pub struct InviteForm {
    user: Option<String>,
}

fn back(error: Option<&str>) -> Response {
    match error {
        Some(code) => Redirect::to(&format!("{PAGE}?error={code}")),
        None => Redirect::to(PAGE),
    }
    .into_response()
}

fn steam_id(raw: Option<&str>) -> Option<i64> {
    match parse_owner(raw?.trim()) {
        Ok(Some(id)) => Some(id),
        _ => None,
    }
}

pub async fn invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    MaybeUser(user): MaybeUser,
    axum::Form(form): axum::Form<InviteForm>,
) -> Result<Response, WebError> {
    check_origin(&state, &headers)?;
    let user = MaybeUser(user).required()?;

    if form
        .user
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Ok(back(Some("missing")));
    }
    let Some(target) = steam_id(form.user.as_deref()) else {
        return Ok(back(Some("invalid")));
    };
    if target == user.id {
        return Ok(back(Some("self")));
    }

    let existing: Option<Option<i64>> =
        sqlx::query_scalar("SELECT accepted_at FROM share WHERE owner = ? AND user = ?")
            .bind(user.id)
            .bind(target)
            .fetch_optional(&state.db)
            .await?;
    match existing {
        Some(Some(_)) => return Ok(back(Some("exists"))),
        Some(None) => return Ok(back(Some("pending"))),
        None => {}
    }

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM share WHERE owner = ?")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    if count >= MAX_SHARES_PER_OWNER {
        return Ok(back(Some("limit")));
    }

    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT OR IGNORE INTO user (id) VALUES (?)")
        .bind(target)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO share (owner, user, invited_at) VALUES (?, ?, ?)")
        .bind(user.id)
        .bind(target)
        .bind(stats::now())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(back(None))
}

#[derive(Deserialize)]
pub struct AcceptForm {
    owner: Option<String>,
}

pub async fn accept(
    State(state): State<AppState>,
    headers: HeaderMap,
    MaybeUser(user): MaybeUser,
    axum::Form(form): axum::Form<AcceptForm>,
) -> Result<Response, WebError> {
    check_origin(&state, &headers)?;
    let user = MaybeUser(user).required()?;
    let owner =
        steam_id(form.owner.as_deref()).ok_or(WebError::BadRequest("Missing or invalid owner."))?;

    sqlx::query(
        "UPDATE share SET accepted_at = ? WHERE owner = ? AND user = ? AND accepted_at IS NULL",
    )
    .bind(stats::now())
    .bind(owner)
    .bind(user.id)
    .execute(&state.db)
    .await?;
    Ok(back(None))
}

#[derive(Deserialize)]
pub struct RevokeForm {
    user: Option<String>,
    owner: Option<String>,
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    MaybeUser(user): MaybeUser,
    axum::Form(form): axum::Form<RevokeForm>,
) -> Result<Response, WebError> {
    check_origin(&state, &headers)?;
    let user = MaybeUser(user).required()?;

    let given = |v: &Option<String>| v.as_deref().map(str::trim).is_some_and(|s| !s.is_empty());
    match (given(&form.user), given(&form.owner)) {
        // I stop sharing with `user`.
        (true, false) => {
            let target =
                steam_id(form.user.as_deref()).ok_or(WebError::BadRequest("Invalid target."))?;
            sqlx::query("DELETE FROM share WHERE owner = ? AND user = ?")
                .bind(user.id)
                .bind(target)
                .execute(&state.db)
                .await?;
        }
        // I leave (or decline) `owner`'s sharing.
        (false, true) => {
            let target =
                steam_id(form.owner.as_deref()).ok_or(WebError::BadRequest("Invalid target."))?;
            sqlx::query("DELETE FROM share WHERE owner = ? AND user = ?")
                .bind(target)
                .bind(user.id)
                .execute(&state.db)
                .await?;
        }
        _ => {
            return Err(WebError::BadRequest(
                "Specify exactly one of user or owner.",
            ));
        }
    }
    Ok(back(None))
}
