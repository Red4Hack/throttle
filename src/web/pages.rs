//! The index page, robots.txt and the stylesheet.

use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use minijinja::context;
use serde::Deserialize;

use super::crashes::canonical;
use super::session::MaybeUser;
use super::{WebError, render};
use crate::app::AppState;

#[derive(Deserialize)]
pub struct IndexQuery {
    id: Option<String>,
}

pub async fn index(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Query(query): Query<IndexQuery>,
) -> Result<Response, WebError> {
    let mut error = None;
    if let Some(raw) = query.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        match canonical(raw) {
            Some(id) => return Ok(Redirect::to(&format!("/{id}")).into_response()),
            None => error = Some("That doesn't look like a crash ID."),
        }
    }
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crash")
        .fetch_one(&state.db)
        .await?;
    let last_day: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crash WHERE created_at >= ?")
        .bind(crate::stats::now() - 86_400)
        .fetch_one(&state.db)
        .await?;
    let html = render(
        &state,
        "index.html",
        user.as_ref(),
        context! { error => error, stored => stored, last_day => last_day },
    )?;
    Ok((status, html).into_response())
}

pub async fn robots() -> &'static str {
    "User-agent: *\nDisallow: /\n"
}

pub async fn css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../../static/app.css"),
    )
}

pub async fn favicon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/x-icon"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        include_bytes!("../../static/favicon.ico").as_slice(),
    )
}

pub async fn theme_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../../static/theme.js"),
    )
}
