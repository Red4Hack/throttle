//! Login (Steam OpenID) and logout.

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Redirect, Response};

use super::session::{self, MaybeUser};
use super::steam::{self, LoginError, Lookup};
use super::{WebError, check_origin, site_origin};
use crate::app::AppState;
use crate::stats;

/// The longest a login waits for the Steam profile.
const LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

fn return_to(origin: &str) -> String {
    format!("{origin}/login/callback")
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    MaybeUser(user): MaybeUser,
) -> Redirect {
    if user.is_some() {
        return Redirect::to("/dashboard");
    }
    // Steam sends the browser back to where it started from, wherever that was.
    let origin = site_origin(&state, &headers);
    Redirect::to(&steam::login_url(&origin, &return_to(&origin)))
}

pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Response, WebError> {
    let params: Vec<(String, String)> =
        form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .into_owned()
            .collect();

    let id = steam::verify(
        &state.http,
        &params,
        &return_to(&site_origin(&state, &headers)),
    )
    .await
    .map_err(|e| match e {
        LoginError::Network => {
            WebError::Unavailable("Steam could not be reached. Try again in a moment.")
        }
        LoginError::Invalid(_) | LoginError::Rejected => {
            WebError::BadRequest("The Steam login could not be verified.")
        }
    })?;

    // Steam being slow must not hold the login up: whoever has no profile yet is
    // picked up by the background refresher within a minute.
    let lookup = steam::lookup_profile(&state.http, state.config.steam_api_key.as_deref(), id);
    let profile = match tokio::time::timeout(LOOKUP_BUDGET, lookup).await {
        Ok(Lookup::Found(profile)) => Some(profile),
        _ => None,
    };
    let now = stats::now();
    steam::upsert_user(&state.db, id, profile.as_ref(), now).await?;

    let cookie =
        session::session_cookie(state.config.https, &session::mint(&state.secret, id, now));
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/dashboard")).into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    check_origin(&state, &headers)?;
    let cookie = session::clear_cookie(state.config.https);
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response())
}
