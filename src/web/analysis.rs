//! `/{id}/carburetor`, the "View Raw" page: the dump as the optional external program
//! (see `crate::carburetor`) sees it, in the three tabs the old site had: Stack, Memory,
//! Raw. For people who manage the crash only: it shows registers, plugin frames and
//! memory, which the public crash page does not.

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use minijinja::context;

use super::crashes::managed;
use super::session::MaybeUser;
use super::{WebError, render};
use crate::app::AppState;
use crate::carburetor::{self, RunError};

/// Run the program for `raw` (an ID in any spelling) once the user is allowed to.
async fn analyze(
    state: &AppState,
    user: Option<&super::session::User>,
    raw: &str,
    full: bool,
) -> Result<(String, Vec<u8>), WebError> {
    if state.config.carburetor.path.is_none() {
        return Err(WebError::NotFound);
    }
    let id = managed(state, user, raw).await?;
    if !tokio::fs::try_exists(state.config.dump_path(&id))
        .await
        .unwrap_or(false)
    {
        return Err(WebError::NotFound);
    }
    let json = carburetor::run(state, &id, full)
        .await
        .map_err(|e| match e {
            RunError::Disabled => WebError::NotFound,
            RunError::Busy => WebError::Unavailable(
                "Other analyses are running right now. Try again in a moment.",
            ),
            RunError::TimedOut => WebError::Unavailable("The analysis took too long."),
            RunError::TooBig => WebError::Unavailable("The result of the analysis is too large."),
            RunError::Failed => WebError::Unavailable("The analysis failed for this dump."),
        })?;
    Ok((id, json))
}

pub async fn page(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(raw): Path<String>,
) -> Result<Response, WebError> {
    // The viewer shows the memory and the disassembly too, as the old one did.
    let (id, json) = analyze(&state, user.as_ref(), &raw, true).await?;
    // Parsing and laying out a big dump is real work: not on the async threads.
    let view = tokio::task::spawn_blocking(move || carburetor::viewer(&json))
        .await
        .map_err(|_| WebError::Internal)?
        .ok_or(WebError::Unavailable(
            "The analysis produced output that could not be read.",
        ))?;
    let html = render(
        &state,
        "analysis.html",
        user.as_ref(),
        context! { crash_id => id, view => view },
    )?;
    Ok(html.into_response())
}

/// The program's complete output, memory and disassembly included.
pub async fn data(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(raw): Path<String>,
) -> Result<Response, WebError> {
    let (_, json) = analyze(&state, user.as_ref(), &raw, true).await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], json).into_response())
}
