//! The website: crash pages, dashboard, Steam login, sharing.
//!
//! Server-rendered HTML, no JavaScript. Sessions are signed cookies; every
//! state-changing request is a POST that must come from our own origin.

mod analysis;
mod auth;
mod crashes;
mod dashboard;
mod format;
mod icons;
mod pages;
mod profiles;
mod session;
mod share;
mod statistics;
mod steam;
mod views;

#[cfg(test)]
mod tests;

use axum::Router;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use minijinja::value::merge_maps;
use minijinja::{Value, context};

use crate::app::AppState;
pub use profiles::spawn as spawn_profile_refresh;
use session::User;
pub use views::{Views, build_views};

#[derive(Debug)]
pub enum WebError {
    NotFound,
    Forbidden,
    /// Not logged in: send the visitor to the login page.
    LoginRequired,
    BadRequest(&'static str),
    Unavailable(&'static str),
    Internal,
}

impl From<sqlx::Error> for WebError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error in a page");
        WebError::Internal
    }
}

impl From<std::io::Error> for WebError {
    fn from(e: std::io::Error) -> Self {
        tracing::error!(error = %e, "io error in a page");
        WebError::Internal
    }
}

impl From<minijinja::Error> for WebError {
    fn from(e: minijinja::Error) -> Self {
        tracing::error!(error = ?e, "template error");
        WebError::Internal
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Error pages use static messages (no user input) and no templates, so they
/// work even when the template engine is what failed. Same look as the rest.
fn error_page(status: StatusCode, message: &str) -> Response {
    let title = status.canonical_reason().unwrap_or("Error");
    let icon = match status {
        StatusCode::NOT_FOUND => "search",
        StatusCode::FORBIDDEN => "lock",
        _ => "alert-triangle",
    };
    let body = format!(
        concat!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>Throttle</title><script src=\"/static/theme.js\"></script><link rel=\"icon\" href=\"/favicon.ico\"><link rel=\"stylesheet\" href=\"/static/app.css\"></head><body>",
            "<header class=\"navbar\"><div class=\"container navbar-inner\">",
            "<a class=\"brand\" href=\"/\">{logo} Throttle</a></div></header>",
            "<main class=\"container\"><div class=\"error-page\">{icon}",
            "<h1>{code} {title}</h1><p>{message}</p>",
            "<a class=\"btn btn-primary\" href=\"/\">Back to the start</a></div></main></body></html>"
        ),
        code = status.as_u16(),
        title = escape_html(title),
        message = escape_html(message).replace("&lt;br&gt;", "<br>"),
        icon = icons::icon(icon),
        logo = icons::icon("gauge"),
    );
    (status, Html(body)).into_response()
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        match self {
            WebError::LoginRequired => Redirect::to("/login").into_response(),
            WebError::NotFound => error_page(StatusCode::NOT_FOUND, "What you are looking for is not here.<br>Unless you were looking for this error page of course."),
            WebError::Forbidden => {
                error_page(StatusCode::FORBIDDEN, "You are not allowed to do that.")
            }
            WebError::BadRequest(m) => error_page(StatusCode::BAD_REQUEST, m),
            WebError::Unavailable(m) => error_page(StatusCode::SERVICE_UNAVAILABLE, m),
            WebError::Internal => error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong on our side.",
            ),
        }
    }
}

/// The address this request was made to, e.g. `http://0.0.0.0:8080`. With a
/// pinned `hostname` it is that; otherwise it follows the `Host` header.
pub fn site_origin(state: &AppState, headers: &HeaderMap) -> String {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    state.config.origin(host)
}

/// CSRF defence for POSTs, on top of `SameSite=Lax` cookies: the request must
/// say it comes from this site (Origin, or failing that Referer).
pub fn check_origin(state: &AppState, headers: &HeaderMap) -> Result<(), WebError> {
    let base = site_origin(state, headers);
    if let Some(origin) = headers.get(header::ORIGIN) {
        return if origin.as_bytes().eq_ignore_ascii_case(base.as_bytes()) {
            Ok(())
        } else {
            Err(WebError::Forbidden)
        };
    }
    match headers.get(header::REFERER).and_then(|r| r.to_str().ok()) {
        Some(r) if r == base || r.starts_with(&format!("{base}/")) => Ok(()),
        _ => Err(WebError::Forbidden),
    }
}

/// Render `template` with the page's own data plus what every page needs.
pub fn render(
    state: &AppState,
    template: &str,
    user: Option<&User>,
    page: Value,
) -> Result<Html<String>, WebError> {
    let cfg = &state.config;
    let site = context! {
        user => user,
        hostname => &cfg.hostname,
        show_version => cfg.show_version,
        version => env!("CARGO_PKG_VERSION"),
        maintenance => &cfg.maintenance_message,
    };
    let html = state
        .views
        .get_template(template)?
        .render(merge_maps([page, site]))?;
    Ok(Html(html))
}

/// Applied to every response, API endpoints included.
pub async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' https://*.steamstatic.com; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::index))
        .route("/robots.txt", get(pages::robots))
        .route("/static/app.css", get(pages::css))
        .route("/static/theme.js", get(pages::theme_js))
        .route("/favicon.ico", get(pages::favicon))
        .route("/login", get(auth::login))
        .route("/login/callback", get(auth::callback))
        .route("/logout", post(auth::logout))
        .route("/dashboard", get(dashboard::dashboard))
        .route("/dashboard/delete", post(dashboard::delete_many))
        .route("/stats", get(statistics::stats_page))
        .route("/stats/{module}", get(statistics::stats_module))
        .route("/stats/{module}/{function}", get(statistics::stats_function))
        .route("/settings/share", get(share::page))
        .route("/settings/share/invite", post(share::invite))
        .route("/settings/share/accept", post(share::accept))
        .route("/settings/share/revoke", post(share::revoke))
        .route("/{id}", get(crashes::details))
        .route("/{id}/download", get(crashes::download))
        .route("/{id}/metadata", get(crashes::metadata_file))
        .route("/{id}/console", get(crashes::console))
        .route("/{id}/raw", get(crashes::raw))
        .route("/{id}/delete", post(crashes::delete))
        .route("/{id}/reprocess", post(crashes::reprocess))
        .route("/{id}/carburetor", get(analysis::page))
        .route("/{id}/carburetor/data", get(analysis::data))
}
