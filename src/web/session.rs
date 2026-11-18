//! Login sessions: a signed cookie that carries only the SteamID64 and the
//! issue time. Nothing is stored server side; the HMAC key is the same
//! `secret.key` that signs presubmit tokens (with a different domain prefix).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, header};
use serde::Serialize;

use super::WebError;
use crate::app::AppState;
use crate::ingest::token::{Secret, same};
use crate::stats;

const TTL_SECS: i64 = 30 * 86_400;
const CLOCK_SKEW_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub admin: bool,
}

/// `__Host-` pins the cookie to this exact host over HTTPS (no Domain, Path=/).
pub fn cookie_name(https: bool) -> &'static str {
    if https {
        "__Host-throttle_session"
    } else {
        "throttle_session"
    }
}

pub fn mint(secret: &Secret, steamid: i64, now: i64) -> String {
    let body = format!("{steamid}.{now:x}");
    format!("{body}.{}", secret.sign(&format!("session:{body}")))
}

pub fn verify(secret: &Secret, value: &str, now: i64) -> Option<i64> {
    let mut parts = value.split('.');
    let (id, issued, mac) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    if !same(&secret.sign(&format!("session:{id}.{issued}")), mac) {
        return None;
    }
    let issued = i64::from_str_radix(issued, 16).ok()?;
    if issued > now + CLOCK_SKEW_SECS || now - issued > TTL_SECS {
        return None;
    }
    id.parse().ok()
}

fn set_cookie(https: bool, value: &str, max_age: i64) -> HeaderValue {
    let secure = if https { "; Secure" } else { "" };
    let cookie = format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}",
        cookie_name(https)
    );
    HeaderValue::from_str(&cookie).expect("cookie values are ASCII")
}

pub fn session_cookie(https: bool, value: &str) -> HeaderValue {
    set_cookie(https, value, TTL_SECS)
}

pub fn clear_cookie(https: bool) -> HeaderValue {
    set_cookie(https, "", 0)
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(k, v)| (k == name).then_some(v))
}

/// The logged-in user, if any. A missing, forged or expired cookie simply
/// means "anonymous"; handlers that need a login call [`MaybeUser::required`].
pub struct MaybeUser(pub Option<User>);

impl MaybeUser {
    pub fn required(self) -> Result<User, WebError> {
        self.0.ok_or(WebError::LoginRequired)
    }
}

async fn load_user(state: &AppState, id: i64) -> User {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT name, avatar FROM user WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "could not load the session user");
                None
            });
    let (name, avatar) = row.unwrap_or((None, None));
    let admin = u64::try_from(id).is_ok_and(|id| state.config.admins.contains(&id));
    User {
        id,
        name,
        avatar,
        admin,
    }
}

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let name = cookie_name(state.config.https);
        let id =
            cookie_value(&parts.headers, name).and_then(|v| verify(&state.secret, v, stats::now()));
        Ok(match id {
            Some(id) => Self(Some(load_user(state, id).await)),
            None => Self(None),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> Secret {
        Secret::from_bytes(vec![byte; 32])
    }

    #[test]
    fn roundtrip() {
        let s = secret(1);
        let cookie = mint(&s, 76_561_197_960_265_829, 1000);
        assert_eq!(verify(&s, &cookie, 1000), Some(76_561_197_960_265_829));
        assert_eq!(
            verify(&s, &cookie, 1000 + TTL_SECS),
            Some(76_561_197_960_265_829)
        );
    }

    #[test]
    fn forgery_and_expiry_are_refused() {
        let s = secret(1);
        let cookie = mint(&s, 100, 1000);
        assert_eq!(verify(&secret(2), &cookie, 1000), None);
        assert_eq!(verify(&s, &cookie, 1000 + TTL_SECS + 1), None);
        assert_eq!(verify(&s, &cookie, 1000 - CLOCK_SKEW_SECS - 1), None);
        // Another user id with the old MAC.
        let swapped = cookie.replacen("100", "101", 1);
        assert_eq!(verify(&s, &swapped, 1000), None);
        // A presubmit token is not a session.
        let token = crate::ingest::token::mint(
            &s,
            crate::ingest::token::Kind::Full,
            "0123456789abcdef",
            1000,
        );
        assert_eq!(verify(&s, &token, 1000), None);
        for bad in ["", "1", "1.2", "1.2.3.4", "a.b.c"] {
            assert_eq!(verify(&s, bad, 1000), None, "{bad}");
        }
    }

    #[test]
    fn cookie_attributes() {
        let plain = session_cookie(false, "v").to_str().unwrap().to_string();
        assert!(
            plain.starts_with("throttle_session=v;")
                && plain.contains("HttpOnly")
                && plain.contains("SameSite=Lax")
        );
        assert!(!plain.contains("Secure"));
        let tls = session_cookie(true, "v").to_str().unwrap().to_string();
        assert!(tls.starts_with("__Host-throttle_session=v;") && tls.contains("; Secure"));
        assert!(clear_cookie(false).to_str().unwrap().contains("Max-Age=0"));
    }

    #[test]
    fn finds_the_cookie_among_others() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            "a=1; throttle_session=xyz; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&h, "throttle_session"), Some("xyz"));
        assert_eq!(cookie_value(&h, "missing"), None);
    }
}
