//! Steam OpenID 2.0 login and profile lookups.
//!
//! Login: we redirect to Steam, Steam redirects back with a signed assertion,
//! and we (1) check locally that it is about the right thing, then (2) ask
//! Steam to confirm the signature with `check_authentication`. Steam marks the
//! response nonce as used when it confirms, which is what stops replays.

use sqlx::SqlitePool;

use crate::ingest::steam::parse_owner;

const ENDPOINT: &str = "https://steamcommunity.com/openid/login";
const NS: &str = "http://specs.openid.net/auth/2.0";
const IDENTIFIER_SELECT: &str = "http://specs.openid.net/auth/2.0/identifier_select";
const ID_PREFIX: &str = "https://steamcommunity.com/openid/id/";
/// Everything that identifies the user and ties the response to our request
/// must be covered by Steam's signature.
const REQUIRED_SIGNED: &[&str] = &[
    "op_endpoint",
    "claimed_id",
    "identity",
    "return_to",
    "response_nonce",
    "assoc_handle",
];

pub fn login_url(realm: &str, return_to: &str) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("openid.ns", NS)
        .append_pair("openid.mode", "checkid_setup")
        .append_pair("openid.return_to", return_to)
        .append_pair("openid.realm", realm)
        .append_pair("openid.identity", IDENTIFIER_SELECT)
        .append_pair("openid.claimed_id", IDENTIFIER_SELECT)
        .finish();
    format!("{ENDPOINT}?{query}")
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    /// The response is not a valid Steam assertion for this site.
    Invalid(&'static str),
    /// Steam says the signature is not valid (or already used).
    Rejected,
    /// Steam could not be reached.
    Network,
}

/// A parameter that appears exactly once; duplicates are suspicious.
fn single<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    let mut found = params.iter().filter(|(k, _)| k == key);
    let first = found.next()?;
    found.next().is_none().then_some(first.1.as_str())
}

/// The local half of the verification. Returns the SteamID64.
pub fn check_params(params: &[(String, String)], return_to: &str) -> Result<i64, LoginError> {
    let get =
        |k: &str| single(params, k).ok_or(LoginError::Invalid("missing or repeated parameter"));

    if get("openid.ns")? != NS || get("openid.mode")? != "id_res" {
        return Err(LoginError::Invalid("not a positive assertion"));
    }
    if get("openid.op_endpoint")? != ENDPOINT {
        return Err(LoginError::Invalid("wrong provider"));
    }
    if get("openid.return_to")? != return_to {
        return Err(LoginError::Invalid("wrong return address"));
    }
    let signed: Vec<&str> = get("openid.signed")?.split(',').collect();
    if !REQUIRED_SIGNED.iter().all(|f| signed.contains(f)) {
        return Err(LoginError::Invalid("required fields are not signed"));
    }

    let claimed = get("openid.claimed_id")?;
    if get("openid.identity")? != claimed {
        return Err(LoginError::Invalid("identity mismatch"));
    }
    let id = claimed
        .strip_prefix(ID_PREFIX)
        .ok_or(LoginError::Invalid("not a Steam identity"))?;
    match parse_owner(id) {
        // Only the canonical decimal spelling is accepted.
        Ok(Some(parsed)) if parsed.to_string() == id => Ok(parsed),
        _ => Err(LoginError::Invalid("not a Steam ID")),
    }
}

pub async fn verify(
    http: &reqwest::Client,
    params: &[(String, String)],
    return_to: &str,
) -> Result<i64, LoginError> {
    let id = check_params(params, return_to)?;

    let mut form: Vec<(&str, &str)> = params
        .iter()
        .filter(|(k, _)| k.starts_with("openid."))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    for (k, v) in form.iter_mut() {
        if *k == "openid.mode" {
            *v = "check_authentication";
        }
    }

    let body = async {
        http.post(ENDPOINT)
            .form(&form)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    }
    .await
    .map_err(|_| LoginError::Network)?;

    if body.lines().any(|l| l.trim() == "is_valid:true") {
        Ok(id)
    } else {
        Err(LoginError::Rejected)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Profile {
    pub name: Option<String>,
    pub avatar: Option<String>,
}

fn clean_name(name: &str) -> Option<String> {
    let cleaned: String = name.chars().filter(|c| !c.is_control()).collect();
    let cleaned: String = cleaned.trim().chars().take(64).collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Only Steam's own CDN, over HTTPS, with a boring URL.
fn valid_avatar(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    let host_ok = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
        && (host == "steamstatic.com" || host.ends_with(".steamstatic.com"));
    host_ok
        && url.len() <= 300
        && url
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\'' | b'<' | b'>' | b'\\'))
}

pub fn parse_profile(body: &str) -> Option<Profile> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let player = json.get("response")?.get("players")?.get(0)?;
    let name = player
        .get("personaname")
        .and_then(|n| n.as_str())
        .and_then(clean_name);
    let avatar = player
        .get("avatarfull")
        .and_then(|a| a.as_str())
        .map(|a| a.replacen("http://", "https://", 1))
        .filter(|a| valid_avatar(a));
    Some(Profile { name, avatar })
}

async fn get_text(http: &reqwest::Client, url: &str) -> reqwest::Result<String> {
    http.get(url).send().await?.error_for_status()?.text().await
}

/// What a profile lookup found out.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(Profile),
    /// Steam answered, but has nothing usable for this id.
    Missing,
    /// Steam could not be reached (or is rate limiting us): ask again later.
    Unreachable,
}

/// The next child element of a profile document, `<tag>text</tag>`, where the
/// text is plain or a run of CDATA sections. Elements are read strictly in order
/// and nothing is searched for, because the persona name is chosen by the user:
/// a name that spells out `</steamID><avatarFull>...` stays inside its own CDATA.
/// An element with children is not understood and ends the scan.
fn next_element(s: &str) -> Option<(&str, String, &str)> {
    let s = s.trim_start().strip_prefix('<')?;
    let (tag, mut rest) = s.split_once('>')?;
    if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let mut text = String::new();
    while let Some(cdata) = rest.strip_prefix("<![CDATA[") {
        let (chunk, after) = cdata.split_once("]]>")?;
        text.push_str(chunk);
        rest = after;
    }
    let end = rest.find('<')?;
    text.push_str(&rest[..end]);
    let rest = rest[end..]
        .strip_prefix("</")?
        .strip_prefix(tag)?
        .strip_prefix('>')?;
    Some((tag, text, rest))
}

/// Name and avatar from `steamcommunity.com/profiles/<id>?xml=1`. `None` when the
/// document is not a profile, is about another id, or has neither a name nor a
/// usable avatar.
pub fn parse_profile_xml(body: &str, steamid: i64) -> Option<Profile> {
    const OPEN: &str = "<profile>";
    let mut rest = &body[body.find(OPEN)? + OPEN.len()..];
    let mut id_checked = false;
    let (mut name, mut avatar) = (None, None);
    while let Some((tag, text, after)) = next_element(rest) {
        rest = after;
        match tag {
            "steamID64" => {
                if text.trim() != steamid.to_string() {
                    return None;
                }
                id_checked = true;
            }
            "steamID" => name = clean_name(&text),
            "avatarFull" => {
                let url = text.trim().replacen("http://", "https://", 1);
                avatar = valid_avatar(&url).then_some(url);
                break;
            }
            _ => {}
        }
    }
    (id_checked && (name.is_some() || avatar.is_some())).then_some(Profile { name, avatar })
}

/// The name and avatar are near the top of the document; the rest (groups,
/// games) is not needed.
const MAX_PROFILE_XML: usize = 256 * 1024;

/// The public profile page. Needs no API key.
async fn fetch_profile_xml(http: &reqwest::Client, steamid: i64) -> Lookup {
    let url = format!("https://steamcommunity.com/profiles/{steamid}?xml=1");
    let Ok(mut res) = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
    else {
        return Lookup::Unreachable;
    };
    let mut body = Vec::new();
    while body.len() < MAX_PROFILE_XML {
        match res.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(_) => return Lookup::Unreachable,
        }
    }
    // Steam answers 200 for a profile that does not exist, too.
    match parse_profile_xml(&String::from_utf8_lossy(&body), steamid) {
        Some(profile) => Lookup::Found(profile),
        None => Lookup::Missing,
    }
}

/// The Web API when there is a key, the public profile page otherwise (and when
/// the API has nothing, say because of a wrong key).
pub async fn lookup_profile(http: &reqwest::Client, api_key: Option<&str>, steamid: i64) -> Lookup {
    if let Some(key) = api_key
        && let Some(profile) = fetch_profile(http, key, steamid).await
    {
        return Lookup::Found(profile);
    }
    fetch_profile_xml(http, steamid).await
}

async fn fetch_profile(http: &reqwest::Client, api_key: &str, steamid: i64) -> Option<Profile> {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("key", api_key)
        .append_pair("steamids", &steamid.to_string())
        .finish();
    let url = format!("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?{query}");
    match get_text(http, &url).await {
        Ok(body) => parse_profile(&body),
        Err(_) => {
            // The error text would contain the URL, and with it the API key.
            tracing::warn!("steam profile lookup failed");
            None
        }
    }
}

/// A login. `updated_at` only moves when a profile came back, so a user whose
/// lookup failed is picked up by the background refresher right away.
pub async fn upsert_user(
    db: &SqlitePool,
    id: i64,
    profile: Option<&Profile>,
    now: i64,
) -> sqlx::Result<()> {
    let (name, avatar): (Option<&str>, Option<&str>) =
        profile.map_or((None, None), |p| (p.name.as_deref(), p.avatar.as_deref()));
    sqlx::query(
        "INSERT INTO user (id, name, avatar, updated_at, last_active) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT (id) DO UPDATE SET \
           name = COALESCE(excluded.name, name), \
           avatar = COALESCE(excluded.avatar, avatar), \
           updated_at = COALESCE(excluded.updated_at, updated_at), \
           last_active = excluded.last_active",
    )
    .bind(id)
    .bind(name)
    .bind(avatar)
    .bind(profile.map(|_| now))
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

/// The outcome of a background lookup. `updated_at` is when Steam was last asked,
/// whatever it answered; what we already know is kept when it has nothing new.
pub async fn store_lookup(
    db: &SqlitePool,
    id: i64,
    profile: Option<&Profile>,
    now: i64,
) -> sqlx::Result<()> {
    let (name, avatar): (Option<&str>, Option<&str>) =
        profile.map_or((None, None), |p| (p.name.as_deref(), p.avatar.as_deref()));
    sqlx::query(
        "INSERT INTO user (id, name, avatar, updated_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT (id) DO UPDATE SET \
           name = COALESCE(excluded.name, name), \
           avatar = COALESCE(excluded.avatar, avatar), \
           updated_at = excluded.updated_at",
    )
    .bind(id)
    .bind(name)
    .bind(avatar)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETURN_TO: &str = "https://throttle.test/login/callback";
    const CLAIMED: &str = "https://steamcommunity.com/openid/id/76561197960265829";

    fn good() -> Vec<(String, String)> {
        [
            ("openid.ns", NS),
            ("openid.mode", "id_res"),
            ("openid.op_endpoint", ENDPOINT),
            ("openid.claimed_id", CLAIMED),
            ("openid.identity", CLAIMED),
            ("openid.return_to", RETURN_TO),
            ("openid.response_nonce", "2026-10-06T00:00:00Zabc"),
            ("openid.assoc_handle", "1234567890"),
            (
                "openid.signed",
                "signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle",
            ),
            ("openid.sig", "xx"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn with(key: &str, value: &str) -> Vec<(String, String)> {
        good()
            .into_iter()
            .map(|(k, v)| {
                if k == key {
                    (k, value.to_string())
                } else {
                    (k, v)
                }
            })
            .collect()
    }

    fn with_identity(claimed: &str) -> Vec<(String, String)> {
        good()
            .into_iter()
            .map(|(k, v)| {
                if k == "openid.claimed_id" || k == "openid.identity" {
                    (k, claimed.to_string())
                } else {
                    (k, v)
                }
            })
            .collect()
    }

    #[test]
    fn accepts_a_genuine_looking_response() {
        assert_eq!(check_params(&good(), RETURN_TO), Ok(76_561_197_960_265_829));
    }

    #[test]
    fn rejects_tampered_responses() {
        for (key, value) in [
            ("openid.mode", "cancel"),
            ("openid.ns", "http://specs.openid.net/auth/1.1"),
            ("openid.op_endpoint", "https://evil.example/openid/login"),
            ("openid.return_to", "https://evil.example/login/callback"),
            (
                "openid.claimed_id",
                "https://steamcommunity.com/openid/id/76561197960265830",
            ),
            ("openid.signed", "signed,return_to,response_nonce"),
        ] {
            assert!(
                check_params(&with(key, value), RETURN_TO).is_err(),
                "{key}={value}"
            );
        }
        // A claimed id that is not a Steam profile, even if identity matches.
        assert!(
            check_params(
                &with_identity("https://evil.example/openid/id/76561197960265829"),
                RETURN_TO
            )
            .is_err()
        );
        // Non-canonical ID spellings are not accepted.
        assert!(
            check_params(
                &with_identity(&format!("{ID_PREFIX}STEAM_0:1:2")),
                RETURN_TO
            )
            .is_err()
        );
        assert!(
            check_params(
                &with_identity(&format!("{ID_PREFIX}076561197960265829")),
                RETURN_TO
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_and_repeated_parameters() {
        let mut p = good();
        p.retain(|(k, _)| k != "openid.sig" && k != "openid.identity");
        assert!(check_params(&p, RETURN_TO).is_err());

        let mut p = good();
        p.push((
            "openid.claimed_id".into(),
            "https://steamcommunity.com/openid/id/76561197960265999".into(),
        ));
        assert!(check_params(&p, RETURN_TO).is_err());
        assert!(check_params(&[], RETURN_TO).is_err());
    }

    #[test]
    fn login_url_has_the_required_parameters() {
        let url = login_url("https://throttle.test", RETURN_TO);
        assert!(url.starts_with("https://steamcommunity.com/openid/login?"));
        assert!(url.contains("openid.mode=checkid_setup"));
        assert!(url.contains("openid.return_to=https%3A%2F%2Fthrottle.test%2Flogin%2Fcallback"));
        assert!(url.contains("openid.realm=https%3A%2F%2Fthrottle.test"));
    }

    #[test]
    fn profiles_are_sanitized() {
        let body = r#"{"response":{"players":[{"personaname":"  Al\u0000ice\n ","avatarfull":"http://cdn.akamai.steamstatic.com/a/b.jpg"}]}}"#;
        assert_eq!(
            parse_profile(body),
            Some(Profile {
                name: Some("Alice".into()),
                avatar: Some("https://cdn.akamai.steamstatic.com/a/b.jpg".into())
            })
        );
        assert_eq!(parse_profile(r#"{"response":{"players":[]}}"#), None);
        assert_eq!(parse_profile("not json"), None);

        let long = format!(
            r#"{{"response":{{"players":[{{"personaname":"{}"}}]}}}}"#,
            "x".repeat(200)
        );
        assert_eq!(
            parse_profile(&long).and_then(|p| p.name).map(|n| n.len()),
            Some(64)
        );
    }

    #[test]
    fn only_steam_cdn_avatars_are_kept() {
        assert!(valid_avatar("https://avatars.steamstatic.com/abc_full.jpg"));
        for bad in [
            "http://avatars.steamstatic.com/a.jpg",
            "https://evil.example/a.jpg",
            "https://evil.example#.steamstatic.com/a.jpg",
            "https://steamstatic.com@evil.example/a.jpg",
            "https://evil.example\\.steamstatic.com/a.jpg",
            "https://avatars.steamstatic.com/a\".jpg",
            "javascript:alert(1)",
        ] {
            assert!(!valid_avatar(bad), "{bad}");
        }
    }

    const ID: i64 = 76561197960287930;
    const REAL_AVATAR: &str = "https://avatars.akamai.steamstatic.com/c5d5_full.jpg";

    fn doc(id: &str, name: &str, avatar: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n<profile>\n\t<steamID64>{id}</steamID64>\n\t<steamID><![CDATA[{name}]]></steamID>\n\t<onlineState>offline</onlineState>\n\t<stateMessage><![CDATA[Offline]]></stateMessage>\n\t<avatarIcon><![CDATA[{avatar}]]></avatarIcon>\n\t<avatarFull><![CDATA[{avatar}]]></avatarFull>\n\t<groups>\n\t\t<group isPrimary=\"1\"><groupID64>1</groupID64></group>\n\t</groups>\n</profile>"
        )
    }

    #[test]
    fn the_public_profile_page_gives_a_name_and_an_avatar() {
        assert_eq!(
            parse_profile_xml(&doc(&ID.to_string(), "Rabscuttle", REAL_AVATAR), ID),
            Some(Profile {
                name: Some("Rabscuttle".into()),
                avatar: Some(REAL_AVATAR.into())
            })
        );
    }

    #[test]
    fn a_profile_page_about_somebody_else_is_ignored() {
        assert_eq!(
            parse_profile_xml(&doc("76561197960265829", "Other", REAL_AVATAR), ID),
            None
        );
    }

    #[test]
    fn pages_that_are_not_profiles_give_nothing() {
        let missing = "<?xml version=\"1.0\" ?><response><error><![CDATA[The specified profile could not be found.]]></error></response>";
        for body in [
            missing,
            "",
            "<html>Steam Community :: Error</html>",
            "<profile>",
        ] {
            assert_eq!(parse_profile_xml(body, ID), None, "{body}");
        }
    }

    #[test]
    fn an_avatar_from_another_host_is_dropped_but_the_name_stays() {
        let body = doc(&ID.to_string(), "Alice", "https://evil.example/a.jpg");
        assert_eq!(
            parse_profile_xml(&body, ID),
            Some(Profile {
                name: Some("Alice".into()),
                avatar: None
            })
        );
    }

    #[test]
    fn a_persona_name_cannot_smuggle_in_an_avatar() {
        // The name is `x]]></steamID><avatarFull><![CDATA[https://evil.example/a.jpg]]></avatarFull>...`,
        // with every `]]>` split the way Steam does it.
        let body = format!(
            "<profile><steamID64>{ID}</steamID64>\
             <steamID><![CDATA[x]]]]><![CDATA[></steamID><avatarFull><![CDATA[https://evil.example/a.jpg]]]]><![CDATA[></avatarFull><steamID><![CDATA[y]]></steamID>\
             <avatarFull><![CDATA[{REAL_AVATAR}]]></avatarFull></profile>"
        );
        let profile = parse_profile_xml(&body, ID).unwrap();
        assert_eq!(profile.avatar.as_deref(), Some(REAL_AVATAR));
        assert!(profile.name.unwrap().starts_with("x]]></steamID>"));
    }

    #[test]
    fn control_characters_and_length_are_cleaned_in_xml_names_too() {
        let body = doc(
            &ID.to_string(),
            &format!(" Al\u{0}ice{} ", "z".repeat(100)),
            REAL_AVATAR,
        );
        let name = parse_profile_xml(&body, ID).unwrap().name.unwrap();
        assert!(name.starts_with("Alicez") && name.chars().count() == 64);
    }

    async fn row(db: &SqlitePool, id: i64) -> (Option<String>, Option<i64>, Option<i64>) {
        sqlx::query_as("SELECT avatar, updated_at, last_active FROM user WHERE id = ?")
            .bind(id)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_login_without_a_profile_leaves_the_user_due_for_a_lookup() {
        let db = crate::db::open_memory().await.unwrap();
        upsert_user(&db, 5, None, 1000).await.unwrap();
        assert_eq!(row(&db, 5).await, (None, None, Some(1000)));

        let profile = Profile {
            name: Some("Five".into()),
            avatar: Some(REAL_AVATAR.into()),
        };
        upsert_user(&db, 5, Some(&profile), 2000).await.unwrap();
        assert_eq!(
            row(&db, 5).await,
            (Some(REAL_AVATAR.into()), Some(2000), Some(2000))
        );

        // A later login that fails to look the profile up keeps what we have.
        upsert_user(&db, 5, None, 3000).await.unwrap();
        assert_eq!(
            row(&db, 5).await,
            (Some(REAL_AVATAR.into()), Some(2000), Some(3000))
        );
    }

    #[tokio::test]
    async fn a_background_lookup_does_not_count_as_a_login() {
        let db = crate::db::open_memory().await.unwrap();
        store_lookup(&db, 6, None, 1000).await.unwrap();
        assert_eq!(row(&db, 6).await, (None, Some(1000), None));
    }
}
