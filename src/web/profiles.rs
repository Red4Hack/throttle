//! Keeps the names and avatars of Steam users up to date.
//!
//! The login looks up whoever logs in, but people also show up as the owner of
//! crashes or as a sharing partner without ever logging in, and profiles change.
//! A background pass looks a few of them up at a time: through the Web API when
//! there is a key, on the public profile page otherwise (`steam::lookup_profile`).
//!
//! `user.updated_at` is when a profile was last asked for, whatever the answer
//! was, so an id Steam does not know is not asked for again right away. A user
//! that was never asked for has none, and goes first.

use std::time::Duration;

use sqlx::SqlitePool;

use super::steam::{self, Lookup};
use crate::app::AppState;
use crate::stats;

const DAY: i64 = 86_400;
/// Lookups per pass; with one pass a minute that is a polite trickle for Steam.
const BATCH: i64 = 20;
const PASS_EVERY: Duration = Duration::from_secs(60);
const PACE: Duration = Duration::from_millis(500);
const FIRST_PASS_AFTER: Duration = Duration::from_secs(5);
/// A known profile is looked up again after this long (names and avatars change).
const REFRESH_AFTER: i64 = 7 * DAY;
/// A user without an avatar (unknown to Steam, or a failed lookup) is retried after this long.
const RETRY_AFTER: i64 = DAY;
/// Steam is not answering: stop the pass instead of timing out 20 times.
const MAX_UNREACHABLE_IN_A_ROW: u32 = 3;
/// Crashes uploaded while a pass runs must not slip between two discoveries.
const DISCOVERY_OVERLAP: i64 = 60;

/// Logged-in users first, then those never asked for, then the stalest.
const DUE: &str = "SELECT id FROM user \
    WHERE updated_at IS NULL OR updated_at < ? OR (avatar IS NULL AND updated_at < ?) \
    ORDER BY last_active IS NULL, updated_at IS NOT NULL, updated_at \
    LIMIT ?";

#[derive(Debug, Default, PartialEq, Eq)]
struct Pass {
    found: u32,
    missing: u32,
    unreachable: u32,
}

/// Crash owners get a user row, so they are looked up like everybody else.
async fn discover(db: &SqlitePool, since: i64) -> sqlx::Result<u64> {
    let done = sqlx::query(
        "INSERT OR IGNORE INTO user (id) \
         SELECT DISTINCT owner FROM crash WHERE owner IS NOT NULL AND created_at >= ?",
    )
    .bind(since)
    .execute(db)
    .await?;
    Ok(done.rows_affected())
}

async fn run_pass<F, Fut>(
    db: &SqlitePool,
    now: i64,
    pace: Duration,
    mut lookup: F,
) -> sqlx::Result<Pass>
where
    F: FnMut(i64) -> Fut,
    Fut: Future<Output = Lookup>,
{
    let due: Vec<i64> = sqlx::query_scalar(DUE)
        .bind(now - REFRESH_AFTER)
        .bind(now - RETRY_AFTER)
        .bind(BATCH)
        .fetch_all(db)
        .await?;

    let mut pass = Pass::default();
    let mut unreachable_in_a_row = 0;
    for (n, id) in due.into_iter().enumerate() {
        if n > 0 {
            tokio::time::sleep(pace).await;
        }
        match lookup(id).await {
            Lookup::Found(profile) => {
                steam::store_lookup(db, id, Some(&profile), now).await?;
                pass.found += 1;
                unreachable_in_a_row = 0;
            }
            Lookup::Missing => {
                steam::store_lookup(db, id, None, now).await?;
                pass.missing += 1;
                unreachable_in_a_row = 0;
            }
            // Nothing is recorded: the same users are due again on the next pass.
            Lookup::Unreachable => {
                pass.unreachable += 1;
                unreachable_in_a_row += 1;
                if unreachable_in_a_row >= MAX_UNREACHABLE_IN_A_ROW {
                    break;
                }
            }
        }
    }
    Ok(pass)
}

async fn refresh(state: &AppState, since: i64, now: i64) -> sqlx::Result<Pass> {
    discover(&state.db, since).await?;
    let key = state.config.steam_api_key.as_deref();
    run_pass(&state.db, now, PACE, |id| {
        steam::lookup_profile(&state.http, key, id)
    })
    .await
}

pub fn spawn(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_PASS_AFTER).await;
        let mut since = 0;
        loop {
            let now = stats::now();
            match refresh(&state, since, now).await {
                Ok(pass) if pass == Pass::default() => {}
                Ok(pass) => tracing::debug!(
                    found = pass.found,
                    missing = pass.missing,
                    unreachable = pass.unreachable,
                    "steam profile pass"
                ),
                Err(e) => tracing::error!(error = %e, "steam profile pass failed"),
            }
            since = now - DISCOVERY_OVERLAP;
            tokio::time::sleep(PASS_EVERY).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::web::steam::Profile;

    const NOW: i64 = 1_800_000_000;

    async fn user(
        db: &SqlitePool,
        id: i64,
        name: Option<&str>,
        avatar: Option<&str>,
        updated_at: Option<i64>,
        last_active: Option<i64>,
    ) {
        sqlx::query(
            "INSERT INTO user (id, name, avatar, updated_at, last_active) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(avatar)
        .bind(updated_at)
        .bind(last_active)
        .execute(db)
        .await
        .unwrap();
    }

    async fn row(db: &SqlitePool, id: i64) -> (Option<String>, Option<String>, Option<i64>) {
        sqlx::query_as("SELECT name, avatar, updated_at FROM user WHERE id = ?")
            .bind(id)
            .fetch_one(db)
            .await
            .unwrap()
    }

    const AVATAR: &str = "https://avatars.steamstatic.com/old_full.jpg";

    #[tokio::test]
    async fn logged_in_first_then_never_asked_then_the_stalest() {
        let db = db::open_memory().await.unwrap();
        let (fresh, week, hours, days2) = (NOW - 10, NOW - 8 * DAY, NOW - 7200, NOW - 2 * DAY);
        user(&db, 1, Some("Fresh"), Some(AVATAR), Some(fresh), None).await;
        user(&db, 2, None, None, None, None).await;
        user(&db, 3, Some("Old"), Some(AVATAR), Some(week), None).await;
        user(
            &db,
            4,
            Some("Active"),
            Some(AVATAR),
            Some(NOW - 9 * DAY),
            Some(NOW),
        )
        .await;
        user(&db, 5, None, None, Some(hours), None).await;
        user(&db, 6, None, None, Some(days2), None).await;
        user(
            &db,
            7,
            Some("Recent"),
            Some(AVATAR),
            Some(NOW - 3 * DAY),
            None,
        )
        .await;

        let mut asked = Vec::new();
        run_pass(&db, NOW, Duration::ZERO, |id| {
            asked.push(id);
            async { Lookup::Missing }
        })
        .await
        .unwrap();

        // 1 and 7 are fresh, 5 was asked a moment ago and has no avatar yet.
        assert_eq!(asked, [4, 2, 3, 6]);
    }

    #[tokio::test]
    async fn answers_are_stored_and_misses_are_stamped() {
        let db = db::open_memory().await.unwrap();
        user(
            &db,
            10,
            Some("Old"),
            Some(AVATAR),
            Some(NOW - 8 * DAY),
            None,
        )
        .await;
        user(&db, 11, None, None, None, None).await;

        let pass = run_pass(&db, NOW, Duration::ZERO, |id| {
            let out = if id == 10 {
                Lookup::Found(Profile {
                    name: Some("New".into()),
                    avatar: None,
                })
            } else {
                Lookup::Missing
            };
            async { out }
        })
        .await
        .unwrap();

        assert_eq!(
            pass,
            Pass {
                found: 1,
                missing: 1,
                unreachable: 0
            }
        );
        // A name arrives, the avatar we already had is not lost.
        assert_eq!(
            row(&db, 10).await,
            (Some("New".into()), Some(AVATAR.into()), Some(NOW))
        );
        // Nothing to store, but now it is known that Steam has nothing.
        assert_eq!(row(&db, 11).await, (None, None, Some(NOW)));
    }

    #[tokio::test]
    async fn a_silent_steam_ends_the_pass_and_records_nothing() {
        let db = db::open_memory().await.unwrap();
        for id in 1..=6 {
            user(&db, id, None, None, None, None).await;
        }
        let mut asked = 0;
        let pass = run_pass(&db, NOW, Duration::ZERO, |_| {
            asked += 1;
            async { Lookup::Unreachable }
        })
        .await
        .unwrap();

        assert_eq!(asked, 3);
        assert_eq!(pass.unreachable, 3);
        let stamped: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user WHERE updated_at IS NOT NULL")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(stamped, 0);
    }

    #[tokio::test]
    async fn a_batch_is_capped() {
        let db = db::open_memory().await.unwrap();
        for id in 1..=50 {
            user(&db, id, None, None, None, None).await;
        }
        let mut asked = 0;
        run_pass(&db, NOW, Duration::ZERO, |_| {
            asked += 1;
            async { Lookup::Missing }
        })
        .await
        .unwrap();
        assert_eq!(asked, BATCH);
    }

    #[tokio::test]
    async fn owners_of_recent_crashes_become_users() {
        let db = db::open_memory().await.unwrap();
        user(&db, 1, Some("Known"), None, None, None).await;
        for (id, created, owner) in [
            ("aaaaaaaaaaaa", 100, Some(1)),
            ("bbbbbbbbbbbb", 100, Some(2)),
            ("cccccccccccc", 500, Some(3)),
            ("dddddddddddd", 500, None),
        ] {
            sqlx::query(
                "INSERT INTO crash (id, created_at, ip, owner, status) VALUES (?, ?, x'01020304', ?, 2)",
            )
            .bind(id)
            .bind(created)
            .bind(owner)
            .execute(&db)
            .await
            .unwrap();
        }

        assert_eq!(discover(&db, 200).await.unwrap(), 1);
        assert_eq!(discover(&db, 0).await.unwrap(), 1);
        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM user ORDER BY id")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(ids, [1, 2, 3]);
        // A user that already exists is left alone.
        assert_eq!(row(&db, 1).await.0.as_deref(), Some("Known"));
    }
}
