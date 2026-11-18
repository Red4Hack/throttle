//! Hourly counters in SQLite. Replaces Redis HINCRBY + munin/rrdtool.

use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;

/// Current unix time in seconds.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Add `by` to the counter `name` for the current hour. Never fails the
/// request: a stats write error is logged and dropped.
pub async fn bump(db: &SqlitePool, name: &str, by: i64) {
    let bucket = now() / 3600 * 3600;
    let result = sqlx::query(
        "INSERT INTO counter (bucket, name, value) VALUES (?, ?, ?) \
         ON CONFLICT (bucket, name) DO UPDATE SET value = value + excluded.value",
    )
    .bind(bucket)
    .bind(name)
    .bind(by)
    .execute(db)
    .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, counter = name, "could not update counter");
    }
}

/// Keep the largest (`max`) or smallest value seen in the current hour under `name`.
pub async fn bump_extreme(db: &SqlitePool, name: &str, value: i64, max: bool) {
    let bucket = now() / 3600 * 3600;
    let sql = if max {
        "INSERT INTO counter (bucket, name, value) VALUES (?, ?, ?) \
         ON CONFLICT (bucket, name) DO UPDATE SET value = MAX(value, excluded.value)"
    } else {
        "INSERT INTO counter (bucket, name, value) VALUES (?, ?, ?) \
         ON CONFLICT (bucket, name) DO UPDATE SET value = MIN(value, excluded.value)"
    };
    if let Err(e) = sqlx::query(sql).bind(bucket).bind(name).bind(value).execute(db).await {
        tracing::warn!(error = %e, counter = name, "could not update counter");
    }
}
