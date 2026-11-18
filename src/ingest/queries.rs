//! The few queries the ingestion path needs.

use sqlx::SqlitePool;

/// Crashes by this owner (`None` = anonymous) from this IP since `since`.
pub async fn count_recent(
    db: &SqlitePool,
    owner: Option<i64>,
    ip: &[u8],
    since: i64,
) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM crash WHERE owner IS ? AND ip = ? AND created_at >= ?")
        .bind(owner)
        .bind(ip)
        .bind(since)
        .fetch_one(db)
        .await
}

/// Are at least `limit` crashes waiting to be processed? Bounded scan, so it
/// stays cheap however large the queue gets.
pub async fn pending_at_least(db: &SqlitePool, limit: u32) -> sqlx::Result<bool> {
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT 1 FROM crash WHERE status = 0 LIMIT ?)")
            .bind(i64::from(limit))
            .fetch_one(db)
            .await?;
    Ok(n >= i64::from(limit))
}

pub async fn count_signature(db: &SqlitePool, signature: &str, since: i64) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM crash WHERE signature = ? AND created_at >= ?")
        .bind(signature)
        .bind(since)
        .fetch_one(db)
        .await
}

pub async fn has_symbol(db: &SqlitePool, name: &str, identifier: &str) -> sqlx::Result<bool> {
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM symbol WHERE name = ? AND identifier = ? LIMIT 1")
            .bind(name)
            .bind(identifier)
            .fetch_optional(db)
            .await?;
    Ok(found.is_some())
}

/// Did a crash from this owner+IP get a `nosteam-*` notice since `since`?
/// (Notices only exist once a crash is processed, as before.)
pub async fn has_recent_nosteam(
    db: &SqlitePool,
    owner: Option<i64>,
    ip: &[u8],
    since: i64,
) -> sqlx::Result<bool> {
    let prefix = crate::notice::NOSTEAM_PREFIX;
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM crash c JOIN crashnotice n ON n.crash = c.id \
         WHERE c.owner IS ? AND c.ip = ? AND c.created_at >= ? AND substr(n.notice, 1, ?) = ? LIMIT 1",
    )
    .bind(owner)
    .bind(ip)
    .bind(since)
    .bind(prefix.len() as i64)
    .bind(prefix)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

/// The crash a new one repeats: same fingerprint, and the same owner (anonymous crashes:
/// the same address), most recently active no earlier than `since`. A crash with a dump
/// is preferred, so the page people land on has a stack.
pub async fn find_repeat(
    db: &SqlitePool,
    signature: &str,
    owner: Option<i64>,
    ip: &[u8],
    since: i64,
) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar(
        "SELECT id FROM crash \
         WHERE signature = ? AND owner IS ? AND (? IS NOT NULL OR ip = ?) \
           AND COALESCE(last_repeat_at, created_at) >= ? \
         ORDER BY has_dump DESC, created_at DESC LIMIT 1",
    )
    .bind(signature)
    .bind(owner)
    .bind(owner)
    .bind(ip)
    .bind(since)
    .fetch_optional(db)
    .await
}

/// One more time for `id`. `false` when it was deleted meanwhile.
pub async fn bump_repeat(db: &SqlitePool, id: &str, now: i64) -> sqlx::Result<bool> {
    let done =
        sqlx::query("UPDATE crash SET repeats = repeats + 1, last_repeat_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(db)
            .await?;
    Ok(done.rows_affected() > 0)
}
