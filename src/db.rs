//! SQLite access: one pool, WAL mode, migrations applied at startup.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

pub async fn open(path: &Path) -> anyhow::Result<SqlitePool> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let url = format!("sqlite://{}", path.display());
    connect(SqliteConnectOptions::from_str(&url)?.create_if_missing(true)).await
}

/// In-memory database for tests. A single connection, otherwise every
/// connection would get its own empty database.
#[cfg(test)]
pub async fn open_memory() -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts.foreign_keys(true))
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

async fn connect(opts: SqliteConnectOptions) -> anyhow::Result<SqlitePool> {
    let opts = opts
        .journal_mode(SqliteJournalMode::Wal)
        // NORMAL is crash-safe in WAL mode (a power cut can lose the last
        // commits, never corrupt the file) and much faster than FULL.
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(10));

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .context("opening database")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running migrations")?;

    Ok(pool)
}

/// A consistent copy of the database (`VACUUM INTO`), safe while the server
/// runs. Refuses to overwrite an existing file.
pub async fn backup(pool: &SqlitePool, dest: &Path) -> anyhow::Result<()> {
    if dest.exists() {
        anyhow::bail!("{} already exists", dest.display());
    }
    let dest = dest.to_str().context("destination must be valid UTF-8")?;
    sqlx::query("VACUUM INTO ?")
        .bind(dest)
        .execute(pool)
        .await
        .context("writing the backup")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrations_apply_and_enforce_foreign_keys() {
        let pool = open_memory().await.unwrap();

        sqlx::query(
            "INSERT INTO crash (id, created_at, ip) VALUES ('abcdefghijkl', 1, x'7f000001')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO frame (crash, thread, frame, rendered) VALUES ('abcdefghijkl', 0, 0, 'x')",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Orphan rows are refused.
        let orphan = sqlx::query(
            "INSERT INTO frame (crash, thread, frame, rendered) VALUES ('zzzzzzzzzzzz', 0, 0, 'x')",
        )
        .execute(&pool)
        .await;
        assert!(orphan.is_err());

        // Deleting a crash cascades to its frames.
        sqlx::query("DELETE FROM crash WHERE id = 'abcdefghijkl'")
            .execute(&pool)
            .await
            .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM frame")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn bad_ids_and_status_are_rejected() {
        let pool = open_memory().await.unwrap();
        let short =
            sqlx::query("INSERT INTO crash (id, created_at, ip) VALUES ('short', 1, x'7f000001')")
                .execute(&pool)
                .await;
        assert!(short.is_err());
        let status = sqlx::query("INSERT INTO crash (id, created_at, ip, status) VALUES ('abcdefghijkl', 1, x'7f000001', 9)")
            .execute(&pool)
            .await;
        assert!(status.is_err());
    }
}

#[cfg(test)]
mod backup_tests {
    use super::*;

    #[tokio::test]
    async fn backup_is_a_usable_copy_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("a.sqlite")).await.unwrap();
        sqlx::query(
            "INSERT INTO crash (id, created_at, ip) VALUES ('abcdefghijkl', 1, x'7f000001')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let dest = dir.path().join("b.sqlite");
        backup(&pool, &dest).await.unwrap();

        let copy = open(&dest).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crash")
            .fetch_one(&copy)
            .await
            .unwrap();
        assert_eq!(n, 1);
        assert!(backup(&pool, &dest).await.is_err());
    }
}
