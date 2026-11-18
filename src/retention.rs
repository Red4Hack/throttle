//! Retention: keeps disk and database bounded, in small batches.
//!
//! The PHP version deleted at most 100 rows per run and loaded every crash ID
//! into memory. Once uploads outpaced that, the disk filled up and the public
//! server switched submissions off ("capacity reached"). Here:
//!
//! * every rule deletes in batches of `retention.batch_size`, repeatedly, until
//!   nothing is left (bounded by [`MAX_BATCHES`] per rule and run);
//! * the disk quota is enforced by *evicting* (unviewed and oldest first)
//!   instead of refusing uploads;
//! * uploads are only refused (HTTP 503) when the disk is nearly full anyway.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use sqlx::SqlitePool;

use crate::app::AppState;
use crate::config::Config;
use crate::{ids, stats};

const DAY: i64 = 86_400;
/// One run deletes at most `MAX_BATCHES * batch_size` crashes per rule.
const MAX_BATCHES: usize = 200;
/// Files without a database row are only removed once they are this old, so
/// an upload in flight is never touched.
const ORPHAN_GRACE: Duration = Duration::from_secs(24 * 3600);
const TMP_GRACE: Duration = Duration::from_secs(3600);
/// The orphan scan walks every file, so it runs every N-th pass only.
const ORPHAN_SCAN_EVERY: u32 = 12;
const COUNTER_KEEP_DAYS: i64 = 400;

const UNVIEWED_EXPIRED: &str = "SELECT id FROM crash \
    WHERE last_view IS NULL AND created_at < ? AND COALESCE(last_repeat_at, 0) < ? \
      AND status != 1 ORDER BY created_at LIMIT ?";
const VIEWED_EXPIRED: &str = "SELECT id FROM crash \
    WHERE last_view < ? AND COALESCE(last_repeat_at, 0) < ? \
      AND status != 1 ORDER BY last_view LIMIT ?";
/// Unviewed crashes beyond the newest N of their (owner, IP) group.
const OVER_CAP: &str = "SELECT id FROM (\
      SELECT id, owner, ROW_NUMBER() OVER (PARTITION BY owner, ip ORDER BY created_at DESC, id DESC) AS rn \
      FROM crash WHERE last_view IS NULL AND status != 1) \
    WHERE rn > CASE WHEN owner IS NULL THEN ? ELSE ? END LIMIT ?";
const EVICTION_ORDER: &str = "SELECT id, dump_bytes FROM crash WHERE has_dump = 1 AND status != 1 \
    ORDER BY last_view IS NOT NULL, COALESCE(last_view, created_at), id LIMIT ?";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub expired: u64,
    pub over_cap: u64,
    pub evicted: u64,
    pub orphans: u64,
}

/// Bytes available to unprivileged writers on the file system holding `path`.
pub fn free_bytes(path: &Path) -> Option<u64> {
    let stat = rustix::fs::statvfs(path).ok()?;
    Some(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// Is the disk too full to accept another upload?
pub fn low_disk(config: &Config) -> bool {
    free_bytes(&config.data_dir).is_some_and(|free| free < config.limits.disk_min_free_bytes)
}

/// Remove a crash's files; a file that is already gone is fine.
pub async fn remove_files(config: &Config, id: &str) {
    for path in [config.dump_path(id), config.meta_path(id)] {
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "could not remove a deleted crash's file")
            }
        }
    }
}

/// Delete these crashes (frames, modules, notices cascade) in one short
/// transaction, then their files. Crashes being processed are skipped.
/// Returns the IDs that were actually deleted.
async fn delete_batch(
    db: &SqlitePool,
    config: &Config,
    batch: &[String],
) -> sqlx::Result<Vec<String>> {
    let mut tx = db.begin().await?;
    let mut gone = Vec::with_capacity(batch.len());
    for id in batch {
        let n = sqlx::query("DELETE FROM crash WHERE id = ? AND status != 1")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n > 0 {
            gone.push(id.clone());
        }
    }
    tx.commit().await?;
    for id in &gone {
        remove_files(config, id).await;
    }
    Ok(gone)
}

/// Run `select` (binding `args`, then the batch size) and delete what it
/// returns, batch after batch.
async fn delete_selected(
    db: &SqlitePool,
    config: &Config,
    select: &'static str,
    args: &[i64],
) -> sqlx::Result<u64> {
    let size = i64::from(config.retention.batch_size);
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let mut query = sqlx::query_scalar::<_, String>(select);
        for arg in args {
            query = query.bind(*arg);
        }
        let batch = query.bind(size).fetch_all(db).await?;
        if batch.is_empty() {
            break;
        }
        let removed = delete_batch(db, config, &batch).await?.len();
        total += removed as u64;
        if removed == 0 || (batch.len() as i64) < size {
            break;
        }
    }
    Ok(total)
}

/// Keep the dumps under `limits.disk_quota_bytes`: evict unviewed crashes
/// first (oldest first), viewed ones only when that is not enough.
async fn enforce_quota(db: &SqlitePool, config: &Config) -> sqlx::Result<u64> {
    let quota = i64::try_from(config.limits.disk_quota_bytes).unwrap_or(i64::MAX);
    let size = i64::from(config.retention.batch_size);
    let mut used: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(dump_bytes), 0) FROM crash WHERE has_dump = 1")
            .fetch_one(db)
            .await?;
    let mut evicted = 0;

    for _ in 0..MAX_BATCHES {
        let over = used - quota;
        if over <= 0 {
            break;
        }
        let rows: Vec<(String, i64)> = sqlx::query_as(EVICTION_ORDER)
            .bind(size)
            .fetch_all(db)
            .await?;

        let (mut plan, mut planned) = (Vec::new(), 0);
        for (id, bytes) in &rows {
            plan.push(id.clone());
            planned += bytes;
            if planned >= over {
                break;
            }
        }
        if plan.is_empty() {
            break;
        }
        let gone = delete_batch(db, config, &plan).await?;
        if gone.is_empty() {
            break;
        }
        let sizes: HashMap<&str, i64> = rows
            .iter()
            .map(|(id, bytes)| (id.as_str(), *bytes))
            .collect();
        used -= gone
            .iter()
            .filter_map(|id| sizes.get(id.as_str()))
            .sum::<i64>();
        evicted += gone.len() as u64;
    }
    Ok(evicted)
}

async fn old_enough(entry: &tokio::fs::DirEntry, grace: Duration) -> bool {
    entry
        .metadata()
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age > grace)
}

async fn crash_exists(db: &SqlitePool, id: &str) -> sqlx::Result<bool> {
    let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM crash WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(found.is_some())
}

/// Remove dump/metadata files whose crash is gone, and abandoned temp files.
/// Anything that doesn't look like ours is left alone.
pub async fn sweep_files(db: &SqlitePool, config: &Config) -> std::io::Result<u64> {
    let mut removed = 0;
    let mut buckets = match tokio::fs::read_dir(config.dumps_dir()).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    while let Some(bucket) = buckets.next_entry().await? {
        if !bucket.file_type().await?.is_dir() {
            continue;
        }
        let is_tmp = bucket.file_name() == ".tmp";
        let grace = if is_tmp { TMP_GRACE } else { ORPHAN_GRACE };

        let mut files = tokio::fs::read_dir(bucket.path()).await?;
        while let Some(file) = files.next_entry().await? {
            if !file.file_type().await?.is_file() || !old_enough(&file, grace).await {
                continue;
            }
            let name = file.file_name().to_string_lossy().into_owned();
            let orphan = is_tmp || {
                let id = name.split('.').next().unwrap_or("");
                // On a database error assume the crash exists.
                ids::normalize(id).as_deref() == Some(id)
                    && !crash_exists(db, id).await.unwrap_or(true)
            };
            if orphan && tokio::fs::remove_file(file.path()).await.is_ok() {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// One full pass. `sweep` also walks the dumps directory for orphans.
pub async fn run_once(db: &SqlitePool, config: &Config, sweep: bool) -> sqlx::Result<Report> {
    let now = stats::now();
    let r = &config.retention;
    let cutoff = now - i64::from(r.max_age_days) * DAY;

    let expired = delete_selected(db, config, UNVIEWED_EXPIRED, &[cutoff, cutoff]).await?
        + delete_selected(db, config, VIEWED_EXPIRED, &[cutoff, cutoff]).await?;
    let over_cap = delete_selected(
        db,
        config,
        OVER_CAP,
        &[
            i64::from(r.keep_per_anonymous_ip),
            i64::from(r.keep_per_owner),
        ],
    )
    .await?;
    let evicted = enforce_quota(db, config).await?;

    let orphans = if sweep {
        sweep_files(db, config).await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "orphan file scan failed");
            0
        })
    } else {
        0
    };

    sqlx::query("DELETE FROM counter WHERE bucket < ?")
        .bind(now - COUNTER_KEEP_DAYS * DAY)
        .execute(db)
        .await?;

    // Keep a miss at least as long as the fetcher would wait before asking again.
    let miss_keep = i64::from(config.symbol_fetch.retry_days.max(90));
    sqlx::query("DELETE FROM symbol_miss WHERE tried_at < ?")
        .bind(now - miss_keep * DAY)
        .execute(db)
        .await?;

    for (name, n) in [
        ("cleaned:age", expired),
        ("cleaned:user-limit", over_cap),
        ("cleaned:quota", evicted),
        ("cleaned:orphans", orphans),
    ] {
        if n > 0 {
            stats::bump(db, name, n as i64).await;
        }
    }

    Ok(Report {
        expired,
        over_cap,
        evicted,
        orphans,
    })
}

pub fn spawn(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        let every = Duration::from_secs(state.config.retention.interval_secs);
        let mut pass = 0u32;
        loop {
            match run_once(
                &state.db,
                &state.config,
                pass.is_multiple_of(ORPHAN_SCAN_EVERY),
            )
            .await
            {
                Ok(r) if r == Report::default() => {}
                Ok(r) => tracing::info!(
                    expired = r.expired,
                    over_cap = r.over_cap,
                    evicted = r.evicted,
                    orphans = r.orphans,
                    "retention pass"
                ),
                Err(e) => tracing::error!(error = %e, "retention pass failed"),
            }
            pass = pass.wrapping_add(1);
            tokio::time::sleep(every).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use tempfile::TempDir;

    struct Env {
        db: SqlitePool,
        config: Config,
        _dir: TempDir,
    }

    struct Spec {
        id: String,
        age_days: i64,
        viewed_days_ago: Option<i64>,
        owner: Option<i64>,
        ip: u8,
        status: i64,
        bytes: i64,
    }

    fn spec(id: impl Into<String>) -> Spec {
        Spec {
            id: id.into(),
            age_days: 0,
            viewed_days_ago: None,
            owner: None,
            ip: 1,
            status: 2,
            bytes: 10,
        }
    }

    /// `id(0)` = "aaaaaaaaaaaa", `id(1)` = "bbbbbbbbbbbb", ...
    fn id(n: u8) -> String {
        char::from(b'a' + n).to_string().repeat(12)
    }

    async fn env(tweak: impl FnOnce(&mut Config)) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        tweak(&mut config);
        Env {
            db: db::open_memory().await.unwrap(),
            config,
            _dir: dir,
        }
    }

    fn age(path: &Path, secs: u64) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(secs))
            .unwrap();
    }

    impl Env {
        async fn add(&self, s: Spec) {
            let now = stats::now();
            sqlx::query(
                "INSERT INTO crash (id, created_at, ip, owner, status, has_dump, dump_bytes, last_view) \
                 VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            )
            .bind(&s.id)
            .bind(now - s.age_days * DAY)
            .bind(vec![10, 0, 0, s.ip])
            .bind(s.owner)
            .bind(s.status)
            .bind(s.bytes)
            .bind(s.viewed_days_ago.map(|d| now - d * DAY))
            .execute(&self.db)
            .await
            .unwrap();
            for path in [self.config.dump_path(&s.id), self.config.meta_path(&s.id)] {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, b"x").unwrap();
            }
        }

        async fn row(&self, id: &str) -> bool {
            crash_exists(&self.db, id).await.unwrap()
        }

        fn files(&self, id: &str) -> bool {
            self.config.dump_path(id).exists() || self.config.meta_path(id).exists()
        }

        /// Row and files go together.
        async fn assert_kept(&self, id: &str) {
            assert!(
                self.row(id).await && self.files(id),
                "{id} should have been kept"
            );
        }

        async fn assert_gone(&self, id: &str) {
            assert!(
                !self.row(id).await && !self.files(id),
                "{id} should have been deleted"
            );
        }
    }

    #[tokio::test]
    async fn old_crashes_expire_unless_viewed_recently() {
        let env = env(|_| {}).await;
        let (a, b, c, d, e) = (id(0), id(1), id(2), id(3), id(4));
        env.add(Spec {
            age_days: 100,
            ..spec(&a)
        })
        .await;
        env.add(Spec {
            age_days: 100,
            viewed_days_ago: Some(1),
            ..spec(&b)
        })
        .await;
        env.add(Spec {
            age_days: 100,
            viewed_days_ago: Some(100),
            ..spec(&c)
        })
        .await;
        env.add(Spec {
            age_days: 1,
            ..spec(&d)
        })
        .await;
        env.add(Spec {
            age_days: 100,
            status: 1,
            ..spec(&e)
        })
        .await;

        let report = run_once(&env.db, &env.config, false).await.unwrap();
        assert_eq!(
            report,
            Report {
                expired: 2,
                ..Report::default()
            }
        );
        env.assert_gone(&a).await;
        env.assert_kept(&b).await;
        env.assert_gone(&c).await;
        env.assert_kept(&d).await;
        env.assert_kept(&e).await; // being processed
    }

    #[tokio::test]
    async fn a_crash_that_keeps_repeating_does_not_expire() {
        let env = env(|_| {}).await;
        let (a, b, c) = (id(0), id(1), id(2));
        env.add(Spec {
            age_days: 100,
            ..spec(&a)
        })
        .await;
        env.add(Spec {
            age_days: 100,
            ..spec(&b)
        })
        .await;
        env.add(Spec {
            age_days: 100,
            viewed_days_ago: Some(100),
            ..spec(&c)
        })
        .await;
        // `a` and `c` came again yesterday; `b` did not.
        for which in [&a, &c] {
            sqlx::query("UPDATE crash SET repeats = 3, last_repeat_at = ? WHERE id = ?")
                .bind(stats::now() - DAY)
                .bind(which)
                .execute(&env.db)
                .await
                .unwrap();
        }

        let report = run_once(&env.db, &env.config, false).await.unwrap();
        assert_eq!(report.expired, 1);
        env.assert_kept(&a).await;
        env.assert_gone(&b).await;
        env.assert_kept(&c).await;
    }

    #[tokio::test]
    async fn deletion_continues_across_batches() {
        let env = env(|c| c.retention.batch_size = 2).await;
        for n in 0..7 {
            env.add(Spec {
                age_days: 100,
                ..spec(id(n))
            })
            .await;
        }
        assert_eq!(
            run_once(&env.db, &env.config, false).await.unwrap().expired,
            7
        );
        for n in 0..7 {
            env.assert_gone(&id(n)).await;
        }
    }

    #[tokio::test]
    async fn unviewed_crashes_are_capped_per_owner_and_ip() {
        let env = env(|c| {
            c.retention.keep_per_owner = 2;
            c.retention.keep_per_anonymous_ip = 1;
        })
        .await;
        // Owner: five unviewed (oldest first) plus one viewed, which doesn't count.
        for (n, days) in [(0, 5), (1, 4), (2, 3), (3, 2), (4, 1)] {
            env.add(Spec {
                age_days: days,
                owner: Some(7),
                ..spec(id(n))
            })
            .await;
        }
        env.add(Spec {
            age_days: 6,
            owner: Some(7),
            viewed_days_ago: Some(1),
            ..spec(id(5))
        })
        .await;
        // Anonymous, address 1: four. Address 2: one.
        for (n, days) in [(6, 4), (7, 3), (8, 2), (9, 1)] {
            env.add(Spec {
                age_days: days,
                ..spec(id(n))
            })
            .await;
        }
        env.add(Spec {
            ip: 2,
            ..spec(id(10))
        })
        .await;

        let report = run_once(&env.db, &env.config, false).await.unwrap();
        assert_eq!(report.over_cap, 6);
        for n in [0, 1, 2, 6, 7, 8] {
            env.assert_gone(&id(n)).await;
        }
        for n in [3, 4, 5, 9, 10] {
            env.assert_kept(&id(n)).await;
        }
    }

    #[tokio::test]
    async fn the_quota_evicts_unviewed_first_and_stops_when_under() {
        let env = env(|c| c.limits.disk_quota_bytes = 150).await;
        let (a, b, c) = (id(0), id(1), id(2));
        env.add(Spec {
            age_days: 30,
            viewed_days_ago: Some(1),
            bytes: 100,
            ..spec(&a)
        })
        .await;
        env.add(Spec {
            age_days: 20,
            bytes: 100,
            ..spec(&b)
        })
        .await;
        env.add(Spec {
            age_days: 10,
            bytes: 100,
            ..spec(&c)
        })
        .await;

        let report = run_once(&env.db, &env.config, false).await.unwrap();
        assert_eq!(report.evicted, 2);
        env.assert_kept(&a).await; // viewed: spared although it is the oldest
        env.assert_gone(&b).await;
        env.assert_gone(&c).await;

        // Now under quota: nothing more happens.
        assert_eq!(
            run_once(&env.db, &env.config, false).await.unwrap(),
            Report::default()
        );
    }

    #[tokio::test]
    async fn the_quota_takes_only_as_much_as_needed() {
        let env = env(|c| c.limits.disk_quota_bytes = 250).await;
        for n in 0..3 {
            env.add(Spec {
                age_days: 30 - i64::from(n),
                bytes: 100,
                ..spec(id(n))
            })
            .await;
        }
        assert_eq!(
            run_once(&env.db, &env.config, false).await.unwrap().evicted,
            1
        );
        env.assert_gone(&id(0)).await; // the oldest
        env.assert_kept(&id(1)).await;
        env.assert_kept(&id(2)).await;
    }

    #[tokio::test]
    async fn only_old_unclaimed_files_are_swept() {
        let env = env(|_| {}).await;
        env.add(spec(id(0))).await;
        let dumps = env.config.dumps_dir();
        let make = |rel: &str, secs: u64| {
            let path = dumps.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"x").unwrap();
            age(&path, secs);
            path
        };
        let week = 7 * 86_400;
        age(&env.config.dump_path(&id(0)), week); // old, but its crash exists
        let old_orphan = make("zz/zzzzzzzzzzzz.dmp", week);
        let old_meta = make("zz/zzzzzzzzzzzz.meta.txt.gz", week);
        let young_orphan = make("yy/yyyyyyyyyyyy.dmp", 60);
        let stray = make("xx/notes.txt", week);
        let tmp_old = make(".tmp/abc.part", 2 * 3600);
        let tmp_young = make(".tmp/def.part", 60);

        // Without the scan nothing is touched.
        assert_eq!(
            run_once(&env.db, &env.config, false).await.unwrap().orphans,
            0
        );
        assert!(old_orphan.exists());

        assert_eq!(
            run_once(&env.db, &env.config, true).await.unwrap().orphans,
            3
        );
        for gone in [&old_orphan, &old_meta, &tmp_old] {
            assert!(!gone.exists(), "{}", gone.display());
        }
        for kept in [
            &young_orphan,
            &stray,
            &tmp_young,
            &env.config.dump_path(&id(0)),
        ] {
            assert!(kept.exists(), "{}", kept.display());
        }
    }

    #[tokio::test]
    async fn old_counters_are_pruned() {
        let env = env(|_| {}).await;
        for bucket in [1, stats::now() / 3600 * 3600] {
            sqlx::query("INSERT INTO counter (bucket, name, value) VALUES (?, 'x', 1)")
                .bind(bucket)
                .execute(&env.db)
                .await
                .unwrap();
        }
        run_once(&env.db, &env.config, false).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM counter")
            .fetch_one(&env.db)
            .await
            .unwrap();
        assert_eq!(left, 1);
    }

    #[test]
    fn free_space_is_measured() {
        let dir = tempfile::tempdir().unwrap();
        assert!(free_bytes(dir.path()).is_some_and(|b| b > 0));
        assert_eq!(free_bytes(&dir.path().join("missing")), None);

        let mut config = Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        config.limits.disk_min_free_bytes = u64::MAX;
        assert!(low_disk(&config));
        config.limits.disk_min_free_bytes = 0;
        assert!(!low_disk(&config));
    }
}
