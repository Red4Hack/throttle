//! Crash processing. The queue is the `crash.status` column (0 pending,
//! 1 processing, 2 done, 3 failed); a pool of workers drains it oldest-first.
//!
//! Compared with the PHP cron job: workers run in parallel, there is no file
//! lock, nothing is processed inside one giant transaction, symbols are looked
//! up once per module, and a dump that keeps killing the processor is given up
//! on instead of blocking the queue forever.

mod analyze;
pub mod cache;
mod render;
mod repo;
mod supplier;
mod sys_error;
#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use sqlx::SqlitePool;

use crate::app::AppState;
use crate::config::Processing;
use crate::notice::{self, Subject};
use crate::stats;
use analyze::Analysis;
use supplier::SymbolStores;

const IDLE_POLL: Duration = Duration::from_secs(5);
const REQUEUE_EVERY: Duration = Duration::from_secs(60);
const REQUEUE_BATCH: i64 = 500;
const MAX_ERROR_CHARS: usize = 500;

/// Put back (or give up on) crashes a previous run left in `processing`.
pub async fn recover(db: &SqlitePool, max_attempts: u32) -> sqlx::Result<()> {
    let gave_up = sqlx::query(
        "UPDATE crash SET status = 3, processed_at = ?, \
         error = 'gave up: the server stopped while processing this crash too many times' \
         WHERE status = 1 AND attempts >= ?",
    )
    .bind(stats::now())
    .bind(i64::from(max_attempts))
    .execute(db)
    .await?
    .rows_affected();
    let requeued = sqlx::query("UPDATE crash SET status = 0 WHERE status = 1")
        .execute(db)
        .await?
        .rows_affected();
    if gave_up + requeued > 0 {
        tracing::warn!(
            requeued,
            gave_up,
            "recovered crashes interrupted by a restart"
        );
    }
    Ok(())
}

pub fn spawn(state: &AppState) {
    let workers = worker_count(&state.config.processing);
    tracing::info!(workers, "starting crash processors");
    for n in 0..workers {
        tokio::spawn(worker(state.clone(), n));
    }
    tokio::spawn(requeue_loop(state.clone()));
    // Whatever was queued before we started.
    state.wake.notify_one();
}

fn worker_count(cfg: &Processing) -> usize {
    if cfg.workers > 0 {
        return cfg.workers;
    }
    let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
    (cores / 2).max(1)
}

async fn claim(db: &SqlitePool) -> sqlx::Result<Option<String>> {
    // One statement, so two workers can never claim the same crash.
    sqlx::query_scalar(
        "UPDATE crash SET status = 1, attempts = attempts + 1 \
         WHERE id = (SELECT id FROM crash WHERE status = 0 ORDER BY created_at, id LIMIT 1) \
         RETURNING id",
    )
    .fetch_optional(db)
    .await
}

async fn worker(state: AppState, n: usize) {
    let max_attempts = state.config.processing.max_attempts;
    loop {
        match claim(&state.db).await {
            Ok(Some(id)) => {
                // There may be more waiting; let an idle worker look.
                state.wake.notify_one();
                if let Err(e) = process_one(&state, &id).await {
                    tracing::error!(worker = n, %id, error = %e, "database error while processing; releasing the crash");
                    release(&state.db, &id, max_attempts, &e.to_string()).await;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            Ok(None) => {
                tokio::select! {
                    () = state.wake.notified() => {}
                    () = tokio::time::sleep(IDLE_POLL) => {}
                }
            }
            Err(e) => {
                tracing::error!(worker = n, error = %e, "could not claim a crash");
                tokio::time::sleep(IDLE_POLL).await;
            }
        }
    }
}

/// After an infrastructure error: retry later, unless it has been tried too often.
async fn release(db: &SqlitePool, id: &str, max_attempts: u32, why: &str) {
    let max = i64::from(max_attempts);
    let result = sqlx::query(
        "UPDATE crash SET status = CASE WHEN attempts >= ? THEN 3 ELSE 0 END, \
         error = CASE WHEN attempts >= ? THEN ? ELSE error END \
         WHERE id = ? AND status = 1",
    )
    .bind(max)
    .bind(max)
    .bind(clip(why))
    .bind(id)
    .execute(db)
    .await;
    if let Err(e) = result {
        // recover() will pick it up on the next start.
        tracing::error!(%id, error = %e, "could not release crash");
    }
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_ERROR_CHARS).collect()
}

/// The dump `id` as text, the way `minidump_stackwalk` prints it (see `analyze::raw_text`).
pub async fn raw_report(state: &AppState, id: &str) -> anyhow::Result<String> {
    let cfg = &state.config;
    let stores = SymbolStores::new(cfg.symbol_store_dirs(), cfg.limits.max_symbol_bytes)
        .with_cache(state.symbol_cache.clone());
    analyze::raw_text(&cfg.dump_path(id), &stores).await
}

async fn process_one(state: &AppState, id: &str) -> sqlx::Result<()> {
    let started = Instant::now();
    let cfg = &state.config;
    let stores = SymbolStores::new(cfg.symbol_store_dirs(), cfg.limits.max_symbol_bytes)
        .with_cache(state.symbol_cache.clone());
    let path = cfg.dump_path(id);

    let timeout = Duration::from_secs(cfg.processing.timeout_secs);
    match tokio::time::timeout(timeout, analyze::analyze(&path, &stores)).await {
        Ok(Ok(analysis)) => {
            let notices = matching_notices(&state.db, id, &analysis).await?;
            if save(&state.db, id, &analysis, &notices).await? {
                stats::bump(&state.db, "crashes:processed", 1).await;
            }
        }
        // The dump itself is unusable: retrying won't help.
        Ok(Err(e)) => fail(&state.db, id, &format!("{e:#}")).await?,
        Err(_) => fail(&state.db, id, "timed out while processing").await?,
    }

    let ms = started.elapsed().as_millis() as i64;
    stats::bump(&state.db, "processing:millis", ms).await;
    stats::bump(&state.db, "processing:count", 1).await;
    stats::bump_extreme(&state.db, "processing:max-ms", ms, true).await;
    stats::bump_extreme(&state.db, "processing:min-ms", ms, false).await;
    for (name, n) in stores.counts.take() {
        if n > 0 {
            stats::bump(&state.db, name, n).await;
        }
    }
    Ok(())
}

/// Ids of the notices whose rules match this crash.
async fn matching_notices(db: &SqlitePool, id: &str, a: &Analysis) -> sqlx::Result<Vec<String>> {
    let rules = notice::load(db).await?;
    if rules.is_empty() {
        return Ok(Vec::new());
    }
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT metadata, cmdline FROM crash WHERE id = ?")
            .bind(id)
            .fetch_optional(db)
            .await?;
    let Some((metadata, cmdline)) = row else {
        return Ok(Vec::new());
    };
    let metadata: Map<String, Value> = serde_json::from_str(&metadata).unwrap_or_default();
    let frames: Vec<(&str, &str)> = a
        .frames
        .iter()
        .filter(|f| f.thread == a.thread)
        .map(|f| (f.module.as_str(), f.function.as_str()))
        .collect();
    let modules: Vec<&str> = a.modules.iter().map(|m| m.name.as_str()).collect();
    let subject = Subject {
        frames: &frames,
        modules: &modules,
        metadata: &metadata,
        cmdline: cmdline.as_deref(),
    };
    Ok(notice::matching(&rules, &subject))
}

async fn fail(db: &SqlitePool, id: &str, why: &str) -> sqlx::Result<()> {
    tracing::warn!(%id, why, "crash could not be processed");
    let updated = sqlx::query(
        "UPDATE crash SET status = 3, error = ?, processed_at = ? WHERE id = ? AND status = 1",
    )
    .bind(clip(why))
    .bind(stats::now())
    .bind(id)
    .execute(db)
    .await?
    .rows_affected();
    if updated > 0 {
        stats::bump(db, "crashes:failed", 1).await;
    }
    Ok(())
}

/// Replace the stored results of `id` with `a`. Returns `false` when the crash
/// is gone or was taken over meanwhile (nothing is written then).
async fn save(db: &SqlitePool, id: &str, a: &Analysis, notices: &[String]) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;

    // First statement is the write that decides everything: no stale read
    // snapshot, and the crash cannot be deleted under us afterwards.
    let updated = sqlx::query(
        "UPDATE crash SET status = 2, thread = ?, stackhash = ?, crash_module = ?, crash_function = ?, \
         sys_error = ?, crash_reason = ?, crash_address = ?, bad_jump = ?, \
         processed_at = ?, error = NULL WHERE id = ? AND status = 1",
    )
    .bind(a.thread)
    .bind(&a.stackhash)
    .bind(&a.crash_module)
    .bind(&a.crash_function)
    .bind(&a.sys_error)
    .bind(&a.crash_reason)
    .bind(&a.crash_address)
    .bind(i64::from(a.bad_jump))
    .bind(stats::now())
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        return Ok(false);
    }

    sqlx::query("DELETE FROM frame WHERE crash = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM module WHERE crash = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM crashnotice WHERE crash = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    for m in &a.modules {
        sqlx::query("INSERT OR IGNORE INTO module (crash, name, identifier, base, present) VALUES (?, ?, ?, ?, ?)")
            .bind(id)
            .bind(&m.name)
            .bind(&m.identifier)
            .bind(&m.base)
            .bind(m.present)
            .execute(&mut *tx)
            .await?;
    }

    for f in &a.frames {
        sqlx::query(
            "INSERT INTO frame (crash, thread, frame, module, function, file, line, offset, rendered, url) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(f.thread)
        .bind(f.frame)
        .bind(&f.module)
        .bind(&f.function)
        .bind(&f.file)
        .bind(f.line)
        .bind(&f.offset)
        .bind(&f.rendered)
        .bind(&f.url)
        .execute(&mut *tx)
        .await?;
    }

    for n in notices {
        // Selecting from `notice` means a notice removed meanwhile is simply skipped.
        sqlx::query("INSERT OR IGNORE INTO crashnotice (crash, notice) SELECT ?, id FROM notice WHERE id = ?")
            .bind(id)
            .bind(n)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(true)
}

async fn requeue_loop(state: AppState) {
    loop {
        tokio::time::sleep(REQUEUE_EVERY).await;
        match requeue_new_symbols(&state).await {
            Ok(0) => {}
            Ok(n) => {
                tracing::info!(count = n, "requeued crashes whose symbols have arrived");
                stats::bump(&state.db, "crashes:needs-reprocessing", n as i64).await;
                state.wake.notify_one();
            }
            Err(e) => tracing::error!(error = %e, "requeue failed"),
        }
    }
}

/// Crashes that were processed without symbols for a module whose symbols were
/// uploaded afterwards (and into a store we actually read) get processed again.
/// `created_at > processed_at` keeps a symbol file we cannot use from causing
/// an endless loop.
async fn requeue_new_symbols(state: &AppState) -> sqlx::Result<u64> {
    let stores = &state.config.processing.symbol_stores;
    let marks = vec!["?"; stores.len()].join(", ");
    let sql = format!(
        "UPDATE crash SET status = 0, attempts = 0, error = NULL WHERE id IN (\
           SELECT c.id FROM crash c \
           JOIN module m ON m.crash = c.id AND m.present = 0 \
           JOIN symbol s ON s.name = m.name AND s.identifier = m.identifier \
           WHERE c.status = 2 AND c.has_dump = 1 AND s.store IN ({marks}) \
             AND s.created_at > COALESCE(c.processed_at, 0) \
           LIMIT ?)"
    );
    // `sql` only contains `?` placeholders generated above; no external data.
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
    for store in stores {
        query = query.bind(store);
    }
    Ok(query
        .bind(REQUEUE_BATCH)
        .execute(&state.db)
        .await?
        .rows_affected())
}

/// Process everything pending, then return how many were handled.
#[cfg(test)]
pub async fn drain(state: &AppState) -> sqlx::Result<usize> {
    let mut handled = 0;
    while let Some(id) = claim(&state.db).await? {
        process_one(state, &id).await?;
        handled += 1;
    }
    Ok(handled)
}
