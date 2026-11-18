//! Persisting an accepted crash: dump on disk first, then the database row.
//! The order matters: a worker that sees a pending row must always find its file.

use std::io::Write;
use std::net::IpAddr;

use flate2::Compression;
use flate2::write::GzEncoder;

use super::Reject;
use super::form::TempFile;
use crate::app::AppState;
use crate::{ids, stats};

pub struct NewCrash {
    pub ip: IpAddr,
    pub owner: Option<i64>,
    pub server_id: Option<String>,
    /// JSON object.
    pub metadata: String,
    pub cmdline: Option<String>,
    pub signature: Option<String>,
    /// `None` for a metadata-only upload.
    pub dump: Option<TempFile>,
    /// The raw metadata file, kept gzipped next to the dump.
    pub raw_metadata: Option<Vec<u8>>,
}

pub fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

pub fn gzip(data: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::with_capacity(data.len() / 4), Compression::new(level));
    enc.write_all(data)?;
    enc.finish()
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.is_unique_violation())
}

/// Returns the new crash ID.
pub async fn persist(state: &AppState, new: NewCrash) -> Result<String, Reject> {
    let has_dump = new.dump.is_some();
    let dump_bytes = new.dump.as_ref().map_or(0, |d| d.size);
    let now = stats::now();
    // Metadata-only crashes have nothing to process: they are born "done".
    let (status, processed_at) = if has_dump {
        (0_i64, None)
    } else {
        (2_i64, Some(now))
    };

    for _ in 0..10 {
        let id = ids::generate();
        let dir = state.config.dumps_dir().join(&id[..2]);
        tokio::fs::create_dir_all(&dir).await?;
        let dump_path = dir.join(format!("{id}.dmp"));

        if let Some(dump) = &new.dump {
            // A hard link refuses to overwrite, which makes an ID clash safe.
            match tokio::fs::hard_link(&dump.path, &dump_path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let inserted = sqlx::query(
            "INSERT INTO crash (id, created_at, ip, owner, server_id, metadata, cmdline, status, \
             has_dump, dump_bytes, signature, processed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(now)
        .bind(ip_bytes(new.ip))
        .bind(new.owner)
        .bind(&new.server_id)
        .bind(&new.metadata)
        .bind(&new.cmdline)
        .bind(status)
        .bind(has_dump)
        .bind(dump_bytes as i64)
        .bind(&new.signature)
        .bind(processed_at)
        .execute(&state.db)
        .await;

        match inserted {
            Ok(_) => {
                if let Some(raw) = new.raw_metadata {
                    write_metadata(&dir, &id, raw).await;
                }
                if has_dump {
                    state.wake.notify_one();
                }
                return Ok(id);
            }
            Err(e) => {
                if has_dump {
                    let _ = tokio::fs::remove_file(&dump_path).await;
                }
                if is_unique_violation(&e) {
                    continue;
                }
                return Err(e.into());
            }
        }
    }

    tracing::error!("could not find a free crash id after 10 attempts");
    Err(Reject::Internal)
}

/// The crash is already recorded, so a failure here is logged, not fatal.
async fn write_metadata(dir: &std::path::Path, id: &str, raw: Vec<u8>) {
    let compressed = tokio::task::spawn_blocking(move || gzip(&raw, 6)).await;
    match compressed {
        Ok(Ok(bytes)) => {
            if let Err(e) = tokio::fs::write(dir.join(format!("{id}.meta.txt.gz")), bytes).await {
                tracing::warn!(error = %e, id, "could not store metadata file");
            }
        }
        Ok(Err(e)) => tracing::warn!(error = %e, id, "could not compress metadata file"),
        Err(e) => tracing::warn!(error = %e, id, "metadata compression task failed"),
    }
}
