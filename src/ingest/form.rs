//! Reads the form bodies the Accelerator sends (multipart, or urlencoded for
//! other clients). The minidump is streamed to a temp file with a hard size cap;
//! nothing large is ever buffered in memory except the metadata file (also capped).

use std::path::{Path, PathBuf};

use axum::body::to_bytes;
use axum::extract::multipart::{Field, MultipartError};
use axum::extract::{FromRequest, Multipart, Request};
use axum::http::{StatusCode, header};
use tokio::io::AsyncWriteExt;

use super::Reject;
use crate::config::Limits;

const MAX_FIELDS: usize = 128;
const MAX_FIELD_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 1024 * 1024;

/// A file on disk that is deleted when dropped (a hard link made from it
/// elsewhere is unaffected).
pub struct TempFile {
    pub path: PathBuf,
    pub size: u64,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Default)]
pub struct Submission {
    pub fields: Vec<(String, String)>,
    pub dump: Option<TempFile>,
    pub metadata: Option<Vec<u8>>,
}

impl Submission {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub fn content_type(req: &Request) -> String {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}

pub fn multipart_error(e: MultipartError) -> Reject {
    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
        Reject::TooLarge
    } else {
        Reject::BadRequest("malformed multipart body")
    }
}

/// Read a field into memory, failing with 413 past `cap` bytes.
pub async fn read_capped(mut field: Field<'_>, cap: usize) -> Result<Vec<u8>, Reject> {
    let mut buf = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
        if buf.len() + chunk.len() > cap {
            return Err(Reject::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

async fn save_file(mut field: Field<'_>, max: u64, tmp_dir: &Path) -> Result<TempFile, Reject> {
    tokio::fs::create_dir_all(tmp_dir).await?;
    let mut tmp = TempFile {
        path: tmp_dir.join(format!("{}.part", hex::encode(rand::random::<[u8; 12]>()))),
        size: 0,
    };
    let mut file = tokio::fs::File::create(&tmp.path).await?;
    while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
        tmp.size += chunk.len() as u64;
        if tmp.size > max {
            return Err(Reject::TooLarge);
        }
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    Ok(tmp)
}

pub async fn read(req: Request, limits: &Limits, tmp_dir: &Path) -> Result<Submission, Reject> {
    let ct = content_type(&req);
    let mut sub = Submission::default();

    if ct.starts_with("multipart/form-data") {
        let mut mp = Multipart::from_request(req, &())
            .await
            .map_err(|_| Reject::BadRequest("malformed multipart body"))?;

        while let Some(field) = mp.next_field().await.map_err(multipart_error)? {
            let name = field.name().unwrap_or("").to_string();
            match name.as_str() {
                "upload_file_minidump" if sub.dump.is_none() => {
                    sub.dump = Some(save_file(field, limits.max_dump_bytes, tmp_dir).await?);
                }
                "upload_file_metadata" if sub.metadata.is_none() => {
                    sub.metadata =
                        Some(read_capped(field, limits.max_metadata_bytes as usize).await?);
                }
                // Unknown file uploads are skipped without being read.
                _ if field.file_name().is_some() => {}
                _ if sub.fields.len() >= MAX_FIELDS => {}
                _ => {
                    let cap = if name == "CrashSignature" {
                        MAX_SIGNATURE_BYTES
                    } else {
                        MAX_FIELD_BYTES
                    };
                    let bytes = read_capped(field, cap).await?;
                    sub.fields
                        .push((name, String::from_utf8_lossy(&bytes).into_owned()));
                }
            }
        }
    } else if ct.starts_with("application/x-www-form-urlencoded") {
        let bytes = to_bytes(req.into_body(), MAX_SIGNATURE_BYTES)
            .await
            .map_err(|_| Reject::TooLarge)?;
        sub.fields = form_urlencoded::parse(&bytes)
            .take(MAX_FIELDS)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    } else {
        return Err(Reject::BadRequest("expected a form submission"));
    }

    Ok(sub)
}
