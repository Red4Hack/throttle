//! Symbol lookup for rust-minidump, backed by the on-disk symbol stores
//! (`symbols/<store>/<name>/<build id>/<name>.sym[.gz]`).

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use breakpad_symbols::{
    FileError, FileKind, LocateSymbolsResult, Module, SymbolError, SymbolFile, SymbolSupplier,
    breakpad_sym_lookup,
};
use flate2::read::GzDecoder;

use super::cache::{Key, Loaded, SymbolCache};
use super::repo::{self, Repo};

/// `INFO REPO` data of every symbol file loaded during one analysis, keyed by
/// the file's path inside its store.
pub type RepoMap = Arc<Mutex<HashMap<String, Arc<Vec<Repo>>>>>;

/// How the symbol lookups of an analysis ended; flushed into the hourly counters.
#[derive(Default)]
pub struct LookupCounts {
    cached: AtomicU64,
    found: AtomicU64,
    compressed: AtomicU64,
    missing: AtomicU64,
}

impl LookupCounts {
    /// Counter names with what was counted since the last call.
    pub fn take(&self) -> [(&'static str, i64); 4] {
        let t = |a: &AtomicU64| a.swap(0, Ordering::Relaxed) as i64;
        [
            ("symbols:lookup:cached", t(&self.cached)),
            ("symbols:lookup:found", t(&self.found)),
            ("symbols:lookup:compressed", t(&self.compressed)),
            ("symbols:lookup:missing", t(&self.missing)),
        ]
    }
}

#[derive(Clone)]
pub struct SymbolStores {
    pub counts: Arc<LookupCounts>,
    dirs: Arc<Vec<PathBuf>>,
    /// Cap on the decompressed size of one symbol file (zip-bomb guard).
    max_bytes: u64,
    /// Parsed files shared between analyses; without it every use reloads.
    cache: Option<Arc<SymbolCache>>,
}

impl SymbolStores {
    pub fn new(dirs: Vec<PathBuf>, max_bytes: u64) -> Self {
        Self {
            dirs: Arc::new(dirs),
            max_bytes,
            cache: None,
            counts: Arc::default(),
        }
    }

    pub fn with_cache(mut self, cache: Arc<SymbolCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// The path comes from an untrusted minidump (debug file name), so refuse
    /// anything that could leave the store.
    fn is_safe(rel: &str) -> bool {
        !rel.is_empty()
            && rel
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains('\0'))
    }

    /// First store that has `rel` (`.sym.gz` preferred over plain `.sym`).
    pub fn find(&self, rel: &str) -> Option<PathBuf> {
        if !Self::is_safe(rel) {
            return None;
        }
        for dir in self.dirs.iter() {
            let gz = dir.join(format!("{rel}.gz"));
            if gz.is_file() {
                return Some(gz);
            }
            let plain = dir.join(rel);
            if plain.is_file() {
                return Some(plain);
            }
        }
        None
    }

    pub fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        let file = std::fs::File::open(path)?;
        let limit = self.max_bytes.saturating_add(1);
        let mut out = Vec::new();
        if path.extension().is_some_and(|e| e == "gz") {
            GzDecoder::new(file).take(limit).read_to_end(&mut out)?;
        } else {
            file.take(limit).read_to_end(&mut out)?;
        }
        if out.len() as u64 > self.max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "symbol file too large",
            ));
        }
        Ok(out)
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, SymbolError> + Send + 'static,
) -> Result<T, SymbolError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| SymbolError::LoadError(std::io::Error::other(e)))?
}

pub struct StoreSupplier {
    stores: SymbolStores,
    repos: RepoMap,
}

impl StoreSupplier {
    pub fn new(stores: SymbolStores, repos: RepoMap) -> Self {
        Self { stores, repos }
    }
}

#[async_trait]
impl SymbolSupplier for StoreSupplier {
    async fn locate_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> Result<LocateSymbolsResult, SymbolError> {
        let rel = breakpad_sym_lookup(module)
            .ok_or(SymbolError::MissingDebugFileOrId)?
            .cache_rel;

        // Finding the file is cheap; the cache is keyed by what we find (path,
        // size and modification time), so a replaced file is never served stale.
        let stores = self.stores.clone();
        let lookup = rel.clone();
        let (path, key) = blocking(move || -> Result<_, SymbolError> {
            let path = stores.find(&lookup).ok_or(SymbolError::NotFound)?;
            let meta = std::fs::metadata(&path)?;
            let key = Key {
                path: path.clone(),
                modified: meta.modified().ok(),
                len: meta.len(),
            };
            Ok((path, key))
        })
        .await
        .inspect_err(|e| {
            if matches!(e, SymbolError::NotFound) {
                self.stores.counts.missing.fetch_add(1, Ordering::Relaxed);
            }
        })?;

        let gz = path.extension().is_some_and(|e| e == "gz");
        let ran = Arc::new(AtomicBool::new(false));
        let load = {
            let stores = self.stores.clone();
            let ran = ran.clone();
            move || async move {
                ran.store(true, Ordering::Relaxed);
                // Reading, gunzipping and parsing are blocking work.
                blocking(move || -> Result<Loaded, SymbolError> {
                    let bytes = stores.read(&path)?;
                    Ok(Loaded {
                        repos: Arc::new(repo::parse(&bytes)),
                        symbols: SymbolFile::from_bytes(&bytes)?,
                        text_bytes: bytes.len() as u64,
                    })
                })
                .await
            }
        };
        let loaded = match &self.stores.cache {
            Some(cache) => cache.get_or_load(key, load).await?,
            None => Arc::new(load().await?),
        };
        let counts = &self.stores.counts;
        let counter = if !ran.load(Ordering::Relaxed) {
            &counts.cached
        } else if gz {
            &counts.compressed
        } else {
            &counts.found
        };
        counter.fetch_add(1, Ordering::Relaxed);
        // The cache keeps its copy; breakpad-symbols wants to own one.
        let Loaded { symbols, repos, .. } =
            Arc::try_unwrap(loaded).unwrap_or_else(|shared| (*shared).clone());

        self.repos
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(rel, repos);
        Ok(LocateSymbolsResult {
            symbols,
            extra_debug_info: None,
        })
    }

    async fn locate_file(
        &self,
        _module: &(dyn Module + Sync),
        _kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        Err(FileError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn traversal_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret.sym"), "x").unwrap();
        let stores = SymbolStores::new(vec![dir.path().join("store")], 1024);
        for bad in [
            "",
            "../secret.sym",
            "a/../../secret.sym",
            "/etc/passwd",
            "a//b",
            "./a",
            "a\0b",
        ] {
            assert_eq!(stores.find(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn first_store_wins_and_gz_is_read() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        for (dir, text) in [(&a, "from a"), (&b, "from b")] {
            std::fs::create_dir_all(dir.path().join("m.so/ID")).unwrap();
            std::fs::write(dir.path().join("m.so/ID/m.so.sym.gz"), gz(text.as_bytes())).unwrap();
        }
        let stores = SymbolStores::new(vec![a.path().into(), b.path().into()], 1024);
        let path = stores.find("m.so/ID/m.so.sym").unwrap();
        assert!(path.starts_with(a.path()));
        assert_eq!(stores.read(&path).unwrap(), b"from a");
        assert_eq!(stores.find("m.so/OTHER/m.so.sym"), None);
    }

    #[test]
    fn plain_files_work_and_limits_apply_after_decompression() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("plain.sym"), "hello").unwrap();
        std::fs::write(dir.path().join("bomb.sym.gz"), gz(&[b'a'; 1000])).unwrap();

        let stores = SymbolStores::new(vec![dir.path().into()], 100);
        assert_eq!(
            stores.read(&stores.find("plain.sym").unwrap()).unwrap(),
            b"hello"
        );

        let bomb = stores.find("bomb.sym").unwrap();
        assert!(std::fs::metadata(&bomb).unwrap().len() < 100); // small on disk...
        assert!(stores.read(&bomb).is_err()); // ...but refused once inflated
    }
}
