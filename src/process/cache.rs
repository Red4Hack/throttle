//! A bounded cache of parsed symbol files, shared by all workers.
//!
//! Without it every dump re-reads, gunzips and parses each `.sym` it needs.
//! Measured on a synthetic 28 MiB file (150 000 functions): about 280 ms to
//! load, about 43 ms to hand out a copy of the parsed result. The parsed file
//! takes 3.5 to 5.7 times the size of its text in memory, so the cache is
//! limited by an estimated memory budget (LRU), not by a number of entries.
//!
//! Properties worth knowing:
//!
//! * Only files that were found and parsed are kept. A module without symbols
//!   never reaches the cache, so a symbol file uploaded later is always seen.
//! * The key includes the file's size and modification time, so a replaced
//!   file is a different entry (the old one just ages out).
//! * Concurrent requests for the same file load it once; the others wait.
//! * `breakpad-symbols` wants an owned `SymbolFile`, so every use copies the
//!   cached one. Memory can therefore briefly exceed the budget by the files
//!   being loaded or copied right now (about workers x the biggest module).
//! * A file whose estimate alone exceeds the budget is not kept.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use breakpad_symbols::{SymbolError, SymbolFile};
use tokio::sync::OnceCell;

use super::repo::Repo;

/// Parsed size / text size, rounded up from what was measured.
const PARSED_FACTOR: u64 = 4;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub path: PathBuf,
    pub modified: Option<SystemTime>,
    pub len: u64,
}

/// What loading one symbol file produces.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub symbols: SymbolFile,
    pub repos: Arc<Vec<Repo>>,
    /// Size of the (decompressed) text; the memory estimate derives from it.
    pub text_bytes: u64,
}

impl Loaded {
    fn weight(&self) -> u64 {
        self.text_bytes.saturating_mul(PARSED_FACTOR)
    }
}

type Init = Arc<OnceCell<Arc<Loaded>>>;

struct Slot {
    cell: Init,
    /// 0 until the file has been loaded (such a slot is never evicted).
    weight: u64,
    used: u64,
}

#[derive(Default)]
struct Inner {
    slots: HashMap<Key, Slot>,
    total: u64,
    tick: u64,
}

pub struct SymbolCache {
    budget: u64,
    inner: Mutex<Inner>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl SymbolCache {
    /// `budget_bytes` of estimated parsed size; 0 turns the cache off.
    pub fn new(budget_bytes: u64) -> Self {
        Self {
            budget: budget_bytes,
            inner: Mutex::new(Inner::default()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Estimated memory held by the cache.
    pub fn bytes(&self) -> u64 {
        self.lock().total
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn entries(&self) -> usize {
        self.lock().slots.len()
    }

    /// The file for `key`: from the cache, or loaded by `load` (once, however
    /// many callers ask at the same time).
    pub async fn get_or_load<F, Fut>(&self, key: Key, load: F) -> Result<Arc<Loaded>, SymbolError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<Loaded, SymbolError>> + Send,
    {
        if self.budget == 0 {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return load().await.map(Arc::new);
        }

        let cell = {
            let mut guard = self.lock();
            let inner = &mut *guard;
            inner.tick += 1;
            let tick = inner.tick;
            let slot = inner.slots.entry(key.clone()).or_insert_with(|| Slot {
                cell: Init::default(),
                weight: 0,
                used: tick,
            });
            slot.used = tick;
            slot.cell.clone()
        };

        let loaded_here = AtomicBool::new(false);
        let flag = &loaded_here;
        let result = cell
            .get_or_try_init(move || async move {
                flag.store(true, Ordering::Relaxed);
                load().await.map(Arc::new)
            })
            .await
            .map(Arc::clone);

        match result {
            Ok(loaded) => {
                if loaded_here.load(Ordering::Relaxed) {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    self.admit(&key, loaded.weight());
                } else {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                }
                Ok(loaded)
            }
            Err(e) => {
                self.forget_failed(&key, &cell);
                Err(e)
            }
        }
    }

    /// Count a freshly loaded file and evict the least recently used ones
    /// until the cache fits its budget again.
    fn admit(&self, key: &Key, weight: u64) {
        let mut guard = self.lock();
        let inner = &mut *guard;

        if weight > self.budget {
            // Evicting everything else would not make room for it.
            inner.slots.remove(key);
            return;
        }
        match inner.slots.get_mut(key) {
            Some(slot) if slot.weight == 0 => {
                slot.weight = weight;
                inner.total += weight;
            }
            _ => return,
        }

        while inner.total > self.budget {
            let victim = inner
                .slots
                .iter()
                .filter(|(k, s)| s.weight > 0 && *k != key)
                .min_by_key(|(_, s)| s.used)
                .map(|(k, _)| k.clone());
            let Some(victim) = victim else { break };
            if let Some(slot) = inner.slots.remove(&victim) {
                inner.total -= slot.weight;
            }
        }
    }

    /// A failed load leaves nothing behind, so the next request tries again.
    fn forget_failed(&self, key: &Key, cell: &Init) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let ours = inner
            .slots
            .get(key)
            .is_some_and(|s| Arc::ptr_eq(&s.cell, cell));
        if ours && !cell.initialized() {
            inner.slots.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use super::*;

    const SYM: &[u8] = include_bytes!(
        "../../tests/fixtures/symbols/test_app.pdb/5A9832E5287241C1838ED98914E9B7FF1/test_app.sym"
    );

    fn loaded(text_bytes: u64) -> Loaded {
        Loaded {
            symbols: SymbolFile::from_bytes(SYM).unwrap(),
            repos: Arc::default(),
            text_bytes,
        }
    }

    fn key(name: &str, len: u64) -> Key {
        Key {
            path: PathBuf::from(name),
            modified: None,
            len,
        }
    }

    /// Estimated size of an entry with `text` bytes of text.
    fn w(text: u64) -> u64 {
        text * PARSED_FACTOR
    }

    /// Ask for `key`; did the loader have to run?
    async fn fetch_key(cache: &SymbolCache, key: Key, text: u64) -> bool {
        let ran = AtomicBool::new(false);
        let flag = &ran;
        cache
            .get_or_load(key, move || async move {
                flag.store(true, Ordering::SeqCst);
                Ok(loaded(text))
            })
            .await
            .unwrap();
        ran.load(Ordering::SeqCst)
    }

    async fn fetch(cache: &SymbolCache, name: &str, text: u64) -> bool {
        fetch_key(cache, key(name, text), text).await
    }

    #[tokio::test]
    async fn concurrent_requests_load_once() {
        let cache = Arc::new(SymbolCache::new(w(1000)));
        let loads = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (cache, loads) = (cache.clone(), loads.clone());
                tokio::spawn(async move {
                    cache
                        .get_or_load(key("big.sym", 100), || async move {
                            loads.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            Ok(loaded(100))
                        })
                        .await
                        .unwrap()
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert_eq!((cache.hits(), cache.misses()), (7, 1));
        assert_eq!(cache.bytes(), w(100));
    }

    #[tokio::test]
    async fn the_least_recently_used_entry_goes_first() {
        let cache = SymbolCache::new(w(300));
        for name in ["a", "b", "c"] {
            assert!(fetch(&cache, name, 100).await);
        }
        assert_eq!(cache.bytes(), w(300));

        assert!(
            !fetch(&cache, "a", 100).await,
            "a hit; a is now the most recently used"
        );
        assert!(
            fetch(&cache, "d", 100).await,
            "over budget: b, the oldest use, goes"
        );
        assert_eq!(cache.bytes(), w(300));

        for name in ["a", "c", "d"] {
            assert!(!fetch(&cache, name, 100).await, "{name} is still cached");
        }
        assert!(fetch(&cache, "b", 100).await, "b was evicted");
    }

    #[tokio::test]
    async fn an_entry_bigger_than_the_budget_is_not_kept_and_evicts_nothing() {
        let cache = SymbolCache::new(w(300));
        assert!(fetch(&cache, "small", 100).await);
        assert!(fetch(&cache, "huge", 5000).await);
        assert!(
            fetch(&cache, "huge", 5000).await,
            "loaded again, it was not kept"
        );
        assert!(
            !fetch(&cache, "small", 100).await,
            "the small one is still there"
        );
        assert_eq!((cache.bytes(), cache.entries()), (w(100), 1));
    }

    #[tokio::test]
    async fn a_zero_budget_turns_it_off() {
        let cache = SymbolCache::new(0);
        assert!(fetch(&cache, "a", 100).await);
        assert!(fetch(&cache, "a", 100).await);
        assert_eq!(
            (cache.bytes(), cache.entries(), cache.hits(), cache.misses()),
            (0, 0, 0, 2)
        );
    }

    #[tokio::test]
    async fn failures_are_not_remembered() {
        let cache = SymbolCache::new(w(1000));
        let failed = cache
            .get_or_load(key("a", 1), || async { Err(SymbolError::NotFound) })
            .await;
        assert!(failed.is_err());
        assert_eq!((cache.entries(), cache.bytes()), (0, 0));

        assert!(
            fetch(&cache, "a", 1).await,
            "tried again, and this time it works"
        );
        assert_eq!(cache.entries(), 1);
    }

    #[tokio::test]
    async fn a_changed_file_is_a_different_entry() {
        let cache = SymbolCache::new(w(10_000));
        assert!(fetch(&cache, "a", 100).await);
        assert!(!fetch(&cache, "a", 100).await);
        // Same path, other size; and same size, other modification time.
        assert!(fetch_key(&cache, key("a", 101), 101).await);
        let touched = Key {
            modified: Some(SystemTime::UNIX_EPOCH),
            ..key("a", 100)
        };
        assert!(fetch_key(&cache, touched, 100).await);
        assert_eq!(cache.entries(), 3);
    }
}
