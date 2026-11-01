//! A small bounded time-to-live cache.
//!
//! The cache is intentionally simple: a mutex-guarded hash map with a fixed
//! TTL and a hard entry cap. It is suitable for template lookups, small board
//! settings and other values that can be recomputed cheaply. It is not an LRU
//! and it is not a substitute for a generation-based response cache.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A bounded TTL cache.
pub struct TimedCache<K, V> {
    entries: Mutex<HashMap<K, (Instant, V)>>,
    ttl: Duration,
    max_entries: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> TimedCache<K, V> {
    /// Create a cache that keeps at most `max_entries` values for `ttl`.
    ///
    /// `max_entries == 0` disables storage: [`put`](Self::put) is a no-op and
    /// [`get`](Self::get) always returns `None`.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// Return a clone of the live value for `key`, or `None`.
    pub fn get(&self, key: &K) -> Option<V> {
        let mut map = self.lock();
        if let Some((at, value)) = map.get(key) {
            if at.elapsed() < self.ttl {
                return Some(value.clone());
            }
            map.remove(key);
        }
        None
    }

    /// Insert or replace a value.
    pub fn put(&self, key: K, value: V) {
        if self.max_entries == 0 {
            return;
        }
        let mut map = self.lock();
        if map.len() >= self.max_entries && !map.contains_key(&key) {
            let now = Instant::now();
            map.retain(|_, (at, _)| now.duration_since(*at) < self.ttl);
            if map.len() >= self.max_entries {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, (at, _))| *at)
                    .map(|(key, _)| key.clone())
                {
                    map.remove(&oldest);
                }
            }
        }
        map.insert(key, (Instant::now(), value));
    }

    /// Remove one value and return it when it was still live.
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut map = self.lock();
        match map.remove(key) {
            Some((at, value)) if at.elapsed() < self.ttl => Some(value),
            _ => None,
        }
    }

    /// Drop every entry.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Number of stored entries, including entries that have not been read
    /// since they expired.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache currently stores no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<K, (Instant, V)>> {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_disables_the_cache() {
        let cache = TimedCache::new(Duration::from_secs(60), 0);
        cache.put("key", 1);
        assert_eq!(cache.get(&"key"), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn expires_after_the_ttl() {
        let cache = TimedCache::new(Duration::from_millis(5), 4);
        cache.put("key", 1);
        assert_eq!(cache.get(&"key"), Some(1));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cache.get(&"key"), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn never_exceeds_the_entry_cap() {
        let cache = TimedCache::new(Duration::from_secs(60), 2);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn remove_and_clear() {
        let cache = TimedCache::new(Duration::from_secs(60), 4);
        cache.put("a", 1);
        assert_eq!(cache.remove(&"a"), Some(1));
        assert_eq!(cache.remove(&"a"), None);
        cache.put("b", 2);
        cache.clear();
        assert!(cache.is_empty());
    }
}
