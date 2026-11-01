//! Optional cross-render caches for resolver answers.
//!
//! A render asks the same questions several times: a template is transcluded
//! by two pages, a link target is checked twice in one page, an image appears
//! in a gallery and in its caption. [`ParserCache`] keeps those answers for a
//! short time. It is deliberately a small TTL cache, not a correctness layer:
//! every value is exactly what the resolver would return, and dropping the
//! cache only costs queries.

use std::time::Duration;

use fador_core::cache::TimedCache;

use crate::resolver::{FileInfo, PageFlags, SiteStats};

/// A bounded TTL cache for one wiki's resolver answers.
///
/// [`Parser::render`](crate::Parser::render) uses a disabled cache and never
/// keeps state between calls. [`Parser::render_cached`](crate::Parser::render_cached)
/// takes a caller-owned cache so a server can reuse template text and link
/// colours across requests.
pub struct ParserCache {
    pub(crate) templates: TimedCache<(i32, String), Option<String>>,
    pub(crate) pages: TimedCache<(i32, String), PageFlags>,
    pub(crate) files: TimedCache<String, Option<FileInfo>>,
    pub(crate) stats: TimedCache<(), SiteStats>,
}

impl ParserCache {
    /// Create a cache whose entries live for `ttl`.
    ///
    /// The capacities are 2,048 templates, 8,192 page flags, 2,048 files and
    /// one site-statistics value. A zero `ttl` disables storage.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            templates: TimedCache::new(ttl, 2_048),
            pages: TimedCache::new(ttl, 8_192),
            files: TimedCache::new(ttl, 2_048),
            stats: TimedCache::new(ttl, 1),
        }
    }

    /// A cache that stores nothing.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            templates: TimedCache::new(Duration::ZERO, 0),
            pages: TimedCache::new(Duration::ZERO, 0),
            files: TimedCache::new(Duration::ZERO, 0),
            stats: TimedCache::new(Duration::ZERO, 0),
        }
    }

    /// Drop every stored answer.
    pub fn clear(&self) {
        self.templates.clear();
        self.pages.clear();
        self.files.clear();
        self.stats.clear();
    }

    /// The total number of stored entries, including expired ones that have
    /// not been read since they expired.
    #[must_use]
    pub fn len(&self) -> usize {
        self.templates.len() + self.pages.len() + self.files.len() + self.stats.len()
    }

    /// Whether the cache stores no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_cache_never_stores() {
        let cache = ParserCache::disabled();
        cache.templates.put((10, "A".into()), Some("x".into()));
        cache
            .pages
            .put((0, "A".into()), PageFlags::new(true, false));
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_stores_and_clears() {
        let cache = ParserCache::new(Duration::from_secs(60));
        cache.templates.put((10, "A".into()), Some("x".into()));
        cache
            .pages
            .put((0, "A".into()), PageFlags::new(true, false));
        cache.files.put("A.png".into(), None);
        cache.stats.put((), SiteStats::default());
        assert_eq!(cache.len(), 4);
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }
}
