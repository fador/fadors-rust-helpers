//! The data the renderer needs from a wiki, behind one trait.
//!
//! [`WikiResolver`] is the whole database surface of the parser: page text,
//! page existence, file metadata, two counters and the site statistics. An
//! application implements it over its own storage; [`MemoryResolver`] is the
//! same trait backed by a map, for tests and small embeds.

use std::collections::HashMap;

/// The key of a page in a resolver: namespace id and database title.
pub type TitleKey = (i32, String);

/// Whether a page exists and whether it is a redirect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PageFlags {
    /// Whether the page exists.
    pub exists: bool,
    /// Whether the page is a redirect.
    pub redirect: bool,
}

impl PageFlags {
    /// Build flags from an existence and redirect pair.
    #[must_use]
    pub fn new(exists: bool, redirect: bool) -> Self {
        Self { exists, redirect }
    }

    /// Flags for a page that does not exist.
    #[must_use]
    pub fn missing() -> Self {
        Self::default()
    }
}

/// Metadata for one uploaded file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    /// File name in database form (underscores, no namespace prefix).
    pub name: String,
    /// File size in bytes, when known.
    pub size: u64,
    /// Original image width in pixels. Zero for a non-image file.
    pub width: u32,
    /// Original image height in pixels. Zero for a non-image file.
    pub height: u32,
}

impl FileInfo {
    /// Build file metadata with an unknown size.
    #[must_use]
    pub fn new(name: impl Into<String>, width: u32, height: u32) -> Self {
        Self {
            name: name.into(),
            size: 0,
            width,
            height,
        }
    }

    /// Set the file size in bytes.
    #[must_use]
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }
}

/// The counters behind the `NUMBEROF...` magic words.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SiteStats {
    /// All edits.
    pub edits: u64,
    /// Content pages.
    pub articles: u64,
    /// All pages.
    pub pages: u64,
    /// Registered users.
    pub users: u64,
    /// Recently active users.
    pub active_users: u64,
    /// Uploaded files.
    pub images: u64,
}

/// The revision values behind `REVISIONID`, `REVISIONTIMESTAMP` and
/// `REVISIONUSER`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevisionInfo {
    /// Revision id.
    pub id: u64,
    /// MediaWiki 14-digit timestamp.
    pub timestamp: String,
    /// User name.
    pub user: String,
}

/// Everything the renderer needs to read from a wiki.
///
/// Every method is allowed to be slow; the renderer caches the answers in a
/// [`crate::ParserCache`] when the caller supplies one. A method that has no
/// answer returns `None`, and the renderer treats that as "missing".
pub trait WikiResolver {
    /// The stored wikitext of a page, without the namespace prefix.
    ///
    /// `title` is in database form (underscores). Returning `None` means the
    /// page does not exist.
    fn page_wikitext(&self, ns: i32, title: &str) -> Option<String>;

    /// Whether a page exists and whether it is a redirect.
    fn page_flags(&self, ns: i32, title: &str) -> PageFlags;

    /// Metadata for a file name in database form.
    fn file_info(&self, name: &str) -> Option<FileInfo>;

    /// The number of pages in a category, for `PAGESINCATEGORY`.
    fn category_count(&self, name: &str) -> Option<u64>;

    /// The number of pages in a namespace, for `PAGESINNAMESPACE`.
    fn page_count_in_namespace(&self, ns: i32) -> Option<u64>;

    /// The site statistics, for the `NUMBEROF...` magic words.
    fn site_stats(&self) -> SiteStats;

    /// Batch existence lookup used to prefetch link colours.
    ///
    /// The default implementation calls [`WikiResolver::page_flags`] once per
    /// key and returns only the pages that exist. A database resolver should
    /// override it with one query.
    fn existing_titles(&self, titles: &[TitleKey]) -> Vec<(TitleKey, PageFlags)> {
        titles
            .iter()
            .filter_map(|key| {
                let flags = self.page_flags(key.0, &key.1);
                flags.exists.then(|| (key.clone(), flags))
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
struct MemoryPage {
    text: String,
    redirect: bool,
}

/// A [`WikiResolver`] backed by maps.
///
/// This is the stub resolver the tests and the crate examples use. Page titles
/// are stored in database form, so `with_page(10, "Hello world", ...)` is
/// found by a link to `[[Template:Hello world]]`.
#[derive(Debug, Clone, Default)]
pub struct MemoryResolver {
    pages: HashMap<TitleKey, MemoryPage>,
    files: HashMap<String, FileInfo>,
    category_counts: HashMap<String, u64>,
    namespace_counts: HashMap<i32, u64>,
    stats: SiteStats,
}

impl MemoryResolver {
    /// An empty resolver: every page is missing and every counter is zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a page.
    #[must_use]
    pub fn with_page(mut self, ns: i32, title: &str, text: impl Into<String>) -> Self {
        self.pages.insert(
            (ns, database_title(title)),
            MemoryPage {
                text: text.into(),
                redirect: false,
            },
        );
        self
    }

    /// Add a redirect page that points at `target`.
    ///
    /// The stored text is `#REDIRECT [[target]]`, so the renderer follows it
    /// exactly as it follows a redirect read from a database.
    #[must_use]
    pub fn with_redirect(mut self, ns: i32, title: &str, target: &str) -> Self {
        self.pages.insert(
            (ns, database_title(title)),
            MemoryPage {
                text: format!("#REDIRECT [[{target}]]"),
                redirect: true,
            },
        );
        self
    }

    /// Add or replace a file.
    ///
    /// The file name is normalized to database form (spaces become
    /// underscores), matching what the renderer asks for.
    #[must_use]
    pub fn with_file(mut self, file: FileInfo) -> Self {
        let mut file = file;
        file.name = database_title(&file.name);
        self.files.insert(file.name.clone(), file);
        self
    }

    /// Set the page count of a category.
    #[must_use]
    pub fn with_category_count(mut self, name: &str, count: u64) -> Self {
        self.category_counts.insert(database_title(name), count);
        self
    }

    /// Set the page count of a namespace.
    #[must_use]
    pub fn with_namespace_count(mut self, ns: i32, count: u64) -> Self {
        self.namespace_counts.insert(ns, count);
        self
    }

    /// Set the site statistics.
    #[must_use]
    pub fn with_site_stats(mut self, stats: SiteStats) -> Self {
        self.stats = stats;
        self
    }
}

impl WikiResolver for MemoryResolver {
    fn page_wikitext(&self, ns: i32, title: &str) -> Option<String> {
        self.pages
            .get(&(ns, database_title(title)))
            .map(|page| page.text.clone())
    }

    fn page_flags(&self, ns: i32, title: &str) -> PageFlags {
        self.pages
            .get(&(ns, database_title(title)))
            .map(|page| PageFlags::new(true, page.redirect))
            .unwrap_or_default()
    }

    fn file_info(&self, name: &str) -> Option<FileInfo> {
        self.files.get(&database_title(name)).cloned()
    }

    fn category_count(&self, name: &str) -> Option<u64> {
        self.category_counts.get(&database_title(name)).copied()
    }

    fn page_count_in_namespace(&self, ns: i32) -> Option<u64> {
        self.namespace_counts.get(&ns).copied()
    }

    fn site_stats(&self) -> SiteStats {
        self.stats
    }
}

fn database_title(title: &str) -> String {
    title.trim().replace(' ', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_resolver_answers_every_question() {
        let resolver = MemoryResolver::new()
            .with_page(10, "Hello world", "Hi")
            .with_redirect(10, "Old", "Hello world")
            .with_file(FileInfo::new("Pic.png", 640, 480).with_size(1234))
            .with_category_count("People", 7)
            .with_namespace_count(0, 42)
            .with_site_stats(SiteStats {
                pages: 9,
                ..SiteStats::default()
            });
        assert_eq!(
            resolver.page_wikitext(10, "Hello_world").as_deref(),
            Some("Hi")
        );
        assert_eq!(resolver.page_wikitext(10, "Missing"), None);
        assert_eq!(
            resolver.page_flags(10, "Hello_world"),
            PageFlags::new(true, false)
        );
        assert_eq!(resolver.page_flags(10, "Old"), PageFlags::new(true, true));
        assert_eq!(resolver.page_flags(10, "Missing"), PageFlags::missing());
        let file = resolver.file_info("Pic.png").unwrap();
        assert_eq!((file.width, file.height, file.size), (640, 480, 1234));
        assert_eq!(resolver.category_count("People"), Some(7));
        assert_eq!(resolver.page_count_in_namespace(0), Some(42));
        assert_eq!(resolver.page_count_in_namespace(1), None);
        assert_eq!(resolver.site_stats().pages, 9);
    }

    #[test]
    fn file_names_are_normalized_to_database_form() {
        let resolver = MemoryResolver::new().with_file(FileInfo::new("Pic one.png", 10, 20));
        let file = resolver.file_info("Pic_one.png").expect("file");
        assert_eq!(file.name, "Pic_one.png");
        assert_eq!(
            resolver.file_info("Pic one.png").map(|file| file.name),
            Some("Pic_one.png".into())
        );
    }

    #[test]
    fn default_existing_titles_returns_only_existing_pages() {
        let resolver = MemoryResolver::new().with_page(0, "A", "a");
        let found =
            resolver.existing_titles(&[(0, "A".into()), (0, "B".into()), (1, "Talk".into())]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, (0, "A".to_string()));
        assert!(found[0].1.exists);
    }
}
