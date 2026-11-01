//! Parser configuration and resource limits.
//!
//! [`ParserConfig`] is a plain value object. It carries the URL layout the
//! renderer must reproduce, the interface language, the namespace table and
//! every limit that keeps a hostile page bounded. It has no I/O and no
//! database knowledge, so a caller can build one per site and reuse it.

use crate::namespaces::Namespaces;

/// Site layout and resource limits for one render.
///
/// The defaults describe a small English wiki: script path `/w`, article path
/// `/wiki/$1`, upload path `/images`, a 40-template depth and 2 MiB expansion
/// and page budgets. [`ParserConfig::default`] is safe for untrusted input;
/// the builder methods only replace the values a deployment needs.
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Path of the MediaWiki entry point, without a trailing slash.
    ///
    /// Used for `index.php?title=...` links, red links and `LOCALURL`/
    /// `FULLURL` query strings.
    pub script_path: String,
    /// Article path template. It must contain `$1`, which is replaced with the
    /// percent-encoded title.
    pub article_path: String,
    /// Absolute server URL (`https://wiki.example`) used by `FULLURL`,
    /// `SERVER` and canonical links. `None` keeps links local.
    pub server_url: Option<String>,
    /// Path of the uploaded files, without a trailing slash.
    pub upload_path: String,
    /// Path of the skin and style assets, without a trailing slash.
    pub style_path: String,
    /// Interface language code, used for `lang` attributes and
    /// `CONTENTLANGUAGE`.
    pub language: String,
    /// Site name used by `SITENAME`, the message context and `grammar` helpers.
    pub site_name: String,
    /// Version string returned by `CURRENTVERSION`.
    pub version: String,
    /// Namespace table used to parse and display titles.
    pub namespaces: Namespaces,
    /// Maximum template transclusion depth.
    pub max_template_depth: usize,
    /// Maximum number of bytes templates may add to the expanded source.
    pub max_expansion_bytes: usize,
    /// Maximum size of one transcluded page, in bytes.
    pub max_page_bytes: usize,
    /// Whether `{{#if:...}}` and the other parser functions are enabled.
    ///
    /// MediaWiki only provides these through the ParserFunctions extension.
    /// The default is `true`; a wiki that does not load the extension sets
    /// this to `false` and the functions render as literal text.
    pub enable_parser_functions: bool,
    /// URL prefixes allowed as external images.
    ///
    /// An empty list (the default) refuses every external image, matching a
    /// wiki with `$wgAllowExternalImages = false`.
    pub allow_external_images: Vec<String>,
    /// Plural rule used to select a `{{PLURAL:...}}` form.
    ///
    /// The value follows the phpBB/Mozilla rule numbering used by
    /// [`fador_i18n::plural_form`]; rule `1` is the two-form
    /// Germanic/Finno-Ugric rule MediaWiki uses for English and Finnish.
    pub plural_rule: u8,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            script_path: "/w".into(),
            article_path: "/wiki/$1".into(),
            server_url: None,
            upload_path: "/images".into(),
            style_path: "/skins".into(),
            language: "en".into(),
            site_name: "Wiki".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            namespaces: Namespaces::default(),
            max_template_depth: 40,
            max_expansion_bytes: 2 * 1024 * 1024,
            max_page_bytes: 2 * 1024 * 1024,
            enable_parser_functions: true,
            allow_external_images: Vec::new(),
            plural_rule: 1,
        }
    }
}

impl ParserConfig {
    /// A configuration with the documented defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the MediaWiki script path (`/w`).
    #[must_use]
    pub fn with_script_path(mut self, path: impl Into<String>) -> Self {
        self.script_path = path.into();
        self
    }

    /// Set the article path template (`/wiki/$1`).
    #[must_use]
    pub fn with_article_path(mut self, path: impl Into<String>) -> Self {
        self.article_path = path.into();
        self
    }

    /// Set the absolute server URL used by `FULLURL` and `SERVER`.
    #[must_use]
    pub fn with_server_url(mut self, url: impl Into<String>) -> Self {
        self.server_url = Some(url.into());
        self
    }

    /// Set the upload path (`/images`).
    #[must_use]
    pub fn with_upload_path(mut self, path: impl Into<String>) -> Self {
        self.upload_path = path.into();
        self
    }

    /// Set the style path (`/skins`).
    #[must_use]
    pub fn with_style_path(mut self, path: impl Into<String>) -> Self {
        self.style_path = path.into();
        self
    }

    /// Set the interface language code (`en`).
    #[must_use]
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = language.into();
        self
    }

    /// Set the site name returned by `SITENAME`.
    #[must_use]
    pub fn with_site_name(mut self, name: impl Into<String>) -> Self {
        self.site_name = name.into();
        self
    }

    /// Set the version string returned by `CURRENTVERSION`.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Replace the namespace table.
    #[must_use]
    pub fn with_namespaces(mut self, namespaces: Namespaces) -> Self {
        self.namespaces = namespaces;
        self
    }

    /// Set the maximum template transclusion depth.
    #[must_use]
    pub fn with_template_depth(mut self, depth: usize) -> Self {
        self.max_template_depth = depth;
        self
    }

    /// Set the maximum number of bytes templates may add.
    #[must_use]
    pub fn with_expansion_bytes(mut self, bytes: usize) -> Self {
        self.max_expansion_bytes = bytes;
        self
    }

    /// Set the maximum size of one transcluded page.
    #[must_use]
    pub fn with_page_bytes(mut self, bytes: usize) -> Self {
        self.max_page_bytes = bytes;
        self
    }

    /// Enable or disable the parser functions.
    #[must_use]
    pub fn with_parser_functions(mut self, enabled: bool) -> Self {
        self.enable_parser_functions = enabled;
        self
    }

    /// Allow external images from `prefix` (for example `https://cdn.example/`).
    #[must_use]
    pub fn with_external_image_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.allow_external_images.push(prefix.into());
        self
    }

    /// Set the plural rule used by `{{PLURAL:...}}`.
    #[must_use]
    pub fn with_plural_rule(mut self, rule: u8) -> Self {
        self.plural_rule = rule;
        self
    }

    /// The script path without a trailing slash, ready to concatenate.
    pub(crate) fn script_root(&self) -> &str {
        self.script_path.trim_end_matches('/')
    }

    /// The upload path without a trailing slash, ready to concatenate.
    pub(crate) fn upload_root(&self) -> &str {
        self.upload_path.trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bounded_and_english() {
        let config = ParserConfig::default();
        assert_eq!(config.script_path, "/w");
        assert_eq!(config.article_path, "/wiki/$1");
        assert_eq!(config.language, "en");
        assert!(config.enable_parser_functions);
        assert!(config.max_template_depth > 0);
        assert!(config.max_expansion_bytes > 0);
        assert!(config.max_page_bytes > 0);
        assert_eq!(config.plural_rule, 1);
        assert_eq!(config.script_root(), "/w");
        assert_eq!(config.upload_root(), "/images");
    }

    #[test]
    fn builders_replace_only_their_field() {
        let config = ParserConfig::new()
            .with_script_path("/mediawiki/")
            .with_article_path("/p/$1")
            .with_server_url("https://wiki.example/")
            .with_language("fi")
            .with_site_name("Testi")
            .with_template_depth(7)
            .with_expansion_bytes(1234)
            .with_page_bytes(4321)
            .with_parser_functions(false)
            .with_external_image_prefix("https://cdn.example/")
            .with_plural_rule(0);
        assert_eq!(config.script_root(), "/mediawiki");
        assert_eq!(config.article_path, "/p/$1");
        assert_eq!(config.server_url.as_deref(), Some("https://wiki.example/"));
        assert_eq!(config.language, "fi");
        assert_eq!(config.site_name, "Testi");
        assert_eq!(config.max_template_depth, 7);
        assert_eq!(config.max_expansion_bytes, 1234);
        assert_eq!(config.max_page_bytes, 4321);
        assert!(!config.enable_parser_functions);
        assert_eq!(config.allow_external_images.len(), 1);
        assert_eq!(config.plural_rule, 0);
    }
}
