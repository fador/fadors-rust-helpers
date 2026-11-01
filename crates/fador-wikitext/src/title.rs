//! MediaWiki title parsing and URL construction.
//!
//! A [`Title`] is a namespace id, normalized text and an optional fragment.
//! Parsing follows MediaWiki's common cases: a leading `:` forces the main
//! namespace, underscores become spaces, whitespace collapses, the first
//! character is uppercased and characters that cannot occur in a title are
//! rejected. The text is repaired from the common Latin-1/UTF-8 double encoding
//! the legacy editor produced, so a page stored as `KylÃ¤t` still links to
//! `Kylät`.

use fador_core::util::{anchor_encode, encode_title, normalize_title_text, repair_mojibake};

use crate::config::ParserConfig;
use crate::namespaces::Namespaces;

/// A parsed page title.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Title {
    /// Namespace id (`0` main, `-1` special, `6` file, `14` category, ...).
    pub ns: i32,
    /// Title text without the namespace prefix, using spaces (not
    /// underscores).
    pub text: String,
    /// Optional section fragment, without the `#`.
    pub fragment: Option<String>,
}

impl Title {
    /// Build a title from an already normalized namespace id and text.
    ///
    /// Underscores become spaces and the text is repaired from double-encoded
    /// UTF-8. Unlike [`Title::parse`] this never fails: it is for callers that
    /// already know the namespace.
    #[must_use]
    pub fn new(ns: i32, text: impl Into<String>) -> Self {
        let text = repair_mojibake(&text.into());
        Self {
            ns,
            text: text.replace('_', " "),
            fragment: None,
        }
    }

    /// Parse a title as it appears in wikitext.
    ///
    /// Returns `None` when the text is empty, longer than 255 bytes or contains
    /// a character MediaWiki forbids in a title (`#`, `<`, `>`, `[`, `]`, `{`,
    /// `}`, `|` or a control character).
    #[must_use]
    pub fn parse(input: &str, namespaces: &Namespaces) -> Option<Title> {
        let mut text = input.trim();
        let mut forced_main = false;
        if let Some(rest) = text.strip_prefix(':') {
            forced_main = true;
            text = rest.trim_start();
        }
        let (mut ns, mut text) = (0, text);
        if !forced_main {
            if let Some(colon) = text.find(':') {
                let prefix = &text[..colon];
                if let Some(id) = namespaces.lookup(prefix) {
                    ns = id;
                    text = &text[colon + 1..];
                }
            }
        }
        let mut fragment = None;
        if let Some(hash) = text.find('#') {
            let candidate = text[hash + 1..].to_string();
            text = &text[..hash];
            if !candidate.is_empty() {
                fragment = Some(candidate);
            }
        }
        let normalized = normalize_title_text(text)?;
        let normalized = repair_mojibake(&normalized);
        Some(Title {
            ns,
            text: normalized,
            fragment,
        })
    }

    /// Whether this is a special-page title (namespace `-1`).
    #[must_use]
    pub fn is_special(&self) -> bool {
        self.ns == -1
    }

    /// Whether this is a file title (namespace `6`).
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.ns == 6
    }

    /// Whether this is a category title (namespace `14`).
    #[must_use]
    pub fn is_category(&self) -> bool {
        self.ns == 14
    }

    /// The title text in database form (spaces become underscores).
    #[must_use]
    pub fn db_title(&self) -> String {
        self.text.replace(' ', "_")
    }

    /// The namespace-prefixed title shown to readers.
    ///
    /// A special-page name is localized through
    /// [`Namespaces::localized_special`].
    #[must_use]
    pub fn full_text(&self, namespaces: &Namespaces) -> String {
        if self.ns == 0 {
            return self.text.clone();
        }
        let name = namespaces.name(self.ns);
        if name.is_empty() {
            return self.text.clone();
        }
        if self.ns == -1 {
            format!("{name}:{}", namespaces.localized_special(&self.text))
        } else {
            format!("{name}:{}", self.text)
        }
    }

    /// The namespace-prefixed title in database form.
    #[must_use]
    pub fn full_db(&self, namespaces: &Namespaces) -> String {
        if self.ns == 0 {
            self.db_title()
        } else {
            format!("{}:{}", namespaces.name(self.ns), self.db_title())
        }
    }

    /// The local article URL, including the encoded fragment.
    ///
    /// `config.article_path` normally contains `$1`. A path without it is
    /// treated as a prefix so a misconfiguration cannot silently produce the
    /// same URL for every page.
    #[must_use]
    pub fn local_url(&self, config: &ParserConfig, namespaces: &Namespaces) -> String {
        let encoded = encode_title(&self.full_text(namespaces));
        let mut url = if config.article_path.contains("$1") {
            config.article_path.replace("$1", &encoded)
        } else {
            format!("{}{encoded}", config.article_path)
        };
        if let Some(fragment) = &self.fragment {
            if !url.ends_with('#') {
                url.push('#');
            }
            url.push_str(&anchor_encode(fragment));
        }
        url
    }

    /// The absolute article URL when `config.server_url` is set, otherwise the
    /// local URL.
    #[must_use]
    pub fn canonical_url(&self, config: &ParserConfig, namespaces: &Namespaces) -> String {
        let path = self.local_url(config, namespaces);
        match &config.server_url {
            Some(server) if !server.is_empty() => {
                format!("{}{path}", server.trim_end_matches('/'))
            }
            _ => path,
        }
    }

    /// The display form used by the renderer.
    #[must_use]
    pub fn display(&self, namespaces: &Namespaces) -> String {
        if self.ns == -1 {
            return format!(
                "{}:{}",
                namespaces.name(-1),
                namespaces.localized_special(&self.text)
            );
        }
        self.full_text(namespaces)
    }

    /// The first subpage component (`A/B/C` becomes `A`).
    #[must_use]
    pub fn root_page(&self) -> String {
        self.text
            .split('/')
            .next()
            .unwrap_or(&self.text)
            .to_string()
    }

    /// The subject title of a talk page, or the title itself.
    #[must_use]
    pub fn subject(&self) -> Title {
        let ns = if self.ns > 0 && self.ns % 2 == 1 {
            self.ns - 1
        } else {
            self.ns
        };
        Title {
            ns,
            text: self.text.clone(),
            fragment: self.fragment.clone(),
        }
    }

    /// The talk title of a subject page, or the title itself.
    #[must_use]
    pub fn talk(&self) -> Title {
        let ns = if self.ns < 0 || self.ns % 2 == 1 {
            self.ns
        } else {
            self.ns + 1
        };
        Title {
            ns,
            text: self.text.clone(),
            fragment: self.fragment.clone(),
        }
    }

    /// A copy of this title with a different fragment.
    #[must_use]
    pub fn with_fragment(&self, fragment: Option<String>) -> Self {
        Self {
            ns: self.ns,
            text: self.text.clone(),
            fragment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespaces() -> Namespaces {
        let mut namespaces = Namespaces::standard();
        for (id, name, canonical) in [
            (-1, "Toiminnot", "Special"),
            (6, "Tiedosto", "File"),
            (14, "Luokka", "Category"),
        ] {
            namespaces.insert(crate::namespaces::Namespace {
                id,
                name: name.into(),
                canonical: canonical.into(),
                aliases: Vec::new(),
            });
        }
        namespaces
    }

    #[test]
    fn parses_titles() {
        let namespaces = namespaces();
        let title = Title::parse("Luokka:Naruto", &namespaces).unwrap();
        assert_eq!(title.ns, 14);
        assert_eq!(title.text, "Naruto");

        let title = Title::parse("naruto uzumaki", &namespaces).unwrap();
        assert_eq!(title.ns, 0);
        assert_eq!(title.text, "Naruto uzumaki");

        let title = Title::parse("Tiedosto:Kuva.jpg#osa", &namespaces).unwrap();
        assert_eq!(title.ns, 6);
        assert_eq!(title.text, "Kuva.jpg");
        assert_eq!(title.fragment.as_deref(), Some("osa"));

        let title = Title::parse(":Luokka:Naruto", &namespaces).unwrap();
        assert_eq!(title.ns, 0);
        assert_eq!(title.text, "Luokka:Naruto");
    }

    #[test]
    fn rejects_invalid_titles() {
        let namespaces = namespaces();
        assert!(Title::parse("", &namespaces).is_none());
        assert!(Title::parse("a|b", &namespaces).is_none());
        assert!(Title::parse("\0", &namespaces).is_none());
        assert!(Title::parse(&"x".repeat(300), &namespaces).is_none());
    }

    #[test]
    fn repairs_mojibake_titles() {
        let namespaces = namespaces();
        for variant in fador_core::util::mojibake_variants("Sisältö puutteellinen") {
            let title = Title::parse(&format!("Luokka:{variant}"), &namespaces).unwrap();
            assert_eq!(title.ns, 14);
            assert_eq!(title.text, "Sisältö puutteellinen");
        }
    }

    #[test]
    fn builds_urls_and_family_titles() {
        let namespaces = namespaces();
        let config = ParserConfig::default()
            .with_article_path("/wiki/$1")
            .with_server_url("https://wiki.example/");
        let title = Title::parse("Tiedosto:Kuva.jpg#osa yksi", &namespaces).unwrap();
        assert_eq!(
            title.local_url(&config, &namespaces),
            "/wiki/Tiedosto:Kuva.jpg#osa_yksi"
        );
        assert_eq!(
            title.canonical_url(&config, &namespaces),
            "https://wiki.example/wiki/Tiedosto:Kuva.jpg#osa_yksi"
        );
        assert_eq!(title.db_title(), "Kuva.jpg");
        assert_eq!(title.full_db(&namespaces), "Tiedosto:Kuva.jpg");

        let title = Title::parse("Talk:Naruto/A/1", &namespaces).unwrap();
        assert_eq!(title.ns, 1);
        assert_eq!(title.root_page(), "Naruto");
        assert_eq!(title.subject().ns, 0);
        assert_eq!(title.talk().ns, 1);
        assert_eq!(
            title.with_fragment(Some("x".into())).fragment.as_deref(),
            Some("x")
        );

        let special = Title::parse("Toiminnot:Haku", &namespaces).unwrap();
        assert!(special.is_special());
        assert_eq!(special.full_text(&namespaces), "Toiminnot:Haku");
        assert_eq!(special.display(&namespaces), "Toiminnot:Haku");
    }

    #[test]
    fn article_path_without_placeholder_is_a_prefix() {
        let namespaces = Namespaces::standard();
        let config = ParserConfig::default().with_article_path("/p/");
        let title = Title::new(0, "Page");
        assert_eq!(title.local_url(&config, &namespaces), "/p/Page");
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::testutil::{Rng, MALICIOUS_STRINGS};

    #[test]
    fn fuzz_title_parsing_and_urls() {
        let namespaces = Namespaces::standard();
        let config = ParserConfig::default().with_article_path("/wiki/$1");
        let mut rng = Rng::new(0x71a7_0001);
        for _ in 0..2_000 {
            let length = rng.below(400);
            let input = rng.text(length);
            if let Some(title) = Title::parse(&input, &namespaces) {
                assert!(!title.text.is_empty());
                assert!(title.text.len() <= 255);
                assert!(!title.text.chars().any(char::is_control));
                assert!(!title
                    .text
                    .chars()
                    .any(|c| matches!(c, '#' | '<' | '>' | '[' | ']' | '{' | '}' | '|')));
                let url = title.local_url(&config, &namespaces);
                assert!(url.starts_with("/wiki/"));
                assert!(!url.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n'));
                let db = title.db_title();
                assert!(!db.is_empty());
                assert!(!db.contains(' '));
            }
        }
        for input in MALICIOUS_STRINGS {
            let _ = Title::parse(input, &namespaces);
            if let Some(title) = Title::parse(input, &namespaces) {
                let url = title.local_url(&config, &namespaces);
                assert!(!url.contains('\r') && !url.contains('\n') && !url.contains('\0'));
            }
        }
        assert!(Title::parse(&"x".repeat(100_000), &namespaces).is_none());
        assert!(Title::parse("\0", &namespaces).is_none());
    }
}
