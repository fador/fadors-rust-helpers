//! Namespace identifiers, localized names and special-page aliases.
//!
//! A wiki page title is a namespace id plus text. MediaWiki identifies the
//! namespace with a stable number and lets each language localize the prefix
//! (`File:` in English, `Tiedosto:` in Finnish). [`Namespaces`] stores both: the
//! localized name is what a reader sees, and the canonical English name is an
//! alias that always resolves, so stored wikitext written with either spelling
//! keeps working after a site language change.

use std::collections::HashMap;

/// One namespace and its accepted prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    /// The numeric namespace id (`0` is the main namespace, negative ids are
    /// special and media namespaces).
    pub id: i32,
    /// The localized prefix shown to readers. Empty for the main namespace.
    pub name: String,
    /// The language-independent MediaWiki name (`File`, `Category`, ...).
    pub canonical: String,
    /// Extra accepted prefixes (`Image` for the file namespace, ...).
    pub aliases: Vec<String>,
}

/// A namespace table with prefix lookup and special-page localization.
///
/// [`Namespaces::default`] contains the canonical English MediaWiki
/// namespaces. A deployment replaces the localized names with
/// [`Namespaces::insert`] and can add site-specific aliases there too.
#[derive(Debug, Clone)]
pub struct Namespaces {
    by_id: HashMap<i32, Namespace>,
    lookup: HashMap<String, i32>,
    special_names: HashMap<String, String>,
}

impl Default for Namespaces {
    fn default() -> Self {
        Self::standard()
    }
}

impl Namespaces {
    /// An empty table with no namespaces at all.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            lookup: HashMap::new(),
            special_names: HashMap::new(),
        }
    }

    /// The canonical English MediaWiki namespace table.
    ///
    /// The names are the stable identifiers from MediaWiki's canonical
    /// namespace list, not a translated language pack. `Image` is accepted as
    /// an alias of `File` because old wikitext uses it.
    #[must_use]
    pub fn standard() -> Self {
        let mut namespaces = Self::new();
        for (id, name, canonical, aliases) in [
            (-2, "Media", "Media", &[][..]),
            (-1, "Special", "Special", &[][..]),
            (0, "", "Main", &[][..]),
            (1, "Talk", "Talk", &[][..]),
            (2, "User", "User", &[][..]),
            (3, "User talk", "User talk", &[][..]),
            (4, "Project", "Project", &["Wiki"][..]),
            (5, "Project talk", "Project talk", &[][..]),
            (6, "File", "File", &["Image"][..]),
            (7, "File talk", "File talk", &["Image talk"][..]),
            (8, "MediaWiki", "MediaWiki", &[][..]),
            (9, "MediaWiki talk", "MediaWiki talk", &[][..]),
            (10, "Template", "Template", &[][..]),
            (11, "Template talk", "Template talk", &[][..]),
            (12, "Help", "Help", &[][..]),
            (13, "Help talk", "Help talk", &[][..]),
            (14, "Category", "Category", &[][..]),
            (15, "Category talk", "Category talk", &[][..]),
        ] {
            namespaces.insert(Namespace {
                id,
                name: name.to_string(),
                canonical: canonical.to_string(),
                aliases: aliases.iter().map(|alias| (*alias).to_string()).collect(),
            });
        }
        namespaces
    }

    /// The localized name for `id`, or an empty string for an unknown id.
    #[must_use]
    pub fn name(&self, id: i32) -> &str {
        self.by_id
            .get(&id)
            .map(|namespace| namespace.name.as_str())
            .unwrap_or("")
    }

    /// The full namespace record for `id`.
    #[must_use]
    pub fn namespace(&self, id: i32) -> Option<&Namespace> {
        self.by_id.get(&id)
    }

    /// Resolve a prefix (`File`, `Tiedosto`, `image`) to a namespace id.
    ///
    /// Matching is ASCII case-insensitive and treats underscores as spaces,
    /// exactly like MediaWiki's title parser.
    #[must_use]
    pub fn lookup(&self, prefix: &str) -> Option<i32> {
        self.lookup.get(&normalize_prefix(prefix)).copied()
    }

    /// The localized spelling of a canonical special-page name.
    ///
    /// Returns the input unchanged when the site has not localized it.
    #[must_use]
    pub fn localized_special(&self, name: &str) -> String {
        self.special_names
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    /// Record a localized spelling for a canonical special-page name.
    pub fn set_special_name(&mut self, canonical: &str, localized: &str) {
        self.special_names
            .insert(canonical.to_lowercase(), localized.to_string());
    }

    /// Insert or replace a namespace.
    ///
    /// Every non-empty prefix (name, canonical name and aliases) resolves to
    /// the namespace id. The first inserted spelling of a prefix wins, so a
    /// site that localizes `File` to `Tiedosto` keeps both `File` and
    /// `Tiedosto` working.
    pub fn insert(&mut self, namespace: Namespace) {
        for alias in std::iter::once(&namespace.name)
            .chain(std::iter::once(&namespace.canonical))
            .chain(namespace.aliases.iter())
        {
            if !alias.is_empty() {
                self.lookup
                    .entry(normalize_prefix(alias))
                    .or_insert(namespace.id);
            }
        }
        self.by_id.insert(namespace.id, namespace);
    }

    /// The number of namespaces in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the table contains no namespaces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Iterate over the namespaces in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = &Namespace> {
        self.by_id.values()
    }
}

fn normalize_prefix(prefix: &str) -> String {
    prefix.trim().replace('_', " ").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_table_resolves_canonical_and_alias_prefixes() {
        let namespaces = Namespaces::standard();
        assert_eq!(namespaces.name(6), "File");
        assert_eq!(namespaces.lookup("File"), Some(6));
        assert_eq!(namespaces.lookup("file"), Some(6));
        assert_eq!(namespaces.lookup("Image"), Some(6));
        assert_eq!(namespaces.lookup("Category"), Some(14));
        assert_eq!(namespaces.lookup("Nope"), None);
        assert_eq!(namespaces.name(0), "");
        assert!(namespaces.len() >= 18);
        assert!(!namespaces.is_empty());
    }

    #[test]
    fn localized_names_keep_the_canonical_alias() {
        let mut namespaces = Namespaces::standard();
        namespaces.insert(Namespace {
            id: 6,
            name: "Tiedosto".into(),
            canonical: "File".into(),
            aliases: vec!["Kuva".into()],
        });
        assert_eq!(namespaces.name(6), "Tiedosto");
        assert_eq!(namespaces.lookup("Tiedosto"), Some(6));
        assert_eq!(namespaces.lookup("tiedosto"), Some(6));
        assert_eq!(namespaces.lookup("File"), Some(6));
        assert_eq!(namespaces.lookup("Kuva"), Some(6));
    }

    #[test]
    fn special_names_are_localized() {
        let mut namespaces = Namespaces::standard();
        assert_eq!(namespaces.localized_special("Search"), "Search");
        namespaces.set_special_name("Search", "Haku");
        assert_eq!(namespaces.localized_special("search"), "Haku");
        assert_eq!(namespaces.localized_special("Unknown"), "Unknown");
    }
}
