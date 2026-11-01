//! Interface messages and the message syntax the renderer understands.
//!
//! The renderer never reads a language pack. It asks a [`MessageSource`] for a
//! key and falls back to a small English table for the strings it emits itself
//! (the table of contents title, the section edit link, Cite errors and the
//! month and day names). A deployment supplies its own translated values by
//! implementing the trait or filling a [`MapMessages`].
//!
//! Message expansion supports the subset of MediaWiki message syntax the
//! source wiki uses: `$1`..`$9` parameters, `{{int:key}}`, `{{PLURAL:...}}`,
//! `{{GRAMMAR:...}}`, `{{GENDER:...}}` and the common page/date variables.
//! The `$n` placeholders stay local because MediaWiki messages use `$1` rather
//! than `sprintf`'s `%s`; `{{PLURAL:...}}` selection uses
//! [`fador_i18n::plural_form`].

use std::collections::HashMap;

use crate::config::ParserConfig;

/// The source of interface messages.
///
/// A key that is not present may fall back to the renderer's built-in English
/// text; [`MessageSource::has`] reports only what the source itself provides.
pub trait MessageSource {
    /// Return the raw text for `key`, or `None` when the source does not
    /// provide it.
    fn message(&self, key: &str) -> Option<String>;

    /// Whether the source itself provides `key`.
    fn has(&self, key: &str) -> bool {
        self.message(key).is_some()
    }
}

/// A simple in-memory [`MessageSource`].
#[derive(Debug, Clone, Default)]
pub struct MapMessages {
    messages: HashMap<String, String>,
}

impl MapMessages {
    /// An empty message map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A map preloaded with the renderer's built-in English messages.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut messages = Self::new();
        for (key, text) in DEFAULT_MESSAGES {
            messages.insert(*key, *text);
        }
        messages
    }

    /// Insert or replace one message.
    pub fn insert(&mut self, key: impl Into<String>, text: impl Into<String>) {
        self.messages.insert(key.into(), text.into());
    }

    /// Insert one message and return the map, for chaining.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, text: impl Into<String>) -> Self {
        self.insert(key, text);
        self
    }

    /// Build a map from an iterator of key/value pairs.
    #[must_use]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut messages = Self::new();
        for (key, value) in pairs {
            messages.insert(key, value);
        }
        messages
    }

    /// The number of messages in the map.
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the map contains no messages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

impl MessageSource for MapMessages {
    fn message(&self, key: &str) -> Option<String> {
        self.messages.get(key).cloned()
    }
}

/// The page and date values a message may interpolate.
#[derive(Debug, Clone, Default)]
pub struct MessageContext {
    /// `{{SITENAME}}`.
    pub sitename: String,
    /// `{{PAGENAME}}`.
    pub pagename: String,
    /// `{{FULLPAGENAME}}`.
    pub fullpagename: String,
    /// `{{NAMESPACE}}`.
    pub namespace: String,
    /// `{{CURRENTYEAR}}`.
    pub year: i32,
    /// `{{CURRENTMONTH}}`.
    pub month: u32,
    /// `{{CURRENTDAY}}`.
    pub day: u32,
    /// `{{CURRENTHOUR}}` / `{{CURRENTTIME}}`.
    pub hour: u32,
    /// `{{CURRENTTIME}}`.
    pub minute: u32,
}

/// The renderer's own English fallback messages.
///
/// These are short functional phrases written for this crate, not a copy of a
/// MediaWiki language pack. A deployment overrides them through its
/// [`MessageSource`].
pub(crate) const DEFAULT_MESSAGES: &[(&str, &str)] = &[
    ("toc", "Contents"),
    ("editsection", "edit"),
    ("editsectionhint", "Edit section: $1"),
    ("red-link-title", "$1 (page does not exist)"),
    ("thumbnail-more", "Enlarge"),
    (
        "parser-template-recursion-error",
        "Template recursion depth exceeded: $1",
    ),
    ("cite_error", "Cite error: $1"),
    ("cite_error_ref_no_input", "ref with no content"),
    ("cite_error_references_no_text", "ref $1 has no text"),
    ("sunday", "Sunday"),
    ("monday", "Monday"),
    ("tuesday", "Tuesday"),
    ("wednesday", "Wednesday"),
    ("thursday", "Thursday"),
    ("friday", "Friday"),
    ("saturday", "Saturday"),
    ("january", "January"),
    ("february", "February"),
    ("march", "March"),
    ("april", "April"),
    ("may", "May"),
    ("june", "June"),
    ("july", "July"),
    ("august", "August"),
    ("september", "September"),
    ("october", "October"),
    ("november", "November"),
    ("december", "December"),
];

pub(crate) fn default_message(key: &str) -> Option<&'static str> {
    DEFAULT_MESSAGES
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, text)| *text)
}

/// Expands interface messages for one page.
pub(crate) struct MessageFormatter<'a> {
    source: &'a dyn MessageSource,
    config: &'a ParserConfig,
    context: MessageContext,
}

impl<'a> MessageFormatter<'a> {
    pub(crate) fn new(
        source: &'a dyn MessageSource,
        config: &'a ParserConfig,
        context: MessageContext,
    ) -> Self {
        Self {
            source,
            config,
            context,
        }
    }

    /// The raw message text, without parameter or magic-word expansion.
    pub(crate) fn raw(&self, key: &str) -> String {
        self.source
            .message(key)
            .or_else(|| default_message(key).map(str::to_string))
            .unwrap_or_else(|| key.to_string())
    }

    /// The expanded message text.
    pub(crate) fn text(&self, key: &str) -> String {
        self.format(key, &[])
    }

    /// The expanded message with `$1`..`$9` substituted.
    pub(crate) fn format(&self, key: &str, params: &[&str]) -> String {
        let raw = self.raw(key);
        expand_message(&raw, params, &self.context, self, 0)
    }
}

const PARAM_MARKERS: [&str; 9] = ["$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9"];

fn expand_message(
    raw: &str,
    params: &[&str],
    context: &MessageContext,
    formatter: &MessageFormatter<'_>,
    depth: u32,
) -> String {
    if depth > 8 {
        return raw.to_string();
    }
    // Substitute parameters in two stages. First replace $1..$9 with opaque
    // placeholders so a value containing "$2" cannot be substituted again.
    // Then insert the value with braces neutralised: numeric parameters still
    // work inside {{PLURAL:$1|...}}, but caller data can never be parsed as a
    // message or template invocation.
    const LBRACE: &str = "\u{1}MWLBRACE\u{1}";
    const RBRACE: &str = "\u{1}MWRBRACE\u{1}";
    let mut text = raw.to_string();
    let mut substitutions: Vec<(String, String)> = Vec::new();
    for (index, marker) in PARAM_MARKERS.iter().enumerate() {
        if let Some(value) = params.get(index) {
            let placeholder = format!("\u{1}MWPARAM{index}\u{1}");
            text = text.replace(marker, &placeholder);
            substitutions.push((placeholder, value.replace('{', LBRACE).replace('}', RBRACE)));
        }
    }
    for (placeholder, value) in &substitutions {
        text = text.replace(placeholder, value);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    let mut guard = 0;
    while let Some(position) = rest.find("{{") {
        out.push_str(&rest[..position]);
        let after = &rest[position + 2..];
        let Some(end) = find_message_end(after) else {
            out.push_str("{{");
            rest = after;
            continue;
        };
        let inner = &after[..end];
        let replacement = if let Some(key) = inner.strip_prefix("int:") {
            let key = key.trim();
            let raw_inner = formatter.raw(key);
            expand_message(&raw_inner, &[], context, formatter, depth + 1)
        } else if let Some(rest) = inner.strip_prefix("PLURAL:") {
            if let Some((number, forms)) = rest.split_once('|') {
                let count = number.trim().parse::<u64>().unwrap_or(0);
                let parts = split_top(forms, '|');
                let chosen = select_plural_form(&parts, count, formatter.config.plural_rule);
                expand_message(&chosen, &[], context, formatter, depth + 1)
            } else {
                inner.to_string()
            }
        } else if let Some(rest) = inner.strip_prefix("GRAMMAR:") {
            if let Some((_case, word)) = rest.split_once('|') {
                let word = expand_message(word, &[], context, formatter, depth + 1);
                grammar_fi(&word)
            } else {
                inner.to_string()
            }
        } else if let Some(rest) = inner.strip_prefix("GENDER:") {
            let parts = split_top(rest, '|');
            let chosen = parts.get(1).cloned().unwrap_or_default();
            expand_message(&chosen, &[], context, formatter, depth + 1)
        } else {
            match inner.trim() {
                "SITENAME" => context.sitename.clone(),
                "PAGENAME" | "PAGENAMEE" => context.pagename.clone(),
                "FULLPAGENAME" | "FULLPAGENAMEE" => context.fullpagename.clone(),
                "NAMESPACE" | "NAMESPACEE" => context.namespace.clone(),
                "CURRENTYEAR" => context.year.to_string(),
                "CURRENTMONTH" => format!("{:02}", context.month),
                "CURRENTMONTH1" => context.month.to_string(),
                "CURRENTDAY" => context.day.to_string(),
                "CURRENTDAY2" => format!("{:02}", context.day),
                "CURRENTHOUR" => format!("{:02}", context.hour),
                "CURRENTTIME" => format!("{:02}:{:02}", context.hour, context.minute),
                _ => {
                    // Unknown magic word: leave it alone, mirroring the
                    // renderer's behaviour for an unregistered template.
                    format!("{{{{{inner}}}}}")
                }
            }
        };
        out.push_str(&replacement);
        rest = &after[end + 2..];
        guard += 1;
        if guard > 64 {
            out.push_str(rest);
            break;
        }
    }
    out.push_str(rest);
    out.replace(LBRACE, "{").replace(RBRACE, "}")
}

/// Pick a `{{PLURAL:...}}` form using the configured phpBB/Mozilla rule.
///
/// `plural_form` returns a 1-based form number; the message's first form is
/// form 1. A missing form falls back to the last one, exactly like MediaWiki's
/// plural fallback for a language with fewer forms than the message.
fn select_plural_form(parts: &[String], count: u64, rule: u8) -> String {
    if parts.is_empty() {
        return String::new();
    }
    let form = fador_i18n::plural_form(count as i64, rule);
    let index = (form as usize).saturating_sub(1).min(parts.len() - 1);
    parts[index].clone()
}

fn find_message_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 1i32;
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'{' && bytes[index + 1] == b'{' {
            depth += 1;
            index += 2;
            continue;
        }
        if bytes[index] == b'}' && bytes[index + 1] == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
            index += 2;
            continue;
        }
        index += 1;
    }
    None
}

fn split_top(text: &str, separator: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for character in text.chars() {
        match character {
            '{' | '[' => {
                depth += 1;
                current.push(character);
            }
            '}' | ']' => {
                depth -= 1;
                current.push(character);
            }
            value if value == separator && depth == 0 => out.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    out.push(current);
    out
}

/// A conservative Finnish elative.
///
/// MediaWiki's `{{GRAMMAR:elative|word}}` needs language-specific case
/// inflection. [`fador_i18n`] supplies plural rules but no case grammar, so
/// this one rule stays local. It follows vowel harmony and the common
/// `i`/`a`/`ä` endings; a deployment that needs real inflection overrides the
/// word before it reaches the parser.
pub(crate) fn grammar_fi(word: &str) -> String {
    let front = word
        .chars()
        .rev()
        .find(|character| matches!(character, 'ä' | 'ö' | 'y' | 'a' | 'o' | 'u'))
        .is_some_and(|vowel| matches!(vowel, 'ä' | 'ö' | 'y'));
    let suffix = if front { "stä" } else { "sta" };
    if let Some(stem) = word.strip_suffix('i') {
        format!("{stem}istä")
    } else if let Some(stem) = word.strip_suffix('a') {
        format!("{stem}asta")
    } else if let Some(stem) = word.strip_suffix('ä') {
        format!("{stem}ästä")
    } else {
        format!("{word}{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_formatter<'a>(
        messages: &'a MapMessages,
        config: &'a ParserConfig,
    ) -> MessageFormatter<'a> {
        MessageFormatter::new(messages, config, MessageContext::default())
    }

    #[test]
    fn defaults_are_available_without_a_source() {
        let messages = MapMessages::new();
        let config = ParserConfig::default();
        let formatter = make_formatter(&messages, &config);
        assert_eq!(formatter.text("toc"), "Contents");
        assert_eq!(formatter.text("editsectionhint"), "Edit section: $1");
        assert_eq!(formatter.raw("january"), "January");
        assert_eq!(formatter.raw("missing-key"), "missing-key");
        assert!(!messages.has("toc"));
    }

    #[test]
    fn source_overrides_defaults() {
        let messages = MapMessages::new().with("toc", "Sisällys");
        let config = ParserConfig::default();
        let formatter = make_formatter(&messages, &config);
        assert_eq!(formatter.text("toc"), "Sisällys");
        assert!(messages.has("toc"));
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn parameters_are_not_reparsed_as_magic_words() {
        let messages = MapMessages::new()
            .with("greeting", "Hello, $1!")
            .with("int-key", "{{int:greeting}}")
            .with("plural", "{{PLURAL:$1|one item|$1 items}}");
        let config = ParserConfig::default();
        let formatter = make_formatter(&messages, &config);
        assert_eq!(
            formatter.format("greeting", &["{{int:greeting}}"]),
            "Hello, {{int:greeting}}!"
        );
        assert_eq!(formatter.format("plural", &["1"]), "one item");
        assert_eq!(formatter.format("plural", &["3"]), "3 items");
        assert_eq!(formatter.text("int-key"), "Hello, $1!");
    }

    #[test]
    fn grammar_and_gender_use_the_documented_forms() {
        let messages = MapMessages::new()
            .with("grammar", "{{GRAMMAR:elative|Talo}}")
            .with("gender", "{{GENDER:user|hän|häntä}}");
        let config = ParserConfig::default();
        let formatter = make_formatter(&messages, &config);
        assert_eq!(formatter.text("grammar"), "Talosta");
        assert_eq!(formatter.text("gender"), "hän");
    }

    #[test]
    fn context_variables_expand() {
        let messages = MapMessages::new().with(
            "context",
            "{{SITENAME}}/{{PAGENAME}}/{{NAMESPACE}}/{{CURRENTYEAR}}/{{CURRENTTIME}}",
        );
        let config = ParserConfig::default();
        let formatter = MessageFormatter::new(
            &messages,
            &config,
            MessageContext {
                sitename: "Test Wiki".into(),
                pagename: "Page".into(),
                fullpagename: "Help:Page".into(),
                namespace: "Help".into(),
                year: 2026,
                month: 11,
                day: 1,
                hour: 9,
                minute: 5,
            },
        );
        assert_eq!(formatter.text("context"), "Test Wiki/Page/Help/2026/09:05");
    }

    #[test]
    fn plural_rule_changes_the_selected_form() {
        let messages = MapMessages::new().with("p", "{{PLURAL:$1|one|many}}");
        let english = ParserConfig::default();
        let formatter = make_formatter(&messages, &english);
        assert_eq!(formatter.format("p", &["0"]), "many");
        assert_eq!(formatter.format("p", &["1"]), "one");
        assert_eq!(formatter.format("p", &["2"]), "many");

        let asian = ParserConfig::default().with_plural_rule(0);
        let formatter = make_formatter(&messages, &asian);
        assert_eq!(formatter.format("p", &["0"]), "one");
        assert_eq!(formatter.format("p", &["2"]), "one");
    }

    #[test]
    fn malformed_message_syntax_is_left_literal() {
        let messages = MapMessages::new()
            .with("open", "a {{PLURAL:1|b")
            .with("unknown", "{{NOPE:x}}");
        let config = ParserConfig::default();
        let formatter = make_formatter(&messages, &config);
        assert_eq!(formatter.text("open"), "a {{PLURAL:1|b");
        assert_eq!(formatter.text("unknown"), "{{NOPE:x}}");
    }

    #[test]
    fn fuzz_message_expansion_is_bounded() {
        use crate::testutil::Rng;
        let config = ParserConfig::default();
        let mut rng = Rng::new(0x4d53_0001);
        for _ in 0..500 {
            let length = rng.below(80);
            let key = rng.text(length);
            let length = rng.below(200);
            let value = rng.text(length);
            let messages = MapMessages::new().with(key.clone(), value);
            let formatter = make_formatter(&messages, &config);
            let out = formatter.text(&key);
            assert!(out.len() < 100_000);
        }
    }
}
