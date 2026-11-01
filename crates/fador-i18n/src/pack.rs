//! Language packs and the primary/fallback set a board resolves messages in.
//!
//! A pack is a JSON document. The crate ships no pack data: an application
//! embeds its own translation files with `include_str!` and passes them to
//! [`LanguagePack::from_json`], or keeps them in a directory and calls
//! [`LanguagePack::load`]. A [`LanguageSet`] pairs the requested pack with an
//! English fallback, the same lookup order phpBB uses.
//!
//! ```
//! use fador_i18n::LanguagePack;
//!
//! let pack = LanguagePack::from_json(
//!     r#"{"code":"en","messages":{"PLURAL_RULE":1,"POSTS":["no posts","1 post","%d posts"]}}"#,
//!     "en",
//! )
//! .unwrap();
//! assert_eq!(pack.lang("POSTS", &["0".to_string()]), "no posts");
//! assert_eq!(pack.lang("POSTS", &["7".to_string()]), "7 posts");
//! ```

use crate::date::{format_date_php, format_offset, DateTimeNames};
use crate::format::format_placeholders;
use crate::plural::{select_plural, select_plural_entries};
use crate::tz::Tzdb;
use fador_core::json::{self, Json};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;

/// Why a language pack could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    /// The JSON text could not be parsed.
    Json(String),
    /// The document is valid JSON but not an object.
    NotAnObject,
    /// No pack with this code exists in the directory or the embedded set.
    UnknownLanguage(String),
    /// A pack file exists but could not be read.
    Io {
        /// The path that failed.
        path: String,
        /// The operating-system error.
        message: String,
    },
}

impl fmt::Display for PackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message) => write!(formatter, "language pack is not valid JSON: {message}"),
            Self::NotAnObject => formatter.write_str("language pack must be a JSON object"),
            Self::UnknownLanguage(code) => {
                write!(formatter, "language pack {code:?} is not available")
            }
            Self::Io { path, message } => write!(formatter, "{path}: {message}"),
        }
    }
}

impl std::error::Error for PackError {}

/// Language packs compiled into the application binary.
///
/// The registry only stores borrowed `&'static str` values, so it is filled
/// once at startup with `include_str!` results and then shared.
#[derive(Debug, Clone, Default)]
pub struct EmbeddedPacks {
    entries: Vec<(String, &'static str)>,
}

impl EmbeddedPacks {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register `text` under `code`, returning the updated registry.
    ///
    /// The code is normalized with [`normalize_language_code`], and a later
    /// registration of the same code wins.
    #[must_use]
    pub fn add(mut self, code: &str, text: &'static str) -> Self {
        self.entries.push((normalize_language_code(code), text));
        self
    }

    /// The JSON text registered for `code`.
    #[must_use]
    pub fn get(&self, code: &str) -> Option<&'static str> {
        let code = normalize_language_code(code);
        self.entries
            .iter()
            .rev()
            .find(|(name, _)| *name == code)
            .map(|(_, text)| *text)
    }

    /// Every registered code, in registration order.
    pub fn codes(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(code, _)| code.as_str())
    }

    /// Number of registered packs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no pack is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One parsed language pack.
#[derive(Debug, Clone)]
pub struct LanguagePack {
    code: String,
    english_name: String,
    local_name: String,
    author: String,
    translation_info: String,
    messages: HashMap<String, Json>,
    files: HashMap<String, HashMap<String, Json>>,
    help: HashMap<String, Vec<(String, String)>>,
    timezones: HashMap<String, String>,
    datetime: DateTimeNames,
    synonyms: Vec<String>,
    ignore_words: Vec<String>,
}

impl LanguagePack {
    /// Parse a pack from JSON text.
    ///
    /// `expected_code` is used when the document does not name a `code`. The
    /// document must be a JSON object; every section is optional, so an empty
    /// object is a valid (but empty) pack.
    pub fn from_json(text: &str, expected_code: &str) -> Result<Self, PackError> {
        let value = json::parse(text).map_err(PackError::Json)?;
        let Json::Object(root) = value else {
            return Err(PackError::NotAnObject);
        };
        let code = object_string(&root, "code").map_or_else(
            || normalize_language_code(expected_code),
            |code| normalize_language_code(&code),
        );
        let english_name = object_string(&root, "english_name").unwrap_or_default();
        let local_name = object_string(&root, "local_name").unwrap_or_else(|| english_name.clone());
        let author = object_string(&root, "author").unwrap_or_default();
        let translation_info = object_string(&root, "translation_info").unwrap_or_default();
        let messages: HashMap<String, Json> = object_get(&root, "messages")
            .and_then(as_object)
            .map(|values| {
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let files = parse_files(&root);
        let help = parse_help(&root);
        let timezones = parse_timezones(&root, &messages);
        let datetime = object_get(&root, "datetime")
            .map(DateTimeNames::from_json)
            .unwrap_or_default();
        let synonyms = string_array(&root, "synonyms");
        let ignore_words = string_array(&root, "ignore_words");
        Ok(Self {
            code,
            english_name,
            local_name,
            author,
            translation_info,
            messages,
            files,
            help,
            timezones,
            datetime,
            synonyms,
            ignore_words,
        })
    }

    /// Read `<dir>/<code>.json`.
    ///
    /// The code is normalized first, so `en_US` looks for `en.json`. A missing
    /// file is [`PackError::UnknownLanguage`]; an unreadable one is
    /// [`PackError::Io`].
    pub fn load(code: &str, directory: &Path) -> Result<Self, PackError> {
        let code = normalize_language_code(code);
        let path = directory.join(format!("{code}.json"));
        if !path.is_file() {
            return Err(PackError::UnknownLanguage(code));
        }
        let text = fs::read_to_string(&path).map_err(|error| PackError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        Self::from_json(&text, &code)
    }

    /// Read `<dir>/<code>.json`, falling back to the embedded registry.
    ///
    /// The file wins when both exist, so a deployment can override one pack
    /// without recompiling.
    pub fn load_with_embedded(
        code: &str,
        directory: &Path,
        embedded: &EmbeddedPacks,
    ) -> Result<Self, PackError> {
        let code = normalize_language_code(code);
        let path = directory.join(format!("{code}.json"));
        if path.is_file() {
            let text = fs::read_to_string(&path).map_err(|error| PackError::Io {
                path: path.display().to_string(),
                message: error.to_string(),
            })?;
            return Self::from_json(&text, &code);
        }
        let text = embedded
            .get(&code)
            .ok_or_else(|| PackError::UnknownLanguage(code.clone()))?;
        Self::from_json(text, &code)
    }

    /// Parse the pack registered for `code` in `embedded`.
    pub fn from_embedded(embedded: &EmbeddedPacks, code: &str) -> Result<Self, PackError> {
        let code = normalize_language_code(code);
        let text = embedded
            .get(&code)
            .ok_or_else(|| PackError::UnknownLanguage(code.clone()))?;
        Self::from_json(text, &code)
    }

    /// The pack's language code, for example `fi`.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The language's English name.
    #[must_use]
    pub fn english_name(&self) -> &str {
        &self.english_name
    }

    /// The language's name in its own language.
    #[must_use]
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// The translator credited by the pack.
    #[must_use]
    pub fn author(&self) -> &str {
        &self.author
    }

    /// Free-form translation metadata.
    #[must_use]
    pub fn translation_info(&self) -> &str {
        &self.translation_info
    }

    /// The phpBB plural rule the pack declares, defaulting to rule 1.
    #[must_use]
    pub fn plural_rule(&self) -> u8 {
        match self.messages.get("PLURAL_RULE") {
            Some(Json::Number(value)) if (0.0..=15.0).contains(value) => *value as u8,
            _ => 1,
        }
    }

    /// The raw message value, for callers that need a nested or numeric entry.
    #[must_use]
    pub fn message(&self, key: &str) -> Option<&Json> {
        self.messages.get(key)
    }

    /// Whether the pack defines `key`.
    #[must_use]
    pub fn lang_defined(&self, key: &str) -> bool {
        self.messages.contains_key(key)
    }

    /// The message for `key`, with plural selection and placeholders applied.
    ///
    /// A missing key is returned verbatim, which makes an untranslated string
    /// visible instead of blank.
    #[must_use]
    pub fn lang(&self, key: &str, args: &[String]) -> String {
        match self.messages.get(key) {
            Some(value) => {
                let value = plural_value(value, args, self.plural_rule());
                format_placeholders(&json_text(value), args)
            }
            None => key.to_string(),
        }
    }

    /// Whether one language file defines `key`.
    #[must_use]
    pub fn lang_file_defined(&self, file: &str, key: &str) -> bool {
        self.files
            .get(file)
            .is_some_and(|values| values.contains_key(key))
    }

    /// The message for `key` from one language file.
    ///
    /// phpBB loads only the files a page needs, and the same key may mean
    /// different things in different files (`NO_UNREAD_POSTS` in `viewforum`
    /// and `viewtopic`), so a page resolves keys per file. A key the file does
    /// not define falls back to the pack-wide messages.
    #[must_use]
    pub fn lang_file(&self, file: &str, key: &str, args: &[String]) -> String {
        match self.files.get(file).and_then(|values| values.get(key)) {
            Some(value) => {
                let value = plural_value(value, args, self.plural_rule());
                format_placeholders(&json_text(value), args)
            }
            None => self.lang(key, args),
        }
    }

    /// The message for `key` from the last of `files` that defines it.
    ///
    /// phpBB loads the common file first and the page file last, and the later
    /// file wins; this walks the list in reverse for that reason.
    #[must_use]
    pub fn lang_page(&self, files: &[&str], key: &str, args: &[String]) -> String {
        for file in files.iter().rev() {
            if self.lang_file_defined(file, key) {
                return self.lang_file(file, key, args);
            }
        }
        self.lang(key, args)
    }

    /// A nested message value, for example `("timezones", ["UTC_OFFSET"])`.
    #[must_use]
    pub fn nested(&self, key: &str, path: &[&str]) -> Option<String> {
        let mut value = self.messages.get(key)?;
        for part in path {
            let Json::Object(entries) = value else {
                return None;
            };
            value = object_get(entries, part)?;
        }
        Some(json_text(value))
    }

    /// The FAQ/help rows of one file, as `(question, answer)` pairs.
    #[must_use]
    pub fn help(&self, file: &str) -> Option<&[(String, String)]> {
        self.help.get(file).map(Vec::as_slice)
    }

    /// The display label of one zone, or the zone identifier itself.
    #[must_use]
    pub fn timezone_label(&self, zone: &str) -> String {
        self.timezones
            .get(zone)
            .cloned()
            .unwrap_or_else(|| zone.to_string())
    }

    /// The zone identifiers the pack offers, sorted, without `UTC_OFFSET`
    /// templates.
    #[must_use]
    pub fn timezone_ids(&self) -> Vec<String> {
        let mut ids = self
            .timezones
            .keys()
            .filter(|id| !id.starts_with("UTC_OFFSET"))
            .cloned()
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }

    /// The offset label for a fixed offset, where zero is shown as `UTC`.
    #[must_use]
    pub fn timezone_offset_label(&self, offset_seconds: i32) -> String {
        let offset = if offset_seconds == 0 {
            String::new()
        } else {
            format_offset(offset_seconds, true)
        };
        match self.timezones.get("UTC_OFFSET") {
            Some(template) => format_placeholders(template, std::slice::from_ref(&offset)),
            None if offset.is_empty() => "UTC".to_string(),
            None => format!("UTC{offset}"),
        }
    }

    /// The offset label used by a zone selector, where zero is `+00:00`.
    #[must_use]
    pub fn timezone_select_offset_label(&self, offset_seconds: i32) -> String {
        let offset = format_offset(offset_seconds, true);
        match self.timezones.get("UTC_OFFSET") {
            Some(template) => format_placeholders(template, std::slice::from_ref(&offset)),
            None => format!("UTC{offset}"),
        }
    }

    /// The label for the current offset, for example `UTC+03:00 - EEST`.
    #[must_use]
    pub fn timezone_current_label(&self, offset_seconds: i32, current: &str) -> String {
        let offset = format_offset(offset_seconds, true);
        match self.timezones.get("UTC_OFFSET_CURRENT") {
            Some(template) => format_placeholders(template, &[offset, current.to_string()]),
            None => format!("UTC{offset} - {current}"),
        }
    }

    /// The date-format keys the pack offers, in pack order.
    #[must_use]
    pub fn dateformats(&self) -> Vec<String> {
        match self.messages.get("dateformats") {
            Some(Json::Object(items)) => items.iter().map(|(key, _)| key.clone()).collect(),
            _ => Vec::new(),
        }
    }

    /// The localized day and month names.
    #[must_use]
    pub fn datetime(&self) -> &DateTimeNames {
        &self.datetime
    }

    /// Words the search index treats as synonyms.
    #[must_use]
    pub fn synonyms(&self) -> &[String] {
        &self.synonyms
    }

    /// Words the search index ignores.
    #[must_use]
    pub fn ignore_words(&self) -> &[String] {
        &self.ignore_words
    }

    /// Format a timestamp in `zone` with PHP `date()` tokens.
    ///
    /// English packs keep PHP's `S` ordinal suffix; other packs render no
    /// suffix, which is what the ported board expects.
    #[must_use]
    pub fn format_date(&self, unix_time: i64, zone: &str, format: &str) -> String {
        format_date_php(
            Tzdb::embedded(),
            &self.datetime,
            self.code.starts_with("en"),
            unix_time,
            zone,
            format,
        )
    }
}

/// A primary language pack with an English fallback.
#[derive(Debug, Clone)]
pub struct LanguageSet {
    primary: LanguagePack,
    fallback: LanguagePack,
}

impl LanguageSet {
    /// Pair two packs.
    #[must_use]
    pub fn new(primary: LanguagePack, fallback: LanguagePack) -> Self {
        Self { primary, fallback }
    }

    /// A set whose fallback is a copy of the primary pack.
    #[must_use]
    pub fn single(pack: LanguagePack) -> Self {
        Self {
            fallback: pack.clone(),
            primary: pack,
        }
    }

    /// Load the requested pack and the `en` fallback from `directory`.
    ///
    /// When `en.json` is missing, the primary pack doubles as the fallback.
    pub fn load(code: &str, directory: &Path) -> Result<Self, PackError> {
        let primary = LanguagePack::load(code, directory)?;
        let fallback = LanguagePack::load("en", directory).unwrap_or_else(|_| primary.clone());
        Ok(Self { primary, fallback })
    }

    /// Load the requested pack and the `en` fallback from a directory, with
    /// the embedded registry as the second source.
    pub fn load_with_embedded(
        code: &str,
        directory: &Path,
        embedded: &EmbeddedPacks,
    ) -> Result<Self, PackError> {
        let primary = LanguagePack::load_with_embedded(code, directory, embedded)?;
        let fallback = LanguagePack::load_with_embedded("en", directory, embedded)
            .unwrap_or_else(|_| primary.clone());
        Ok(Self { primary, fallback })
    }

    /// The pack messages are resolved in first.
    #[must_use]
    pub fn primary(&self) -> &LanguagePack {
        &self.primary
    }

    /// The pack used when the primary does not define a key.
    #[must_use]
    pub fn fallback(&self) -> &LanguagePack {
        &self.fallback
    }

    /// Switch to another installed pack.
    ///
    /// English regional tags (`en_us`, `en-GB`) select `en`. An unknown code
    /// keeps the current set, matching phpBB's fallback to the board default.
    #[must_use]
    pub fn select(&self, code: &str) -> Self {
        let code = normalize_language_code(code);
        if self.primary.code == code {
            return self.clone();
        }
        if self.fallback.code == code {
            return Self {
                primary: self.fallback.clone(),
                fallback: self.primary.clone(),
            };
        }
        self.clone()
    }

    /// The message for `key` in the primary pack, then the fallback, then the
    /// key itself.
    #[must_use]
    pub fn lang(&self, key: &str, args: &[String]) -> String {
        if self.primary.lang_defined(key) {
            self.primary.lang(key, args)
        } else if self.fallback.lang_defined(key) {
            self.fallback.lang(key, args)
        } else {
            key.to_string()
        }
    }

    /// Whether either pack defines `key`.
    #[must_use]
    pub fn lang_defined(&self, key: &str) -> bool {
        self.primary.lang_defined(key) || self.fallback.lang_defined(key)
    }

    /// The message for `key` from one file, in the primary pack then the
    /// fallback.
    #[must_use]
    pub fn lang_file(&self, file: &str, key: &str, args: &[String]) -> String {
        if self.primary.lang_file_defined(file, key) {
            self.primary.lang_file(file, key, args)
        } else if self.fallback.lang_file_defined(file, key) {
            self.fallback.lang_file(file, key, args)
        } else {
            self.lang(key, args)
        }
    }

    /// The message for `key` from the last of `files` that defines it, in
    /// either pack.
    #[must_use]
    pub fn lang_page(&self, files: &[&str], key: &str, args: &[String]) -> String {
        for file in files.iter().rev() {
            if self.primary.lang_file_defined(file, key) {
                return self.primary.lang_file(file, key, args);
            }
            if self.fallback.lang_file_defined(file, key) {
                return self.fallback.lang_file(file, key, args);
            }
        }
        self.lang(key, args)
    }

    /// The help rows of `file`, from either pack.
    #[must_use]
    pub fn help(&self, file: &str) -> Option<&[(String, String)]> {
        self.primary.help(file).or_else(|| self.fallback.help(file))
    }

    /// A nested message value, from either pack.
    #[must_use]
    pub fn nested(&self, key: &str, path: &[&str]) -> Option<String> {
        self.primary
            .nested(key, path)
            .or_else(|| self.fallback.nested(key, path))
    }

    /// The display label of one zone, from either pack.
    #[must_use]
    pub fn timezone_label(&self, zone: &str) -> String {
        if self.primary.timezones.contains_key(zone) {
            self.primary.timezone_label(zone)
        } else {
            self.fallback.timezone_label(zone)
        }
    }

    /// The zone identifiers the primary pack offers.
    #[must_use]
    pub fn timezone_ids(&self) -> Vec<String> {
        self.primary.timezone_ids()
    }

    /// The date-format keys the primary pack offers.
    #[must_use]
    pub fn dateformats(&self) -> Vec<String> {
        self.primary.dateformats()
    }

    /// The primary pack's localized day and month names.
    #[must_use]
    pub fn datetime(&self) -> &DateTimeNames {
        self.primary.datetime()
    }

    /// The offset label for a fixed offset, from either pack.
    #[must_use]
    pub fn timezone_offset_label(&self, offset_seconds: i32) -> String {
        if self.primary.timezones.contains_key("UTC_OFFSET") {
            self.primary.timezone_offset_label(offset_seconds)
        } else {
            self.fallback.timezone_offset_label(offset_seconds)
        }
    }

    /// The selector offset label for a fixed offset, from either pack.
    #[must_use]
    pub fn timezone_select_offset_label(&self, offset_seconds: i32) -> String {
        if self.primary.timezones.contains_key("UTC_OFFSET") {
            self.primary.timezone_select_offset_label(offset_seconds)
        } else {
            self.fallback.timezone_select_offset_label(offset_seconds)
        }
    }

    /// The current-offset label, from either pack.
    #[must_use]
    pub fn timezone_current_label(&self, offset_seconds: i32, current: &str) -> String {
        if self.primary.timezones.contains_key("UTC_OFFSET_CURRENT") {
            self.primary.timezone_current_label(offset_seconds, current)
        } else {
            self.fallback
                .timezone_current_label(offset_seconds, current)
        }
    }

    /// Format a timestamp with the primary pack's names.
    #[must_use]
    pub fn format_date(&self, unix_time: i64, zone: &str, format: &str) -> String {
        self.primary.format_date(unix_time, zone, format)
    }

    /// The primary pack's translation metadata.
    #[must_use]
    pub fn translation_info(&self) -> &str {
        self.primary.translation_info()
    }
}

/// Normalize a language code for lookups.
///
/// Codes are trimmed and lowercased, and the English regional tags phpBB
/// commonly sees collapse to `en`. Other codes are kept as they are, because a
/// pack may legitimately ship `pt_br` next to `pt`.
#[must_use]
pub fn normalize_language_code(code: &str) -> String {
    let code = code.trim().to_ascii_lowercase();
    match code.as_str() {
        "en_us" | "en_gb" | "en-us" | "en-gb" => "en".to_string(),
        _ => code,
    }
}

impl DateTimeNames {
    /// Read the `datetime` object of a pack.
    fn from_json(value: &Json) -> Self {
        let values: HashMap<&str, Json> = match value {
            Json::Object(items) => items
                .iter()
                .map(|(key, value)| (key.as_str(), value.clone()))
                .collect(),
            _ => HashMap::new(),
        };
        let mut out = Self::english();
        for (index, key) in [
            "Sunday",
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
        ]
        .iter()
        .enumerate()
        {
            out.days_full[index] = values
                .get(key)
                .and_then(as_string)
                .unwrap_or(key)
                .to_string();
        }
        for (index, key) in ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
            .iter()
            .enumerate()
        {
            out.days_short[index] = values
                .get(key)
                .and_then(as_string)
                .unwrap_or(key)
                .to_string();
        }
        for (index, key) in [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ]
        .iter()
        .enumerate()
        {
            out.months_full[index] = values
                .get(key)
                .and_then(as_string)
                .unwrap_or(key)
                .to_string();
        }
        for (index, key) in [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ]
        .iter()
        .enumerate()
        {
            // phpBB stores the short May under `May_short` to keep the full
            // name and the abbreviation apart.
            let fallback_key = if *key == "May" { "May_short" } else { key };
            out.months_short[index] = values
                .get(fallback_key)
                .or_else(|| values.get(key))
                .and_then(as_string)
                .unwrap_or(key)
                .to_string();
        }
        out.today = values
            .get("TODAY")
            .and_then(as_string)
            .unwrap_or("Today")
            .to_string();
        out.tomorrow = values
            .get("TOMORROW")
            .and_then(as_string)
            .unwrap_or("Tomorrow")
            .to_string();
        out.yesterday = values
            .get("YESTERDAY")
            .and_then(as_string)
            .unwrap_or("Yesterday")
            .to_string();
        out.ago = values
            .get("AGO")
            .and_then(as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(as_string)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        out
    }
}

/// The `files` section: `lang` keys per file and `help` rows.
fn parse_files(root: &[(String, Json)]) -> HashMap<String, HashMap<String, Json>> {
    let mut out: HashMap<String, HashMap<String, Json>> = HashMap::new();
    let Some(entries) = object_get(root, "files").and_then(as_object) else {
        return out;
    };
    for (file, value) in entries {
        let Some(sections) = as_object(value) else {
            continue;
        };
        let target = out.entry(file.clone()).or_default();
        for section in ["lang", "help"] {
            if let Some(Json::Object(items)) = object_get(sections, section) {
                for (key, value) in items {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
    }
    out
}

/// The `files.*.help` section: bounded `[question, answer]` pairs.
fn parse_help(root: &[(String, Json)]) -> HashMap<String, Vec<(String, String)>> {
    let mut out = HashMap::new();
    let Some(entries) = object_get(root, "files").and_then(as_object) else {
        return out;
    };
    for (file, value) in entries {
        let Some(sections) = as_object(value) else {
            continue;
        };
        let Some(Json::Array(items)) = object_get(sections, "help") else {
            continue;
        };
        let mut rows = Vec::new();
        for item in items.iter().take(1000) {
            let Json::Array(pair) = item else {
                continue;
            };
            let (Some(Json::String(question)), Some(Json::String(answer))) =
                (pair.first(), pair.get(1))
            else {
                continue;
            };
            rows.push((question.clone(), answer.clone()));
        }
        out.insert(file.clone(), rows);
    }
    out
}

/// The zone labels, either from the root `tz` object or `messages.timezones`.
fn parse_timezones(
    root: &[(String, Json)],
    messages: &HashMap<String, Json>,
) -> HashMap<String, String> {
    let parse = |value: &Json| {
        as_object(value)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(key, value)| {
                        as_string(value).map(|text| (key.clone(), text.to_string()))
                    })
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default()
    };
    match object_get(root, "tz").map(parse) {
        Some(map) if !map.is_empty() => map,
        _ => messages.get("timezones").map(parse).unwrap_or_default(),
    }
}

/// The `synonyms` or `ignore_words` array.
fn string_array(root: &[(String, Json)], key: &str) -> Vec<String> {
    object_get(root, key)
        .and_then(as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(as_string)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Select the plural entry phpBB's `lang()` would use.
fn plural_value<'a>(value: &'a Json, args: &[String], plural_rule: u8) -> &'a Json {
    let count = args.iter().find_map(|value| {
        if let Ok(number) = value.trim().parse::<i64>() {
            Some(number)
        } else {
            value
                .trim()
                .parse::<f64>()
                .ok()
                .map(|number| number.floor() as i64)
        }
    });
    match value {
        Json::Array(values) => select_plural(values, count, plural_rule).unwrap_or(value),
        Json::Object(values) => {
            let mut entries = values
                .iter()
                .filter_map(|(key, value)| key.parse::<i64>().ok().map(|number| (number, value)))
                .collect::<Vec<_>>();
            if entries.is_empty() {
                return value;
            }
            entries.sort_by_key(|(key, _)| *key);
            select_plural_entries(&entries, count, plural_rule)
                .copied()
                .unwrap_or(value)
        }
        _ => value,
    }
}

/// A JSON scalar as the text a message renders.
fn json_text(value: &Json) -> String {
    match value {
        Json::Null => String::new(),
        Json::Bool(value) => {
            if *value {
                "1".to_string()
            } else {
                String::new()
            }
        }
        Json::Number(value) => {
            if value.fract() == 0.0 {
                format!("{}", *value as i64)
            } else {
                format!("{value}")
            }
        }
        Json::String(value) => value.clone(),
        Json::Array(_) | Json::Object(_) => String::new(),
    }
}

fn object_get<'a>(values: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    values
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn object_string(values: &[(String, Json)], key: &str) -> Option<String> {
    object_get(values, key)
        .and_then(as_string)
        .map(str::to_string)
}

fn as_object(value: &Json) -> Option<&[(String, Json)]> {
    match value {
        Json::Object(values) => Some(values),
        _ => None,
    }
}

fn as_array(value: &Json) -> Option<&[Json]> {
    match value {
        Json::Array(values) => Some(values),
        _ => None,
    }
}

fn as_string(value: &Json) -> Option<&str> {
    match value {
        Json::String(value) => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fador_testutil::{iterations, Rng};

    const EN: &str = r#"{
        "code": "en",
        "english_name": "English",
        "local_name": "English",
        "author": "phpBB",
        "translation_info": "1.0",
        "messages": {
            "PLURAL_RULE": 1,
            "COLON": ":",
            "POSTS": ["no posts", "1 post", "%d posts"],
            "CHARACTERS": {"0": "no characters", "1": "1 character", "2": "%d characters"},
            "WELCOME": "Welcome, %1$s! You have %2$d new messages.",
            "DATE_FORMAT": "D M d, Y H:i",
            "NESTED": {"outer": {"inner": "deep"}, "number": 7},
            "dateformats": {"D M d, Y H:i": "D M d, Y H:i", "d.m.Y H:i": "d.m.Y H:i"}
        },
        "tz": {
            "UTC_OFFSET": "UTC%s",
            "UTC_OFFSET_CURRENT": "UTC%s - %s",
            "Etc/GMT-3": "UTC+3",
            "Europe/Helsinki": "Helsinki"
        },
        "files": {
            "common": {"lang": {"INDEX": "Index page", "SAME": "common"}},
            "viewforum": {"lang": {"NO_UNREAD_POSTS": "No unread posts", "SAME": "forum"}},
            "viewtopic": {"lang": {"NO_UNREAD_POSTS": "No unread posts in this topic"}, "help": [["Why?", "Because."], ["bad"], [1, 2]]}
        },
        "datetime": {
            "Sunday": "Sunday", "Monday": "Monday", "Tuesday": "Tuesday",
            "Wednesday": "Wednesday", "Thursday": "Thursday", "Friday": "Friday",
            "Saturday": "Saturday",
            "Sun": "Sun", "Mon": "Mon", "Tue": "Tue", "Wed": "Wed", "Thu": "Thu",
            "Fri": "Fri", "Sat": "Sat",
            "January": "January", "February": "February", "March": "March",
            "April": "April", "May": "May", "June": "June", "July": "July",
            "August": "August", "September": "September", "October": "October",
            "November": "November", "December": "December",
            "Jan": "Jan", "Feb": "Feb", "Mar": "Mar", "Apr": "Apr",
            "May_short": "May", "Jun": "Jun", "Jul": "Jul", "Aug": "Aug",
            "Sep": "Sep", "Oct": "Oct", "Nov": "Nov", "Dec": "Dec",
            "TODAY": "Today", "TOMORROW": "Tomorrow", "YESTERDAY": "Yesterday",
            "AGO": ["less than a minute ago", "%d minute ago", "%d minutes ago"]
        },
        "synonyms": ["topic", "thread"],
        "ignore_words": ["the"]
    }"#;

    const FI: &str = r#"{
        "code": "fi",
        "english_name": "Finnish",
        "local_name": "Suomi",
        "messages": {
            "COLON": ":",
            "POSTS": {"0": "ei viestejä", "1": "1 viesti", "2": "%d viestiä"},
            "WELCOME": "Tervetuloa, %1$s!",
            "timezones": {"UTC_OFFSET": "UTC%s", "Etc/GMT-3": "UTC+3"},
            "dateformats": {"d.m.Y H:i": "d.m.Y H:i"}
        },
        "files": {"common": {"lang": {"INDEX": "Etusivu"}}},
        "datetime": {
            "Wednesday": "Keskiviikko", "Wed": "Ke",
            "Thursday": "Torstai", "Thu": "To",
            "January": "Tammikuu", "Jan": "Tammi", "July": "Heinäkuu", "Jul": "Heinä",
            "TODAY": "Tänään"
        }
    }"#;

    fn en() -> LanguagePack {
        LanguagePack::from_json(EN, "en").expect("English pack")
    }

    fn fi() -> LanguagePack {
        LanguagePack::from_json(FI, "fi").expect("Finnish pack")
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn reads_pack_metadata_and_sections() {
        let pack = en();
        assert_eq!(pack.code(), "en");
        assert_eq!(pack.english_name(), "English");
        assert_eq!(pack.local_name(), "English");
        assert_eq!(pack.author(), "phpBB");
        assert_eq!(pack.translation_info(), "1.0");
        assert_eq!(pack.plural_rule(), 1);
        assert_eq!(pack.synonyms(), ["topic", "thread"]);
        assert_eq!(pack.ignore_words(), ["the"]);
        assert!(pack.lang_defined("COLON"));
        assert!(!pack.lang_defined("MISSING"));
        assert_eq!(pack.dateformats(), vec!["D M d, Y H:i", "d.m.Y H:i"]);
        assert_eq!(
            pack.nested("NESTED", &["outer", "inner"]).as_deref(),
            Some("deep")
        );
        assert_eq!(pack.nested("NESTED", &["number"]).as_deref(), Some("7"));
        assert_eq!(pack.nested("NESTED", &["outer", "missing"]), None);
        assert_eq!(pack.nested("MISSING", &[]), None);
        assert!(matches!(pack.message("COLON"), Some(Json::String(value)) if value == ":"));
    }

    #[test]
    fn resolves_messages_with_plurals_and_placeholders() {
        let pack = en();
        assert_eq!(pack.lang("COLON", &[]), ":");
        assert_eq!(pack.lang("POSTS", &args(&["0"])), "no posts");
        assert_eq!(pack.lang("POSTS", &args(&["1"])), "1 post");
        assert_eq!(pack.lang("POSTS", &args(&["9"])), "9 posts");
        // Without a numeric argument the last (plural) entry wins, and the
        // placeholder renders as zero because no argument supplies a count.
        assert_eq!(pack.lang("POSTS", &[]), "0 posts");
        assert_eq!(pack.lang("CHARACTERS", &args(&["0"])), "no characters");
        assert_eq!(pack.lang("CHARACTERS", &args(&["1"])), "1 character");
        assert_eq!(pack.lang("CHARACTERS", &args(&["3"])), "3 characters");
        assert_eq!(
            pack.lang("WELCOME", &args(&["Ada", "2"])),
            "Welcome, Ada! You have 2 new messages."
        );
        assert_eq!(pack.lang("MISSING", &[]), "MISSING");
    }

    #[test]
    fn resolves_keys_per_file_and_per_page() {
        let pack = en();
        assert_eq!(pack.lang_file("common", "INDEX", &[]), "Index page");
        assert_eq!(
            pack.lang_file("viewforum", "NO_UNREAD_POSTS", &[]),
            "No unread posts"
        );
        assert_eq!(
            pack.lang_file("viewtopic", "NO_UNREAD_POSTS", &[]),
            "No unread posts in this topic"
        );
        // A key the file does not define falls back to the pack messages.
        assert_eq!(pack.lang_file("common", "COLON", &[]), ":");
        assert!(pack.lang_file_defined("common", "INDEX"));
        assert!(!pack.lang_file_defined("viewtopic", "INDEX"));
        // The last file in the list wins.
        assert_eq!(
            pack.lang_page(&["common", "viewforum"], "SAME", &[]),
            "forum"
        );
        assert_eq!(pack.lang_page(&["common"], "SAME", &[]), "common");
        assert_eq!(
            pack.lang_page(&["common", "viewtopic"], "NO_UNREAD_POSTS", &[]),
            "No unread posts in this topic"
        );
        assert_eq!(pack.lang_page(&["missing"], "COLON", &[]), ":");
        assert_eq!(pack.help("viewtopic").map(|rows| rows.len()), Some(1));
        assert_eq!(pack.help("common"), None);
    }

    #[test]
    fn labels_timezones_and_offsets() {
        let pack = en();
        assert_eq!(pack.timezone_label("Etc/GMT-3"), "UTC+3");
        assert_eq!(pack.timezone_label("Not/AZone"), "Not/AZone");
        assert_eq!(
            pack.timezone_ids(),
            vec!["Etc/GMT-3".to_string(), "Europe/Helsinki".to_string()]
        );
        assert_eq!(pack.timezone_offset_label(0), "UTC");
        assert_eq!(pack.timezone_offset_label(3 * 3_600), "UTC+03:00");
        assert_eq!(pack.timezone_offset_label(-4 * 3_600), "UTC-04:00");
        assert_eq!(pack.timezone_select_offset_label(0), "UTC+00:00");
        assert_eq!(
            pack.timezone_current_label(3 * 3_600, "EEST"),
            "UTC+03:00 - EEST"
        );
        // A pack without the template falls back to the built-in wording.
        let bare = LanguagePack::from_json(r#"{"code":"xx"}"#, "xx").unwrap();
        assert_eq!(bare.timezone_offset_label(0), "UTC");
        assert_eq!(bare.timezone_offset_label(7_200), "UTC+02:00");
        assert_eq!(bare.timezone_select_offset_label(0), "UTC+00:00");
        assert_eq!(bare.timezone_current_label(7_200, "EET"), "UTC+02:00 - EET");
    }

    #[test]
    fn formats_dates_with_pack_names() {
        let pack = en();
        assert_eq!(
            pack.format_date(0, "UTC", "D M d, Y H:i"),
            "Thu Jan 01, 1970 00:00"
        );
        assert_eq!(pack.format_date(0, "UTC", "jS F Y"), "1st January 1970");
        let pack = fi();
        // 2026-07-01T12:00:00Z is 15:00 EEST in Helsinki.
        assert_eq!(
            pack.format_date(1_782_907_200, "Europe/Helsinki", "D d.m.Y H:i"),
            "Ke 01.07.2026 15:00"
        );
        // Non-English packs render no ordinal suffix.
        assert_eq!(pack.format_date(0, "UTC", "jS F"), "1 Tammikuu");
        assert_eq!(pack.datetime().today(), "Tänään");
        assert_eq!(en().datetime().ago(2), "2 minutes ago");
        assert_eq!(fi().datetime().ago(2), "", "a pack without AGO has none");
    }

    #[test]
    fn falls_back_to_the_secondary_pack() {
        let set = LanguageSet::new(fi(), en());
        assert_eq!(set.lang("COLON", &[]), ":");
        assert_eq!(set.lang("INDEX", &[]), "INDEX");
        assert_eq!(set.lang_file("common", "INDEX", &[]), "Etusivu");
        assert_eq!(
            set.lang_page(&["common", "viewtopic"], "NO_UNREAD_POSTS", &[]),
            "No unread posts in this topic"
        );
        assert_eq!(set.lang("POSTS", &args(&["1"])), "1 viesti");
        assert_eq!(set.lang("WELCOME", &args(&["Ada"])), "Tervetuloa, Ada!");
        assert!(set.lang_defined("COLON"));
        assert!(!set.lang_defined("MISSING"));
        assert_eq!(set.lang("MISSING", &[]), "MISSING");
        assert_eq!(set.timezone_label("Europe/Helsinki"), "Helsinki");
        assert_eq!(set.timezone_ids(), vec!["Etc/GMT-3".to_string()]);
        assert_eq!(set.dateformats(), vec!["d.m.Y H:i"]);
        assert_eq!(set.datetime().today(), "Tänään");
        assert_eq!(set.translation_info(), "");
        assert_eq!(set.timezone_offset_label(0), "UTC");
        assert_eq!(set.timezone_select_offset_label(0), "UTC+00:00");
        assert_eq!(set.timezone_current_label(0, "UTC"), "UTC+00:00 - UTC");
        assert_eq!(set.help("viewtopic").map(|rows| rows.len()), Some(1));
        assert_eq!(
            set.nested("NESTED", &["outer", "inner"]).as_deref(),
            Some("deep")
        );
        assert_eq!(set.format_date(0, "UTC", "jS"), "1");
    }

    #[test]
    fn selects_installed_packs_by_code() {
        let set = LanguageSet::new(fi(), en());
        assert_eq!(set.select("fi").lang("COLON", &[]), ":");
        let english = set.select("en_us");
        assert_eq!(english.primary().code(), "en");
        assert_eq!(english.fallback().code(), "fi");
        assert_eq!(english.lang("COLON", &[]), ":");
        assert_eq!(english.lang("INDEX", &[]), "INDEX");
        assert_eq!(english.lang_file("common", "INDEX", &[]), "Index page");
        // An unknown code keeps the current set.
        assert_eq!(set.select("de").primary().code(), "fi");
        assert_eq!(set.select("FI").primary().code(), "fi");
        assert_eq!(normalize_language_code(" EN_GB "), "en");
        assert_eq!(normalize_language_code("pt_br"), "pt_br");
    }

    #[test]
    fn single_pack_set_has_itself_as_fallback() {
        let set = LanguageSet::single(fi());
        assert_eq!(set.primary().code(), "fi");
        assert_eq!(set.fallback().code(), "fi");
        assert_eq!(set.lang("COLON", &[]), ":");
    }

    #[test]
    fn loads_packs_from_disk_and_the_embedded_set() {
        let directory = std::env::temp_dir().join(format!(
            "fador-i18n-packs-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).expect("create pack directory");
        std::fs::write(directory.join("fi.json"), FI).expect("write Finnish pack");

        let pack = LanguagePack::load("fi", &directory).expect("load from disk");
        assert_eq!(pack.code(), "fi");
        assert_eq!(pack.lang("COLON", &[]), ":");
        assert!(matches!(
            LanguagePack::load("de", &directory),
            Err(PackError::UnknownLanguage(_))
        ));
        assert!(matches!(
            LanguagePack::load("fi", &directory.join("missing")),
            Err(PackError::UnknownLanguage(_))
        ));

        let embedded = EmbeddedPacks::new().add("en", EN).add("en_gb", EN);
        assert_eq!(embedded.len(), 2);
        assert!(!embedded.is_empty());
        assert!(embedded.get("en_US").is_some());
        assert_eq!(embedded.codes().count(), 2);
        assert!(embedded.get("fi").is_none());
        let from_registry = LanguagePack::from_embedded(&embedded, "en").expect("embedded pack");
        assert_eq!(from_registry.lang("COLON", &[]), ":");
        assert!(matches!(
            LanguagePack::from_embedded(&embedded, "fi"),
            Err(PackError::UnknownLanguage(_))
        ));

        // The file wins over the registry, and the registry fills the gap.
        let set = LanguageSet::load_with_embedded("fi", &directory, &embedded)
            .expect("load primary from disk and fallback from registry");
        assert_eq!(set.primary().code(), "fi");
        assert_eq!(set.fallback().code(), "en");
        assert_eq!(set.lang("COLON", &[]), ":");
        assert_eq!(set.lang("INDEX", &[]), "INDEX");
        assert_eq!(set.lang_file("common", "INDEX", &[]), "Etusivu");
        let english_only = LanguagePack::load_with_embedded("en", &directory, &embedded)
            .expect("fallback to registry");
        assert_eq!(english_only.code(), "en");
        assert!(matches!(
            LanguageSet::load("fi", &directory.join("missing")),
            Err(PackError::UnknownLanguage(_))
        ));

        std::fs::remove_dir_all(&directory).expect("remove pack directory");
    }

    #[test]
    fn rejects_invalid_packs() {
        assert!(matches!(
            LanguagePack::from_json("[]", "en"),
            Err(PackError::NotAnObject)
        ));
        assert!(matches!(
            LanguagePack::from_json("{", "en"),
            Err(PackError::Json(_))
        ));
        assert!(matches!(
            LanguagePack::from_json("\"text\"", "en"),
            Err(PackError::NotAnObject)
        ));
        // Every section is optional and a wrong type is ignored.
        let bare = LanguagePack::from_json(
            r#"{"messages": "nope", "files": [], "tz": 3, "datetime": [], "synonyms": 1}"#,
            "en",
        )
        .expect("empty pack");
        assert_eq!(bare.code(), "en");
        assert_eq!(bare.plural_rule(), 1);
        assert_eq!(bare.lang("COLON", &[]), "COLON");
        assert_eq!(bare.datetime().month_full(0), "January");
        assert_eq!(bare.dateformats(), Vec::<String>::new());
        assert!(bare.synonyms().is_empty());
        // A plural rule outside 0-15 falls back to rule 1.
        let odd = LanguagePack::from_json(
            r#"{"messages": {"PLURAL_RULE": 99, "X": ["no X", "one X", "%d X"]}}"#,
            "xx",
        )
        .unwrap();
        assert_eq!(odd.plural_rule(), 1);
        assert_eq!(odd.lang("X", &args(&["0"])), "no X");
        assert_eq!(odd.lang("X", &args(&["1"])), "one X");
        assert_eq!(odd.lang("X", &args(&["5"])), "5 X");
        // A string code in the document wins over the hint.
        let named = LanguagePack::from_json(r#"{"code": "sv"}"#, "en").unwrap();
        assert_eq!(named.code(), "sv");
    }

    #[test]
    fn reads_datetime_names_from_a_pack() {
        let pack = en();
        let names = pack.datetime();
        assert_eq!(names.day_full(4), "Thursday");
        assert_eq!(names.day_short(4), "Thu");
        assert_eq!(names.month_full(4), "May");
        assert_eq!(names.month_short(4), "May");
        assert_eq!(names.month_full(0), "January");
        assert_eq!(names.ago(1), "1 minute ago");
        assert_eq!(names.tomorrow(), "Tomorrow");
        assert_eq!(names.yesterday(), "Yesterday");
        let partial = LanguagePack::from_json(
            r#"{"datetime": {"Monday": "Maanantai", "May_short": "Touko"}}"#,
            "fi",
        )
        .unwrap();
        assert_eq!(partial.datetime().day_full(1), "Maanantai");
        assert_eq!(partial.datetime().day_full(0), "Sunday");
        assert_eq!(partial.datetime().month_short(4), "Touko");
        assert_eq!(partial.datetime().month_full(4), "May");
    }

    #[test]
    fn fuzz_pack_parsing_does_not_panic() {
        let mut rng = Rng::new(0x1a18_0001);
        let cases = iterations(300);
        for _ in 0..cases {
            let length = rng.below(120);
            let text = rng.text(length);
            let _ = LanguagePack::from_json(&text, "xx");
        }
        for hostile in fador_testutil::MALICIOUS_STRINGS {
            if let Ok(pack) = LanguagePack::from_json(hostile, "xx") {
                let _ = pack.lang("COLON", &args(&["1"]));
                let _ = pack.lang_file("common", "COLON", &[]);
                let _ = pack.timezone_label("UTC");
                let _ = pack.timezone_offset_label(3_600);
                let _ = pack.format_date(0, "UTC", "Y-m-d");
            }
        }
    }
}
