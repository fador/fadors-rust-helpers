//! Word censoring.
//!
//! A [`Censor`] is a list of words and their replacements. Matching is
//! case-insensitive, Unicode-aware and whole-word: a word only matches when the
//! characters around it are neither alphanumeric nor an underscore, so `damn`
//! censors `Damn!` but leaves `damnation` and `damn_2` alone. When several
//! rules match at the same position the longest word wins, and the replacement
//! text is never rescanned by another rule.

use crate::fold::match_prefix_ci;

/// One censored word and the text that replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    word: String,
    /// `None` replaces the word with one asterisk per character.
    replacement: Option<String>,
}

/// Which characters count as a word boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CensorBoundary {
    /// Any character that is not alphanumeric and not `_`.
    #[default]
    Word,
    /// The exact punctuation set used by SMF 2.x.
    Smf,
}

/// A word censor.
///
/// ```
/// use fador_markup::Censor;
///
/// let censor = Censor::new().with_word("damn");
/// assert_eq!(censor.apply("Damn it, damnation"), "**** it, damnation");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Censor {
    rules: Vec<Rule>,
    boundary: CensorBoundary,
    case_insensitive: bool,
}

impl Default for Censor {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            boundary: CensorBoundary::Word,
            case_insensitive: true,
        }
    }
}

impl Censor {
    /// An empty censor that leaves every text unchanged.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select the word-boundary rule.
    pub fn with_boundary(mut self, boundary: CensorBoundary) -> Self {
        self.boundary = boundary;
        self
    }

    /// Select case-sensitive (`false`) or case-insensitive (`true`) matching.
    pub fn with_case_insensitive(mut self, case_insensitive: bool) -> Self {
        self.case_insensitive = case_insensitive;
        self
    }

    /// Add a word that is replaced with one asterisk per character.
    ///
    /// The word is trimmed; an empty word is ignored.
    pub fn with_word(mut self, word: &str) -> Self {
        self.push(word, None);
        self
    }

    /// Add a word and the text that replaces it.
    ///
    /// The word is trimmed; an empty word is ignored and an empty replacement
    /// falls back to one asterisk per character.
    pub fn with_replacement(mut self, word: &str, replacement: &str) -> Self {
        self.push(word, Some(replacement));
        self
    }

    /// Number of rules, including duplicates.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Apply every rule to `text`.
    pub fn apply(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        self.apply_into(text, &mut out);
        out
    }

    /// Append `text` with every rule applied to `out`.
    pub fn apply_into(&self, text: &str, out: &mut String) {
        if self.rules.is_empty() || text.is_empty() {
            out.push_str(text);
            return;
        }
        out.reserve(text.len());
        let mut previous: Option<char> = None;
        let mut index = 0usize;
        while index < text.len() {
            let rest = &text[index..];
            if previous.is_none_or(|ch| self.is_boundary(ch)) {
                if let Some((len, rule)) = self.match_at(rest) {
                    if rest[len..]
                        .chars()
                        .next()
                        .is_none_or(|ch| self.is_boundary(ch))
                    {
                        match &rule.replacement {
                            Some(replacement) => out.push_str(replacement),
                            None => {
                                for _ in 0..rule.word.chars().count() {
                                    out.push('*');
                                }
                            }
                        }
                        previous = rest[..len].chars().next_back();
                        index += len;
                        continue;
                    }
                }
            }
            let ch = rest.chars().next().unwrap_or('\0');
            out.push(ch);
            previous = Some(ch);
            index += ch.len_utf8();
        }
    }

    /// Longest rule that matches at the start of `rest`, with its byte length.
    fn match_at(&self, rest: &str) -> Option<(usize, &Rule)> {
        for rule in &self.rules {
            let matched = if self.case_insensitive {
                match_prefix_ci(rest, &rule.word)
            } else {
                rest.starts_with(&rule.word).then_some(rule.word.len())
            };
            if let Some(len) = matched {
                return Some((len, rule));
            }
        }
        None
    }

    fn is_boundary(&self, ch: char) -> bool {
        match self.boundary {
            CensorBoundary::Word => !(ch.is_alphanumeric() || ch == '_'),
            CensorBoundary::Smf => {
                ch.is_whitespace()
                    || matches!(
                        ch,
                        '>' | '.'
                            | '-'
                            | ','
                            | ';'
                            | ':'
                            | '!'
                            | '?'
                            | '('
                            | ')'
                            | '['
                            | ']'
                            | '"'
                            | '\''
                            | '&'
                    )
            }
        }
    }

    /// Insert a rule and keep the list ordered longest word first.
    fn push(&mut self, word: &str, replacement: Option<&str>) {
        let word = word.trim();
        if word.is_empty() {
            return;
        }
        let replacement = replacement
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        self.rules.push(Rule {
            word: word.to_string(),
            replacement,
        });
        // A stable sort keeps insertion order for equal lengths, so the first
        // rule added wins a tie.
        self.rules
            .sort_by_key(|rule| std::cmp::Reverse(rule.word.chars().count()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn censored_words_become_asterisks() {
        let censor = Censor::new().with_word("damn");
        assert_eq!(censor.apply("damn"), "****");
        assert_eq!(censor.apply("Damn it"), "**** it");
        assert_eq!(censor.apply("DAMN"), "****");
        assert_eq!(censor.apply("perkele ja saatana"), "perkele ja saatana");
    }

    #[test]
    fn respects_word_boundaries() {
        let censor = Censor::new().with_word("damn");
        assert_eq!(censor.apply("damnation"), "damnation");
        assert_eq!(censor.apply("damn_2"), "damn_2");
        assert_eq!(censor.apply("2damn"), "2damn");
        assert_eq!(censor.apply("(damn)"), "(****)");
        assert_eq!(censor.apply("damn!"), "****!");
        assert_eq!(censor.apply("damn'd"), "****'d");
        assert_eq!(censor.apply("a-damn-b"), "a-****-b");
    }

    #[test]
    fn uses_a_custom_replacement() {
        let censor = Censor::new().with_replacement("heck", "h***");
        assert_eq!(censor.apply("Heck, heck."), "h***, h***.");
    }

    #[test]
    fn empty_replacement_falls_back_to_asterisks() {
        let censor = Censor::new().with_replacement("damn", "");
        assert_eq!(censor.apply("damn"), "****");
    }

    #[test]
    fn longest_word_wins() {
        let censor = Censor::new()
            .with_word("damn")
            .with_replacement("damnation", "[removed]");
        assert_eq!(censor.apply("damnation and damn"), "[removed] and ****");
    }

    #[test]
    fn replacement_is_not_rescanned() {
        let censor = Censor::new()
            .with_replacement("foo", "bar")
            .with_word("bar");
        assert_eq!(censor.apply("foo bar"), "bar ***");
    }

    #[test]
    fn unicode_words_and_boundaries() {
        let censor = Censor::new().with_word("sää");
        assert_eq!(censor.apply("SÄÄ"), "***");
        assert_eq!(censor.apply("säästä"), "säästä");
        assert_eq!(censor.apply("sää!"), "***!");
    }

    #[test]
    fn empty_censor_is_identity() {
        let censor = Censor::new();
        assert!(censor.is_empty());
        assert_eq!(censor.apply("anything at all"), "anything at all");
        assert_eq!(censor.len(), 0);
    }

    #[test]
    fn ignores_empty_words() {
        let censor = Censor::new().with_word("").with_word("  ");
        assert!(censor.is_empty());
    }

    #[test]
    fn apply_into_appends() {
        let censor = Censor::new().with_word("damn");
        let mut out = String::from(">");
        censor.apply_into("damn", &mut out);
        assert_eq!(out, ">****");
    }

    #[test]
    fn smf_boundary_and_case_policy() {
        let smf = Censor::new()
            .with_word("damn")
            .with_boundary(CensorBoundary::Smf);
        assert_eq!(smf.apply("damn."), "****.");
        assert_eq!(smf.apply("damn<"), "damn<");
        assert_eq!(smf.apply("xdamn"), "xdamn");

        let case_sensitive = Censor::new().with_word("damn").with_case_insensitive(false);
        assert_eq!(case_sensitive.apply("Damn damn"), "Damn ****");
    }

    #[test]
    fn apply_is_idempotent_for_asterisk_rules() {
        let censor = Censor::new().with_word("damn").with_word("heck");
        let once = censor.apply("Damn, heck, damnation");
        assert_eq!(censor.apply(&once), once);
    }
}
