//! Literal code matching and replacement (smilies, emoji and autolink
//! prefixes).
//!
//! A "code" is a literal string a renderer replaces with markup: `:)`,
//! `:lol:`, `:-)`. The helpers here find the longest code at a position and
//! replace codes only at the boundaries the source board accepts, so `:)` in
//! `http://` or in `a:)b` is left alone.

/// The longest code in `codes` that `text` starts with.
///
/// Empty codes are ignored. Ties are impossible because the longest match is
/// returned, but if two codes have the same length the first one in `codes`
/// wins.
///
/// ```
/// use fador_markup::match_longest_code;
///
/// let codes = [":)", ":))", ":lol:"];
/// assert_eq!(match_longest_code(":)) hi", &codes), Some(":))"));
/// assert_eq!(match_longest_code("nope", &codes), None);
/// ```
pub fn match_longest_code<'a>(text: &str, codes: &[&'a str]) -> Option<&'a str> {
    let mut best: Option<&'a str> = None;
    for code in codes {
        if code.is_empty() || !text.starts_with(code) {
            continue;
        }
        if best.is_none_or(|current| code.len() > current.len()) {
            best = Some(code);
        }
    }
    best
}

/// Whether `ch` may directly precede a smiley code.
///
/// The source boards only expand a smiley after whitespace or one of the
/// punctuation characters that commonly surround one.
pub fn smiley_boundary_before(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '>' | ':' | '?' | '.' | '[' | ']' | '(' | ')' | '*' | '\\' | ';' | '\u{a0}'
        )
}

/// Whether `ch` may directly follow a smiley code.
///
/// A letter or digit directly after the code means it was part of a word and
/// not a smiley.
pub fn smiley_boundary_after(ch: char) -> bool {
    !ch.is_alphanumeric()
}

/// Replace every code in `pairs` with its markup, longest code first.
///
/// A code is only replaced when [`smiley_boundary_before`] accepts the
/// preceding character and [`smiley_boundary_after`] accepts the following one.
/// The replacement text is emitted verbatim, so the caller must escape it
/// before it reaches the document.
///
/// ```
/// use fador_markup::replace_codes;
///
/// let pairs = [(":)", "<img alt=\"smile\">")];
/// assert_eq!(replace_codes("hi :)", &pairs), "hi <img alt=\"smile\">");
/// assert_eq!(replace_codes("a:)b", &pairs), "a:)b");
/// ```
pub fn replace_codes(text: &str, pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() || text.is_empty() {
        return text.to_string();
    }
    let mut codes = pairs
        .iter()
        .map(|(code, _)| *code)
        .filter(|code| !code.is_empty())
        .collect::<Vec<_>>();
    if codes.is_empty() {
        return text.to_string();
    }
    // Longest first so the scan can stop at the first match.
    codes.sort_by_key(|code| std::cmp::Reverse(code.len()));
    let mut out = String::with_capacity(text.len());
    let mut previous: Option<char> = None;
    let mut index = 0usize;
    while index < text.len() {
        let rest = &text[index..];
        if previous.is_none_or(smiley_boundary_before) {
            if let Some(code) = match_longest_code(rest, &codes) {
                if rest[code.len()..]
                    .chars()
                    .next()
                    .is_none_or(smiley_boundary_after)
                {
                    if let Some((_, replacement)) =
                        pairs.iter().find(|(candidate, _)| *candidate == code)
                    {
                        out.push_str(replacement);
                        previous = rest[..code.len()].chars().next_back();
                        index += code.len();
                        continue;
                    }
                }
            }
        }
        let ch = rest.chars().next().unwrap_or('\0');
        out.push(ch);
        previous = Some(ch);
        index += ch.len_utf8();
    }
    out
}

/// PHP `strtr($input, $pairs)`: one pass, longest key first, no recursion.
///
/// Unlike [`replace_codes`] this has no boundary rules, and the replacement
/// text is not rescanned.
///
/// ```
/// use fador_markup::strtr;
///
/// let pairs = [("a", "1"), ("ab", "2")];
/// assert_eq!(strtr("ab a", &pairs), "2 1");
/// ```
pub fn strtr(input: &str, pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() || input.is_empty() {
        return input.to_string();
    }
    let mut ordered = pairs
        .iter()
        .filter(|(key, _)| !key.is_empty())
        .copied()
        .collect::<Vec<_>>();
    if ordered.is_empty() {
        return input.to_string();
    }
    ordered.sort_by_key(|(key, _)| std::cmp::Reverse(key.len()));
    let mut out = String::with_capacity(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let rest = &input[index..];
        match ordered.iter().find(|(key, _)| rest.starts_with(key)) {
            Some((key, replacement)) => {
                out.push_str(replacement);
                index += key.len();
            }
            None => {
                let ch = rest.chars().next().unwrap_or('\0');
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_code_wins() {
        let codes = [":)", ":))", ":)))"];
        assert_eq!(match_longest_code(":)))", &codes), Some(":)))"));
        assert_eq!(match_longest_code(":))", &codes), Some(":))"));
        assert_eq!(match_longest_code(":)", &codes), Some(":)"));
    }

    #[test]
    fn ignores_empty_codes_and_misses() {
        assert_eq!(match_longest_code("", &[""]), None);
        assert_eq!(match_longest_code("abc", &[]), None);
        assert_eq!(match_longest_code("abc", &["b"]), None);
    }

    #[test]
    fn keeps_order_for_equal_lengths() {
        assert_eq!(match_longest_code("ab", &["ab", "ab"]), Some("ab"));
        assert_eq!(match_longest_code("ab", &["ax", "ab"]), Some("ab"));
    }

    #[test]
    fn replace_respects_boundaries() {
        let pairs = [(":)", "[smile]")];
        assert_eq!(replace_codes("hi :)", &pairs), "hi [smile]");
        assert_eq!(replace_codes("a:)b", &pairs), "a:)b");
        assert_eq!(replace_codes("(:)", &pairs), "([smile]");
        assert_eq!(replace_codes(":)", &pairs), "[smile]");
    }

    #[test]
    fn replace_uses_the_longest_code() {
        let pairs = [(":)", "[a]"), (":))", "[b]")];
        assert_eq!(replace_codes(":))", &pairs), "[b]");
        assert_eq!(replace_codes(":) )", &pairs), "[a] )");
    }

    #[test]
    fn replace_does_not_rescan_its_output() {
        let pairs = [("a", "b"), ("b", "c")];
        assert_eq!(replace_codes("a b", &pairs), "b c");
    }

    #[test]
    fn replace_ignores_empty_input() {
        assert_eq!(replace_codes("", &[(":)", "[x]")]), "");
        assert_eq!(replace_codes("abc", &[]), "abc");
        assert_eq!(replace_codes("abc", &[("", "[x]")]), "abc");
    }

    #[test]
    fn strtr_prefers_the_longest_key() {
        assert_eq!(strtr("ab", &[("a", "1"), ("ab", "2")]), "2");
        assert_eq!(strtr("ab", &[("ab", "2"), ("a", "1")]), "2");
        assert_eq!(strtr("aaa", &[("aa", "x")]), "xa");
    }

    #[test]
    fn strtr_is_single_pass() {
        assert_eq!(strtr("&amp;", &[("&", "&amp;")]), "&amp;amp;");
        assert_eq!(strtr("abc", &[("b", "")]), "ac");
        assert_eq!(strtr("abc", &[("", "x")]), "abc");
        assert_eq!(strtr("", &[("a", "b")]), "");
    }

    #[test]
    fn boundaries_match_the_source_boards() {
        assert!(smiley_boundary_before(' '));
        assert!(smiley_boundary_before('>'));
        assert!(smiley_boundary_before('\u{a0}'));
        assert!(!smiley_boundary_before('a'));
        assert!(smiley_boundary_after(' '));
        assert!(smiley_boundary_after('.'));
        assert!(!smiley_boundary_after('a'));
        assert!(!smiley_boundary_after('ä'));
        assert!(!smiley_boundary_after('2'));
    }
}
