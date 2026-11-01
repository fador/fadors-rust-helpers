//! Search-keyword highlighting and excerpts.
//!
//! Highlighting never breaks markup: [`highlight_html`] copies `<...>` tags and
//! character references through untouched and only wraps text between them.
//! Matching is case-insensitive and Unicode-aware, and every inserted range is
//! a char boundary of the original string, so slicing can never panic and a
//! lowercasing that changes byte length cannot shift a highlight.

use crate::escape::{escape_into, EscapePolicy};
use crate::fold::find_ranges_ci;

/// Markup inserted before a highlighted range.
pub const HIGHLIGHT_OPEN: &str = "<strong class=\"highlight\">";

/// Markup inserted after a highlighted range.
pub const HIGHLIGHT_CLOSE: &str = "</strong>";

/// The most highlight ranges one segment may carry.
const MAX_RANGES: usize = 512;

/// The most matches [`excerpt`] collects before merging.
const MAX_EXCERPT_MATCHES: usize = 64;

/// The most snippets [`excerpt`] returns.
const MAX_EXCERPT_SNIPPETS: usize = 8;

/// The longest `<...>` run the tag scanner treats as a tag.
const MAX_TAG_LENGTH: usize = 8192;

/// The longest character reference the scanner treats as one.
const MAX_ENTITY_LENGTH: usize = 40;

/// Wrap every case-insensitive occurrence of `keywords` in `html` with
/// [`HIGHLIGHT_OPEN`] and [`HIGHLIGHT_CLOSE`].
///
/// Tags and character references are copied through untouched, so a keyword
/// such as `b` never highlights an element name and `amp` never splits
/// `&amp;`. The text is assumed to be HTML already; it is not escaped again.
///
/// ```
/// use fador_markup::highlight_html;
///
/// assert_eq!(
///     highlight_html("<p>Hello <b>world</b></p>", &["world"]),
///     "<p>Hello <b><strong class=\"highlight\">world</strong></b></p>"
/// );
/// ```
pub fn highlight_html<K: AsRef<str>>(html: &str, keywords: &[K]) -> String {
    if html.is_empty() || keywords.is_empty() {
        return html.to_string();
    }
    let mut out = String::with_capacity(html.len() + 32);
    let mut index = 0usize;
    while index < html.len() {
        let rest = &html[index..];
        if rest.starts_with('<') {
            if let Some(len) = tag_length(rest) {
                out.push_str(&rest[..len]);
                index += len;
                continue;
            }
        }
        if rest.starts_with('&') {
            if let Some(len) = entity_length(rest) {
                out.push_str(&rest[..len]);
                index += len;
                continue;
            }
        }
        let next = rest
            .find(['<', '&'])
            .map_or(html.len(), |offset| index + offset);
        if next == index {
            let ch = rest.chars().next().unwrap_or('\0');
            out.push(ch);
            index += ch.len_utf8();
        } else {
            out.push_str(&highlight_segment(&html[index..next], keywords));
            index = next;
        }
    }
    out
}

/// Wrap every case-insensitive occurrence of `keywords` in a plain text
/// segment with [`HIGHLIGHT_OPEN`] and [`HIGHLIGHT_CLOSE`].
///
/// `segment` is inserted verbatim, so it must already be escaped HTML text.
/// Removing the two highlight markers from the result returns the input
/// exactly.
///
/// ```
/// use fador_markup::highlight_segment;
///
/// assert_eq!(
///     highlight_segment("Ääkkösiä", &["äkkö"]),
///     "Ä<strong class=\"highlight\">äkkö</strong>siä"
/// );
/// ```
pub fn highlight_segment<K: AsRef<str>>(segment: &str, keywords: &[K]) -> String {
    if segment.is_empty() || keywords.is_empty() {
        return segment.to_string();
    }
    let ranges = collect_ranges(segment, keywords, MAX_RANGES);
    render(segment, &ranges, None)
}

/// Build a short HTML excerpt around the first matches of `keywords`.
///
/// `text` is plain text (run [`crate::strip_markup`] first when it is markup)
/// and `context` is the number of characters kept on each side of a match.
/// Up to eight snippets are returned, separated by a space, with `&hellip;`
/// where a snippet was cut out of a longer text. Each snippet is escaped and
/// then highlighted, so the result is safe to insert into a document. An empty
/// string means "no match".
///
/// ```
/// use fador_markup::excerpt;
///
/// assert_eq!(excerpt("the fox", &["cat"], 10), "");
/// assert!(excerpt("<b>fox", &["fox"], 8).contains("&lt;b&gt;"));
/// ```
pub fn excerpt<K: AsRef<str>>(text: &str, keywords: &[K], context: usize) -> String {
    if text.is_empty() || keywords.is_empty() {
        return String::new();
    }
    let matches = collect_ranges(text, keywords, MAX_EXCERPT_MATCHES);
    if matches.is_empty() {
        return String::new();
    }
    let mut expanded = matches
        .into_iter()
        .map(|(start, end)| expand_chars(text, start, end, context))
        .collect::<Vec<_>>();
    expanded.sort_unstable();
    let snippets = merge_ranges(expanded);
    let mut out = String::new();
    for (start, end) in snippets.into_iter().take(MAX_EXCERPT_SNIPPETS) {
        let normalized = normalize_whitespace(&text[start..end]);
        if normalized.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        if start > 0 {
            out.push_str("&hellip;");
        }
        let ranges = collect_ranges(&normalized, keywords, MAX_RANGES);
        out.push_str(&render(&normalized, &ranges, Some(EscapePolicy::Text)));
        if end < text.len() {
            out.push_str("&hellip;");
        }
    }
    out
}

/// Collect merged highlight ranges for every keyword.
fn collect_ranges<K: AsRef<str>>(text: &str, keywords: &[K], limit: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for keyword in keywords {
        let keyword = keyword.as_ref();
        if keyword.is_empty() || ranges.len() >= limit {
            continue;
        }
        find_ranges_ci(text, keyword, limit, &mut ranges);
    }
    ranges.sort_unstable();
    merge_ranges(ranges)
}

/// Merge overlapping and adjacent ranges.
fn merge_ranges(ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some((_, last_end)) if start <= *last_end => *last_end = (*last_end).max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Grow `[start, end)` by `context` characters on both sides.
fn expand_chars(text: &str, start: usize, end: usize, context: usize) -> (usize, usize) {
    let mut from = start;
    for _ in 0..context {
        match text[..from].chars().next_back() {
            Some(ch) => from -= ch.len_utf8(),
            None => break,
        }
    }
    let mut to = end;
    for _ in 0..context {
        match text[to..].chars().next() {
            Some(ch) => to += ch.len_utf8(),
            None => break,
        }
    }
    (from, to)
}

/// Collapse whitespace runs to one space and trim the result.
fn normalize_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_space = true;
        } else {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push(ch);
        }
    }
    out
}

/// Emit `text` with the ranges wrapped, optionally escaping each piece.
fn render(text: &str, ranges: &[(usize, usize)], policy: Option<EscapePolicy>) -> String {
    let mut out = String::with_capacity(
        text.len() + ranges.len() * (HIGHLIGHT_OPEN.len() + HIGHLIGHT_CLOSE.len()),
    );
    let mut position = 0usize;
    for (start, end) in ranges {
        push_escaped(&mut out, &text[position..*start], policy);
        out.push_str(HIGHLIGHT_OPEN);
        push_escaped(&mut out, &text[*start..*end], policy);
        out.push_str(HIGHLIGHT_CLOSE);
        position = *end;
    }
    push_escaped(&mut out, &text[position..], policy);
    out
}

/// Append `text`, escaping it when a policy is given.
fn push_escaped(out: &mut String, text: &str, policy: Option<EscapePolicy>) {
    match policy {
        Some(policy) => escape_into(policy, text, out),
        None => out.push_str(text),
    }
}

/// Length of the tag at the start of `rest`, including both angle brackets.
fn tag_length(rest: &str) -> Option<usize> {
    if rest.starts_with("<!--") {
        return rest.find("-->").map(|end| end + 3);
    }
    let end = rest.find('>')?;
    if end > MAX_TAG_LENGTH {
        return None;
    }
    Some(end + 1)
}

/// Length of the character reference at the start of `rest`.
fn entity_length(rest: &str) -> Option<usize> {
    let semicolon = rest
        .char_indices()
        .take(MAX_ENTITY_LENGTH)
        .find(|(_, ch)| *ch == ';')
        .map(|(index, _)| index)?;
    let body = &rest[1..semicolon];
    if body.is_empty() {
        return None;
    }
    let valid = if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
        !hex.is_empty() && hex.len() <= 8 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else if let Some(decimal) = body.strip_prefix('#') {
        !decimal.is_empty()
            && decimal.len() <= 8
            && decimal.bytes().all(|byte| byte.is_ascii_digit())
    } else {
        body.len() <= 32 && body.bytes().all(|byte| byte.is_ascii_alphanumeric())
    };
    valid.then_some(semicolon + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlights_text_between_tags_only() {
        assert_eq!(
            highlight_html("<p>Hello <b>world</b></p>", &["world"]),
            "<p>Hello <b><strong class=\"highlight\">world</strong></b></p>"
        );
        assert_eq!(highlight_html("<b>x</b>", &["b"]), "<b>x</b>");
        assert_eq!(
            highlight_html("<a href=\"target\">target</a>", &["target"]),
            "<a href=\"target\"><strong class=\"highlight\">target</strong></a>"
        );
    }

    #[test]
    fn skips_character_references() {
        assert_eq!(highlight_html("a &amp; b", &["amp"]), "a &amp; b");
        assert_eq!(highlight_html("&nbsp;", &["nbsp"]), "&nbsp;");
        assert_eq!(
            highlight_html("x &amp; fox", &["fox"]),
            "x &amp; <strong class=\"highlight\">fox</strong>"
        );
    }

    #[test]
    fn unicode_case_folding_keeps_offsets() {
        assert_eq!(
            highlight_segment("Ääkkösiä ja ää", &["ÄÄKKÖSIÄ"]),
            "<strong class=\"highlight\">Ääkkösiä</strong> ja ää"
        );
        // `İ` lowercases to two code points; the highlight must still slice the
        // original string at char boundaries.
        assert_eq!(
            highlight_segment("İstanbul", &["stan"]),
            "İ<strong class=\"highlight\">stan</strong>bul"
        );
    }

    #[test]
    fn merges_overlapping_keywords() {
        assert_eq!(
            highlight_segment("naruto uzumaki", &["naruto", "uto uz", "uzumaki"]),
            "<strong class=\"highlight\">naruto uzumaki</strong>"
        );
    }

    #[test]
    fn adjacent_ranges_merge() {
        assert_eq!(
            highlight_segment("abcd", &["ab", "cd"]),
            "<strong class=\"highlight\">abcd</strong>"
        );
    }

    #[test]
    fn empty_inputs_are_identity() {
        assert_eq!(highlight_html("", &["x"]), "");
        assert_eq!(highlight_html("<p>x</p>", &[] as &[&str]), "<p>x</p>");
        assert_eq!(highlight_segment("x", &[] as &[&str]), "x");
        assert_eq!(highlight_segment("", &["x"]), "");
    }

    #[test]
    fn removes_back_to_the_input() {
        let input = "<p>Hello <b>world</b> &amp; <i>fox</i></p>";
        let highlighted = highlight_html(input, &["world", "fox", "hello"]);
        let stripped = highlighted
            .replace(HIGHLIGHT_OPEN, "")
            .replace(HIGHLIGHT_CLOSE, "");
        assert_eq!(stripped, input);
    }

    #[test]
    fn excerpt_shows_context() {
        let text = "The quick brown fox jumps over the lazy dog";
        assert_eq!(
            excerpt(text, &["fox"], 10),
            "&hellip;ick brown <strong class=\"highlight\">fox</strong> jumps ove&hellip;"
        );
        assert_eq!(
            excerpt("fox", &["fox"], 10),
            "<strong class=\"highlight\">fox</strong>"
        );
    }

    #[test]
    fn excerpt_escapes_markup() {
        let result = excerpt("<script>alert(fox)</script>", &["fox"], 4);
        assert!(!result.contains("<script>"), "{result}");
        assert!(result.contains("&lt;"), "{result}");
        assert!(result.contains("<strong class=\"highlight\">fox</strong>"));
    }

    #[test]
    fn excerpt_without_a_match_is_empty() {
        assert_eq!(excerpt("the fox", &["cat"], 10), "");
        assert_eq!(excerpt("", &["cat"], 10), "");
        assert_eq!(excerpt("the fox", &[] as &[&str], 10), "");
    }

    #[test]
    fn excerpt_collapses_whitespace() {
        assert_eq!(
            excerpt("a\n\n  fox\tb", &["fox"], 20),
            "a <strong class=\"highlight\">fox</strong> b"
        );
    }

    #[test]
    fn excerpt_limits_the_snippet_count() {
        let text = (0..20)
            .map(|index| format!("fox{index:02}"))
            .collect::<Vec<_>>()
            .join(" ");
        let result = excerpt(&text, &["fox"], 1);
        let count = result.matches(HIGHLIGHT_OPEN).count();
        assert_eq!(count, MAX_EXCERPT_SNIPPETS);
    }

    #[test]
    fn tag_scanner_is_bounded() {
        let long = format!("<{}>", "a".repeat(MAX_TAG_LENGTH + 1));
        assert_eq!(tag_length(&long), None);
        assert_eq!(tag_length("<b>"), Some(3));
        assert_eq!(tag_length("<!-- x -->"), Some(10));
    }

    #[test]
    fn entity_scanner_matches_the_decoder() {
        assert_eq!(entity_length("&amp;"), Some(5));
        assert_eq!(entity_length("&#x1F600;"), Some(9));
        assert_eq!(entity_length("&unknown;"), Some(9));
        assert_eq!(entity_length("& b"), None);
        assert_eq!(entity_length("&#;"), None);
    }
}
