//! Plain-text extraction from HTML-ish markup.

use crate::escape::decode_entities;
use crate::fold::find_ci;

/// The longest tag the scanner will look for a `>` in.
///
/// A `<` that is not followed by a complete tag within this many bytes is
/// treated as literal text, which keeps a pathological input linear.
const MAX_TAG_LENGTH: usize = 8192;

/// Elements that start a new line in plain text.
const BLOCK_ELEMENTS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "ul",
];

/// A tag found at the start of a string.
struct Tag<'a> {
    /// Lowercase comparison is done with `eq_ignore_ascii_case`, so this keeps
    /// the original spelling.
    name: &'a str,
    /// Bytes to consume, including the angle brackets.
    len: usize,
}

/// Strip every tag from `html` and decode character references.
///
/// Block-level elements and `<br>` become a single newline, so `<p>a</p><p>b</p>`
/// reads as `a\nb\n`. Inline tags disappear. The bodies of `<script>` and
/// `<style>` are dropped entirely, as are comments and doctypes. A `<` that does
/// not begin a complete tag is kept as literal text.
///
/// The result is never longer than the input: tags are removed and every
/// character reference decodes to something shorter. No whitespace is
/// collapsed and a literal NUL is copied unchanged; use [`crate::excerpt`] when
/// a single-line summary is wanted and [`crate::escape`] before the text
/// reaches a document.
///
/// ```
/// use fador_markup::strip_markup;
///
/// assert_eq!(
///     strip_markup("<p>Hello <b>world</b></p><script>alert(1)</script>"),
///     "Hello world\n"
/// );
/// ```
pub fn strip_markup(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut index = 0usize;
    while index < html.len() {
        let rest = &html[index..];
        if rest.starts_with('<') {
            if let Some(tag) = parse_tag(rest) {
                if is_block_element(tag.name) {
                    push_break(&mut out);
                }
                index += tag.len;
                continue;
            }
            out.push('<');
            index += 1;
            continue;
        }
        let next = rest.find('<').map_or(html.len(), |offset| index + offset);
        push_text(&mut out, &html[index..next]);
        index = next;
    }
    out
}

/// Parse the tag at the start of `rest` (which begins with `<`).
fn parse_tag(rest: &str) -> Option<Tag<'_>> {
    if rest.starts_with("<!--") {
        return Some(Tag {
            name: "",
            len: rest.find("-->").map_or(rest.len(), |end| end + 3),
        });
    }
    if rest.starts_with("<![CDATA[") {
        return Some(Tag {
            name: "",
            len: rest.find("]]>").map_or(rest.len(), |end| end + 3),
        });
    }
    let bytes = rest.as_bytes();
    let closing = bytes.get(1) == Some(&b'/');
    let name_start = if closing { 2 } else { 1 };
    let first = *bytes.get(name_start)?;
    if !(first.is_ascii_alphabetic() || (!closing && matches!(first, b'!' | b'?'))) {
        return None;
    }
    let close = rest.find('>')?;
    if close > MAX_TAG_LENGTH {
        return None;
    }
    let name = tag_name(&rest[name_start..close]);
    if !closing && (name.eq_ignore_ascii_case("script") || name.eq_ignore_ascii_case("style")) {
        // The body of a script or style element is never plain text.
        let closing_tag = if name.eq_ignore_ascii_case("script") {
            "</script"
        } else {
            "</style"
        };
        let body_start = close + 1;
        let len = match find_ci(&rest[body_start..], closing_tag) {
            Some(offset) => {
                let close_start = body_start + offset;
                match rest[close_start..].find('>') {
                    Some(end) => close_start + end + 1,
                    None => rest.len(),
                }
            }
            None => rest.len(),
        };
        return Some(Tag { name, len });
    }
    Some(Tag {
        name,
        len: close + 1,
    })
}

/// The element name in `inner`, without attributes or a trailing slash.
fn tag_name(inner: &str) -> &str {
    inner
        .trim_start()
        .split(|ch: char| ch.is_ascii_whitespace() || ch == '/')
        .next()
        .unwrap_or("")
}

/// Whether `name` starts a new line.
fn is_block_element(name: &str) -> bool {
    BLOCK_ELEMENTS
        .iter()
        .any(|element| name.eq_ignore_ascii_case(element))
}

/// Append a newline unless the output already ends with one.
fn push_break(out: &mut String) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
}

/// Append text with character references decoded and NBSP turned into a space.
fn push_text(out: &mut String, text: &str) {
    if text.is_empty() {
        return;
    }
    for ch in decode_entities(text).chars() {
        out.push(if ch == '\u{a0}' { ' ' } else { ch });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_inline_tags_and_keeps_text() {
        assert_eq!(strip_markup("<b>Hello</b> <i>world</i>"), "Hello world");
        assert_eq!(strip_markup("no markup"), "no markup");
        assert_eq!(strip_markup(""), "");
    }

    #[test]
    fn block_elements_become_newlines() {
        assert_eq!(strip_markup("<p>Hello <b>world</b></p>"), "Hello world\n");
        assert_eq!(strip_markup("<p>a</p><p>b</p>"), "a\nb\n");
        assert_eq!(strip_markup("a<br>b<br><br>c"), "a\nb\nc");
        assert_eq!(strip_markup("<li>a</li><li>b</li>"), "a\nb\n");
    }

    #[test]
    fn drops_script_and_style_bodies() {
        assert_eq!(
            strip_markup("a<script>alert('<b>')</script>b"),
            "ab".to_string()
        );
        assert_eq!(
            strip_markup("a<STYLE>p { color: red }</STYLE>b"),
            "ab".to_string()
        );
        assert_eq!(strip_markup("a<script>never closed"), "a");
    }

    #[test]
    fn decodes_entities() {
        assert_eq!(strip_markup("a &amp; b &lt;c&gt;"), "a & b <c>");
        assert_eq!(strip_markup("a&nbsp;b"), "a b");
        assert_eq!(strip_markup("&#65;&#x42;"), "AB");
    }

    #[test]
    fn keeps_literal_less_than() {
        assert_eq!(strip_markup("1 < 2"), "1 < 2");
        assert_eq!(strip_markup("a <b"), "a <b");
        assert_eq!(strip_markup("x <3 y"), "x <3 y");
    }

    #[test]
    fn skips_comments_and_doctypes() {
        assert_eq!(strip_markup("a<!-- hidden -->b"), "ab");
        assert_eq!(strip_markup("<!DOCTYPE html><p>x</p>"), "x\n");
        assert_eq!(strip_markup("a<!-- open"), "a");
    }

    #[test]
    fn treats_a_long_angle_bracket_as_text() {
        let long = format!("<{}>", "a".repeat(MAX_TAG_LENGTH + 1));
        assert_eq!(strip_markup(&long), long);
    }

    #[test]
    fn output_never_exceeds_the_input() {
        for input in [
            "<p>Hello <b>world</b></p>",
            "a &amp; b",
            "<script>alert(1)</script>",
            "<br>",
            "1 < 2",
            "&amp;",
        ] {
            assert!(strip_markup(input).len() <= input.len(), "{input:?} grew");
        }
    }
}
