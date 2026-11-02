//! HTML/XML escaping and character-reference decoding.
//!
//! The policies mirror the four places the fador servers write text into a
//! document: element content, a quoted attribute, phpBB's `ENT_COMPAT`
//! attribute output and XSLT text output. A NUL byte cannot survive in an
//! HTML or XML document (browsers replace it with U+FFFD), so every policy
//! normalises it instead of emitting it.

/// Where an escaped string will be placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscapePolicy {
    /// Element text: `&`, `<` and `>` are escaped, quotes are left alone.
    Text,
    /// A quoted attribute value: `&`, `<`, `>`, `"` and `'` (`&#039;`) are
    /// escaped.
    Attribute,
    /// phpBB's `htmlspecialchars($value, ENT_COMPAT)`: like
    /// [`EscapePolicy::Attribute`], but apostrophes are left alone because the
    /// board always writes double-quoted attributes.
    CompatAttr,
    /// XML/XSLT text output: `&`, `<`, `>` and a carriage return (`&#13;`) are
    /// escaped. An XML parser normalises a literal CR to LF, so a text node
    /// that must keep it has to use a reference.
    XsltText,
}

/// Escape `input` for the document position named by `policy`.
///
/// ```
/// use fador_markup::{escape, EscapePolicy};
///
/// assert_eq!(escape(EscapePolicy::Text, "a & b"), "a &amp; b");
/// assert_eq!(
///     escape(EscapePolicy::Attribute, "\"quoted\""),
///     "&quot;quoted&quot;"
/// );
/// ```
pub fn escape(policy: EscapePolicy, input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    escape_into(policy, input, &mut out);
    out
}

/// Append `input` escaped by `policy` to `out`.
pub fn escape_into(policy: EscapePolicy, input: &str, out: &mut String) {
    out.reserve(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if matches!(policy, EscapePolicy::Attribute | EscapePolicy::CompatAttr) => {
                out.push_str("&quot;");
            }
            '\'' if policy == EscapePolicy::Attribute => out.push_str("&#039;"),
            '\r' if policy == EscapePolicy::XsltText => out.push_str("&#13;"),
            '\0' => out.push('\u{fffd}'),
            _ => out.push(ch),
        }
    }
}

/// The references [`unescape_compat`] decodes, longest first is not required
/// because no entry is a prefix of another.
const COMPAT_ENTITIES: &[(&str, &str)] = &[
    ("&amp;", "&"),
    ("&lt;", "<"),
    ("&gt;", ">"),
    ("&quot;", "\""),
    ("&apos;", "'"),
    ("&#039;", "'"),
    ("&#39;", "'"),
    ("&nbsp;", "\u{a0}"),
];

/// Decode the references phpBB and SMF emit, in one left-to-right pass.
///
/// Only the special characters and the apostrophe spellings are decoded:
/// `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&#039;`, `&#39;` and
/// `&nbsp;`. Because the pass never rescans its own output, `&amp;lt;` becomes
/// `&lt;` and not `<`. Unknown references such as `&copy;` are kept verbatim.
///
/// ```
/// use fador_markup::unescape_compat;
///
/// assert_eq!(unescape_compat("&amp;lt; &#039;"), "&lt; '");
/// ```
pub fn unescape_compat(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(position) = rest.find('&') {
        out.push_str(&rest[..position]);
        rest = &rest[position..];
        match COMPAT_ENTITIES
            .iter()
            .find(|(pattern, _)| rest.starts_with(pattern))
        {
            Some((pattern, decoded)) => {
                out.push_str(decoded);
                rest = &rest[pattern.len()..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Decode character references, stopping once `limit` bytes are written.
///
/// Named references are limited to the HTML 4 subset the fador servers emit
/// (see [`decode_entities`]); numeric references accept `&#123;` and `&#x7b;`
/// with at most eight digits. An unknown or malformed reference is copied
/// verbatim, a lone `&` is copied as is, and an invalid code point (NUL, a
/// surrogate or anything above U+10FFFF) becomes U+FFFD. A literal NUL in the
/// input is copied unchanged; [`escape`] normalises it when the text reaches a
/// document.
///
/// Decoding never produces more bytes than it consumes, so a `limit` of at
/// least `input.len()` is lossless. The result is truncated at a char boundary
/// when the limit is reached.
///
/// ```
/// use fador_markup::decode_entities_bounded;
///
/// assert_eq!(decode_entities_bounded("&amp;x", 1), "&");
/// assert_eq!(decode_entities_bounded("&amp;x", 2), "&x");
/// ```
pub fn decode_entities_bounded(input: &str, limit: usize) -> String {
    let mut out = String::with_capacity(input.len().min(limit));
    let mut rest = input;
    while let Some(position) = rest.find('&') {
        if !push_bounded(&mut out, &rest[..position], limit) {
            return out;
        }
        rest = &rest[position..];
        match parse_reference(rest) {
            Some((decoded, len)) => {
                if out.len() + decoded.len_utf8() > limit {
                    return out;
                }
                out.push(decoded);
                rest = &rest[len..];
            }
            None => {
                if out.len() >= limit {
                    return out;
                }
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    push_bounded(&mut out, rest, limit);
    out
}

/// Decode character references without an output limit.
///
/// This is [`decode_entities_bounded`] with `input.len()` as the limit, which
/// cannot truncate because every decoded reference is shorter than its source.
pub fn decode_entities(input: &str) -> String {
    decode_entities_bounded(input, input.len())
}

/// Copy as much of `text` as fits in `limit`, never splitting a code point.
///
/// Returns `false` when the text did not fit completely.
fn push_bounded(out: &mut String, text: &str, limit: usize) -> bool {
    let remaining = limit.saturating_sub(out.len());
    if text.len() <= remaining {
        out.push_str(text);
        return true;
    }
    let mut end = remaining;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    out.push_str(&text[..end]);
    false
}

/// Parse one reference at the start of `rest` (which begins with `&`).
///
/// Returns the decoded character and the number of bytes the reference spans.
fn parse_reference(rest: &str) -> Option<(char, usize)> {
    let semicolon = rest
        .char_indices()
        .take(40)
        .find(|(_, ch)| *ch == ';')
        .map(|(index, _)| index)?;
    let body = &rest[1..semicolon];
    if body.is_empty() {
        return None;
    }
    let decoded = if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let hex_sig = hex.trim_start_matches('0');
        if hex_sig.len() > 8 {
            return None;
        }
        let value = if hex_sig.is_empty() {
            0
        } else {
            u32::from_str_radix(hex_sig, 16).ok()?
        };
        numeric_character(value)
    } else if let Some(decimal) = body.strip_prefix('#') {
        if decimal.is_empty() || !decimal.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let dec_sig = decimal.trim_start_matches('0');
        if dec_sig.len() > 8 {
            return None;
        }
        let value = if dec_sig.is_empty() {
            0
        } else {
            dec_sig.parse::<u32>().ok()?
        };
        numeric_character(value)
    } else {
        if body.len() > 32 || !body.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return None;
        }
        named_entity(body)?
    };
    Some((decoded, semicolon + 1))
}

/// Map a numeric reference to a character, replacing invalid code points.
fn numeric_character(value: u32) -> char {
    match char::from_u32(value) {
        Some('\0') | None => '\u{fffd}',
        Some(ch) => ch,
    }
}

/// The named references the fador servers emit, plus the ASCII punctuation
/// aliases HTML5 defines. The punctuation names matter for URL checking: a
/// browser decodes `&colon;` to `:` before it parses a link.
fn named_entity(name: &str) -> Option<char> {
    let ch = match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => '\u{a0}',
        "Tab" => '\t',
        "NewLine" => '\n',
        "colon" => ':',
        "semi" => ';',
        "sol" => '/',
        "bsol" => '\\',
        "num" => '#',
        "quest" => '?',
        "percnt" => '%',
        "lpar" => '(',
        "rpar" => ')',
        "commat" => '@',
        "equals" => '=',
        "copy" => '\u{a9}',
        "reg" => '\u{ae}',
        "trade" => '\u{2122}',
        "hellip" => '\u{2026}',
        "ndash" => '\u{2013}',
        "mdash" => '\u{2014}',
        "lsquo" => '\u{2018}',
        "rsquo" => '\u{2019}',
        "ldquo" => '\u{201c}',
        "rdquo" => '\u{201d}',
        "laquo" => '\u{ab}',
        "raquo" => '\u{bb}',
        "times" => '\u{d7}',
        "divide" => '\u{f7}',
        "deg" => '\u{b0}',
        "plusmn" => '\u{b1}',
        "middot" => '\u{b7}',
        "euro" => '\u{20ac}',
        "pound" => '\u{a3}',
        "yen" => '\u{a5}',
        "cent" => '\u{a2}',
        "sect" => '\u{a7}',
        "para" => '\u{b6}',
        "micro" => '\u{b5}',
        "sup2" => '\u{b2}',
        "sup3" => '\u{b3}',
        "frac14" => '\u{bc}',
        "frac12" => '\u{bd}',
        "frac34" => '\u{be}',
        "iexcl" => '\u{a1}',
        "iquest" => '\u{bf}',
        _ => return None,
    };
    Some(ch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_policy_leaves_quotes_alone() {
        assert_eq!(
            escape(EscapePolicy::Text, "<a href=\"x\">&'"),
            "&lt;a href=\"x\"&gt;&amp;'"
        );
    }

    #[test]
    fn attribute_policy_escapes_both_quotes() {
        assert_eq!(
            escape(EscapePolicy::Attribute, "\"a\" 'b' <&>"),
            "&quot;a&quot; &#039;b&#039; &lt;&amp;&gt;"
        );
    }

    #[test]
    fn compat_attribute_keeps_apostrophes() {
        assert_eq!(
            escape(EscapePolicy::CompatAttr, "phpBB's \"quote\" <&>"),
            "phpBB's &quot;quote&quot; &lt;&amp;&gt;"
        );
    }

    #[test]
    fn xslt_text_escapes_carriage_returns() {
        assert_eq!(escape(EscapePolicy::XsltText, "a\r\nb"), "a&#13;\nb");
        assert_eq!(escape(EscapePolicy::Text, "a\r\nb"), "a\r\nb");
    }

    #[test]
    fn nul_becomes_the_replacement_character() {
        for policy in [
            EscapePolicy::Text,
            EscapePolicy::Attribute,
            EscapePolicy::CompatAttr,
            EscapePolicy::XsltText,
        ] {
            assert_eq!(escape(policy, "a\0b"), "a\u{fffd}b");
        }
    }

    #[test]
    fn escape_into_appends() {
        let mut out = String::from("prefix:");
        escape_into(EscapePolicy::Text, "<x>", &mut out);
        assert_eq!(out, "prefix:&lt;x&gt;");
    }

    #[test]
    fn unescape_compat_is_single_pass() {
        assert_eq!(unescape_compat("&amp;lt;"), "&lt;");
        assert_eq!(unescape_compat("&#039;&#39;&apos;"), "'''");
        assert_eq!(unescape_compat("&nbsp;"), "\u{a0}");
        assert_eq!(unescape_compat("&copy; &unknown;"), "&copy; &unknown;");
        assert_eq!(unescape_compat("a & b"), "a & b");
        assert_eq!(unescape_compat(""), "");
    }

    #[test]
    fn escape_and_unescape_roundtrip() {
        for policy in [EscapePolicy::Text, EscapePolicy::Attribute] {
            let input = "<a href=\"x\">&' \u{fffd} ä 💣";
            assert_eq!(unescape_compat(&escape(policy, input)), input);
        }
    }

    #[test]
    fn decodes_named_and_numeric_references() {
        assert_eq!(decode_entities("a&amp;b"), "a&b");
        assert_eq!(decode_entities("&#65;&#x42;&#X43;"), "ABC");
        assert_eq!(decode_entities("&euro;&hellip;"), "\u{20ac}\u{2026}");
        assert_eq!(decode_entities("&unknown;"), "&unknown;");
        assert_eq!(decode_entities("&#x1F600;"), "😀");
        assert_eq!(decode_entities("a & b"), "a & b");
        assert_eq!(decode_entities("&amp"), "&amp");
    }

    #[test]
    fn maps_invalid_code_points_to_replacement() {
        assert_eq!(decode_entities("&#0;"), "\u{fffd}");
        assert_eq!(decode_entities("&#000000000000;"), "\u{fffd}");
        assert_eq!(decode_entities("&#x000000000000;"), "\u{fffd}");
        assert_eq!(decode_entities("&#00000000058;"), ":");
        assert_eq!(decode_entities("&#x0000000003a;"), ":");
        assert_eq!(decode_entities("&#xD800;"), "\u{fffd}");
        assert_eq!(decode_entities("&#x110000;"), "\u{fffd}");
        assert_eq!(decode_entities("&#999999999999;"), "&#999999999999;");
    }

    #[test]
    fn bounded_decoding_stops_at_the_limit() {
        assert_eq!(decode_entities_bounded("&amp;x", 0), "");
        assert_eq!(decode_entities_bounded("&amp;x", 1), "&");
        assert_eq!(decode_entities_bounded("&amp;x", 2), "&x");
        assert_eq!(decode_entities_bounded("&amp;x", 99), "&x");
        assert_eq!(decode_entities_bounded("&#x1F600;!", 4), "😀");
        assert_eq!(decode_entities_bounded("&#x1F600;!", 3), "");
        assert_eq!(decode_entities_bounded("äö", 3), "ä");
    }

    #[test]
    fn bounded_decoding_never_exceeds_the_limit() {
        for input in [
            "&amp;&lt;&gt;",
            "&#x1F600;&#x1F600;",
            "plain text with & references",
            "ääääääää",
        ] {
            for limit in 0..=input.len() + 2 {
                let decoded = decode_entities_bounded(input, limit);
                assert!(decoded.len() <= limit, "{decoded:?} > {limit}");
                assert!(decoded.is_char_boundary(decoded.len()));
            }
        }
    }

    #[test]
    fn reference_scan_is_bounded() {
        let long = format!("&{}", "a".repeat(64));
        assert_eq!(decode_entities(&long), long);
        let long_numeric = format!("&#{};", "1".repeat(64));
        assert_eq!(decode_entities(&long_numeric), long_numeric);
    }
}
