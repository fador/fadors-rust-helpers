//! HTML, attribute, entity and anchor sanitising.
//!
//! The generic decisions come from [`fador_markup`]: the attribute allow-list,
//! the inline-style declaration check and the URL scheme policy. What stays
//! local is the MediaWiki-specific part: the tag allow-list, the bounded
//! character-reference normaliser (which keeps `&copy;` as `&#169;` rather than
//! decoding it) and the section anchor encoding that matches MediaWiki's
//! `Sanitizer::escapeIdForAttribute`.

use fador_markup::{escape, EscapePolicy, SchemePolicy};

/// Escape text for an HTML text or quoted attribute position.
///
/// This is [`EscapePolicy::Attribute`], which escapes the same five characters
/// MediaWiki's `Sanitizer` does. Using one policy everywhere keeps the output
/// byte-identical whether the value lands in text or between quotes.
pub(crate) fn escape_html(text: &str) -> String {
    escape(EscapePolicy::Attribute, text)
}

/// Encode a section anchor the way MediaWiki does.
pub(crate) fn sanitize_anchor(text: &str) -> String {
    fador_core::util::anchor_encode(text)
}

/// The tags raw wikitext HTML may use.
pub(crate) fn is_allowed_tag(name: &str) -> bool {
    matches!(
        name,
        "a" | "abbr"
            | "b"
            | "bdi"
            | "bdo"
            | "big"
            | "blockquote"
            | "br"
            | "caption"
            | "center"
            | "cite"
            | "code"
            | "data"
            | "dd"
            | "del"
            | "dfn"
            | "div"
            | "dl"
            | "dt"
            | "em"
            | "figcaption"
            | "figure"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "hr"
            | "i"
            | "ins"
            | "kbd"
            | "li"
            | "mark"
            | "ol"
            | "p"
            | "pre"
            | "q"
            | "rb"
            | "rp"
            | "rt"
            | "rtc"
            | "ruby"
            | "s"
            | "samp"
            | "section"
            | "small"
            | "span"
            | "strike"
            | "strong"
            | "sub"
            | "sup"
            | "table"
            | "tbody"
            | "td"
            | "tfoot"
            | "th"
            | "thead"
            | "time"
            | "tr"
            | "tt"
            | "u"
            | "ul"
            | "var"
            | "wbr"
            | "audio"
            | "video"
            | "source"
            | "track"
    )
}

/// Parse one attribute value out of an opening tag.
pub(crate) fn parse_tag_attr(tag: &str, name: &str) -> Option<String> {
    let attrs = tag
        .split_once(char::is_whitespace)
        .map(|(_, rest)| rest)
        .unwrap_or("");
    let mut index = 0;
    let bytes = attrs.as_bytes();
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b'=' {
            index += 1;
        }
        let key = &attrs[start..index];
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let mut value = String::new();
        if index < bytes.len() && bytes[index] == b'=' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index < bytes.len() && (bytes[index] == b'"' || bytes[index] == b'\'') {
                let quote = bytes[index];
                index += 1;
                let value_start = index;
                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }
                value = attrs[value_start..index].to_string();
                if index < bytes.len() {
                    index += 1;
                }
            } else {
                let value_start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && bytes[index] != b'>'
                {
                    index += 1;
                }
                value = attrs[value_start..index].to_string();
            }
        }
        if key.eq_ignore_ascii_case(name) {
            return Some(value);
        }
    }
    None
}

/// Sanitise an attribute list for a table, raw tag or `<pre>` element.
///
/// The allow-list and the style check come from [`fador_markup`]. A URL
/// attribute is dropped when its value fails the scheme policy, which is what
/// MediaWiki's `Sanitizer::validateAttributes` does. The result always starts
/// with a leading space (or is empty) and is safe to concatenate into a tag.
pub(crate) fn sanitize_attrs(raw: &str) -> String {
    if raw.trim().is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let mut index = 0;
    let bytes = raw.as_bytes();
    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b'/') {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let name_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && !matches!(bytes[index], b'=' | b'>' | b'/' | b'"' | b'\'' | b'<')
        {
            index += 1;
        }
        if name_start == index {
            if bytes[index] == b'>' {
                break;
            }
            index += 1;
            continue;
        }
        let name = raw[name_start..index].to_ascii_lowercase();
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let mut value = String::new();
        if index < bytes.len() && bytes[index] == b'=' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index < bytes.len() && (bytes[index] == b'"' || bytes[index] == b'\'') {
                let quote = bytes[index];
                index += 1;
                let value_start = index;
                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }
                value = raw[value_start..index].to_string();
                if index < bytes.len() {
                    index += 1;
                }
            } else {
                let value_start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && bytes[index] != b'>'
                {
                    index += 1;
                }
                value = raw[value_start..index].to_string();
            }
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
            || !fador_markup::is_allowed_attr(&name)
        {
            continue;
        }
        if matches!(name.as_str(), "style" | "href" | "cite" | "src" | "poster")
            && value.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            continue;
        }
        value.retain(|c| !matches!(c, '\u{1}' | '\u{2}' | '\u{4}'));
        // A browser decodes character references in an attribute before it
        // parses a URL or a style, so an entity-encoded `javascript:` must be
        // judged decoded. Re-escaping afterwards keeps the stored spelling
        // safe and idempotent.
        let value = fador_markup::decode_entities(&value);
        let value = match name.as_str() {
            "style" => fador_markup::sanitize_style(&value),
            "href" | "cite" => match fador_markup::sanitize_url(&value, &SchemePolicy::STRICT) {
                Some(value) => value,
                None => continue,
            },
            "src" | "poster" => match fador_markup::sanitize_url(&value, &SchemePolicy::IMAGE) {
                Some(value) => value,
                None => continue,
            },
            _ => value,
        };
        if value.is_empty() && !matches!(name.as_str(), "class" | "id") {
            continue;
        }
        out.push(' ');
        out.push_str(&name);
        out.push_str("=\"");
        out.push_str(&escape_html(&value));
        out.push('"');
    }
    out
}

/// Normalise one HTML character reference.
///
/// Named references become numeric references (`&copy;` becomes `&#169;`), the
/// five XML references keep their named spelling and an unknown but
/// well-formed name is passed through unchanged. This is MediaWiki's
/// `Sanitizer::validateEntities` behaviour, not a decoder: decoding
/// `&#65;` to `A` here would change the stored page's bytes and would run
/// before the text is escaped. `rest` must start with `&`.
pub(crate) fn parse_entity(rest: &str) -> Option<(String, usize)> {
    let semicolon = rest.char_indices().take(40).find(|(_, c)| *c == ';')?.0;
    let candidate = &rest[1..semicolon];
    if candidate.is_empty() {
        return None;
    }
    let valid = if let Some(hex) = candidate
        .strip_prefix("#x")
        .or_else(|| candidate.strip_prefix("#X"))
    {
        !hex.is_empty() && hex.len() <= 8 && hex.chars().all(|c| c.is_ascii_hexdigit())
    } else if let Some(decimal) = candidate.strip_prefix('#') {
        !decimal.is_empty() && decimal.len() <= 8 && decimal.chars().all(|c| c.is_ascii_digit())
    } else {
        candidate.len() <= 32 && candidate.chars().all(|c| c.is_ascii_alphanumeric())
    };
    if !valid {
        return None;
    }
    let normalized = match candidate.to_ascii_lowercase().as_str() {
        "nbsp" => "&#160;".to_string(),
        "copy" => "&#169;".to_string(),
        "reg" => "&#174;".to_string(),
        "trade" => "&#8482;".to_string(),
        "hellip" => "&#8230;".to_string(),
        "ndash" => "&#8211;".to_string(),
        "mdash" => "&#8212;".to_string(),
        "lsquo" => "&#8216;".to_string(),
        "rsquo" => "&#8217;".to_string(),
        "ldquo" => "&#8220;".to_string(),
        "rdquo" => "&#8221;".to_string(),
        "laquo" => "&#171;".to_string(),
        "raquo" => "&#187;".to_string(),
        "times" => "&#215;".to_string(),
        "divide" => "&#247;".to_string(),
        "deg" => "&#176;".to_string(),
        "plusmn" => "&#177;".to_string(),
        "middot" => "&#183;".to_string(),
        "euro" => "&#8364;".to_string(),
        "pound" => "&#163;".to_string(),
        "yen" => "&#165;".to_string(),
        "cent" => "&#162;".to_string(),
        "sect" => "&#167;".to_string(),
        "para" => "&#182;".to_string(),
        "micro" => "&#181;".to_string(),
        "sup2" => "&#178;".to_string(),
        "sup3" => "&#179;".to_string(),
        "frac14" => "&#188;".to_string(),
        "frac12" => "&#189;".to_string(),
        "frac34" => "&#190;".to_string(),
        "iexcl" => "&#161;".to_string(),
        "iquest" => "&#191;".to_string(),
        "amp" => "&amp;".to_string(),
        "lt" => "&lt;".to_string(),
        "gt" => "&gt;".to_string(),
        "quot" => "\"".to_string(),
        "apos" => "'".to_string(),
        _ => rest[..=semicolon].to_string(),
    };
    Some((normalized, semicolon + 1))
}

/// Strip every `<...>` tag from rendered HTML, leaving its text.
pub(crate) fn strip_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    for character in text.chars() {
        match character {
            '<' => in_tag = true,
            '>' => in_tag = false,
            value if !in_tag => out.push(value),
            _ => {}
        }
    }
    out
}

/// Keep a reference name or group usable in an HTML id.
pub(crate) fn sanitize_ref_part(text: &str) -> String {
    text.chars()
        .filter(|character| character.is_alphanumeric() || matches!(character, '_' | '-' | '.'))
        .take(80)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rng, MALICIOUS_STRINGS};

    #[test]
    fn normalizes_named_html_entities() {
        assert_eq!(
            parse_entity("&copy;"),
            Some(("&#169;".to_string(), 6)),
            "&copy; should become a numeric entity"
        );
        assert_eq!(parse_entity("&amp;"), Some(("&amp;".to_string(), 5)));
        assert_eq!(
            parse_entity("&unknown;"),
            Some(("&unknown;".to_string(), 9))
        );
        assert_eq!(parse_entity("&#65;"), Some(("&#65;".to_string(), 5)));
        assert_eq!(parse_entity("&#x41;"), Some(("&#x41;".to_string(), 6)));
        assert_eq!(parse_entity("&"), None);
        assert_eq!(parse_entity("&;"), None);
        assert_eq!(parse_entity("&a b;"), None);
        assert_eq!(
            parse_entity(&format!("&{};", "a".repeat(33))),
            None,
            "a reference name longer than 32 characters is refused"
        );
    }

    #[test]
    fn sanitizes_attributes() {
        assert_eq!(sanitize_attrs("href=\"javascript:alert(1)\""), "");
        assert_eq!(sanitize_attrs("src=\"data:text/html,x\""), "");
        assert_eq!(
            sanitize_attrs("onclick=\"alert(1)\" href=\"https://example.test/\""),
            " href=\"https://example.test/\""
        );
        let dangerous_style = sanitize_attrs("style=\"background:url(javascript:x)\"");
        assert!(!dangerous_style.to_ascii_lowercase().contains("javascript:"));
        assert_eq!(
            sanitize_attrs("style=\"background:u\\72l(javascript:x)\""),
            ""
        );
        assert!(!sanitize_attrs("class=\"x\" onclick=\"x\"").contains("onclick"));
        assert_eq!(
            sanitize_attrs("class=\"wikitable\" style=\"color: red\""),
            " class=\"wikitable\" style=\"color: red\""
        );
        assert_eq!(sanitize_attrs("colspan=2"), " colspan=\"2\"");
        assert_eq!(
            sanitize_attrs("href=\"/wiki/Page\""),
            " href=\"/wiki/Page\""
        );
        assert_eq!(sanitize_attrs("href=\"#fragment\""), " href=\"#fragment\"");
        assert_eq!(sanitize_attrs("src=\"//evil.test/x.png\""), "");
        assert_eq!(
            sanitize_attrs("src=\"https://cdn.test/x.png\""),
            " src=\"https://cdn.test/x.png\""
        );
        assert!(
            !sanitize_attrs("data-x\"onclick=\"alert(1)\"")
                .to_ascii_lowercase()
                .contains("onclick")
        );
        assert!(
            !sanitize_attrs("data-x'onclick='alert(1)'")
                .to_ascii_lowercase()
                .contains("onclick")
        );
        assert_eq!(sanitize_attrs("style=\"background:\u{2}0\u{2}\""), "");
        assert_eq!(sanitize_attrs("href=\"\u{2}0\u{2}\""), "");
        assert_eq!(
            sanitize_attrs("title=\"\u{1}TOC\u{1}\""),
            " title=\"TOC\""
        );
    }

    #[test]
    fn parses_tag_attributes() {
        assert_eq!(
            parse_tag_attr("<ref name=\"a\">", "name").as_deref(),
            Some("a")
        );
        assert_eq!(
            parse_tag_attr("<ref name='a'>", "name").as_deref(),
            Some("a")
        );
        assert_eq!(
            parse_tag_attr("<ref group=notes>", "group").as_deref(),
            Some("notes")
        );
        assert_eq!(
            parse_tag_attr("<references group=\"x\">", "group").as_deref(),
            Some("x")
        );
        assert_eq!(parse_tag_attr("<ref>", "name"), None);
    }

    #[test]
    fn known_tags_only() {
        for tag in ["script", "img", "iframe", "object", "style", "form"] {
            assert!(!is_allowed_tag(tag), "{tag}");
        }
        for tag in ["div", "span", "table", "b", "i", "audio", "video", "source"] {
            assert!(is_allowed_tag(tag), "{tag}");
        }
    }

    #[test]
    fn strips_tags_and_sanitizes_reference_parts() {
        assert_eq!(strip_tags("<b>a</b> <i>b</i>"), "a b");
        assert_eq!(strip_tags("a < b"), "a ");
        assert_eq!(sanitize_ref_part("a b/c:d_e-f.g"), "abcd_e-f.g");
        assert_eq!(sanitize_ref_part(&"x".repeat(200)).len(), 80);
    }

    #[test]
    fn fuzz_html_attribute_sanitizer() {
        let mut rng = Rng::new(0x9a11_0001);
        for _ in 0..2_000 {
            let length = rng.below(200);
            let raw = rng.text(length);
            let sanitized = sanitize_attrs(&raw);
            assert!(!sanitized.contains('<') && !sanitized.contains('>'));
            let lower = sanitized.to_ascii_lowercase();
            assert!(!lower.contains(" onerror="));
            assert!(!lower.contains(" onload="));
            assert!(!lower.contains(" onclick="));
            assert!(!lower.contains("href=\"javascript:"));
            assert!(!lower.contains("src=\"javascript:"));
            assert!(!lower.contains("href=\"vbscript:"));
            assert!(!lower.contains("src=\"vbscript:"));
            assert!(!lower.contains("href=\"data:text/html"));
            assert!(!lower.contains("src=\"data:text/html"));
        }
        for raw in MALICIOUS_STRINGS {
            let sanitized = sanitize_attrs(raw);
            assert!(!sanitized.contains('<') && !sanitized.contains('>'));
        }
    }

    #[test]
    fn fuzz_url_style_anchor_and_entity_parsers() {
        let mut rng = Rng::new(0x9a11_0002);
        for _ in 0..2_000 {
            let length = rng.below(160);
            let input = rng.text(length);
            if let Some(url) = fador_markup::sanitize_url(&input, &SchemePolicy::STRICT) {
                let lower = url.to_ascii_lowercase();
                assert!(!lower.contains("javascript:"));
                assert!(!lower.contains("vbscript:"));
                assert!(!lower.contains("data:"));
                assert!(!url.contains('\0') && !url.contains('\r') && !url.contains('\n'));
            }
            let style = fador_markup::sanitize_style(&input);
            let lower = style.to_ascii_lowercase();
            assert!(!lower.contains("expression"));
            assert!(!lower.contains("javascript:"));
            assert!(!lower.contains("url("));
            assert!(!lower.contains("behavior:"));
            assert!(!lower.contains("-moz-binding"));
            assert!(!lower.contains("@import"));

            let anchor = sanitize_anchor(&input);
            assert!(anchor.is_ascii());
            assert!(!anchor.chars().any(char::is_control));

            let _ = parse_entity(&input);
        }
    }
}
