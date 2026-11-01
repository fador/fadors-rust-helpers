//! Small HTML vocabulary checks used next to a renderer.
//!
//! These are the leaf decisions a template or stored-markup renderer makes per
//! element and attribute: is the element void, does the attribute carry a URL,
//! may the attribute survive sanitising and is the inline style harmless.

/// Elements that never have children and must not be written with an end tag.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "basefont", "br", "col", "command", "embed", "frame", "hr", "img", "input",
    "isindex", "keygen", "link", "meta", "param", "source", "track", "wbr",
];

/// Attributes whose value a browser parses as a URL.
const URL_ATTRIBUTES: &[&str] = &[
    "action",
    "background",
    "cite",
    "data",
    "formaction",
    "href",
    "longdesc",
    "manifest",
    "poster",
    "src",
    "srcset",
    "usemap",
    "xlink:href",
];

/// Attributes the stored-markup sanitizer keeps.
const ALLOWED_ATTRIBUTES: &[&str] = &[
    "abbr",
    "align",
    "alt",
    "aria-describedby",
    "aria-hidden",
    "aria-label",
    "aria-labelledby",
    "autoplay",
    "bgcolor",
    "border",
    "cellpadding",
    "cellspacing",
    "cite",
    "class",
    "clear",
    "colspan",
    "controls",
    "datetime",
    "dir",
    "frame",
    "headers",
    "height",
    "href",
    "id",
    "kind",
    "label",
    "lang",
    "loop",
    "media",
    "muted",
    "poster",
    "preload",
    "rel",
    "reversed",
    "role",
    "rowspan",
    "rules",
    "scope",
    "src",
    "srclang",
    "start",
    "style",
    "summary",
    "target",
    "title",
    "type",
    "valign",
    "value",
    "width",
];

/// The longest inline style the sanitizer accepts, in bytes.
pub const MAX_STYLE_LENGTH: usize = 1024;

/// Whether `name` is an HTML void element.
///
/// The comparison is ASCII case-insensitive.
///
/// ```
/// use fador_markup::is_void_element;
///
/// assert!(is_void_element("br"));
/// assert!(is_void_element("IMG"));
/// assert!(!is_void_element("div"));
/// ```
pub fn is_void_element(name: &str) -> bool {
    VOID_ELEMENTS
        .iter()
        .any(|element| name.eq_ignore_ascii_case(element))
}

/// Whether `name` is an attribute whose value is a URL.
///
/// The comparison is ASCII case-insensitive.
///
/// ```
/// use fador_markup::is_url_attribute;
///
/// assert!(is_url_attribute("href"));
/// assert!(is_url_attribute("xlink:href"));
/// assert!(!is_url_attribute("title"));
/// ```
pub fn is_url_attribute(name: &str) -> bool {
    URL_ATTRIBUTES
        .iter()
        .any(|attribute| name.eq_ignore_ascii_case(attribute))
}

/// Whether `name` may survive the stored-markup sanitizer.
///
/// `data-*` and `aria-*` attributes are allowed by prefix; everything else must
/// be on the explicit list. Event handlers (`onclick`, `onerror`, …) are never
/// on it.
///
/// ```
/// use fador_markup::is_allowed_attr;
///
/// assert!(is_allowed_attr("class"));
/// assert!(is_allowed_attr("data-mw"));
/// assert!(!is_allowed_attr("onerror"));
/// ```
pub fn is_allowed_attr(name: &str) -> bool {
    ALLOWED_ATTRIBUTES
        .iter()
        .any(|attribute| name.eq_ignore_ascii_case(attribute))
        || name
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data-"))
        || name
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("aria-"))
}

/// Return `style` when it is a plain declaration list, otherwise an empty
/// string.
///
/// Inline styles only need simple declarations for wiki tables and spans, so
/// the sanitizer refuses anything that could execute or fetch: CSS escapes
/// (backslash), function calls (parentheses), at-rules, `expression`,
/// `javascript:`, `vbscript:`, `data:`, `url`, `behavior` and `-moz-binding`.
/// A style longer than [`MAX_STYLE_LENGTH`] is refused as well.
///
/// ```
/// use fador_markup::sanitize_style;
///
/// assert_eq!(sanitize_style("color: red"), "color: red");
/// assert_eq!(sanitize_style("background: url(https://x/y)"), "");
/// assert_eq!(sanitize_style("width: expression(alert(1))"), "");
/// ```
pub fn sanitize_style(style: &str) -> String {
    if style.len() > MAX_STYLE_LENGTH {
        return String::new();
    }
    if style.bytes().any(|byte| {
        matches!(
            byte,
            b'\\' | b'(' | b')' | b'{' | b'}' | b'@' | b'<' | b'>' | 0 | b'\r' | b'\n'
        )
    }) {
        return String::new();
    }
    let lower = style.to_ascii_lowercase();
    if lower.contains("expression")
        || lower.contains("javascript:")
        || lower.contains("vbscript:")
        || lower.contains("data:")
        || lower.contains("url")
        || lower.contains("behavior:")
        || lower.contains("-moz-binding")
    {
        return String::new();
    }
    style.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_void_elements() {
        for name in ["area", "br", "hr", "img", "input", "link", "meta", "wbr"] {
            assert!(is_void_element(name), "{name}");
            assert!(is_void_element(&name.to_ascii_uppercase()), "{name}");
        }
        for name in ["div", "span", "p", "script", "", "brr"] {
            assert!(!is_void_element(name), "{name}");
        }
    }

    #[test]
    fn knows_url_attributes() {
        for name in ["href", "src", "action", "poster", "xlink:href", "SRCSET"] {
            assert!(is_url_attribute(name), "{name}");
        }
        for name in ["title", "class", "onclick", ""] {
            assert!(!is_url_attribute(name), "{name}");
        }
    }

    #[test]
    fn allows_safe_attributes_only() {
        for name in [
            "class",
            "href",
            "data-mw",
            "aria-label",
            "DATA-X",
            "colspan",
        ] {
            assert!(is_allowed_attr(name), "{name}");
        }
        for name in ["onclick", "onerror", "style2", "data", "xmlns", ""] {
            assert!(!is_allowed_attr(name), "{name}");
        }
    }

    #[test]
    fn rejects_dangerous_styles() {
        assert_eq!(
            sanitize_style("color: red; font-weight: bold"),
            "color: red; font-weight: bold"
        );
        for style in [
            "background: url(https://example.com/x)",
            "width: expression(alert(1))",
            "behavior: url(x.htc)",
            "-moz-binding: url(x.xml)",
            "color: red\\; background: blue",
            "color: red\n} body {",
            "x: javascript:alert(1)",
            "@import 'x.css'",
        ] {
            assert_eq!(sanitize_style(style), "", "{style:?}");
        }
    }

    #[test]
    fn rejects_overlong_styles() {
        let long = "a".repeat(MAX_STYLE_LENGTH + 1);
        assert_eq!(sanitize_style(&long), "");
        let fits = "a".repeat(MAX_STYLE_LENGTH);
        assert_eq!(sanitize_style(&fits), fits);
    }
}
