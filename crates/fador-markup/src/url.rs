//! URL scheme policy, sanitising and neutralising.
//!
//! Every function here expects a value that has already had HTML character
//! references decoded, exactly as a browser would decode an attribute value
//! before parsing it as a URL. Use [`crate::decode_entities`] first when the
//! input comes from stored markup.
//!
//! The checks are deliberately conservative: a value that cannot be parsed as
//! a scheme and is not a plain relative reference is refused rather than
//! guessed at.

use std::borrow::Cow;

/// The schemes and reference forms a URL policy accepts.
///
/// Construct a policy from one of the constants or with [`SchemePolicy::custom`]
/// and the `with_*` builders. Relative references are off by default so a
/// custom policy is deny-by-default.
///
/// ```
/// use fador_markup::{is_safe_url, SchemePolicy};
///
/// assert!(is_safe_url("https://example.com/", &SchemePolicy::WEB));
/// assert!(!is_safe_url("javascript:alert(1)", &SchemePolicy::WEB));
/// assert!(!is_safe_url("mailto:a@example.com", &SchemePolicy::IMAGE));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemePolicy {
    schemes: &'static [&'static str],
    relative: bool,
    fragment: bool,
    protocol_relative: bool,
}

impl SchemePolicy {
    /// The full set a board or wiki link may use: `http`, `https`, `ftp`,
    /// `ftps`, `mailto`, `irc` and `ircs`, plus relative, fragment and
    /// protocol-relative references.
    pub const STRICT: SchemePolicy = SchemePolicy {
        schemes: &["http", "https", "ftp", "ftps", "mailto", "irc", "ircs"],
        relative: true,
        fragment: true,
        protocol_relative: true,
    };

    /// The web-only set: `http`, `https` and `mailto`, plus relative, fragment
    /// and protocol-relative references.
    pub const WEB: SchemePolicy = SchemePolicy {
        schemes: &["http", "https", "mailto"],
        relative: true,
        fragment: true,
        protocol_relative: true,
    };

    /// Images: `http` and `https`, plus a same-origin relative path. A
    /// protocol-relative `//host/x` and a bare `#fragment` are refused.
    pub const IMAGE: SchemePolicy = SchemePolicy {
        schemes: &["http", "https"],
        relative: true,
        fragment: false,
        protocol_relative: false,
    };

    /// A deny-by-default policy for exactly `schemes`.
    pub const fn custom(schemes: &'static [&'static str]) -> Self {
        Self {
            schemes,
            relative: false,
            fragment: false,
            protocol_relative: false,
        }
    }

    /// Allow or refuse scheme-less relative references (`/x`, `./x`, `x/y`).
    pub const fn with_relative(mut self, allow: bool) -> Self {
        self.relative = allow;
        self
    }

    /// Allow or refuse a bare `#fragment` reference.
    pub const fn with_fragment(mut self, allow: bool) -> Self {
        self.fragment = allow;
        self
    }

    /// Allow or refuse a protocol-relative `//host/path` reference.
    pub const fn with_protocol_relative(mut self, allow: bool) -> Self {
        self.protocol_relative = allow;
        self
    }
}

/// Whether `url` is acceptable under `policy`.
///
/// The value is trimmed of ASCII whitespace first. It is refused when it
/// contains a control character, when an active scheme (`javascript`,
/// `vbscript`, `data`) appears at the start even after invisible format
/// characters are removed, when the scheme is not in the policy, when the
/// scheme contains whitespace (`java script:`), or when the reference form is
/// not allowed by the policy.
///
/// A value containing `&` is also checked after one round of character
/// reference decoding, because that is what a browser parses.
pub fn is_safe_url(url: &str, policy: &SchemePolicy) -> bool {
    if !is_safe_url_form(url, policy) {
        return false;
    }
    // A browser decodes character references in an attribute value before it
    // parses the URL, so `javascript&colon;` must be judged as `javascript:`.
    // The check runs on the decoded form as well; the decode never grows, so a
    // URL without `&` costs nothing.
    if url.contains('&') {
        let decoded = crate::escape::decode_entities_bounded(url, url.len());
        if decoded != url && !is_safe_url_form(&decoded, policy) {
            return false;
        }
    }
    true
}

/// The scheme and reference checks for one already-decoded form of a URL.
fn is_safe_url_form(url: &str, policy: &SchemePolicy) -> bool {
    let url = url.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if url.is_empty() {
        return policy.relative;
    }
    if url.chars().any(char::is_control) {
        return false;
    }
    if has_active_prefix(url) {
        return false;
    }
    match scan_scheme(url) {
        SchemeScan::None => relative_form(url, policy),
        SchemeScan::Scheme { name, spaced } => {
            !spaced
                && policy
                    .schemes
                    .iter()
                    .any(|allowed| name.eq_ignore_ascii_case(allowed))
        }
        SchemeScan::Invalid => false,
    }
}

/// What the leading part of a URL looks like.
enum SchemeScan {
    /// No `:` before the first `/`, `?` or `#`: a relative reference.
    None,
    /// A scheme, with the flag recording whitespace inside it.
    Scheme { name: String, spaced: bool },
    /// A `:` before any path separator, preceded by something that cannot be
    /// part of a scheme.
    Invalid,
}

/// Find the scheme at the start of `url`.
fn scan_scheme(url: &str) -> SchemeScan {
    let mut name = String::new();
    let mut spaced = false;
    let mut invalid = false;
    let mut previous = '\0';
    for ch in url.chars() {
        match ch {
            ':' => {
                if invalid {
                    return SchemeScan::Invalid;
                }
                return SchemeScan::Scheme { name, spaced };
            }
            // `&#` opens a numeric character reference, which a browser
            // decodes even without the closing `;` (`javascript&#58alert(1)`).
            // It may hide the `:` of a scheme, so it is not a fragment start.
            '#' if previous == '&' => return SchemeScan::Invalid,
            '/' | '?' | '#' => return SchemeScan::None,
            c if c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.') => {
                name.push(c.to_ascii_lowercase());
            }
            c if c.is_ascii_whitespace() => spaced = true,
            _ => invalid = true,
        }
        previous = ch;
    }
    SchemeScan::None
}

/// Check the reference forms that carry no scheme.
fn relative_form(url: &str, policy: &SchemePolicy) -> bool {
    let mut bytes = url.bytes();
    let first = bytes.next().unwrap_or(b'/');
    let second = bytes.next().unwrap_or(b'/');
    let slash = |byte: u8| byte == b'/' || byte == b'\\';
    if slash(first) && slash(second) {
        // Browsers treat a backslash as a slash in the authority position, so
        // `\\host` must be judged exactly like `//host`.
        return policy.protocol_relative;
    }
    if first == b'#' {
        return policy.fragment;
    }
    policy.relative
}

/// Detect an active scheme after removing whitespace and invisible characters.
///
/// This is defence in depth: [`scan_scheme`] already refuses a scheme that
/// contains any of those characters. Removing them here makes the refusal
/// explicit and keeps the invariant easy to test.
fn has_active_prefix(url: &str) -> bool {
    let mut prefix = String::new();
    for ch in url.chars() {
        if prefix.len() > 16 {
            break;
        }
        match ch {
            ':' => {
                prefix.push(':');
                break;
            }
            '/' | '?' | '#' => break,
            c if c.is_ascii_whitespace() || is_invisible(c) => {}
            c => prefix.push(c.to_ascii_lowercase()),
        }
    }
    matches!(prefix.as_str(), "javascript:" | "vbscript:" | "data:")
}

/// Zero-width and bidi formatting characters that can disguise a scheme.
fn is_invisible(ch: char) -> bool {
    matches!(
        ch,
        '\u{00ad}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// Return the trimmed URL when it is safe under `policy`.
///
/// ```
/// use fador_markup::{sanitize_url, SchemePolicy};
///
/// assert_eq!(
///     sanitize_url("  https://example.com/x  ", &SchemePolicy::WEB).as_deref(),
///     Some("https://example.com/x")
/// );
/// assert_eq!(sanitize_url("javascript:alert(1)", &SchemePolicy::WEB), None);
/// ```
pub fn sanitize_url(url: &str, policy: &SchemePolicy) -> Option<String> {
    let trimmed = url.trim_matches(char::is_whitespace);
    if trimmed.is_empty() || !is_safe_url(trimmed, policy) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Replace an unacceptable URL with the harmless fragment `#`.
///
/// A safe value is returned borrowed and unchanged, so the common case does
/// not allocate.
///
/// ```
/// use fador_markup::{neutralise_url, SchemePolicy};
///
/// assert_eq!(neutralise_url("javascript:alert(1)", &SchemePolicy::WEB), "#");
/// assert_eq!(neutralise_url("/index.php", &SchemePolicy::WEB), "/index.php");
/// ```
pub fn neutralise_url<'a>(url: &'a str, policy: &SchemePolicy) -> Cow<'a, str> {
    if is_safe_url(url, policy) {
        Cow::Borrowed(url)
    } else {
        Cow::Borrowed("#")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_active_schemes() {
        for url in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "vbscript:msgbox(1)",
            "data:text/html,<script>alert(1)</script>",
            "java\tscript:alert(1)",
            "java\nscript:alert(1)",
            "java script:alert(1)",
            " javascript:alert(1)",
            "\u{202e}javascript:alert(1)",
            "java\u{200b}script:alert(1)",
            "javascript&colon;alert(1)",
            "javascript&#00000000058;alert(1)",
            "javascript&#x0000000003a;alert(1)",
            "javascript&#58alert(1)",
            "javascript&#x3aalert(1)",
            "&#106;avascript:alert(1)",
        ] {
            assert!(!is_safe_url(url, &SchemePolicy::STRICT), "{url:?}");
            assert!(!is_safe_url(url, &SchemePolicy::WEB), "{url:?}");
            assert_eq!(neutralise_url(url, &SchemePolicy::WEB), "#", "{url:?}");
        }
    }

    #[test]
    fn accepts_web_urls() {
        for url in [
            "https://example.com/",
            "http://example.com/a?b=c#d",
            "HTTPS://EXAMPLE.COM/",
            "mailto:someone@example.com",
            "/index.php",
            "./relative",
            "../parent",
            "path/with/slashes",
            "?query=1",
            "#fragment",
            "//example.com/x",
            "",
        ] {
            assert!(is_safe_url(url, &SchemePolicy::WEB), "{url:?}");
        }
    }

    #[test]
    fn rejects_control_characters_anywhere() {
        assert!(!is_safe_url("https://example.com/\0", &SchemePolicy::WEB));
        assert!(!is_safe_url(
            "https://example.com/\r\nX: 1",
            &SchemePolicy::WEB
        ));
        assert!(!is_safe_url(
            "https://example.com/\u{7f}",
            &SchemePolicy::WEB
        ));
    }

    #[test]
    fn rejects_unknown_schemes() {
        for url in ["Luokka:Testi", "foo:bar", "C:\\Windows\\x", ":%"] {
            assert!(!is_safe_url(url, &SchemePolicy::STRICT), "{url:?}");
        }
    }

    #[test]
    fn image_policy_refuses_authority_and_fragment_forms() {
        assert!(is_safe_url("/images/x.png", &SchemePolicy::IMAGE));
        assert!(is_safe_url(
            "https://example.com/x.png",
            &SchemePolicy::IMAGE
        ));
        assert!(!is_safe_url("//example.com/x.png", &SchemePolicy::IMAGE));
        assert!(!is_safe_url("\\\\example.com\\x.png", &SchemePolicy::IMAGE));
        assert!(!is_safe_url("#x.png", &SchemePolicy::IMAGE));
        assert!(!is_safe_url(
            "ftp://example.com/x.png",
            &SchemePolicy::IMAGE
        ));
    }

    #[test]
    fn custom_policy_is_deny_by_default() {
        let policy = SchemePolicy::custom(&["gemini"]);
        assert!(is_safe_url("gemini://example.com", &policy));
        assert!(!is_safe_url("/relative", &policy));
        assert!(!is_safe_url("#fragment", &policy));
        assert!(!is_safe_url("//example.com", &policy));
        let policy = policy
            .with_relative(true)
            .with_fragment(true)
            .with_protocol_relative(true);
        assert!(is_safe_url("/relative", &policy));
        assert!(is_safe_url("#fragment", &policy));
        assert!(is_safe_url("//example.com", &policy));
    }

    #[test]
    fn sanitize_trims_and_rejects_empty() {
        assert_eq!(
            sanitize_url("  https://example.com/x  ", &SchemePolicy::WEB).as_deref(),
            Some("https://example.com/x")
        );
        assert_eq!(sanitize_url("   ", &SchemePolicy::WEB), None);
        assert_eq!(
            sanitize_url("javascript:alert(1)", &SchemePolicy::WEB),
            None
        );
    }

    #[test]
    fn neutralise_borrows_safe_values() {
        let safe = neutralise_url("/index.php", &SchemePolicy::WEB);
        assert!(matches!(safe, Cow::Borrowed("/index.php")));
        let unsafe_url = neutralise_url("data:,x", &SchemePolicy::WEB);
        assert!(matches!(unsafe_url, Cow::Borrowed("#")));
    }

    #[test]
    fn empty_url_follows_the_relative_flag() {
        assert!(is_safe_url("", &SchemePolicy::WEB));
        assert!(!is_safe_url("", &SchemePolicy::custom(&["http"])));
    }
}
