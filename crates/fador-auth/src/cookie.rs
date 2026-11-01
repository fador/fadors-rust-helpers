//! Cookie construction, validation and `Cookie` header parsing.
//!
//! A cookie value is attacker-visible data that ends up in a response header,
//! so this module never copies a configured or generated value straight into a
//! header. [`Cookie::to_header_value`] and [`CookieCodec::encode`]:
//!
//! - reject a name that is not an RFC 6265 token,
//! - percent-encode the value, so CR, LF, `;`, `,`, `=` and spaces cannot split
//!   the header or add an attribute,
//! - validate the path and the domain instead of copying them,
//! - fold `SameSite` to one of three known values,
//! - refuse `SameSite=None` without `Secure`.
//!
//! The value is stored raw and encoded on output, so a caller can compare the
//! value it set with the value it read back through [`CookieCodec::decode`].

use fador_core::util::{http_date, percent_decode, rawurlencode};
use std::fmt;

/// The `SameSite` cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Sent on top-level cross-site navigations.
    Lax,
    /// Never sent on a cross-site request.
    Strict,
    /// Sent on every request, including cross-site ones. Requires `Secure`.
    None,
}

impl SameSite {
    /// The attribute value as it appears in a header.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }

    /// Parse an attribute value case-insensitively.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "lax" => Some(Self::Lax),
            "strict" => Some(Self::Strict),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A cookie value that cannot be written as a header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieError {
    /// The name is empty, too long or contains a byte outside the RFC 6265
    /// token set.
    InvalidName(String),
    /// The value is longer than [`MAX_COOKIE_VALUE`] bytes.
    InvalidValue(usize),
    /// The path is not absolute, is too long or contains a forbidden byte.
    InvalidPath(String),
    /// The domain contains a forbidden byte, an empty label or an over-long
    /// label.
    InvalidDomain(String),
    /// `SameSite=None` was requested without `Secure`; browsers reject it.
    InsecureSameSiteNone,
}

impl fmt::Display for CookieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(value) => write!(f, "invalid cookie name: {value:?}"),
            Self::InvalidValue(length) => {
                write!(
                    f,
                    "cookie value is {length} bytes, limit {MAX_COOKIE_VALUE}"
                )
            }
            Self::InvalidPath(value) => write!(f, "invalid cookie path: {value:?}"),
            Self::InvalidDomain(value) => write!(f, "invalid cookie domain: {value:?}"),
            Self::InsecureSameSiteNone => {
                write!(f, "SameSite=None requires the Secure attribute")
            }
        }
    }
}

impl std::error::Error for CookieError {}

/// The longest accepted cookie name in bytes.
pub const MAX_COOKIE_NAME: usize = 256;
/// The longest accepted raw cookie value in bytes.
pub const MAX_COOKIE_VALUE: usize = 4_096;
/// The longest accepted cookie path in bytes.
pub const MAX_COOKIE_PATH: usize = 1024;
/// The longest accepted cookie domain in bytes.
pub const MAX_COOKIE_DOMAIN: usize = 253;
/// The most pairs [`parse_cookie_header`] returns.
pub const MAX_COOKIE_PAIRS: usize = 256;

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_name(name: &str) -> Result<(), CookieError> {
    if name.is_empty() || name.len() > MAX_COOKIE_NAME || !name.bytes().all(is_token_byte) {
        return Err(CookieError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), CookieError> {
    let invalid = path.is_empty()
        || path.len() > MAX_COOKIE_PATH
        || !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b'"' | b'\\' | b' '));
    if invalid {
        return Err(CookieError::InvalidPath(path.to_string()));
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<(), CookieError> {
    let body = domain.strip_prefix('.').unwrap_or(domain);
    let invalid = body.is_empty()
        || domain.len() > MAX_COOKIE_DOMAIN
        || !domain.is_ascii()
        || body.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    if invalid {
        return Err(CookieError::InvalidDomain(domain.to_string()));
    }
    Ok(())
}

/// One cookie, with every attribute validated before it reaches a header.
///
/// The default is a host-only, `Path=/`, session cookie that is neither
/// `Secure` nor `HttpOnly`. A caller that carries a login must set both:
///
/// ```
/// use fador_auth::cookie::{Cookie, SameSite};
///
/// let cookie = Cookie::new("sid", "0123456789abcdef")
///     .unwrap()
///     .secure(true)
///     .http_only(true)
///     .same_site(Some(SameSite::Lax));
/// assert!(cookie.to_header_value().unwrap().contains("; HttpOnly"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    name: String,
    value: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
    expires: Option<i64>,
    max_age: Option<i64>,
}

impl Cookie {
    /// Start a cookie. The name is validated immediately; the value is encoded
    /// when the header is written.
    pub fn new(name: &str, value: &str) -> Result<Self, CookieError> {
        validate_name(name)?;
        if value.len() > MAX_COOKIE_VALUE {
            return Err(CookieError::InvalidValue(value.len()));
        }
        Ok(Self {
            name: name.to_string(),
            value: value.to_string(),
            path: "/".to_string(),
            domain: None,
            secure: false,
            http_only: false,
            same_site: None,
            expires: None,
            max_age: None,
        })
    }

    /// Set the `Path` attribute.
    pub fn path(mut self, path: &str) -> Result<Self, CookieError> {
        validate_path(path)?;
        self.path = path.to_string();
        Ok(self)
    }

    /// Set the `Domain` attribute. A leading dot is accepted for legacy
    /// configurations.
    pub fn domain(mut self, domain: &str) -> Result<Self, CookieError> {
        validate_domain(domain)?;
        self.domain = Some(domain.to_string());
        Ok(self)
    }

    /// Set or clear `Secure`.
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set or clear `HttpOnly`.
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Set or clear `SameSite`.
    pub fn same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.same_site = same_site;
        self
    }

    /// Set the `Expires` attribute from a Unix timestamp. `None` keeps the
    /// cookie a session cookie.
    pub fn expires(mut self, unix_seconds: Option<i64>) -> Self {
        self.expires = unix_seconds;
        self
    }

    /// Set the `Max-Age` attribute in seconds. `None` omits it.
    pub fn max_age(mut self, seconds: Option<i64>) -> Self {
        self.max_age = seconds;
        self
    }

    /// The cookie name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The raw (unencoded) value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Render the `Set-Cookie` header value.
    ///
    /// # Errors
    ///
    /// Returns [`CookieError::InsecureSameSiteNone`] when `SameSite=None` is
    /// set without `Secure`.
    pub fn to_header_value(&self) -> Result<String, CookieError> {
        if self.same_site == Some(SameSite::None) && !self.secure {
            return Err(CookieError::InsecureSameSiteNone);
        }
        let mut header = String::with_capacity(self.name.len() + self.value.len() + 96);
        header.push_str(&self.name);
        header.push('=');
        header.push_str(&rawurlencode(&self.value));
        if let Some(expires) = self.expires {
            header.push_str("; Expires=");
            header.push_str(&http_date(expires.max(0) as u64));
        }
        if let Some(max_age) = self.max_age {
            header.push_str("; Max-Age=");
            header.push_str(&max_age.to_string());
        }
        header.push_str("; Path=");
        header.push_str(&self.path);
        if let Some(domain) = &self.domain {
            header.push_str("; Domain=");
            header.push_str(domain);
        }
        if self.secure {
            header.push_str("; Secure");
        }
        if self.http_only {
            header.push_str("; HttpOnly");
        }
        if let Some(same_site) = self.same_site {
            header.push_str("; SameSite=");
            header.push_str(same_site.as_str());
        }
        Ok(header)
    }
}

/// The cookie attributes shared by every session cookie of one site.
///
/// The codec is the configured shape; [`CookieCodec::encode`] writes one value
/// in it and [`CookieCodec::clear`] writes the matching deletion header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieCodec {
    name: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
    max_age: Option<i64>,
}

impl CookieCodec {
    /// Create a codec for one cookie name.
    pub fn new(name: &str) -> Result<Self, CookieError> {
        validate_name(name)?;
        Ok(Self {
            name: name.to_string(),
            path: "/".to_string(),
            domain: None,
            secure: true,
            http_only: true,
            same_site: Some(SameSite::Lax),
            max_age: None,
        })
    }

    /// Set the `Path` attribute.
    pub fn with_path(mut self, path: &str) -> Result<Self, CookieError> {
        validate_path(path)?;
        self.path = path.to_string();
        Ok(self)
    }

    /// Set the `Domain` attribute.
    pub fn with_domain(mut self, domain: &str) -> Result<Self, CookieError> {
        validate_domain(domain)?;
        self.domain = Some(domain.to_string());
        Ok(self)
    }

    /// Set or clear `Secure`. It is on by default.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set or clear `HttpOnly`. It is on by default.
    pub fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Set or clear `SameSite`. It defaults to `Lax`.
    pub fn with_same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.same_site = same_site;
        self
    }

    /// Make every encoded cookie persistent for `seconds`. `None` keeps them
    /// session cookies.
    pub fn with_max_age(mut self, seconds: Option<i64>) -> Self {
        self.max_age = seconds;
        self
    }

    /// The cookie name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Build the cookie for one value with the configured attributes.
    pub fn cookie(&self, value: &str) -> Result<Cookie, CookieError> {
        let mut cookie = Cookie::new(&self.name, value)?
            .path(&self.path)?
            .secure(self.secure)
            .http_only(self.http_only)
            .same_site(self.same_site);
        if let Some(domain) = &self.domain {
            cookie = cookie.domain(domain)?;
        }
        if let Some(max_age) = self.max_age {
            cookie = cookie.max_age(Some(max_age));
        }
        Ok(cookie)
    }

    /// Render the `Set-Cookie` header value for `value`.
    pub fn encode(&self, value: &str) -> Result<String, CookieError> {
        self.cookie(value)?.to_header_value()
    }

    /// Render a persistent `Set-Cookie` header value that expires `max_age`
    /// seconds after `now`.
    ///
    /// When the codec has no `max_age`, this is the same as
    /// [`CookieCodec::encode`]: a session cookie with no `Expires` or
    /// `Max-Age`.
    pub fn encode_at(&self, value: &str, now: i64) -> Result<String, CookieError> {
        let Some(max_age) = self.max_age else {
            return self.encode(value);
        };
        let max_age = max_age.max(0);
        let mut cookie = self.cookie(value)?.max_age(Some(max_age));
        cookie = cookie.expires(Some(now.saturating_add(max_age)));
        cookie.to_header_value()
    }

    /// Render the deletion header: an empty value, `Max-Age=0` and an `Expires`
    /// in the past.
    pub fn clear(&self) -> Result<String, CookieError> {
        self.cookie("")?
            .expires(Some(0))
            .max_age(Some(0))
            .to_header_value()
    }

    /// Read this cookie from a `Cookie` request header and percent-decode it.
    ///
    /// The first pair with the configured name wins, matching the browser rule
    /// that the most specific cookie is sent first.
    pub fn decode(&self, header: &str) -> Option<String> {
        parse_cookie_header(header)
            .into_iter()
            .find(|(name, _)| name == &self.name)
            .map(|(_, value)| percent_decode(&value))
    }
}

/// Parse a `Cookie` request header into name/value pairs.
///
/// The parser is deliberately forgiving, like a browser: whitespace around a
/// pair is trimmed, a pair without `=` is skipped, a value may contain `=`, and
/// quotes are not special. At most [`MAX_COOKIE_PAIRS`] pairs are returned.
pub fn parse_cookie_header(header: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for part in header.split(';') {
        if pairs.len() >= MAX_COOKIE_PAIRS {
            break;
        }
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        pairs.push((name.to_string(), value.to_string()));
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_full_header_in_a_fixed_order() {
        let cookie = Cookie::new("board_sid", "abc 123")
            .unwrap()
            .path("/forum")
            .unwrap()
            .domain("example.test")
            .unwrap()
            .secure(true)
            .http_only(true)
            .same_site(Some(SameSite::Lax))
            .expires(Some(1_900_000_000))
            .max_age(Some(3_600));
        assert_eq!(
            cookie.to_header_value().unwrap(),
            "board_sid=abc%20123; Expires=Sun, 17 Mar 2030 17:46:40 GMT; Max-Age=3600; \
             Path=/forum; Domain=example.test; Secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn defaults_to_a_host_only_session_cookie() {
        let cookie = Cookie::new("sid", "x").unwrap();
        assert_eq!(cookie.to_header_value().unwrap(), "sid=x; Path=/");
    }

    #[test]
    fn rejects_names_outside_the_token_set() {
        for name in [
            "", "a b", "a;b", "a=b", "a,b", "a\r\nb", "a\tb", "a(b)", "a/b", "ä",
        ] {
            assert!(
                matches!(Cookie::new(name, "x"), Err(CookieError::InvalidName(_))),
                "accepted name {name:?}"
            );
        }
        assert!(Cookie::new(&"a".repeat(MAX_COOKIE_NAME + 1), "x").is_err());
        assert!(Cookie::new("a!#$%&'*+-.^_`|~Z9", "x").is_ok());
    }

    #[test]
    fn rejects_an_oversized_value() {
        assert!(Cookie::new("sid", &"a".repeat(MAX_COOKIE_VALUE)).is_ok());
        assert_eq!(
            Cookie::new("sid", &"a".repeat(MAX_COOKIE_VALUE + 1)).unwrap_err(),
            CookieError::InvalidValue(MAX_COOKIE_VALUE + 1)
        );
    }

    #[test]
    fn encodes_hostile_values_instead_of_rejecting_them() {
        let cookie = Cookie::new("sid", "a\r\nSet-Cookie: pwned=1; b").unwrap();
        let header = cookie.to_header_value().unwrap();
        assert!(!header.contains('\r') && !header.contains('\n'), "{header}");
        assert!(header.starts_with("sid=a%0D%0ASet-Cookie%3A%20pwned%3D1%3B%20b; Path=/"));
        assert_eq!(header.matches("; ").count(), 1, "{header}");
    }

    #[test]
    fn validates_paths_and_domains() {
        assert!(matches!(
            Cookie::new("s", "x").unwrap().path("relative"),
            Err(CookieError::InvalidPath(_))
        ));
        for path in ["/\r\nX: y", "/a;b", "/a\"b", "/a\\b", "/a b", ""] {
            assert!(
                Cookie::new("s", "x").unwrap().path(path).is_err(),
                "accepted path {path:?}"
            );
        }
        assert!(Cookie::new("s", "x").unwrap().path("/a/b_c-d.e~f").is_ok());

        for domain in [
            "",
            "example..test",
            ".example..test",
            "exa mple.test",
            "example.test;",
            "example.test\r\nX: y",
            "-example.test",
            "example-.test",
            &"a".repeat(64),
        ] {
            assert!(
                Cookie::new("s", "x").unwrap().domain(domain).is_err(),
                "accepted domain {domain:?}"
            );
        }
        assert!(Cookie::new("s", "x")
            .unwrap()
            .domain(".example.test")
            .is_ok());
        assert!(Cookie::new("s", "x")
            .unwrap()
            .domain("a_b.example.test")
            .is_ok());
    }

    #[test]
    fn same_site_none_requires_secure() {
        let cookie = Cookie::new("s", "x")
            .unwrap()
            .same_site(Some(SameSite::None));
        assert_eq!(
            cookie.to_header_value().unwrap_err(),
            CookieError::InsecureSameSiteNone
        );
        assert!(cookie
            .secure(true)
            .to_header_value()
            .unwrap()
            .ends_with("; SameSite=None"));
    }

    #[test]
    fn parses_same_site_case_insensitively() {
        assert_eq!(SameSite::parse(" lax "), Some(SameSite::Lax));
        assert_eq!(SameSite::parse("STRICT"), Some(SameSite::Strict));
        assert_eq!(SameSite::parse("none"), Some(SameSite::None));
        assert_eq!(SameSite::parse(""), None);
        assert_eq!(SameSite::parse("Lax\r\nX: y"), None);
    }

    #[test]
    fn codec_encodes_decodes_and_clears() {
        let codec = CookieCodec::new("board_sid")
            .unwrap()
            .with_path("/forum")
            .unwrap()
            .with_secure(false)
            .with_max_age(Some(3_600));
        let header = codec.encode_at("a b;c", 1_000).unwrap();
        assert_eq!(
            header,
            "board_sid=a%20b%3Bc; Expires=Thu, 01 Jan 1970 01:16:40 GMT; Max-Age=3600; \
             Path=/forum; HttpOnly; SameSite=Lax"
        );
        let request = format!("a=1; {}; b=2", header.split(';').next().unwrap());
        assert_eq!(codec.decode(&request).as_deref(), Some("a b;c"));
        assert_eq!(codec.decode("a=1; b=2"), None);

        let clear = codec.clear().unwrap();
        assert!(clear.starts_with("board_sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0;"));
    }

    /// A codec without `max_age` encodes a session cookie, so `encode_at`
    /// ignores the timestamp.
    #[test]
    fn encode_at_without_max_age_is_a_session_cookie() {
        let codec = CookieCodec::new("sid").unwrap();
        let header = codec.encode_at("abc", 1_000).unwrap();
        assert_eq!(header, "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax");
    }

    #[test]
    fn parses_request_headers_like_a_browser() {
        let pairs = parse_cookie_header(
            "a=b=c; board_sid=0123456789abcdef; empty=; board_sid=second; quoted=\"x;y\"; bare; =x",
        );
        assert_eq!(pairs[0], ("a".to_string(), "b=c".to_string()));
        assert_eq!(
            pairs[1],
            ("board_sid".to_string(), "0123456789abcdef".to_string())
        );
        assert_eq!(pairs[2], ("empty".to_string(), String::new()));
        assert_eq!(pairs[3], ("board_sid".to_string(), "second".to_string()));
        assert_eq!(pairs[4], ("quoted".to_string(), "\"x".to_string()));
        assert_eq!(pairs.len(), 5);
        assert_eq!(
            parse_cookie_header("a=1; board_sid=0123456789abcdef; board_sid=second")
                .into_iter()
                .find(|(name, _)| name == "board_sid")
                .map(|(_, value)| value)
                .as_deref(),
            Some("0123456789abcdef")
        );
        assert!(parse_cookie_header("").is_empty());
    }

    #[test]
    fn bounds_the_number_of_parsed_pairs() {
        let header = (0..1_000)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(parse_cookie_header(&header).len(), MAX_COOKIE_PAIRS);
    }
}
