//! Cross-site request forgery tokens.
//!
//! Three schemes are provided because the applications this crate was extracted
//! from use three different ones:
//!
//! - [`FormKey`] is the phpBB scheme: a hidden `form_token` and
//!   `creation_time` pair, checked against a server-side form salt and a
//!   lifetime window.
//! - [`SessionToken`] is the SMF scheme: a per-session variable name and a
//!   value stored in the session record.
//! - [`CookieToken`] is a stateless HMAC token bound to a session id and an
//!   expiry, for servers that do not want to store a CSRF value.
//!
//! All three are compared with [`crate::constant_time_eq`]. [`CsrfTokens`]
//! bundles them so a login or a password change can rotate every value at once.

use crate::constant_time_eq;
use crate::session::SessionId;
use fador_core::crypto::{hex, hmac_sha256, md5, sha1, sha256};
use fador_core::random::{random_array, random_bytes, random_hex};
use std::fmt;

/// The phpBB default form-token lifetime in seconds.
pub const FORM_TOKEN_LIFETIME: i64 = 7_200;
/// The shortest accepted form salt in bytes.
pub const MIN_FORM_SALT: usize = 8;
/// The longest accepted form salt in bytes.
pub const MAX_FORM_SALT: usize = 64;
/// The longest accepted cookie token in bytes.
pub const MAX_COOKIE_TOKEN: usize = 256;

/// A form salt that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsrfError {
    /// The salt is empty, too long or contains a control character.
    InvalidSalt(String),
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSalt(value) => write!(f, "invalid form salt: {value:?}"),
        }
    }
}

impl std::error::Error for CsrfError {}

/// The phpBB form-key scheme.
///
/// The token is `sha1(creation_time . salt . form_name . token_sid)` in
/// lowercase hexadecimal, where `token_sid` is the session id for a guest and
/// empty for a logged-in visitor. The `creation_time` is sent alongside the
/// token and bounds its age.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormKey {
    salt: String,
}

impl FormKey {
    /// Create a form key from a server-side salt.
    ///
    /// # Errors
    ///
    /// Returns [`CsrfError::InvalidSalt`] when the salt is shorter than
    /// [`MIN_FORM_SALT`], longer than [`MAX_FORM_SALT`] or contains a control
    /// character.
    pub fn new(salt: impl Into<String>) -> Result<Self, CsrfError> {
        let salt = salt.into();
        let invalid = salt.len() < MIN_FORM_SALT
            || salt.len() > MAX_FORM_SALT
            || salt.bytes().any(|byte| !(0x21..=0x7e).contains(&byte));
        if invalid {
            return Err(CsrfError::InvalidSalt(salt));
        }
        Ok(Self { salt })
    }

    /// Generate a form key with a random 16-byte salt.
    pub fn generate() -> Self {
        Self {
            salt: random_hex(16),
        }
    }

    /// The salt, for storing it in a configuration row.
    pub fn salt(&self) -> &str {
        &self.salt
    }

    /// Replace the salt and return the new value.
    ///
    /// Call this after a login, a password change or a privilege change: every
    /// token minted with the old salt stops verifying immediately.
    pub fn rotate(&mut self) -> String {
        self.salt = random_hex(16);
        self.salt.clone()
    }

    /// Mint a token for one form.
    pub fn token(&self, form_name: &str, session_id: &SessionId, now: i64, guest: bool) -> String {
        let token_sid = if guest { session_id.as_str() } else { "" };
        hex(&sha1(
            format!("{now}{}{form_name}{token_sid}", self.salt).as_bytes(),
        ))
    }

    /// The two hidden inputs phpBB puts in a form.
    pub fn fields(&self, form_name: &str, session_id: &SessionId, now: i64, guest: bool) -> String {
        let token = self.token(form_name, session_id, now, guest);
        format!(
            "<input type=\"hidden\" name=\"creation_time\" value=\"{now}\" />\n\
             <input type=\"hidden\" name=\"form_token\" value=\"{token}\" />\n"
        )
    }

    /// Check a submitted token.
    ///
    /// `lifetime` bounds how old the token may be; `None` removes the upper
    /// bound but still rejects a token minted in the current second or in the
    /// future, which a human form submission never is.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        form_name: &str,
        session_id: &SessionId,
        token: &str,
        creation_time: i64,
        now: i64,
        lifetime: Option<i64>,
        guest: bool,
    ) -> bool {
        if creation_time <= 0 || token.is_empty() {
            return false;
        }
        let age = now.saturating_sub(creation_time);
        if age <= 0 {
            return false;
        }
        if lifetime.is_some_and(|lifetime| age > lifetime) {
            return false;
        }
        let expected = self.token(form_name, session_id, creation_time, guest);
        constant_time_eq(expected.as_bytes(), token.as_bytes())
    }
}

/// The SMF per-session CSRF token.
///
/// SMF stores two strings in the session row: a random variable name of 7 to 12
/// lowercase letters and a 32-hex value. A form carries the name as the field
/// name and the value as the field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    var: String,
    value: String,
}

impl SessionToken {
    /// Generate a token bound to `session_id`.
    pub fn generate(session_id: &SessionId) -> Self {
        Self {
            var: random_var(),
            value: token_value(session_id),
        }
    }

    /// The variable (form field) name.
    pub fn var(&self) -> &str {
        &self.var
    }

    /// The token value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Check a submitted value.
    pub fn verify(&self, provided: &str) -> bool {
        constant_time_eq(self.value.as_bytes(), provided.as_bytes())
    }

    /// Replace the value and return it. The variable name is kept so the
    /// templates that render it do not have to change.
    pub fn rotate(&mut self, session_id: &SessionId) -> String {
        self.value = token_value(session_id);
        self.value.clone()
    }
}

fn token_value(session_id: &SessionId) -> String {
    let random = random_hex(8);
    hex(&md5(format!("{}{random}", session_id.as_str()).as_bytes()))
}

fn random_var() -> String {
    let bytes = random_bytes(16);
    let length = 7 + usize::from(bytes[0] % 6);
    bytes
        .iter()
        .take(length)
        .map(|byte| (b'a' + (byte % 26)) as char)
        .collect()
}

/// A stateless HMAC CSRF token bound to a session id and an expiry.
///
/// The format is `v1.<expires>.<hex hmac-sha256>`, where the MAC covers
/// `csrf\0<session id>\0<expires>`.
#[derive(Debug, Clone)]
pub struct CookieToken {
    key: [u8; 32],
}

impl CookieToken {
    /// Create a token codec from a 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Derive the key from a server secret with SHA-256.
    pub fn from_secret(secret: &[u8]) -> Self {
        Self::new(sha256(secret))
    }

    /// Mint a token for `session_id` that expires at `now + lifetime`.
    pub fn issue(&self, session_id: &SessionId, now: i64, lifetime: i64) -> String {
        let expires = now.saturating_add(lifetime.max(0));
        format!("v1.{expires}.{}", hex(&self.mac(session_id, expires)))
    }

    /// Check a token against a session id and the current time.
    pub fn verify(&self, token: &str, session_id: &SessionId, now: i64) -> bool {
        if token.len() > MAX_COOKIE_TOKEN {
            return false;
        }
        let mut parts = token.split('.');
        if parts.next() != Some("v1") {
            return false;
        }
        let Some(expires) = parts.next().and_then(|value| value.parse::<i64>().ok()) else {
            return false;
        };
        let Some(mac) = parts.next() else {
            return false;
        };
        if parts.next().is_some() || now >= expires {
            return false;
        }
        let expected = hex(&self.mac(session_id, expires));
        constant_time_eq(expected.as_bytes(), mac.as_bytes())
    }

    fn mac(&self, session_id: &SessionId, expires: i64) -> [u8; 32] {
        hmac_sha256(
            &self.key,
            format!("csrf\0{}\0{expires}", session_id.as_str()).as_bytes(),
        )
    }
}

/// Every CSRF value of one session, rotated together.
///
/// ```
/// use fador_auth::csrf::CsrfTokens;
/// use fador_auth::session::SessionId;
///
/// let session = SessionId::generate();
/// let mut tokens = CsrfTokens::generate(&session);
/// let token = tokens.cookie_token().issue(&session, 1_000, 3_600);
/// assert!(tokens.cookie_token().verify(&token, &session, 1_001));
///
/// // A password change rotates every value; the old token stops working.
/// tokens.rotate(&session);
/// assert!(!tokens.cookie_token().verify(&token, &session, 1_001));
/// ```
#[derive(Debug, Clone)]
pub struct CsrfTokens {
    form: FormKey,
    cookie: CookieToken,
    session: SessionToken,
}

impl CsrfTokens {
    /// Generate a fresh set for a session.
    pub fn generate(session_id: &SessionId) -> Self {
        Self {
            form: FormKey::generate(),
            cookie: CookieToken::new(random_array::<32>()),
            session: SessionToken::generate(session_id),
        }
    }

    /// Rotate every value. Call this after a login, a password change or an
    /// administrator re-authentication.
    pub fn rotate(&mut self, session_id: &SessionId) {
        self.form.rotate();
        self.cookie = CookieToken::new(random_array::<32>());
        self.session.rotate(session_id);
    }

    /// The form key.
    pub fn form_key(&self) -> &FormKey {
        &self.form
    }

    /// The stateless cookie token codec.
    pub fn cookie_token(&self) -> &CookieToken {
        &self.cookie
    }

    /// The SMF session token.
    pub fn session_token(&self) -> &SessionToken {
        &self.session
    }
}

/// Validate a salt the way [`FormKey::new`] does, for configuration loading.
pub fn validate_form_salt(salt: &str) -> Result<(), CsrfError> {
    FormKey::new(salt).map(|_| ())
}

/// A random form salt, for storing it in a configuration row.
pub fn generate_form_salt() -> String {
    random_hex(16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionId {
        SessionId::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn form_tokens_follow_the_phpbb_contract() {
        let key = FormKey::new("0123456789abcdef").unwrap();
        let guest = key.token("posting", &session(), 1_000, true);
        let user = key.token("posting", &session(), 1_000, false);
        assert_eq!(guest.len(), 40);
        assert!(guest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(guest, user);
        assert!(key.check(
            "posting",
            &session(),
            &guest,
            1_000,
            1_001,
            Some(7_200),
            true
        ));
        assert!(!key.check(
            "posting",
            &session(),
            &guest,
            1_000,
            1_000,
            Some(7_200),
            true
        ));
        assert!(!key.check(
            "posting",
            &session(),
            &guest,
            1_000,
            1_001,
            Some(7_200),
            false
        ));
        // A token is bound to its form name and its session id.
        assert!(!key.check("other", &session(), &guest, 1_000, 1_001, Some(7_200), true));
        assert!(!key.check(
            "posting",
            &SessionId::generate(),
            &guest,
            1_000,
            1_001,
            Some(7_200),
            true
        ));
        assert!(!key.check(
            "posting",
            &session(),
            &user,
            1_000,
            8_201,
            Some(7_200),
            false
        ));
        assert!(key.check(
            "posting",
            &session(),
            &user,
            1_000,
            8_200,
            Some(7_200),
            false
        ));
        assert!(key.check("posting", &session(), &user, 1_000, 10_000_000, None, false));
        assert!(!key.check("posting", &session(), &user, 1_000, 1_000, None, false));
    }

    #[test]
    fn form_fields_render_the_hidden_inputs() {
        let key = FormKey::new("0123456789abcdef").unwrap();
        let fields = key.fields("posting", &session(), 1_000, true);
        assert!(fields.contains("name=\"creation_time\" value=\"1000\""));
        assert!(fields.contains("name=\"form_token\" value=\""));
        assert_eq!(fields.lines().count(), 2);
    }

    #[test]
    fn form_tokens_reject_mutations_and_malformed_times() {
        let key = FormKey::new("0123456789abcdef").unwrap();
        let token = key.token("posting", &session(), 1_000, true);
        let mut wrong = token.clone();
        wrong.replace_range(0..1, if token.starts_with('a') { "b" } else { "a" });
        for candidate in [
            wrong,
            token[..39].to_string(),
            format!("{token}0"),
            String::new(),
            "z".repeat(40),
            token.to_ascii_uppercase(),
        ] {
            assert!(!key.check(
                "posting",
                &session(),
                &candidate,
                1_000,
                1_001,
                Some(7_200),
                true
            ));
        }
        for creation in [0, -1, i64::MIN, 1_001, i64::MAX] {
            assert!(!key.check(
                "posting",
                &session(),
                &token,
                creation,
                1_001,
                Some(7_200),
                true
            ));
        }
    }

    #[test]
    fn form_salts_are_validated_and_rotated() {
        assert!(FormKey::new("").is_err());
        assert!(FormKey::new("short").is_err());
        assert!(FormKey::new("a".repeat(MAX_FORM_SALT + 1)).is_err());
        assert!(FormKey::new("salt\r\nX: y").is_err());
        let mut key = FormKey::new("0123456789abcdef").unwrap();
        let token = key.token("posting", &session(), 1_000, true);
        let new_salt = key.rotate();
        assert_eq!(key.salt(), new_salt);
        assert_ne!(new_salt, "0123456789abcdef");
        assert!(!key.check(
            "posting",
            &session(),
            &token,
            1_000,
            1_001,
            Some(7_200),
            true
        ));
        assert!(validate_form_salt(&new_salt).is_ok());
        assert_eq!(generate_form_salt().len(), 32);
    }

    #[test]
    fn smf_session_tokens_have_the_smf_shape() {
        let mut token = SessionToken::generate(&session());
        assert!((7..=12).contains(&token.var().len()));
        assert!(token.var().bytes().all(|byte| byte.is_ascii_lowercase()));
        assert_eq!(token.value().len(), 32);
        assert!(token.value().bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(token.verify(token.value()));
        assert!(!token.verify("wrong"));
        assert!(!token.verify(""));
        let old = token.value().to_string();
        let new = token.rotate(&session());
        assert_eq!(new, token.value());
        assert_ne!(new, old);
        assert!(!token.verify(&old));
        assert!(token.verify(&new));
    }

    #[test]
    fn cookie_tokens_roundtrip_and_reject_tampering() {
        let codec = CookieToken::from_secret(b"server secret");
        let token = codec.issue(&session(), 1_000, 3_600);
        assert!(token.starts_with("v1.4600."));
        assert!(codec.verify(&token, &session(), 1_000));
        assert!(codec.verify(&token, &session(), 4_599));
        assert!(!codec.verify(&token, &session(), 4_600));
        assert!(!codec.verify(&token, &session(), 9_999));

        let other = SessionId::generate();
        assert!(!codec.verify(&token, &other, 1_000));

        let mut bytes = token.clone().into_bytes();
        for index in 0..bytes.len() {
            let original = bytes[index];
            bytes[index] = if original == b'0' { b'1' } else { b'0' };
            let mutated = String::from_utf8(bytes.clone()).unwrap();
            assert!(
                !codec.verify(&mutated, &session(), 1_000),
                "accepted {mutated:?}"
            );
            bytes[index] = original;
        }
        for malformed in [
            "",
            "v1",
            "v2.4600.00",
            "v1.notanumber.00",
            "v1.4600",
            "v1.4600.00.extra",
        ] {
            assert!(!codec.verify(malformed, &session(), 1_000));
        }
        assert!(!codec.verify(&"v1.1.".repeat(1_000), &session(), 1_000));
        assert!(!codec.verify(&"a".repeat(MAX_COOKIE_TOKEN + 1), &session(), 1_000));
    }

    #[test]
    fn rotating_a_csrf_set_invalidates_every_old_value() {
        let session = session();
        let mut tokens = CsrfTokens::generate(&session);
        let form_token = tokens.form_key().token("posting", &session, 1_000, false);
        let cookie_token = tokens.cookie_token().issue(&session, 1_000, 3_600);
        let session_value = tokens.session_token().value().to_string();

        tokens.rotate(&session);

        assert!(!tokens.form_key().check(
            "posting",
            &session,
            &form_token,
            1_000,
            1_001,
            Some(7_200),
            false
        ));
        assert!(!tokens.cookie_token().verify(&cookie_token, &session, 1_001));
        assert!(!tokens.session_token().verify(&session_value));
        assert!(tokens
            .session_token()
            .verify(tokens.session_token().value()));
    }
}
