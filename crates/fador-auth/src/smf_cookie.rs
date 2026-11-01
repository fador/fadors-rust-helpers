//! SMF's PHP-serialised login cookie.
//!
//! SMF 2.0 stores its remember-me state in a cookie whose value is
//! `serialize(array(0 => id_member, 1 => password_hash, 2 => expires, 3 =>
//! state))`. The `password_hash` is not the password: it is
//! `hmac-sha1(auth_secret, sha1hex(stored_hash . password_salt))`, produced by
//! [`crate::password::smf::cookie_password_hash`].
//!
//! This module reads and writes that value with the bounded PHP serialiser from
//! `fador-core`, so a migrated SMF board keeps its existing login cookies. A new
//! deployment should prefer [`crate::session::RememberMeKey`], which stores only
//! a SHA-256 of a random token and rotates on use.

use crate::error::StoreError;
use crate::password::smf::{verify_cookie_password, COOKIE_HASH_LEN};
use fador_core::php::{serialize, unserialize, PhpKey, PhpValue};

/// A parsed SMF login cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmfLoginCookie {
    /// The member id, or `0` for the guest cookie SMF writes on logout.
    pub user_id: i64,
    /// The 40-hex password HMAC, or an empty string for the guest cookie.
    pub password: String,
    /// The expiry as a Unix timestamp.
    pub expires: i64,
    /// SMF's cookie state bitfield (`local_cookies | global_cookies << 1`).
    pub state: i64,
}

impl SmfLoginCookie {
    /// Create a cookie value.
    pub fn new(user_id: i64, password: impl Into<String>, expires: i64, state: i64) -> Self {
        Self {
            user_id,
            password: password.into(),
            expires,
            state,
        }
    }

    /// The guest cookie SMF writes when it clears the login.
    pub fn guest() -> Self {
        Self::new(0, String::new(), 0, 0)
    }

    /// The exact value SMF writes when clearing the login cookie:
    /// `serialize(array(0, '', 0))`, a three-element array.
    ///
    /// # Errors
    ///
    /// See [`SmfLoginCookie::serialize`].
    pub fn guest_value() -> Result<String, StoreError> {
        serialize(&PhpValue::Array(vec![
            (PhpKey::Int(0), PhpValue::Int(0)),
            (PhpKey::Int(1), PhpValue::Str(String::new())),
            (PhpKey::Int(2), PhpValue::Int(0)),
        ]))
        .map_err(|error| StoreError::new(error.to_string()))
    }

    /// Serialise the cookie.
    ///
    /// # Errors
    ///
    /// The bounded serialiser only fails on a value this struct cannot hold, so
    /// an error means the crate and `fador-core` disagree about the format.
    pub fn serialize(&self) -> Result<String, StoreError> {
        serialize(&PhpValue::Array(vec![
            (PhpKey::Int(0), PhpValue::Int(self.user_id)),
            (PhpKey::Int(1), PhpValue::Str(self.password.clone())),
            (PhpKey::Int(2), PhpValue::Int(self.expires)),
            (PhpKey::Int(3), PhpValue::Int(self.state)),
        ]))
        .map_err(|error| StoreError::new(error.to_string()))
    }

    /// Parse a cookie value.
    ///
    /// Returns `None` for malformed input, an object or a reference, a wrong
    /// arity, a password that is neither empty nor 40 hexadecimal characters,
    /// and an expired member cookie. A guest cookie (`user_id == 0`) is never
    /// expired.
    pub fn parse(value: &str, now: i64) -> Option<Self> {
        let value = unserialize(value).ok()?;
        let PhpValue::Array(items) = value else {
            return None;
        };
        if items.len() < 3 || items.len() > 4 {
            return None;
        }
        let user_id = items[0].1.as_i64()?;
        let password = items[1].1.as_str()?;
        if !password.is_empty()
            && (password.len() != COOKIE_HASH_LEN
                || !password.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return None;
        }
        let expires = items[2].1.as_i64()?;
        if user_id != 0 && expires <= now {
            return None;
        }
        let state = items
            .get(3)
            .and_then(|(_, value)| value.as_i64())
            .unwrap_or(0);
        Some(Self {
            user_id,
            password: password.to_string(),
            expires,
            state,
        })
    }

    /// Whether this is the guest cookie.
    pub fn is_guest(&self) -> bool {
        self.user_id == 0
    }

    /// Whether the cookie has expired at `now`.
    pub fn is_expired(&self, now: i64) -> bool {
        self.user_id != 0 && self.expires <= now
    }
}

/// Verify a parsed SMF login cookie against the member row it names.
///
/// The member id must match, the cookie must not be a guest, the password HMAC
/// must match the stored hash and salt, and the cookie must not have expired.
pub fn verify_smf_login_cookie(
    cookie: &SmfLoginCookie,
    user_id: i64,
    stored_hash: &str,
    password_salt: &str,
    auth_secret: &str,
    now: i64,
) -> bool {
    cookie.user_id != 0
        && cookie.user_id == user_id
        && !stored_hash.is_empty()
        && !cookie.is_expired(now)
        && verify_cookie_password(&cookie.password, stored_hash, password_salt, auth_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::smf::{cookie_password_hash, hash_password};

    #[test]
    fn roundtrips_the_smf_array() {
        let cookie = SmfLoginCookie::new(42, "a".repeat(40), 2_000, 1);
        let value = cookie.serialize().unwrap();
        assert!(value.starts_with("a:4:{i:0;i:42;i:1;s:40:\""));
        assert_eq!(SmfLoginCookie::parse(&value, 1_000), Some(cookie.clone()));
        assert_eq!(SmfLoginCookie::parse(&value, 3_000), None);
    }

    #[test]
    fn guest_cookie_matches_the_smf_shape() {
        let value = SmfLoginCookie::guest_value().unwrap();
        assert_eq!(value, "a:3:{i:0;i:0;i:1;s:0:\"\";i:2;i:0;}");
        let parsed = SmfLoginCookie::parse(&value, 10_000).unwrap();
        assert!(parsed.is_guest());
        assert!(!parsed.is_expired(10_000));
        // The four-element guest record still round-trips.
        let value = SmfLoginCookie::guest().serialize().unwrap();
        assert!(SmfLoginCookie::parse(&value, 10_000).unwrap().is_guest());
    }

    #[test]
    fn rejects_objects_trailing_data_and_bad_arity() {
        for value in [
            "O:8:\"stdClass\":0:{}",
            "N;",
            "a:3:{i:0;i:0;i:1;s:0:\"\";i:2;i:0;}N;",
            "a:2:{i:0;i:7;i:1;s:40:\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";}",
            "a:5:{i:0;i:7;i:1;s:40:\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";i:2;i:2000;i:3;i:1;i:4;i:0;}",
            "a:3:{i:0;s:1:\"7\";i:1;s:40:\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";i:2;i:2000;}",
            "a:3:{i:0;i:7;i:1;s:39:\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";i:2;i:2000;}",
            "a:3:{i:0;i:7;i:1;s:40:\"gggggggggggggggggggggggggggggggggggggggg\";i:2;i:2000;}",
        ] {
            assert!(SmfLoginCookie::parse(value, 1_000).is_none(), "{value}");
        }
        assert!(SmfLoginCookie::parse(&"a".repeat(2_000_000), 0).is_none());
    }

    #[test]
    fn verifies_the_cookie_hmac_and_member() {
        let secret = "dc5e10a1e54043e9bb9da136ad0914541f31cf277f3a13590a54cc13b6b31048";
        let stored = hash_password("Test", "secret");
        let hash = cookie_password_hash(&stored, "ab12", secret);
        let cookie = SmfLoginCookie::new(7, hash, 2_000, 1);
        assert!(verify_smf_login_cookie(
            &cookie, 7, &stored, "ab12", secret, 1_000
        ));
        assert!(!verify_smf_login_cookie(
            &cookie, 8, &stored, "ab12", secret, 1_000
        ));
        assert!(!verify_smf_login_cookie(
            &cookie, 7, &stored, "other", secret, 1_000
        ));
        assert!(!verify_smf_login_cookie(
            &cookie, 7, &stored, "ab12", secret, 2_000
        ));
        assert!(!verify_smf_login_cookie(
            &SmfLoginCookie::guest(),
            7,
            &stored,
            "ab12",
            secret,
            1_000
        ));
    }
}
