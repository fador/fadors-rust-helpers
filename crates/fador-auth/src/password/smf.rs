//! SMF password formats and the SMF login-cookie password hash.
//!
//! SMF 2.0 stores `sha1(lowercase(member_name) . password)`. Upgrades from
//! 1.x and from other forum software left several unsalted MD5 variants in the
//! same column, so verification tries the documented candidate set:
//!
//! - `sha1(lowercase(name) . password)` (current)
//! - `sha1(password)`
//! - `md5(password)`
//! - `md5(password . lowercase(name))`
//! - `md5(md5hex(password))`
//! - `md5(md5hex(password) . lowercase(name))`
//!
//! SMF 2.0 also accepted a stored plaintext password. That candidate is
//! deliberately not implemented: a plaintext row must be reset, not honoured.
//!
//! The login cookie does not carry the password. It carries
//! `hex(hmac-sha1(auth_secret, sha1hex(passwd . password_salt)))`, which changes
//! whenever the password or the per-member salt changes.

use crate::constant_time_eq;
use fador_core::crypto::{hex, hmac_sha1, md5, sha1};

/// The length of an SMF SHA-1 password hash in hexadecimal characters.
pub const SHA1_HASH_LEN: usize = 40;
/// The length of an SMF MD5 password hash in hexadecimal characters.
pub const MD5_HASH_LEN: usize = 32;
/// The length of the login-cookie password hash in hexadecimal characters.
pub const COOKIE_HASH_LEN: usize = 40;

/// Lowercase hexadecimal SHA-1 of a string.
pub fn sha1_hex(data: &str) -> String {
    hex(&sha1(data.as_bytes()))
}

/// Hash a password the way SMF 2.0 does.
pub fn hash_password(member_name: &str, password: &str) -> String {
    sha1_hex(&format!("{}{}", member_name.to_ascii_lowercase(), password))
}

/// Whether `hash` has the shape of an SMF password hash.
pub fn is_smf_hash(hash: &str) -> bool {
    matches!(hash.len(), SHA1_HASH_LEN | MD5_HASH_LEN)
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Verify a password against an SMF hash.
///
/// `member_name` is the stored login name, not the display name. An empty name
/// disables the name-salted candidates but still allows the unsalted ones.
pub fn verify_password(stored_hash: &str, member_name: &str, password: &str) -> bool {
    if !is_smf_hash(stored_hash) {
        return false;
    }
    let name = member_name.to_ascii_lowercase();
    let md5_password = md5(password.as_bytes());
    let md5_hex = hex(&md5_password);
    let mut candidates = vec![
        sha1_hex(&format!("{name}{password}")),
        sha1_hex(password),
        hex(&md5_password),
        hex(&md5(format!("{password}{name}").as_bytes())),
        // The old port hashed the raw 16-byte digest; PHP's md5(md5($password))
        // hashes the 32-character hexadecimal string. Both rows exist in the
        // wild, so both are accepted.
        hex(&md5(&md5_password)),
        hex(&md5(md5_hex.as_bytes())),
    ];
    if stored_hash.len() == MD5_HASH_LEN {
        candidates.push(hex(&md5(format!("{md5_hex}{name}").as_bytes())));
    }
    candidates
        .iter()
        .any(|candidate| constant_time_eq(candidate.as_bytes(), stored_hash.as_bytes()))
}

/// Whether an SMF hash must be replaced after a successful login. Every SMF
/// format is unsalted or fast, so the answer is always yes.
pub fn needs_rehash(stored_hash: &str) -> bool {
    is_smf_hash(stored_hash)
}

/// The value an SMF login cookie carries for one member.
pub fn cookie_password_hash(stored_hash: &str, password_salt: &str, auth_secret: &str) -> String {
    let inner = sha1_hex(&format!("{stored_hash}{password_salt}"));
    hex(&hmac_sha1(auth_secret.as_bytes(), inner.as_bytes()))
}

/// Verify the password field of an SMF login cookie.
pub fn verify_cookie_password(
    cookie_hash: &str,
    stored_hash: &str,
    password_salt: &str,
    auth_secret: &str,
) -> bool {
    if cookie_hash.len() != COOKIE_HASH_LEN {
        return false;
    }
    let expected = cookie_password_hash(stored_hash, password_salt, auth_secret);
    constant_time_eq(expected.as_bytes(), cookie_hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_the_smf_construction() {
        let hash = hash_password("Test", "secret");
        assert_eq!(hash, "dcc4a6fbee930b0b34cf9fc2131b6b70c89e6b9b");
        assert_eq!(hash.len(), SHA1_HASH_LEN);
        assert!(verify_password(&hash, "Test", "secret"));
        assert!(verify_password(&hash, "test", "secret"));
        assert!(!verify_password(&hash, "Test", "wrong"));
        assert!(!verify_password(&hash, "Other", "secret"));
    }

    #[test]
    fn accepts_every_legacy_md5_variant() {
        let vectors = [
            ("5ebe2294ecd0e0f08eab7690d2a6ee69", "md5(password)"),
            ("cb08e6781ef34c8ecb06e1be269a6bdc", "md5(password . name)"),
            ("7022cd14c42ff272619d6beacdc9ffde", "md5(md5hex(password))"),
            (
                "ff5bcb4342b74112747e142e09e88c56",
                "md5(md5hex(password) . name)",
            ),
        ];
        for (hash, label) in vectors {
            assert!(verify_password(hash, "Test", "secret"), "{label}");
            assert!(!verify_password(hash, "Test", "wrong"), "{label}");
        }
    }

    #[test]
    fn never_accepts_a_stored_plaintext_password() {
        assert!(!verify_password("secret", "Test", "secret"));
        assert!(!verify_password("", "Test", ""));
        assert!(!verify_password("nonsense", "Test", "secret"));
        assert!(!verify_password(&"g".repeat(32), "Test", "secret"));
        assert!(!verify_password(&"0".repeat(31), "Test", "secret"));
        assert!(!verify_password(&"0".repeat(41), "Test", "secret"));
    }

    #[test]
    fn login_cookie_hashes_change_with_the_salt() {
        let secret = "dc5e10a1e54043e9bb9da136ad0914541f31cf277f3a13590a54cc13b6b31048";
        let stored = hash_password("Test", "secret");
        let hash = cookie_password_hash(&stored, "ab12", secret);
        assert_eq!(hash.len(), COOKIE_HASH_LEN);
        assert!(verify_cookie_password(&hash, &stored, "ab12", secret));
        assert!(!verify_cookie_password(&hash, &stored, "other", secret));
        assert!(!verify_cookie_password(&hash, &stored, "ab12", "other"));
        assert!(!verify_cookie_password(
            &hash[..39],
            &stored,
            "ab12",
            secret
        ));
        assert!(!verify_cookie_password("", &stored, "ab12", secret));
    }

    #[test]
    fn rehash_policy_always_replaces_an_smf_hash() {
        assert!(needs_rehash(&hash_password("Test", "secret")));
        assert!(needs_rehash("5ebe2294ecd0e0f08eab7690d2a6ee69"));
        assert!(!needs_rehash("nonsense"));
    }
}
