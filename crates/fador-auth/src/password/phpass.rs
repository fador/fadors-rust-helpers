//! The portable PHP salted-MD5 format (`$P$` and `$H$`).
//!
//! This is the phpass construction phpBB 3.0 used and phpBB 3.3 still accepts
//! from an upgraded board: `$P$` followed by one `itoa64` character holding
//! `log2(iterations)`, an eight-character salt and 22 characters of encoded
//! digest. The iteration count is bounded before any hashing starts, so a
//! damaged row cannot turn a login into a minute of MD5 work.

use crate::constant_time_eq;
use fador_core::crypto::{hex, md5};
use fador_core::random::random_array;

const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The smallest accepted `log2` iteration count.
pub const MIN_LOG2: u32 = 7;
/// The largest accepted `log2` iteration count.
pub const MAX_LOG2: u32 = 18;
/// The `log2` count used when writing a new hash.
pub const DEFAULT_LOG2: u32 = 11;
/// The length of a complete phpass hash.
pub const HASH_LEN: usize = 34;

/// Whether `hash` carries the phpass marker.
pub fn is_phpass(hash: &str) -> bool {
    hash.starts_with("$P$") || hash.starts_with("$H$")
}

/// Verify a password against a phpass hash.
pub fn verify(password: &str, hash: &str) -> bool {
    if hash.len() != HASH_LEN || !hash.is_ascii() {
        return false;
    }
    let Some(computed) = hash_with_setting(password, hash) else {
        return false;
    };
    constant_time_eq(computed.as_bytes(), hash.as_bytes())
}

/// Hash a password with the default iteration count and a random salt.
pub fn hash(password: &str) -> String {
    hash_with_log2(password, DEFAULT_LOG2).expect("DEFAULT_LOG2 is inside the accepted range")
}

/// Hash a password with an explicit `log2` iteration count.
///
/// Returns `None` when `log2` is outside [`MIN_LOG2`]..=[`MAX_LOG2`].
pub fn hash_with_log2(password: &str, log2: u32) -> Option<String> {
    if !(MIN_LOG2..=MAX_LOG2).contains(&log2) {
        return None;
    }
    let salt = random_array::<8>();
    let mut setting = String::with_capacity(12);
    setting.push_str("$P$");
    setting.push(ITOA64[log2 as usize] as char);
    for byte in salt {
        setting.push(ITOA64[(byte & 0x3f) as usize] as char);
    }
    hash_with_setting(password, &setting)
}

/// Hash a password with a full 12-character setting (`$P$` + count + salt).
///
/// Returns `None` when the setting is malformed or its iteration count is
/// outside [`MIN_LOG2`]..=[`MAX_LOG2`].
pub fn hash_with_setting(password: &str, setting: &str) -> Option<String> {
    if setting.len() < 12 || !setting.is_ascii() {
        return None;
    }
    let count_log2 = itoa64_index(setting.as_bytes()[3])?;
    if !(MIN_LOG2..=MAX_LOG2).contains(&count_log2) {
        return None;
    }
    let salt = setting.get(4..12)?;
    let count = 1usize << count_log2;
    let mut hash = md5(format!("{salt}{password}").as_bytes());
    for _ in 0..count {
        let mut input = hash.to_vec();
        input.extend_from_slice(password.as_bytes());
        hash = md5(&input);
    }
    let mut output = setting[..12].to_string();
    output.push_str(&hash_encode64(&hash, 16));
    Some(output)
}

/// The `log2` iteration count of a phpass hash, if it parses.
pub fn count_log2(hash: &str) -> Option<u32> {
    if hash.len() != HASH_LEN || !hash.is_ascii() {
        return None;
    }
    let count = itoa64_index(*hash.as_bytes().get(3)?)?;
    (MIN_LOG2..=MAX_LOG2).contains(&count).then_some(count)
}

/// Whether a hash uses the legacy `$H$` marker or a weaker iteration count than
/// `min_log2`.
pub fn needs_rehash(hash: &str, min_log2: u32) -> bool {
    if !is_phpass(hash) {
        return true;
    }
    match count_log2(hash) {
        Some(count) => count < min_log2 || hash.starts_with("$H$"),
        None => true,
    }
}

fn itoa64_index(byte: u8) -> Option<u32> {
    ITOA64
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u32)
}

fn hash_encode64(input: &[u8], count: usize) -> String {
    let mut output = String::with_capacity(count * 2);
    let mut index = 0usize;
    loop {
        if index >= count {
            break;
        }
        let mut value = input[index] as u32;
        index += 1;
        output.push(ITOA64[(value & 0x3f) as usize] as char);
        if index < count {
            value |= (input[index] as u32) << 8;
        }
        output.push(ITOA64[((value >> 6) & 0x3f) as usize] as char);
        if index >= count {
            break;
        }
        index += 1;
        if index < count {
            value |= (input[index] as u32) << 16;
        }
        output.push(ITOA64[((value >> 12) & 0x3f) as usize] as char);
        if index >= count {
            break;
        }
        index += 1;
        output.push(ITOA64[((value >> 18) & 0x3f) as usize] as char);
        if index >= count {
            break;
        }
    }
    output
}

/// The MD5 fallback the old board used when a `$P$` row was truncated.
///
/// A 32-character hexadecimal string is compared with `md5(password)`. It is
/// kept here because a damaged row must not lock an account out silently; the
/// rehash policy always asks for a replacement.
pub fn verify_truncated_md5(password: &str, hash: &str) -> bool {
    if hash.len() != 32 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    constant_time_eq(hex(&md5(password.as_bytes())).as_bytes(), hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_the_phpbb_vector() {
        let hash = "$P$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0";
        assert!(verify("secret", hash));
        assert!(!verify("wrong", hash));
        assert!(!verify("", hash));
        assert_eq!(count_log2(hash), Some(11));
    }

    #[test]
    fn hashes_and_verifies_roundtrip() {
        for log2 in [MIN_LOG2, DEFAULT_LOG2, 12] {
            let hash = hash_with_log2("Hyvää päivää", log2).unwrap();
            assert_eq!(hash.len(), HASH_LEN);
            assert!(hash.starts_with("$P$"));
            assert_eq!(count_log2(&hash), Some(log2));
            assert!(verify("Hyvää päivää", &hash));
            assert!(!verify("Hyvää päivää!", &hash));
        }
        assert!(hash_with_log2("x", MIN_LOG2 - 1).is_none());
        assert!(hash_with_log2("x", MAX_LOG2 + 1).is_none());
    }

    #[test]
    fn rejects_malformed_hashes_and_settings() {
        for hash in [
            "",
            "$P$",
            "$P$9",
            "$P$99C3cFUCU0",
            "$P$I9C3cFUCU0.IqnHcpIA0ItcwQrstsC0",
            "$P$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0-extra",
            "$P$99C3cFUCU0.IqnHcpIA0ItcwQrstsCä",
            "nonsense",
        ] {
            assert!(!verify("secret", hash), "accepted {hash:?}");
        }
        assert!(hash_with_setting("x", "short").is_none());
        assert!(hash_with_setting("x", "$P$99C3cFU").is_none());
        assert_eq!(count_log2("$P$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0"), Some(11));
        assert_eq!(count_log2("$P$99C3cFUCU0"), None);
    }

    #[test]
    fn rehash_policy_prefers_portable_strong_hashes() {
        assert!(!needs_rehash("$P$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0", 10));
        assert!(needs_rehash("$P$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0", 12));
        assert!(needs_rehash("$H$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0", 10));
        assert!(needs_rehash(
            "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye",
            10
        ));
        assert!(needs_rehash("nonsense", 10));
    }

    #[test]
    fn truncated_md5_fallback_is_exact() {
        assert!(verify_truncated_md5(
            "secret",
            "5ebe2294ecd0e0f08eab7690d2a6ee69"
        ));
        assert!(!verify_truncated_md5(
            "wrong",
            "5ebe2294ecd0e0f08eab7690d2a6ee69"
        ));
        assert!(!verify_truncated_md5(
            "secret",
            "5ebe2294ecd0e0f08eab7690d2a6ee6"
        ));
        assert!(!verify_truncated_md5("secret", &"g".repeat(32)));
    }
}
