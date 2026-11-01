//! MediaWiki password formats.
//!
//! MediaWiki has used five storage formats:
//!
//! | prefix | construction |
//! | --- | --- |
//! | `:pbkdf2:<algo>:<iterations>:<length>:<salt>:<hash>` | PBKDF2-HMAC, base64 salt and digest |
//! | `:B:<salt>:<hash>` | `md5(salt . '-' . md5hex(password))` |
//! | `:A:<hash>` | `md5hex(password)` |
//! | `:A:` with an empty digest | a disabled password |
//! | no prefix | `md5(user_id . '-' . md5hex(password))`, the pre-1.24 format |
//!
//! The PBKDF2 verifier is behind the `mediawiki-pbkdf2` feature because a
//! MediaWiki installation can store hundreds of thousands of iterations. The
//! cheap formats are always available.

use crate::constant_time_eq;
use fador_core::crypto::{base64_decode, hex, md5};

#[cfg(feature = "mediawiki-pbkdf2")]
use fador_core::crypto::{base64_encode, pbkdf2_hmac_sha256, pbkdf2_hmac_sha512};
#[cfg(feature = "mediawiki-pbkdf2")]
use fador_core::random::random_array;

/// The smallest PBKDF2 iteration count accepted from a stored row.
pub const MIN_PBKDF2_ITERATIONS: u32 = 1;
/// The largest PBKDF2 iteration count accepted from a stored row.
pub const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;
/// The largest accepted PBKDF2 digest length in bytes.
pub const MAX_PBKDF2_LENGTH: usize = 256;
/// The iteration count used when writing a new PBKDF2 hash.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 120_000;
/// The digest length used when writing a new PBKDF2 hash.
pub const DEFAULT_PBKDF2_LENGTH: usize = 32;

/// The PBKDF2 hash function named by a stored row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbkdf2Algorithm {
    /// PBKDF2-HMAC-SHA-256.
    Sha256,
    /// PBKDF2-HMAC-SHA-512.
    Sha512,
}

impl Pbkdf2Algorithm {
    /// The name as it appears in the stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

/// The bounded parameters of a `:pbkdf2:` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pbkdf2Params {
    /// The hash function.
    pub algorithm: Pbkdf2Algorithm,
    /// The iteration count.
    pub iterations: u32,
    /// The digest length in bytes.
    pub length: usize,
}

/// Whether `hash` looks like a MediaWiki hash this module understands.
pub fn is_mediawiki(hash: &str) -> bool {
    hash.starts_with(":pbkdf2:")
        || hash.starts_with(":A:")
        || hash.starts_with(":B:")
        || (hash.len() == 32 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Verify a password against a MediaWiki hash.
///
/// `user_id` is the account id, which the pre-1.24 unsalted format uses as the
/// salt. Pass `0` when the row does not name an account.
pub fn verify(hash: &str, password: &str, user_id: u64) -> bool {
    if hash.is_empty() || hash == "nologin" {
        return false;
    }
    if let Some(real_hash) = hash.strip_prefix(":A:") {
        return verify_hex_digest(real_hash, &hex(&md5(password.as_bytes())));
    }
    if let Some(rest) = hash.strip_prefix(":B:") {
        let Some((salt, real_hash)) = rest.split_once(':') else {
            return false;
        };
        if salt.len() > 255 {
            return false;
        }
        let first = hex(&md5(password.as_bytes()));
        let second = hex(&md5(format!("{salt}-{first}").as_bytes()));
        return verify_hex_digest(real_hash, &second);
    }
    if hash.starts_with(":pbkdf2:") {
        #[cfg(feature = "mediawiki-pbkdf2")]
        {
            return verify_pbkdf2(hash, password);
        }
        #[cfg(not(feature = "mediawiki-pbkdf2"))]
        {
            return false;
        }
    }
    if !is_mediawiki(hash) {
        return false;
    }
    // Old unsalted MediaWiki hashes used the user id as the salt.
    let legacy = hex(&md5(format!(
        "{user_id}-{}",
        hex(&md5(password.as_bytes()))
    )
    .as_bytes()));
    constant_time_eq(legacy.as_bytes(), hash.as_bytes())
}

fn verify_hex_digest(expected: &str, computed: &str) -> bool {
    expected.len() == computed.len()
        && expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        && constant_time_eq(computed.as_bytes(), expected.as_bytes())
}

/// Parse the parameters of a `:pbkdf2:` row without hashing anything.
pub fn parse_pbkdf2(hash: &str) -> Option<Pbkdf2Params> {
    parse_pbkdf2_full(hash).map(|parsed| parsed.params)
}

struct ParsedPbkdf2 {
    params: Pbkdf2Params,
    #[cfg(feature = "mediawiki-pbkdf2")]
    salt: Vec<u8>,
    #[cfg(feature = "mediawiki-pbkdf2")]
    expected: Vec<u8>,
}

fn parse_pbkdf2_full(hash: &str) -> Option<ParsedPbkdf2> {
    let rest = hash.strip_prefix(":pbkdf2:")?;
    let mut parts = rest.splitn(5, ':');
    let algorithm = match parts.next()? {
        "sha256" => Pbkdf2Algorithm::Sha256,
        "sha512" => Pbkdf2Algorithm::Sha512,
        _ => return None,
    };
    let iterations = parts.next()?.parse::<u32>().ok()?;
    let length = parts.next()?.parse::<usize>().ok()?;
    let salt = base64_decode(parts.next()?)?;
    let expected = base64_decode(parts.next()?)?;
    if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations)
        || length == 0
        || length > MAX_PBKDF2_LENGTH
        || salt.len() > 128
        || expected.len() != length
    {
        return None;
    }
    Some(ParsedPbkdf2 {
        params: Pbkdf2Params {
            algorithm,
            iterations,
            length,
        },
        #[cfg(feature = "mediawiki-pbkdf2")]
        salt,
        #[cfg(feature = "mediawiki-pbkdf2")]
        expected,
    })
}

#[cfg(feature = "mediawiki-pbkdf2")]
fn verify_pbkdf2(hash: &str, password: &str) -> bool {
    let Some(parsed) = parse_pbkdf2_full(hash) else {
        return false;
    };
    let derived = match parsed.params.algorithm {
        Pbkdf2Algorithm::Sha256 => pbkdf2_hmac_sha256(
            password.as_bytes(),
            &parsed.salt,
            parsed.params.iterations,
            parsed.params.length,
        ),
        Pbkdf2Algorithm::Sha512 => pbkdf2_hmac_sha512(
            password.as_bytes(),
            &parsed.salt,
            parsed.params.iterations,
            parsed.params.length,
        ),
    };
    constant_time_eq(&derived, &parsed.expected)
}

/// Whether a stored MediaWiki hash is weaker than the current policy.
///
/// `:A:`, `:B:` and the unsalted format are always replaced; a PBKDF2 row is
/// replaced when its iteration count is below `min_iterations`.
pub fn needs_rehash(hash: &str, min_iterations: u32) -> bool {
    if hash == "nologin" {
        return false;
    }
    if let Some(params) = parse_pbkdf2(hash) {
        return params.iterations < min_iterations;
    }
    true
}

/// Hash a new password with PBKDF2-HMAC-SHA-256 and a random 16-byte salt.
#[cfg(feature = "mediawiki-pbkdf2")]
pub fn hash_pbkdf2(password: &str) -> String {
    let salt = random_array::<16>();
    let derived = pbkdf2_hmac_sha256(
        password.as_bytes(),
        &salt,
        DEFAULT_PBKDF2_ITERATIONS,
        DEFAULT_PBKDF2_LENGTH,
    );
    format!(
        ":pbkdf2:sha256:{}:{}:{}:{}",
        DEFAULT_PBKDF2_ITERATIONS,
        DEFAULT_PBKDF2_LENGTH,
        base64_encode(&salt),
        base64_encode(&derived)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD_MD5: &str = "5f4dcc3b5aa765d61d8327deb882cf99";

    #[test]
    fn verifies_legacy_a_and_b_formats() {
        let a = format!(":A:{PASSWORD_MD5}");
        assert!(verify(&a, "password", 42));
        assert!(!verify(&a, "Password", 42));
        assert!(!verify(":A:zyx", "password", 42));
        assert!(!verify(":A:", "password", 42));

        let b = ":B:abc:3331e311920ad06bb56023d487a4bdde";
        assert!(verify(b, "password", 42));
        assert!(!verify(b, "wrong", 42));
        assert!(!verify(":B:no-colon", "password", 42));
        assert!(!verify(":B:abc:3331", "password", 42));
        assert!(!verify(
            ":B:abc:3331e311920ad06bb56023d487a4bdde0",
            "password",
            42
        ));
    }

    #[test]
    fn verifies_the_unsalted_user_id_format() {
        let legacy = "a3ea030e88200150205b00c6fa1b149d";
        assert!(verify(legacy, "password", 42));
        assert!(!verify(legacy, "password", 43));
        assert!(!verify(legacy, "wrong", 42));
        assert!(!verify(&legacy.to_ascii_uppercase(), "password", 42));
    }

    #[test]
    #[cfg(feature = "mediawiki-pbkdf2")]
    fn verifies_a_fixed_pbkdf2_vector() {
        let hash = ":pbkdf2:sha256:1000:32:MDEyMzQ1Njc4OWFiY2RlZg==:tiKWHy4FAGCWE8gn6GtKhaxD2OeeAUUWXFT/p1aaNl8=";
        assert!(verify(hash, "secret", 1));
        assert!(!verify(hash, "wrong", 1));
        let params = parse_pbkdf2(hash).unwrap();
        assert_eq!(params.algorithm, Pbkdf2Algorithm::Sha256);
        assert_eq!(params.iterations, 1_000);
        assert_eq!(params.length, 32);
        assert_eq!(params.algorithm.as_str(), "sha256");
    }

    #[test]
    fn rejects_hostile_pbkdf2_parameters_without_hashing() {
        for hash in [
            ":pbkdf2:sha256:notanumber:32:AA==:AA==",
            ":pbkdf2:sha512:1:999:AA==:AA==",
            ":pbkdf2:sha256:0:32:AA==:AA==",
            ":pbkdf2:sha256:1:32:AA==:AA==",
            ":pbkdf2:md5:1:32:AA==:AA==",
            ":pbkdf2:sha256:2000001:32:AA==:AA==",
            ":pbkdf2:sha256:1:32:AA==:",
        ] {
            assert!(!verify(hash, "x", 1), "{hash}");
            assert!(parse_pbkdf2(hash).is_none(), "{hash}");
        }
    }

    #[test]
    #[cfg(feature = "mediawiki-pbkdf2")]
    fn hashes_and_verifies_new_pbkdf2_passwords() {
        let hash = hash_pbkdf2("Hyvää päivää");
        assert!(hash.starts_with(":pbkdf2:sha256:120000:32:"));
        assert!(verify(&hash, "Hyvää päivää", 1));
        assert!(!verify(&hash, "Hyvää päivää!", 1));
        assert!(!needs_rehash(&hash, 100_000));
        assert!(needs_rehash(&hash, 200_000));
    }

    #[test]
    fn rejects_empty_disabled_and_unknown_hashes() {
        assert!(!verify("", "", 1));
        assert!(!verify("nologin", "x", 1));
        assert!(!verify("nonsense", "x", 1));
        assert!(!is_mediawiki("nologin"));
        assert!(is_mediawiki(":A:abc"));
        assert!(is_mediawiki(PASSWORD_MD5));
        assert!(needs_rehash(":A:abc", 1));
        assert!(needs_rehash(":B:abc:def", 1));
        assert!(!needs_rehash("nologin", 1));
    }
}
