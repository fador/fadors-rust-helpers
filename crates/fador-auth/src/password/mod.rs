//! Password hash verification for the formats found in phpBB, SMF and
//! MediaWiki databases.
//!
//! The dispatcher reads the prefix of a stored hash and calls the matching
//! verifier. Nothing is ever written to a store: a caller that wants to upgrade
//! a hash calls [`PasswordVerifier::needs_rehash`], hashes the plaintext with
//! [`PasswordVerifier::hash`] and writes the result itself.
//!
//! # Supported formats
//!
//! | format | marker | feature |
//! | --- | --- | --- |
//! | bcrypt | `$2y$`, `$2a$`, `$2b$`, `$2x$` | `bcrypt` |
//! | portable PHP salted MD5 | `$P$`, `$H$` | `phpass` |
//! | chained combined hash | `$P\2y$...` | `bcrypt` |
//! | Argon2 PHC | `$argon2id$`, `$argon2i$`, `$argon2d$` | `argon2` |
//! | SMF SHA-1 | 40 hexadecimal characters | always |
//! | MediaWiki PBKDF2 | `:pbkdf2:` | `mediawiki-pbkdf2` |
//! | MediaWiki MD5 | `:A:`, `:B:` | always |
//! | legacy MD5 | 32 hexadecimal characters | always |
//!
//! A format whose feature is disabled still *detects*: [`PasswordCheck`] then
//! reports `supported: false` and `valid: false` instead of pretending the hash
//! is wrong. That distinction matters when a deployment turns off an expensive
//! verifier and an administrator has to see which accounts cannot log in.
//!
//! # Bounds
//!
//! A password longer than [`MAX_PASSWORD_LEN`] bytes is rejected before any
//! hashing. Every verifier bounds its own work factor (bcrypt cost, phpass
//! `log2`, Argon2 memory/time/parallelism, PBKDF2 iterations), so a hostile
//! database row cannot occupy a worker.

pub mod argon2;
#[cfg(feature = "bcrypt")]
pub mod bcrypt;
#[cfg(feature = "bcrypt")]
mod blowfish_consts;
pub mod mediawiki;
pub mod phpass;
pub mod smf;

pub use argon2::{Argon2Kind, Argon2Params};
pub use mediawiki::{Pbkdf2Algorithm, Pbkdf2Params};

#[cfg(feature = "bcrypt")]
pub use bcrypt::{MAX_KEY_BYTES, MAX_VERIFY_COST, MIN_COST};
pub use phpass::{MAX_LOG2, MIN_LOG2};

#[cfg(feature = "bcrypt")]
use crate::constant_time_eq;
use std::fmt;

/// The longest password accepted by a verifier, in bytes.
pub const MAX_PASSWORD_LEN: usize = 4_096;
/// The longest stored hash a verifier will look at, in bytes.
///
/// A combined hash is under 200 bytes; the limit only stops a damaged TEXT
/// column from being scanned byte by byte.
pub const MAX_HASH_LEN: usize = 4_096;

/// The detected storage format of a password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// bcrypt (`$2y$`, `$2a$`, `$2b$`, `$2x$`).
    Bcrypt,
    /// Portable PHP salted MD5 (`$P$`, `$H$`).
    Phpass,
    /// Chained phpass/bcrypt hash (`$P\2y$...`).
    Combined,
    /// Argon2 PHC string.
    Argon2,
    /// SMF SHA-1 (40 hexadecimal characters).
    Smf,
    /// MediaWiki PBKDF2 (`:pbkdf2:`).
    MediaWikiPbkdf2,
    /// MediaWiki MD5 (`:A:`, `:B:` or the unsalted user-id format).
    MediaWikiMd5,
    /// A bare 32-character MD5 digest, shared by phpBB, SMF and MediaWiki.
    LegacyMd5,
    /// An empty, disabled or unrecognised value.
    Unknown,
}

impl Format {
    /// Whether this build can verify the format.
    pub fn is_supported(self) -> bool {
        match self {
            Self::Bcrypt | Self::Combined => cfg!(feature = "bcrypt"),
            Self::Phpass => cfg!(feature = "phpass"),
            Self::Argon2 => cfg!(feature = "argon2"),
            Self::MediaWikiPbkdf2 => cfg!(feature = "mediawiki-pbkdf2"),
            Self::Smf | Self::MediaWikiMd5 | Self::LegacyMd5 | Self::Unknown => true,
        }
    }

    /// The format name used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bcrypt => "bcrypt",
            Self::Phpass => "phpass",
            Self::Combined => "combined",
            Self::Argon2 => "argon2",
            Self::Smf => "smf-sha1",
            Self::MediaWikiPbkdf2 => "mediawiki-pbkdf2",
            Self::MediaWikiMd5 => "mediawiki-md5",
            Self::LegacyMd5 => "legacy-md5",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of checking one password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordCheck {
    /// Whether the password matches the stored hash.
    pub valid: bool,
    /// The detected format.
    pub format: Format,
    /// Whether the hash is weaker than the policy asks for. Only set when the
    /// password was valid, because a failed check must never trigger a write.
    pub needs_rehash: bool,
    /// Whether this build has the verifier for the detected format.
    pub supported: bool,
}

impl PasswordCheck {
    fn invalid(format: Format) -> Self {
        Self {
            valid: false,
            format,
            needs_rehash: false,
            supported: format.is_supported(),
        }
    }
}

/// The account attributes some formats need.
///
/// SMF salts a hash with the login name and MediaWiki's oldest format salts it
/// with the account id. Formats that do not need them ignore the context.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PasswordContext<'a> {
    /// The stored login name (SMF `member_name`).
    pub user_name: &'a str,
    /// The account id (MediaWiki legacy salt).
    pub user_id: u64,
}

impl<'a> PasswordContext<'a> {
    /// Build a context from a login name and an account id.
    pub fn new(user_name: &'a str, user_id: u64) -> Self {
        Self { user_name, user_id }
    }
}

/// A hash that cannot be written by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    /// No hashing feature is enabled; the caller must enable `bcrypt` or
    /// `mediawiki-pbkdf2`.
    NoHasher,
    /// The password is longer than [`MAX_PASSWORD_LEN`] bytes.
    TooLong,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHasher => write!(f, "no password hashing feature is enabled"),
            Self::TooLong => write!(f, "password is longer than {MAX_PASSWORD_LEN} bytes"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// The work factors below which a hash is replaced on the next successful
/// login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RehashPolicy {
    /// The smallest acceptable bcrypt cost.
    pub bcrypt_min_cost: u32,
    /// The smallest acceptable phpass `log2` iteration count, or `None` to
    /// replace every phpass hash.
    pub phpass_min_log2: Option<u32>,
    /// The smallest acceptable Argon2id memory size in KiB.
    pub argon2_min_memory_kib: u32,
    /// The smallest acceptable Argon2id time cost.
    pub argon2_min_time_cost: u32,
    /// The smallest acceptable MediaWiki PBKDF2 iteration count.
    pub pbkdf2_min_iterations: u32,
}

impl Default for RehashPolicy {
    fn default() -> Self {
        Self {
            bcrypt_min_cost: 10,
            phpass_min_log2: None,
            // RFC 9106's second recommended option is 64 MiB; PHP's default is
            // also 64 MiB. A row below 19 MiB is weaker than bcrypt-10.
            argon2_min_memory_kib: 19_456,
            argon2_min_time_cost: 2,
            pbkdf2_min_iterations: 100_000,
        }
    }
}

impl RehashPolicy {
    /// Whether `hash` is weaker than this policy or uses a legacy variant.
    pub fn needs_rehash(&self, hash: &str) -> bool {
        let hash = peel_conversion_marker(hash);
        if hash.len() > MAX_HASH_LEN {
            return true;
        }
        match detect(hash) {
            Format::Bcrypt => {
                #[cfg(feature = "bcrypt")]
                {
                    bcrypt::needs_rehash(hash, self.bcrypt_min_cost)
                }
                #[cfg(not(feature = "bcrypt"))]
                {
                    true
                }
            }
            Format::Phpass => match self.phpass_min_log2 {
                Some(min_log2) => phpass::needs_rehash(hash, min_log2),
                None => true,
            },
            Format::Combined => true,
            Format::Argon2 => {
                #[cfg(feature = "argon2")]
                {
                    match argon2::params(hash) {
                        Some(params) => {
                            params.kind != Argon2Kind::Id
                                || params.memory_kib < self.argon2_min_memory_kib
                                || params.time_cost < self.argon2_min_time_cost
                        }
                        None => true,
                    }
                }
                #[cfg(not(feature = "argon2"))]
                {
                    true
                }
            }
            Format::Smf | Format::MediaWikiMd5 | Format::LegacyMd5 => true,
            Format::MediaWikiPbkdf2 => mediawiki::needs_rehash(hash, self.pbkdf2_min_iterations),
            Format::Unknown => true,
        }
    }
}

/// Verify passwords against stored hashes.
///
/// ```
/// use fador_auth::password::{PasswordContext, PasswordVerifier};
///
/// let verifier = PasswordVerifier::new();
/// let check = verifier.verify_with(
///     "dcc4a6fbee930b0b34cf9fc2131b6b70c89e6b9b",
///     "secret",
///     &PasswordContext::new("Test", 7),
/// );
/// assert!(check.valid);
/// // SMF's SHA-1 format is always replaced after a successful login.
/// assert!(check.needs_rehash);
/// ```
#[derive(Debug, Clone, Default)]
pub struct PasswordVerifier {
    policy: RehashPolicy,
}

impl PasswordVerifier {
    /// Create a verifier with the default rehash policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a verifier with an explicit rehash policy.
    pub fn with_policy(policy: RehashPolicy) -> Self {
        Self { policy }
    }

    /// The rehash policy.
    pub fn policy(&self) -> &RehashPolicy {
        &self.policy
    }

    /// Verify a password without account context.
    ///
    /// SMF's name-salted format and MediaWiki's user-id format cannot match
    /// without context; use [`PasswordVerifier::verify_with`] for those.
    pub fn verify(&self, hash: &str, password: &str) -> PasswordCheck {
        self.verify_with(hash, password, &PasswordContext::default())
    }

    /// Verify a password with the account attributes some formats need.
    pub fn verify_with(
        &self,
        hash: &str,
        password: &str,
        context: &PasswordContext<'_>,
    ) -> PasswordCheck {
        let hash = peel_conversion_marker(hash);
        if hash.len() > MAX_HASH_LEN {
            return PasswordCheck::invalid(Format::Unknown);
        }
        let format = detect(hash);
        if hash.is_empty() || password.len() > MAX_PASSWORD_LEN {
            return PasswordCheck::invalid(format);
        }
        let valid = match format {
            Format::Bcrypt => {
                #[cfg(feature = "bcrypt")]
                {
                    bcrypt::verify(password, hash)
                }
                #[cfg(not(feature = "bcrypt"))]
                {
                    false
                }
            }
            Format::Phpass => {
                #[cfg(feature = "phpass")]
                {
                    phpass::verify(password, hash)
                }
                #[cfg(not(feature = "phpass"))]
                {
                    false
                }
            }
            Format::Combined => {
                #[cfg(feature = "bcrypt")]
                {
                    verify_combined(password, hash)
                }
                #[cfg(not(feature = "bcrypt"))]
                {
                    false
                }
            }
            Format::Argon2 => {
                #[cfg(feature = "argon2")]
                {
                    argon2::verify(password, hash)
                }
                #[cfg(not(feature = "argon2"))]
                {
                    false
                }
            }
            Format::Smf => smf::verify_password(hash, context.user_name, password),
            Format::MediaWikiPbkdf2 => {
                #[cfg(feature = "mediawiki-pbkdf2")]
                {
                    mediawiki::verify(hash, password, context.user_id)
                }
                #[cfg(not(feature = "mediawiki-pbkdf2"))]
                {
                    false
                }
            }
            Format::MediaWikiMd5 => mediawiki::verify(hash, password, context.user_id),
            Format::LegacyMd5 => {
                phpass::verify_truncated_md5(password, hash)
                    || smf::verify_password(hash, context.user_name, password)
                    || mediawiki::verify(hash, password, context.user_id)
            }
            Format::Unknown => false,
        };
        PasswordCheck {
            valid,
            format,
            needs_rehash: valid && self.policy.needs_rehash(hash),
            supported: format.is_supported(),
        }
    }

    /// Whether a stored hash is weaker than the policy.
    pub fn needs_rehash(&self, hash: &str) -> bool {
        self.policy.needs_rehash(hash)
    }

    /// Hash a new password with the strongest writer this build has: bcrypt
    /// when the `bcrypt` feature is on, MediaWiki PBKDF2 otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::TooLong`] for an oversized password and
    /// [`PasswordError::NoHasher`] when neither writer is enabled.
    pub fn hash(&self, password: &str) -> Result<String, PasswordError> {
        if password.len() > MAX_PASSWORD_LEN {
            return Err(PasswordError::TooLong);
        }
        #[cfg(feature = "bcrypt")]
        {
            Ok(bcrypt::hash(password))
        }
        #[cfg(all(not(feature = "bcrypt"), feature = "mediawiki-pbkdf2"))]
        {
            Ok(mediawiki::hash_pbkdf2(password))
        }
        #[cfg(all(not(feature = "bcrypt"), not(feature = "mediawiki-pbkdf2")))]
        {
            let _ = password;
            Err(PasswordError::NoHasher)
        }
    }
}

/// Strip a phpBB `$CP$` conversion marker, which prefixes a hash that was
/// converted from another format.
fn peel_conversion_marker(mut hash: &str) -> &str {
    for _ in 0..4 {
        match hash.strip_prefix("$CP$") {
            Some(rest) => hash = rest,
            None => break,
        }
    }
    hash
}

/// Detect the storage format of a hash.
pub fn detect(hash: &str) -> Format {
    let hash = peel_conversion_marker(hash);
    if hash.is_empty() {
        return Format::Unknown;
    }
    if hash.starts_with('$') && hash.contains('\\') {
        return Format::Combined;
    }
    if hash.starts_with("$2y$")
        || hash.starts_with("$2a$")
        || hash.starts_with("$2b$")
        || hash.starts_with("$2x$")
    {
        return Format::Bcrypt;
    }
    if hash.starts_with("$P$") || hash.starts_with("$H$") {
        return Format::Phpass;
    }
    if hash.starts_with("$argon2") {
        return Format::Argon2;
    }
    if hash.starts_with(":pbkdf2:") {
        return Format::MediaWikiPbkdf2;
    }
    if hash.starts_with(":A:") || hash.starts_with(":B:") {
        return Format::MediaWikiMd5;
    }
    if hash.len() == smf::SHA1_HASH_LEN && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Format::Smf;
    }
    if hash.len() == smf::MD5_HASH_LEN && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Format::LegacyMd5;
    }
    Format::Unknown
}

/// Verify a phpBB chained hash such as
/// `$P\2y$99C3cFUCU$10\ds5rsPX0jsmq7E4zK9WL9u$YUyFn46vBzQq956pIaOzqTZxCzow1My`.
///
/// The prefix names the algorithms in order; each segment is that algorithm's
/// setting and the last segment is the final digest. A type this crate does not
/// implement fails closed.
#[cfg(feature = "bcrypt")]
fn verify_combined(password: &str, hash: &str) -> bool {
    let Some(rest) = hash.strip_prefix('$') else {
        return false;
    };
    let Some((prefix, payload)) = rest.split_once('$') else {
        return false;
    };
    let types: Vec<&str> = prefix.split('\\').collect();
    if types.len() < 2 || types.len() > 4 {
        return false;
    }
    let segments: Vec<&str> = payload.split('$').collect();
    if segments.len() != types.len() + 1 {
        return false;
    }
    let expected = segments[types.len()];
    let mut current = password.to_string();
    for (index, kind) in types.iter().enumerate() {
        let setting = segments[index];
        current = match *kind {
            "P" | "H" => {
                let rebuilt = format!("$P${setting}");
                let Some(hashed) = phpass::hash_with_setting(&current, &rebuilt) else {
                    return false;
                };
                let Some(digest) = hashed.get(12..) else {
                    return false;
                };
                digest.to_string()
            }
            "2y" | "2a" | "2b" | "2x" => {
                let normalized = setting.replace('\\', "$");
                let Some((cost, salt)) = bcrypt::parse_setting(&normalized) else {
                    return false;
                };
                let hashed = bcrypt::hash_with_salt(&current, cost, salt);
                let Some(digest) = hashed.get(29..) else {
                    return false;
                };
                digest.to_string()
            }
            _ => return false,
        };
    }
    constant_time_eq(current.as_bytes(), expected.as_bytes())
}

/// Verify a password with the default policy and no account context.
pub fn verify_password(hash: &str, password: &str) -> PasswordCheck {
    PasswordVerifier::new().verify(hash, password)
}

/// Whether a hash is weaker than the default policy.
pub fn needs_rehash(hash: &str) -> bool {
    PasswordVerifier::new().needs_rehash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BCRYPT: &str = "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye";
    const PHPASS: &str = "$P$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0";
    const COMBINED: &str =
        "$P\\2y$99C3cFUCU$10\\ds5rsPX0jsmq7E4zK9WL9u$YUyFn46vBzQq956pIaOzqTZxCzow1My";
    const ARGON2: &str = "$argon2id$v=19$m=32,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE";

    #[test]
    fn verifies_the_phpbb_vectors() {
        for (hash, format, rehash) in [
            (BCRYPT, Format::Bcrypt, false),
            (PHPASS, Format::Phpass, true),
            (COMBINED, Format::Combined, true),
            (ARGON2, Format::Argon2, true),
        ] {
            let check = PasswordVerifier::new().verify(hash, "secret");
            assert_eq!(check.format, format);
            if format.is_supported() {
                assert!(check.valid, "{format}");
                assert!(check.supported);
                assert_eq!(check.needs_rehash, rehash, "{format}");
            } else {
                assert!(!check.valid, "{format}");
                assert!(!check.supported);
            }

            let wrong = PasswordVerifier::new().verify(hash, "wrong");
            assert!(!wrong.valid, "{format}");
            assert!(!wrong.needs_rehash);
        }
    }

    #[test]
    fn a_deployment_can_keep_phpass_hashes() {
        let policy = RehashPolicy {
            phpass_min_log2: Some(10),
            ..RehashPolicy::default()
        };
        assert!(!policy.needs_rehash(PHPASS));
        let policy = RehashPolicy {
            phpass_min_log2: Some(12),
            ..RehashPolicy::default()
        };
        assert!(policy.needs_rehash(PHPASS));
        assert!(RehashPolicy::default().needs_rehash(PHPASS));
    }

    #[test]
    fn verifies_combined_hashes_without_panicking_on_damage() {
        for hash in [
            "$P\\2y$",
            "$P\\2y$99C3cFUCU",
            "$P\\2y$99C3cFUCU$10\\ds5rsPX0jsmq7E4zK9WL9u",
            "$P\\2y$99C3cFUCU$10\\ds5rsPX0jsmq7E4zK9WL9u$short",
            "$P\\unknown$99C3cFUCU$10\\ds5rsPX0jsmq7E4zK9WL9u$YUyFn46vBzQq956pIaOzqTZxCzow1My",
            "$P\\2y$99C3cFUCU$99\\ds5rsPX0jsmq7E4zK9WL9u$YUyFn46vBzQq956pIaOzqTZxCzow1My",
            "$P\\2y\\2y\\2y\\2y$99C3cFUCU$10\\ds5rsPX0jsmq7E4zK9WL9u$YUyFn46vBzQq956pIaOzqTZxCzow1My",
        ] {
            assert!(!verify_password(hash, "secret").valid, "{hash}");
        }
    }

    #[test]
    fn conversion_markers_are_peeled() {
        assert_eq!(detect(&format!("$CP${BCRYPT}")), Format::Bcrypt);
        assert_eq!(detect(&format!("$CP$$CP${PHPASS}")), Format::Phpass);
        #[cfg(feature = "bcrypt")]
        assert!(verify_password(&format!("$CP${BCRYPT}"), "secret").valid);
        assert!(!verify_password("$CP\\2y$10\\abc$def", "secret").valid);
        assert_eq!(detect("$CP$"), Format::Unknown);
    }

    #[test]
    fn detects_every_format_and_fails_closed() {
        assert_eq!(detect(BCRYPT), Format::Bcrypt);
        assert_eq!(
            detect("$2a$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye"),
            Format::Bcrypt
        );
        assert_eq!(detect(PHPASS), Format::Phpass);
        assert_eq!(detect("$H$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0"), Format::Phpass);
        assert_eq!(detect(COMBINED), Format::Combined);
        assert_eq!(detect(ARGON2), Format::Argon2);
        assert_eq!(
            detect("dcc4a6fbee930b0b34cf9fc2131b6b70c89e6b9b"),
            Format::Smf
        );
        assert_eq!(
            detect(":A:5f4dcc3b5aa765d61d8327deb882cf99"),
            Format::MediaWikiMd5
        );
        assert_eq!(detect(":B:abc:def"), Format::MediaWikiMd5);
        assert_eq!(
            detect(":pbkdf2:sha256:1000:32:MDEyMzQ1Njc4OWFiY2RlZg==:tiKWHy4FAGCWE8gn6GtKhaxD2OeeAUUWXFT/p1aaNl8="),
            Format::MediaWikiPbkdf2
        );
        assert_eq!(
            detect("5ebe2294ecd0e0f08eab7690d2a6ee69"),
            Format::LegacyMd5
        );
        for unknown in ["", "nonsense", "nologin", "$", "$$$$$", &"a".repeat(10_000)] {
            assert_eq!(detect(unknown), Format::Unknown);
            let check = verify_password(unknown, "secret");
            assert!(!check.valid);
            assert_eq!(check.format, Format::Unknown);
        }
    }

    #[test]
    fn verifies_smf_and_mediawiki_hashes_with_context() {
        let verifier = PasswordVerifier::new();
        let smf = smf::hash_password("Test", "secret");
        let context = PasswordContext::new("Test", 42);
        let check = verifier.verify_with(&smf, "secret", &context);
        assert!(check.valid);
        assert_eq!(check.format, Format::Smf);
        assert!(check.needs_rehash);
        assert!(
            !verifier
                .verify_with(&smf, "secret", &PasswordContext::new("Other", 42))
                .valid
        );
        assert!(!verifier.verify(&smf, "secret").valid);

        let legacy = "a3ea030e88200150205b00c6fa1b149d";
        assert!(
            verifier
                .verify_with(legacy, "password", &PasswordContext::new("", 42))
                .valid
        );
        assert!(
            !verifier
                .verify_with(legacy, "password", &PasswordContext::new("", 43))
                .valid
        );
    }

    #[test]
    fn rejects_oversized_passwords_and_hashes() {
        let verifier = PasswordVerifier::new();
        let long = "a".repeat(MAX_PASSWORD_LEN + 1);
        assert!(!verifier.verify(BCRYPT, &long).valid);
        assert!(!verifier.verify(&"a".repeat(100_000), "x").valid);
        let huge = "a".repeat(MAX_HASH_LEN + 1);
        assert!(!verifier.verify(&huge, "x").valid);
        assert!(verifier.needs_rehash(&huge));
        assert_eq!(verifier.hash(&long).unwrap_err(), PasswordError::TooLong);
    }

    #[test]
    #[cfg(any(feature = "bcrypt", feature = "mediawiki-pbkdf2"))]
    fn writes_and_verifies_a_new_password() {
        let verifier = PasswordVerifier::new();
        let hash = verifier.hash("Hyvää päivää").unwrap();
        let check = verifier.verify(&hash, "Hyvää päivää");
        assert!(check.valid);
        assert!(!check.needs_rehash);
        assert!(!verifier.verify(&hash, "Hyvää päivää!").valid);
    }

    #[test]
    fn rehash_policy_tracks_the_work_factor() {
        let policy = RehashPolicy::default();
        #[cfg(feature = "bcrypt")]
        {
            assert!(!policy.needs_rehash(BCRYPT));
            assert!(
                policy.needs_rehash("$2y$04$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye")
            );
        }
        #[cfg(feature = "argon2")]
        {
            assert!(!policy.needs_rehash("$argon2id$v=19$m=65536,t=4,p=2$MDEyMzQ1Njc4OWFiY2RlZg$3jcZPNqt9+GKqnvGVGshKlkBzqUH6HY1mDtdFKa0Y4Y"));
            assert!(policy.needs_rehash(ARGON2));
            assert!(policy.needs_rehash("$argon2i$v=19$m=65536,t=4,p=2$MDEyMzQ1Njc4OWFiY2RlZg$3jcZPNqt9+GKqnvGVGshKlkBzqUH6HY1mDtdFKa0Y4Y"));
        }
        assert!(!policy.needs_rehash(":pbkdf2:sha256:120000:32:MDEyMzQ1Njc4OWFiY2RlZg==:tiKWHy4FAGCWE8gn6GtKhaxD2OeeAUUWXFT/p1aaNl8="));
        assert!(policy.needs_rehash(":pbkdf2:sha256:1000:32:MDEyMzQ1Njc4OWFiY2RlZg==:tiKWHy4FAGCWE8gn6GtKhaxD2OeeAUUWXFT/p1aaNl8="));
        assert!(policy.needs_rehash(PHPASS));
        assert!(policy.needs_rehash(COMBINED));
        assert!(policy.needs_rehash(&smf::hash_password("Test", "secret")));
        assert!(policy.needs_rehash("5ebe2294ecd0e0f08eab7690d2a6ee69"));
        assert!(policy.needs_rehash(""));
    }

    #[test]
    fn formats_report_their_names() {
        assert_eq!(Format::Bcrypt.as_str(), "bcrypt");
        assert_eq!(Format::Unknown.to_string(), "unknown");
    }
}
