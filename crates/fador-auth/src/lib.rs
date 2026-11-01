//! Schema-agnostic authentication, session, authorization and throttling
//! primitives.
//!
//! This crate contains the parts of a web application's login system that do
//! not depend on a database schema, an HTTP framework or a template dialect:
//!
//! | module | contents |
//! | --- | --- |
//! | [`cookie`] | validated `Set-Cookie` construction and `Cookie` header parsing |
//! | [`session`] | session ids, session records, idle/absolute expiry, remember-me keys |
//! | [`smf_cookie`] | SMF's PHP-serialised login cookie |
//! | [`csrf`] | phpBB form keys, SMF session tokens and an HMAC cookie token |
//! | [`password`] | phpass, bcrypt, Argon2id, SMF and MediaWiki password formats |
//! | [`ban`] | exact/wildcard/prefix/CIDR ban patterns, ban cache, IP safety |
//! | [`throttle`] | bounded fixed-window limiter, SMF password flood, login throttle |
//! | [`acl`] | a generic allow/deny permission set |
//! | [`user`] | the user record, user store and a password-checking login helper |
//! | [`clock`] | `Clock`, `SystemClock`, `ManualClock` |
//!
//! Every store is a trait ([`SessionStore`], [`RememberMeStore`], [`UserStore`],
//! [`BanStore`], [`LoginAttemptStore`]) so the crate never touches a database.
//! In-memory implementations exist for tests and for small deployments.
//!
//! # Invariants
//!
//! - **No `unsafe`.** The crate is `#![deny(unsafe_code)]`.
//! - **Bounded work.** Password hashes, Argon2 parameters, phpass iteration
//!   counts, PBKDF2 iteration counts, cookie lengths, ban patterns and throttle
//!   tables all have explicit upper bounds. A damaged database row or a hostile
//!   cookie returns an error instead of occupying a worker.
//! - **Constant-time comparisons.** Form tokens, session tokens, cookie tokens,
//!   password digests, remember-me hashes and ban cache tokens are compared
//!   with [`constant_time_eq`].
//! - **Rotation.** [`session::SessionManager::login`] always destroys the
//!   presented session id and writes a fresh one, and
//!   [`csrf::CsrfTokens::rotate`] replaces every CSRF value after a login or a
//!   password change.
//!
//! # Example
//!
//! ```
//! use fador_auth::cookie::{Cookie, SameSite};
//!
//! let cookie = Cookie::new("session", "abc 123")
//!     .unwrap()
//!     .secure(true)
//!     .http_only(true)
//!     .same_site(Some(SameSite::Lax))
//!     .expires(Some(1_900_000_000));
//! assert_eq!(
//!     cookie.to_header_value().unwrap(),
//!     "session=abc%20123; Expires=Sun, 17 Mar 2030 17:46:40 GMT; Path=/; \
//!      Secure; HttpOnly; SameSite=Lax"
//! );
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod acl;
pub mod ban;
pub mod clock;
pub mod cookie;
pub mod csrf;
pub mod password;
pub mod session;
pub mod smf_cookie;
pub mod throttle;
pub mod user;

mod error;

#[cfg(test)]
pub(crate) use fador_testutil as testutil;

#[cfg(test)]
mod security_tests;

pub use ban::{
    automatic_ban_allowed, ip_scope, BanCache, BanDecision, BanFlags, BanHit, BanPattern, BanRule,
    BanStore, BanSubject, IpNetwork, IpScope, PatternError,
};
pub use clock::{unix_now, Clock, ManualClock, SystemClock};
pub use cookie::{parse_cookie_header, Cookie, CookieCodec, CookieError, SameSite};
pub use csrf::{CookieToken, CsrfError, CsrfTokens, FormKey, SessionToken};
pub use error::{StoreError, StoreResult};
pub use password::{
    Format, PasswordCheck, PasswordContext, PasswordError, PasswordVerifier, RehashPolicy,
};
pub use session::{
    MemoryRememberMeStore, MemorySessionStore, RememberMeKey, RememberMeRecord, RememberMeStore,
    SessionBinding, SessionId, SessionManager, SessionPolicy, SessionRecord, SessionStore,
    SessionValidity,
};
pub use smf_cookie::{verify_smf_login_cookie, SmfLoginCookie};
pub use throttle::{
    FixedWindowLimiter, FloodCounter, LoginAttempt, LoginAttemptStore, LoginThrottle,
    MemoryLoginAttemptStore, ThrottleDecision,
};
pub use user::{
    authenticate, check_password, normalize_login, LoginOutcome, MemoryUserStore, UserRecord,
    UserStatus, UserStore,
};

/// Compare two byte strings without leaking their first difference through
/// timing.
///
/// The length check is not constant time. Every caller compares values of a
/// fixed, known length (a digest, a token), so the length itself is public.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_equality_is_exact() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"samf"));
        assert!(!constant_time_eq(b"same", b"same!"));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
