//! Seeded fuzz tests for the parsers that read cookies, form tokens, session
//! ids, password hashes, ban patterns and throttle keys.
//!
//! These inputs reach the server from a request header, a form body or a
//! database row. The invariants are:
//!
//! - a `Set-Cookie` value never contains CR or LF and never gains an attribute,
//! - a malformed password hash returns `false` without panicking or hashing for
//!   minutes,
//! - a session id is accepted only in the generated shape,
//! - a ban pattern never panics on hostile text,
//! - the throttle table stays inside its bound.

use crate::acl::{PermissionRow, PermissionSet};
use crate::ban::{BanPattern, BanSubject, IpNetwork};
use crate::cookie::{Cookie, CookieCodec, SameSite};
use crate::csrf::{CookieToken, FormKey};
use crate::password::{PasswordVerifier, MAX_PASSWORD_LEN};
use crate::session::{RememberMeKey, SessionId, SessionPolicy, SessionRecord};
use crate::testutil::{iterations, Rng, MALICIOUS_STRINGS};
use crate::throttle::FixedWindowLimiter;
use crate::user::normalize_login;
use std::net::{IpAddr, Ipv4Addr};

/// Generate a random text value of at most `max` characters.
fn random_text(rng: &mut Rng, max: usize) -> String {
    let length = rng.below(max);
    rng.text(length)
}

#[test]
fn cookie_headers_cannot_inject_lines_or_attributes() {
    let mut rng = Rng::new(0x434f_4f4b_4945_0001);
    let mut values: Vec<String> = MALICIOUS_STRINGS
        .iter()
        .map(|value| value.to_string())
        .collect();
    for _ in 0..iterations(1_000) {
        values.push(random_text(&mut rng, 120));
    }
    for value in &values {
        let cookie = Cookie::new("sid", value)
            .unwrap()
            .secure(true)
            .http_only(true)
            .same_site(Some(SameSite::Lax));
        let header = cookie.to_header_value().unwrap();
        assert!(
            !header.contains('\r') && !header.contains('\n'),
            "{header:?}"
        );
        // The writer adds four separators; a hostile value cannot add a fifth.
        assert_eq!(header.matches("; ").count(), 4, "{header:?}");
        assert!(header.starts_with("sid="), "{header:?}");

        let codec = CookieCodec::new("board_sid").unwrap();
        let header = codec.encode(value).unwrap();
        assert!(
            !header.contains('\r') && !header.contains('\n'),
            "{header:?}"
        );
    }

    // A hostile name is rejected, not encoded.
    for name in MALICIOUS_STRINGS {
        if name.is_empty() || name.bytes().any(|byte| !is_token(byte)) {
            assert!(Cookie::new(name, "x").is_err(), "accepted name {name:?}");
        }
    }
}

fn is_token(byte: u8) -> bool {
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

#[test]
fn hostile_paths_and_domains_never_reach_a_header() {
    for value in MALICIOUS_STRINGS {
        let cookie = Cookie::new("s", "x").unwrap();
        if let Ok(cookie) = cookie.clone().path(value) {
            let header = cookie.to_header_value().unwrap();
            assert!(
                !header.contains('\r') && !header.contains('\n'),
                "{header:?}"
            );
        }
        if let Ok(cookie) = cookie.domain(value) {
            let header = cookie.to_header_value().unwrap();
            assert!(
                !header.contains('\r') && !header.contains('\n'),
                "{header:?}"
            );
        }
    }
}

#[test]
fn form_tokens_stay_hexadecimal_and_exact() {
    let mut rng = Rng::new(0x464f_524d_544f_4b45);
    let key = FormKey::generate();
    let session = SessionId::generate();
    for _ in 0..iterations(2_000) {
        let form = random_text(&mut rng, 40);
        let now = (rng.next_u64() % 1_000_000_000) as i64 + 1;
        let guest = rng.below(2) == 0;
        let token = key.token(&form, &session, now, guest);
        assert_eq!(token.len(), 40);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(key.check(&form, &session, &token, now, now + 1, Some(7_200), guest));
        // Any mutation of the token fails.
        let mut bytes = token.clone().into_bytes();
        let index = rng.below(bytes.len());
        bytes[index] = if bytes[index] == b'0' { b'1' } else { b'0' };
        let mutated = String::from_utf8(bytes).unwrap();
        assert!(!key.check(&form, &session, &mutated, now, now + 1, Some(7_200), guest));
    }
}

#[test]
fn session_ids_are_accepted_only_in_the_generated_shape() {
    let mut rng = Rng::new(0x5345_5353_4944_0001);
    for _ in 0..iterations(3_000) {
        let value = random_text(&mut rng, 80);
        let parsed = SessionId::parse(&value);
        if let Some(id) = &parsed {
            assert_eq!(id.as_str().len(), 32);
            assert!(id
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        }
        assert_eq!(parsed.is_some(), SessionId::is_valid(&value));
    }
    assert!(SessionId::parse(&SessionId::generate().into_string()).is_some());
}

#[test]
fn password_hashes_are_rejected_without_panicking_or_looping() {
    let mut rng = Rng::new(0x5041_5353_574f_5244);
    let prefixes = [
        "$2y$10$",
        "$2a$10$",
        "$2b$10$",
        "$P$9",
        "$H$9",
        "$argon2id$v=19$m=32,t=1,p=1$",
        "$CP$",
        "$P\\2y$",
        ":A:",
        ":B:",
        ":pbkdf2:sha256:1:32:",
        "nologin",
    ];
    let verifier = PasswordVerifier::new();
    let mut hashes: Vec<String> = vec![
        String::new(),
        "nonsense".into(),
        "$".into(),
        "$$$$$".into(),
        "$2y$".into(),
        "$2y$10$".into(),
        "$2y$10$short".into(),
        "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye-extra".into(),
        "$2y$03$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye".into(),
        "$2y$31$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye".into(),
        "$argon2id$v=19$m=262144,t=16,p=1$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE".into(),
        "$argon2id$v=19$m=999999999,t=1,p=1$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE".into(),
        "$P$I9C3cFUCU0.IqnHcpIA0ItcwQrstsC0".into(),
        "$P$99C3cFUCU0".into(),
        "$CP\\2y$10\\abc$def".into(),
        "$P\\2y$10\\ds5rsPX0jsmq7E4zK9WL9u$YUyFn46vBzQq956pIaOzqTZxCzow1My".into(),
        "$P\\31$99C3cFUCU$10\\ds5rsPX0jsmq7E4zK9WL9u$YUyFn46vBzQq956pIaOzqTZxCzow1My".into(),
        "0".repeat(32),
        "g".repeat(32),
        "a".repeat(100_000),
        format!("$2y$10${}{}", "a".repeat(20), format!("中{}", "a".repeat(30))),
    ];
    for text in MALICIOUS_STRINGS {
        hashes.push(format!("$2y$10${text}"));
        hashes.push(format!("$argon2id$v=19$m=32,t=1,p=1${text}"));
        hashes.push(format!("$P${text}"));
        hashes.push(format!(":A:{text}"));
        hashes.push(format!(":B:{text}"));
    }
    for _ in 0..iterations(1_000) {
        let prefix = rng.pick(&prefixes);
        hashes.push(format!("{prefix}{}", random_text(&mut rng, 100)));
    }
    for hash in &hashes {
        let check = verifier.verify(hash, "secret");
        assert!(!check.valid, "hostile hash accepted: {hash:?}");
        assert!(
            !check.needs_rehash,
            "hostile hash asked for a rehash: {hash:?}"
        );
        let _ = verifier.needs_rehash(hash);
    }

    // The cheap known vectors still verify when their feature is enabled.
    #[cfg(feature = "bcrypt")]
    assert!(
        verifier
            .verify(
                "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye",
                "secret"
            )
            .valid
    );
    #[cfg(feature = "phpass")]
    assert!(
        verifier
            .verify("$P$99C3cFUCU0.IqnHcpIA0ItcwQrstsC0", "secret")
            .valid
    );
    #[cfg(feature = "argon2")]
    assert!(verifier
        .verify(
            "$argon2id$v=19$m=32,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE",
            "secret"
        )
        .valid);

    // Oversized passwords are refused before any work.
    let long = "a".repeat(MAX_PASSWORD_LEN + 1);
    assert!(
        !verifier
            .verify(
                "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye",
                &long
            )
            .valid
    );
}

#[test]
fn ban_patterns_never_panic_and_stay_bounded() {
    let mut rng = Rng::new(0x4241_4e50_4154_5445);
    let addresses = ["127.0.0.1", "192.168.1.1", "2001:db8::1", "::ffff:10.0.0.1"];
    for _ in 0..iterations(3_000) {
        let text = random_text(&mut rng, 120);
        let pattern = BanPattern::parse(&text);
        if let Ok(pattern) = pattern {
            let _ = pattern.matches(&text);
            for address in addresses {
                let _ = pattern.matches_ip(address.parse::<IpAddr>().unwrap());
            }
            let _ = pattern.matches_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        if let Some(network) = IpNetwork::parse(&text) {
            let _ = network.contains(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
    }
    for text in MALICIOUS_STRINGS {
        if let Ok(pattern) = BanPattern::parse(text) {
            let _ = pattern.matches(text);
            let _ = pattern.matches_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        }
        let _ = IpNetwork::parse(text);
    }
    // A wildcard pattern cannot be tricked into matching a longer suffix.
    assert!(!BanPattern::parse("*.ru").unwrap().matches("a.ru.evil"));
    let subject = BanSubject::new().with_ip("10.1.2.3".parse().unwrap());
    let rule = crate::ban::BanRule::new(1).with_ip(BanPattern::parse("10.0.0.0/8").unwrap());
    assert!(rule.matches(&subject));
}

#[test]
fn the_throttle_table_stays_bounded_under_random_keys() {
    let mut rng = Rng::new(0x5448_524f_5454_4c45);
    let limiter = FixedWindowLimiter::with_capacity(2, 60, 64);
    for step in 0..iterations(5_000) {
        let key = if rng.below(4) == 0 {
            random_text(&mut rng, 40)
        } else {
            format!("key-{}", rng.below(10_000))
        };
        let now = (step / 10) as i64;
        let decision = limiter.check(&key, now);
        if let crate::throttle::ThrottleDecision::Limited { retry_after } = decision {
            assert!((1..=60).contains(&retry_after), "{retry_after}");
        }
        assert!(
            limiter.len() <= limiter.capacity(),
            "{} > {}",
            limiter.len(),
            limiter.capacity()
        );
    }
}

#[test]
fn remember_me_tokens_are_hashed_and_validated() {
    let mut rng = Rng::new(0x5245_4d45_4d42_4552);
    for _ in 0..iterations(1_000) {
        let token = random_text(&mut rng, 60);
        let key = RememberMeKey { user_id: 7, token };
        if key.is_valid() {
            assert_eq!(key.token.len(), 32);
        }
        let _ = key.token_hash();
    }
    let key = RememberMeKey::generate(7);
    assert_eq!(key.token_hash().len(), 32);
}

#[test]
fn permission_sets_are_order_independent() {
    let mut rng = Rng::new(0x4143_4c50_4552_4d53);
    for _ in 0..iterations(500) {
        let count = rng.below(20);
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            let name = {
                let length = rng.below(12);
                rng.ascii(length, b"abcdefghij_")
            };
            rows.push(if rng.below(2) == 0 {
                PermissionRow::allow(name)
            } else {
                PermissionRow::deny(name)
            });
        }
        let forward = PermissionSet::from_rows(&rows, true);
        let mut reversed = rows.clone();
        reversed.reverse();
        let backward = PermissionSet::from_rows(&reversed, true);
        assert_eq!(forward, backward);
        for row in &rows {
            if forward.is_denied(&row.permission) {
                assert!(!forward.is_allowed(&row.permission));
            }
        }
    }
}

#[test]
fn session_records_survive_hostile_user_agents_and_policies() {
    let policy = SessionPolicy::default();
    let mut rng = Rng::new(0x5345_5353_4249_4e44);
    for _ in 0..iterations(500) {
        let user_agent = random_text(&mut rng, 300);
        let binding = crate::session::SessionBinding::new(None, user_agent.clone());
        let record = SessionRecord::new(SessionId::generate(), Some(7), 1_000, &binding);
        assert!(record.user_agent.chars().count() <= crate::session::MAX_USER_AGENT);
        assert_eq!(
            policy.check(&record, 1_001, &binding),
            crate::session::SessionValidity::Valid
        );
        // The normaliser must accept arbitrary text without panicking.
        let _ = normalize_login(&user_agent);
    }
}

#[test]
fn smf_login_cookies_are_parsed_without_panicking() {
    let mut rng = Rng::new(0x534d_4643_4f4f_4b49);
    let secret = "dc5e10a1e54043e9bb9da136ad0914541f31cf277f3a13590a54cc13b6b31048";
    let stored = crate::password::smf::hash_password("Test", "secret");
    let valid = crate::smf_cookie::SmfLoginCookie::new(
        7,
        crate::password::smf::cookie_password_hash(&stored, "ab12", secret),
        2_000,
        1,
    )
    .serialize()
    .unwrap();
    for _ in 0..iterations(2_000) {
        let value = random_text(&mut rng, 120);
        let _ = crate::smf_cookie::SmfLoginCookie::parse(&value, 1_000);
    }
    for value in MALICIOUS_STRINGS {
        assert!(crate::smf_cookie::SmfLoginCookie::parse(value, 1_000).is_none());
    }
    let parsed = crate::smf_cookie::SmfLoginCookie::parse(&valid, 1_000).unwrap();
    assert!(crate::smf_cookie::verify_smf_login_cookie(
        &parsed, 7, &stored, "ab12", secret, 1_000
    ));
}

#[test]
fn cookie_tokens_reject_every_random_value() {
    let codec = CookieToken::from_secret(b"fuzz secret");
    let session = SessionId::generate();
    let token = codec.issue(&session, 1_000, 3_600);
    let mut rng = Rng::new(0x4353_5246_544f_4b45);
    for _ in 0..iterations(2_000) {
        let value = random_text(&mut rng, 120);
        if value == token {
            continue;
        }
        assert!(!codec.verify(&value, &session, 1_001));
    }
}
