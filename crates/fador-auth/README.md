# fador-auth

Schema-agnostic authentication, session, cookie, CSRF, password, ban and
throttling primitives.

The crate contains the parts of a login system that do not depend on a database
schema, an HTTP framework or a template dialect. Storage is always a trait, so
the crate never opens a connection and never names a table.

## Modules

| Module | Contents |
| --- | --- |
| `cookie` | `Cookie`, `CookieCodec`, `SameSite`, request-header parsing |
| `session` | `SessionId`, `SessionRecord`, `SessionPolicy`, `SessionStore`, `RememberMeStore`, `SessionManager` |
| `smf_cookie` | SMF's PHP-serialised login cookie (`SmfLoginCookie`) |
| `csrf` | phpBB form keys, SMF session tokens, an HMAC cookie token, `CsrfTokens` |
| `password` | phpass, bcrypt, Argon2 PHC, SMF SHA-1/MD5, MediaWiki PBKDF2/`:A:`/`:B:` |
| `ban` | exact/wildcard/prefix/CIDR patterns, `BanRule`, `BanCache`, IP safety |
| `throttle` | `FixedWindowLimiter`, `FloodCounter`, `LoginThrottle` |
| `acl` | `PermissionSet`, `PermissionRow`, `Effect` |
| `user` | `UserRecord`, `UserStore`, `authenticate`, `normalize_login` |
| `clock` | `Clock`, `SystemClock`, `ManualClock` |

The traits are `Clock`, `SessionStore`, `RememberMeStore`, `UserStore`,
`BanStore` and `LoginAttemptStore`. In-memory implementations
(`MemorySessionStore`, `MemoryRememberMeStore`, `MemoryUserStore`,
`MemoryLoginAttemptStore`) exist for tests and small single-process servers.

## Usage

A session id is generated, validated and rotated on login:

```rust
use fador_auth::session::{SessionBinding, SessionManager, SessionPolicy, SessionStore, MemorySessionStore};

let manager = SessionManager::new(MemorySessionStore::default(), SessionPolicy::default());
let binding = SessionBinding::new(None, "Mozilla/5.0");
let guest = manager.start_guest(1_000, &binding).unwrap();
let logged_in = manager.login(Some(&guest.id), 7, 1_001, &binding).unwrap();
assert_ne!(logged_in.id, guest.id); // session fixation is impossible
assert!(manager.store().load(&guest.id).unwrap().is_none());
```

A cookie value is percent-encoded, so a hostile value cannot add an attribute
or split the header:

```rust
use fador_auth::cookie::Cookie;

let cookie = Cookie::new("sid", "a\r\nSet-Cookie: pwned=1").unwrap();
let header = cookie.to_header_value().unwrap();
assert!(!header.contains('\r'));
```

Passwords are verified by format, and a weak format asks for a replacement:

```rust
use fador_auth::password::{PasswordContext, PasswordVerifier};

let verifier = PasswordVerifier::new();
let check = verifier.verify_with(
    "dcc4a6fbee930b0b34cf9fc2131b6b70c89e6b9b", // SMF sha1(lower(name).password)
    "secret",
    &PasswordContext::new("Test", 7),
);
assert!(check.valid);
assert!(check.needs_rehash);
```

CSRF values are rotated together after a login or a password change:

```rust
use fador_auth::csrf::CsrfTokens;
use fador_auth::session::SessionId;

let session = SessionId::generate();
let mut tokens = CsrfTokens::generate(&session);
let token = tokens.cookie_token().issue(&session, 1_000, 3_600);
assert!(tokens.cookie_token().verify(&token, &session, 1_001));
tokens.rotate(&session);
assert!(!tokens.cookie_token().verify(&token, &session, 1_001));
```

## Features

All features are enabled by default. Disable one to remove the verifier from the
binary; the format is still *detected* and reported as `supported: false`
instead of being treated as a wrong password.

| Feature | Contents |
| --- | --- |
| `bcrypt` | bcrypt verification and the preferred password writer (default) |
| `phpass` | portable PHP salted-MD5 verification (default) |
| `argon2` | Argon2id/Argon2i/Argon2d PHC verification (default) |
| `mediawiki-pbkdf2` | MediaWiki PBKDF2 verification and the fallback writer (default) |

SMF SHA-1/MD5 and the MediaWiki `:A:`/`:B:` formats are cheap and always
compiled. `cargo test --no-default-features` passes: only the tests of a
disabled verifier are skipped.

## Bounds

Every parser has an explicit limit:

- cookie names 256 bytes, values 4,096 bytes, paths 1,024 bytes, domains 253
  bytes, 256 header pairs;
- session ids exactly 32 lowercase hex characters, user agents 255 characters;
- passwords 4,096 bytes, stored hashes 4,096 bytes, bcrypt cost 4-16, phpass
  `log2` 7-18, Argon2 memory 8 KiB-256 MiB, time 1-16, parallelism 1-16 and
  `memory × time` ≤ 1,048,576, PBKDF2 at most 2,000,000 iterations and a
  256-byte digest;
- ban patterns 255 bytes, ban reasons 255 characters, matched values 1,024
  bytes;
- the fixed-window limiter hashes its keys (an address is never stored) and
  caps the table per shard, dropping expired buckets first.

## Deliberate deviations

These are not accidents. Each one removes a behaviour that could be abused.

- **Wildcards are anchored.** The source board matched `*.ru` by looking for
  `.ru` anywhere in the value, so `a.ru.evil` matched. Here `*` is a glob over
  the whole value.
- **IP prefixes stop at a label boundary.** `1.2.3.4` no longer matches
  `1.2.3.40`, a real bug in the source ban matcher.
- **A ban exemption wins regardless of row order.** phpBB's `ban.exclude` only
  wins because its loop returns early; a reordered row set could change the
  answer. `BanCache` evaluates exemptions first and reports the lowest denying
  rule id, so the answer is deterministic.
- **ACL precedence is order-independent.** A deny always beats an allow. phpBB
  ORs a global permission with a forum-local one (a local "never" cannot
  override a global "yes"), auto-grants a parent flag when a child is allowed,
  and SMF's group merge depends on row order. `PermissionSet` reproduces none of
  that. `PermissionSet::any(&[])` is `false` (SMF's `allowedTo([])` is `true`).
- **SMF plaintext passwords are not accepted.** SMF 2.0 also compared the stored
  value with the submitted password. A plaintext row must be reset, not honoured.
- **Session ids have one shape.** Only 32 lowercase hex characters are looked
  up. SMF's 16-32 alphanumeric ids and uppercase hex are rejected, because a
  stored id is always one this crate generated.
- **A binding mismatch does not destroy the session.** An expired record is
  deleted, but a request from another address or user agent is only ignored, so
  a stolen id cannot be used to log the real owner out.
- **No DES crypt.** SMF's `crypt_des` fallback is not implemented; its
  provenance is separate and it is not needed by a board that has been upgraded
  past 1.1.
- **No schema-coupled ACL.** Forum ids, group ids, roles and permission masks
  stay in the application. This crate keeps only the allow/deny merge.

## Provenance

MIT. The code is the copyright holder's original work, extracted from the
`keskustelu`, `smf` and `wiki` servers and relicensed here. No Simple Machines
Forum, phpBB or MediaWiki source was copied: the storage *formats* are
reimplemented so existing rows keep working. The Blowfish P-array and S-boxes in
`password/blowfish_consts.rs` are the standard public-domain constants of the
Blowfish algorithm (the hexadecimal digits of pi), not code from a library.

See the repository `LICENSE` and `NOTICE` files.

## Tests

```sh
cargo fmt --all
cargo clippy -p fador-auth --all-targets -- -D warnings
cargo test -p fador-auth
cargo doc -p fador-auth --no-deps
```

The suite includes the phpBB, SMF and MediaWiki password vectors, hostile
cookie and form-token inputs, session-id rotation, ban pattern/CIDR cases,
throttle bounds, ACL precedence regressions and seeded fuzz tests. Set
`FADOR_FUZZ_ITERATIONS` to raise the generated case count.
