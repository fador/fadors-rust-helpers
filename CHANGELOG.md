# Changelog

All notable changes to this workspace are documented here. Versions are
lockstep across all crates while the workspace is `0.x`.

## 0.2.0 - 2026-11-02

### Security & Hardening

- Comprehensive security audit remediation across all 14 workspace crates.
- `fador-markup` & `fador-wikitext`: Strict attribute name validation for `data-*`
  and `aria-*` attributes (`[a-zA-Z0-9_.-]`); tag boundary checks stopping on `/`,
  `"`, `'`, and `<`; internal control marker (`\u{1}`, `\u{2}`, `\u{4}`) stripping;
  rejection of raw ASCII control bytes in CSS styles and attribute URLs (CRIT-01, HIGH-01).
- `fador-core`: Dangling symlink path traversal check in `is_inside` (HIGH-02);
  RFC 7693 final-block fix in `blake2b` for exact 128-byte block multiples (HIGH-10);
  cached `/dev/urandom` descriptor and infallible OS-backed `secure_random_*`
  primitives (HIGH-09); year bound clamping in `civil_to_epoch` (MED-11); cumulative
  limit and pre-allocation capping in PHP unserializer (LOW-07).
- `fador-auth`: All session IDs, CSRF tokens, and salts switched to `secure_random_*`;
  `FormKey::token` session ID binding for authenticated users (MED-07); isolated guest
  and authenticated session storage to protect user sessions from eviction floods (MED-09);
  hardened rate-limiting eviction preserving user attempt records (MED-08); constant-time
  dummy password verifications on inactive/suspended accounts (MED-10).
- `fador-mysql`: Dropped `CLIENT_MULTI_RESULTS` to prevent multi-result set lingering;
  transaction state tracking (`in_transaction`) and automatic rollback on pool drop (HIGH-08);
  aligned `format_sql` lexer with MySQL rules for `--`, `#`, and `/*! ... */` executable
  comments (MED-03); auth handshake iteration limit.
- `fador-http`: Per-request deadlines and keep-alive idle timeouts mitigating Slowloris
  attacks (HIGH-07); preserved `X-Forwarded-For` arrival order and latest `X-Forwarded-Proto` (MED-01);
  strict HTTP request line and CRLF validation (MED-02).
- `fador-smf-theme`: AST and parser depth limits (`MAX_PARSE_DEPTH = 64`, `MAX_EXPR_DEPTH = 64`,
  `MAX_ARRAY_DEPTH = 64`) preventing call-stack exhaustion (HIGH-05); wrapping arithmetic
  across evaluators and builtins preventing overflow panics (HIGH-06); bounded string output
  from `php_sprintf` (HIGH-04); HTML escaping of source in `create_button` (MED-12).
- `fador-wikitext`: Bounded width in `PADLEFT`/`PADRIGHT` (HIGH-04); saturating arithmetic
  in `{{#sub:}}` and template transclusion normalization (MED-12).
- `fador-services`: Chunked transfer decoding in third-party captcha verifier (MED-04);
  rejection sampling for unbiased captcha friendly codes and collision-free audio WAV tones;
  SMTP multiline reply code consistency and credentials sanitization; bounded cron lock
  reading; feed URI scheme validation (`is_safe_feed_link`, INFO-01).
- `fador-compress` & `fador-thumb`: Lowered default allocation limits and enforced target
  dimension limits in thumbnail rendering (MED-05); dynamic Huffman Kraft's inequality validation.
- `fador-i18n`: Validated language pack codes against directory traversal (HIGH-03);
  saturating calendar calculations.
- `fador-phpbb-template`: HTML-escaped NUL byte replacement and `js_escape` for `LA_`
  template variables.
- `fador-testutil`: Added `#![deny(unsafe_code)]` attribute.

### Changed

- All crates updated to `0.2.0`.

## 0.1.1 - 2026-11-02

### Added

- `fador-compress`: the `deflate` and `inflate` modules are public, and
  `inflate_gzip_or_raw` / `inflate_gzip_or_raw_with_limit` handle the
  MediaWiki gzip-else-raw storage shape without treating a raw stream as zlib.
- `fador-core`: `format_bytes_with_units`, `BINARY_UNITS` and `FINNISH_UNITS`;
  `html_escape_compat` now normalises NUL to U+FFFD; PHP serialisation gained
  `unserialize_with_budget`, `PhpScalar`, `parse_scalar_map` and
  `serialize_scalar_map`.
- `fador-http`: `FormSeparators` with `HttpConfig::form_separators`, public
  `parse_form` / `parse_form_with`, per-request separator-aware query and form
  parsing, and `HttpConfig::chunk_in_memory_bodies` for applications that must
  keep the old `Content-Length` dynamic-body framing.
- `fador-markup`: `CensorBoundary::{Word,Smf}` and
  `Censor::with_case_insensitive` for SMF-compatible censor boundaries and
  case-sensitive matching.
- `fador-i18n`: `Tzdb::empty()`.

### Changed

- All crates are versioned `0.1.1`.

## 0.1.0 - 2026-11-01

### Added

- `fador-compress`: dependency-free gzip, zlib and raw DEFLATE encoding with a
  fixed-Huffman LZ77 matcher.
- Strict, bounded decompression for gzip, zlib and raw DEFLATE streams.
- gzip CRC32/ISIZE and zlib Adler-32 trailer verification.
- Configurable output limits and typed decode errors.
- Known-vector tests against zlib/gzip output, including a dynamic-Huffman
  stream, plus a seeded malformed-input fuzz test.
- `fador-core`: SHA-1/256/512, MD5, HMAC, PBKDF2, BLAKE2b, CRC-32, base64 and
  hex; OS-backed random bytes with a fallible API; bounded JSON reader/writer;
  bounded PHP serialisation reader/writer; bounded `multipart/form-data`
  parser; PNG/JPEG/GIF header inspection; TTL cache; platform-aware path
  sandbox; HTML, URL, form, date and MediaWiki title helpers.
- `fador-core` fixes the old TTL cache's zero-capacity bug, adds an oldest-entry
  eviction fallback and rejects non-finite PHP floats, duplicate PHP keys and
  invalid UTF-8 slices.
- `fador-mysql`: dependency-free MySQL/MariaDB text-protocol client,
  `mysql_native_password` and fast `caching_sha2_password` authentication,
  strictly escaped `?` placeholders, and a bounded connection pool.
- `fador-mysql` fixes the old client's non-ASCII SQL-template corruption, adds a
  total reassembled-packet cap, and separates read retry (`query_read`) from
  write execution (`query`/`execute`) so a transport error never replays a
  write.
- `fador-testutil`: seeded PRNG, hostile-string corpus and fuzz iteration
  control shared by the workspace tests.
- `fador-http`: hardened HTTP/1.1 server merging the SMF response-framing engine
  with the keskustelu request hardening. Chunked responses, HEAD/204/304/206,
  reserved-header protection, redirect sanitisation, gzip negotiation,
  rightmost-untrusted `X-Forwarded-For`, `peer_ip`, `trust_local_proxy`,
  `//host` rejection, multipart text fields and a buffered line reader.
- `fador-http` fixes the short-file framing bug on both Content-Length and
  chunked paths and adds an end-to-end HEAD/204/304/206 socket test.
- `fador-auth`: cookie codec, session ids/policies/stores, remember-me,
  phpBB/SMF/HMAC CSRF schemes, phpass/bcrypt/Argon2id/SMF/MediaWiki password
  verifiers, ban patterns with IPv4/IPv6 CIDR, ban cache, fixed-window
  throttling and generic permission primitives. Expensive formats are feature
  gated; no database adapters.
- `fador-i18n`: language-pack loader with fallback, all 16 phpBB plural rules,
  placeholder formatting, PHP `date()` and SMF `strftime` formatting, and a
  merged timezone backend with an embedded 497-zone KTZ1 archive plus POSIX
  footer extrapolation for post-2038 dates.
- `fador-markup`: escape policies, URL scheme policy, censor, smiley/autolink
  code matching, markup stripping and Unicode/tag-safe search highlighting.
- `fador-phpbb-template`: the phpBB template compiler, expression engine,
  context bridge, event assets and sandboxed loader, extracted without any
  phpBB template/style content.
- `fador-services`: SMTP/sendmail/log mail transport with strict address and
  header validation, PNG/WAV captcha rendering and provider verification,
  leader/run-lock cron scheduling with an atomic status file, and a clean-room
  RSS/Atom/RDF feed writer. Each module is feature gated.
- `fador-thumb`: phpBB-compatible thumbnail planning and rendering for JPEG,
  PNG, GIF and WebP, with `image::Limits` bounds and atomic writes.
- `fador-smf-theme`: the sandboxed PHP-subset lexer/parser/evaluator and SMF
  theme resolver, with SMF-specific host functions behind a `HostFunctions`
  trait and timezone formatting delegated to `fador-i18n`.
- `fador-wikitext`: the MediaWiki-compatible wikitext parser, decoupled from
  the database through `WikiResolver`, `ParserConfig` and `MessageSource`;
  titles, namespaces, templates, parser functions, references, tables, links,
  images and sanitising are included.
- `fador`: a facade with feature-gated module re-exports and a `prelude` for
  the common types. Default features cover core, compression, HTTP, MySQL,
  authentication, i18n and markup; `all` adds services, thumbnails and the
  three dialect engines.
