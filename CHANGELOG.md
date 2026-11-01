# Changelog

All notable changes to this workspace are documented here. Versions are
lockstep across all crates while the workspace is `0.x`.

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
