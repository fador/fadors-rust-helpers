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
