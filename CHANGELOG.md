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
