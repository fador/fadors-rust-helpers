# fador-compress

A small, dependency-free gzip, zlib and raw DEFLATE codec.

- One final fixed-Huffman DEFLATE block with a bounded hash-chain LZ77 matcher.
- Strict decoding with gzip CRC32/ISIZE and zlib Adler-32 verification.
- Configurable output limits and typed errors.
- Deterministic output: no timestamp, no optional gzip header fields.
- No `unsafe`, no external crates, MSRV 1.88.

## Usage

```rust
use fador_compress::{gzip_compress, inflate};

let body = b"<html>hello</html>".repeat(64);
let compressed = gzip_compress(&body);
assert_eq!(inflate(&compressed).unwrap(), body);
```

Use `inflate_raw` when the input is known to be a raw DEFLATE stream, because a
raw stream can coincidentally begin with bytes that look like a zlib header.

```rust
use fador_compress::{deflate_compress, inflate_raw};

let raw = deflate_compress(b"hello");
assert_eq!(inflate_raw(&raw).unwrap(), b"hello");
```

## Limits

`inflate`, `gzip_decompress` and `zlib_decompress` use a 512 MiB output limit.
Call the `*_with_limit` variants to bound untrusted input more tightly:

```rust
use fador_compress::{gzip_decompress_with_limit, gzip_compress};

let data = gzip_compress(&vec![0u8; 100_000]);
assert!(gzip_decompress_with_limit(&data, 1024).is_err());
```

## Not a streaming library

The encoder writes one block and the decoder returns one `Vec<u8>`. There is no
`Read`/`Write` integration, no dictionary support and no concatenated-gzip
member support. That is deliberate: the target is one-shot HTTP bodies, database
backup files and PNG IDAT chunks.

## License

MIT. See the repository [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
