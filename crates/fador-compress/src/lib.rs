//! A small, dependency-free gzip, zlib and DEFLATE codec.
//!
//! The encoder writes one final fixed-Huffman DEFLATE block using a bounded
//! hash-chain LZ77 matcher. The decoder is strict and bounded: it verifies the
//! gzip CRC32/ISIZE and zlib Adler-32 trailers, rejects trailing bytes, and
//! never allocates more than the caller's output limit.
//!
//! The codec is deliberately not a general-purpose streaming replacement for
//! `flate2` or `zlib`. It is optimised for the small, one-shot bodies a web
//! server produces: HTML, CSS, JavaScript, JSON, XML and PNG IDAT data.
//!
//! ```
//! use fador_compress::{gzip_compress, inflate};
//!
//! let body = b"<html>hello</html>".repeat(64);
//! let compressed = gzip_compress(&body);
//! assert_eq!(inflate(&compressed).unwrap(), body);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod checksum;
pub mod deflate;
pub mod inflate;

#[cfg(test)]
mod testutil;

pub use checksum::{adler32, crc32};
pub use deflate::{deflate_compress, gzip_compress, zlib_compress};
pub use inflate::{
    gzip_decompress, gzip_decompress_with_limit, inflate, inflate_gzip_or_raw,
    inflate_gzip_or_raw_with_limit, inflate_raw, inflate_raw_with_limit, inflate_with_limit,
    zlib_decompress, zlib_decompress_with_limit, Error, DEFAULT_MAX_OUTPUT,
};
