//! Bounded, dependency-free primitives shared by the fador servers.
//!
//! This crate deliberately has no knowledge of a database schema, HTTP or a
//! template dialect. It contains the parsers, checksums, path guards and small
//! utilities that the higher layers build on.
//!
//! Every parser is bounded: malformed input returns an error or `None` instead
//! of allocating without limit. The one platform-specific `unsafe` block is the
//! Windows CSPRNG FFI in [`random`]; everything else is safe Rust.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod cache;
pub mod crypto;
pub mod imageinfo;
pub mod json;
pub mod multipart;
pub mod path;
pub mod php;
pub mod random;
pub mod util;

#[cfg(test)]
pub(crate) use fador_testutil as testutil;

pub use cache::TimedCache;
pub use imageinfo::ImageInfo;
pub use json::Json;
pub use multipart::Part;
pub use random::RandomError;
