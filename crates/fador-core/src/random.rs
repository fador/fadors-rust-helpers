//! OS-backed random bytes with an explicit fallible API.
//!
//! Session and CSRF tokens must not depend on an external crate. On Unix the
//! kernel entropy source is preferred; Windows uses `BCryptGenRandom`; the
//! final fallback mixes per-process state and is only used by [`random_bytes`]
//! for compatibility. Security-critical callers should use
//! [`try_random_bytes`] and treat an error as fatal.

use crate::crypto::{hex, sha256};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// An operating-system entropy source was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomError;

impl std::fmt::Display for RandomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operating-system random source is unavailable")
    }
}

impl std::error::Error for RandomError {}

/// Return `len` random bytes from the operating system, or an error.
///
/// This is the API security-sensitive callers should use. The error means the
/// process could not reach `/dev/urandom` or `BCryptGenRandom`; continuing with
/// a predictable token would be worse than failing the request.
pub fn try_random_bytes(len: usize) -> Result<Vec<u8>, RandomError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    os_random(len).ok_or(RandomError)
}

/// Return `len` random bytes, falling back to a mixed per-process seed.
///
/// The fallback is kept for callers that cannot handle an error. It is not a
/// substitute for [`try_random_bytes`] on a security boundary.
pub fn random_bytes(len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    if let Some(out) = os_random(len) {
        return out;
    }
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        let n = FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed) ^ counter;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        let mut input = Vec::with_capacity(48);
        input.extend_from_slice(&now.to_le_bytes());
        input.extend_from_slice(&pid.to_le_bytes());
        input.extend_from_slice(&n.to_le_bytes());
        input.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&sha256(&input));
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// Return a lowercase hexadecimal string of `bytes` random bytes.
pub fn random_hex(bytes: usize) -> String {
    hex(&random_bytes(bytes))
}

/// Return a fixed-size array of random bytes.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&random_bytes(N)[..N]);
    out
}

/// Return `len` bytes from the operating-system CSPRNG, panicking if it is
/// unavailable.
///
/// This is for security boundaries whose API cannot return an error (session
/// ids, CSRF tokens, password salts). Unlike [`random_bytes`] it never falls
/// back to a predictable seed: a token an attacker can guess is worse than a
/// failed request. This matches the behaviour of the standard library's
/// `RandomState` and the `getrandom` crate.
///
/// # Panics
///
/// Panics when the OS entropy source cannot be read.
pub fn secure_random_bytes(len: usize) -> Vec<u8> {
    match try_random_bytes(len) {
        Ok(bytes) => bytes,
        Err(error) => panic!("{error}; refusing to generate a predictable secret"),
    }
}

/// Lowercase hexadecimal of `bytes` bytes from [`secure_random_bytes`].
///
/// # Panics
///
/// Panics when the OS entropy source cannot be read.
pub fn secure_random_hex(bytes: usize) -> String {
    hex(&secure_random_bytes(bytes))
}

/// A fixed-size array from [`secure_random_bytes`].
///
/// # Panics
///
/// Panics when the OS entropy source cannot be read.
pub fn secure_random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&secure_random_bytes(N)[..N]);
    out
}

fn os_random(len: usize) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        static URANDOM: std::sync::OnceLock<fs::File> = std::sync::OnceLock::new();
        if URANDOM.get().is_none() {
            if let Ok(file) = fs::File::open("/dev/urandom") {
                let _ = URANDOM.set(file);
            }
        }
        let mut out = vec![0u8; len];
        if let Some(file) = URANDOM.get() {
            if (&*file).read_exact(&mut out).is_ok() {
                return Some(out);
            }
        }
        if let Ok(mut file) = fs::File::open("/dev/urandom") {
            if file.read_exact(&mut out).is_ok() {
                return Some(out);
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(out) = windows_random(len) {
            return Some(out);
        }
    }
    None
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_random(len: usize) -> Option<Vec<u8>> {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, length: u32, flags: u32)
            -> i32;
    }
    let length = u32::try_from(len).ok()?;
    let mut out = vec![0u8; len];
    // SAFETY: the buffer is valid for `length` bytes and the null algorithm
    // selects BCRYPT_USE_SYSTEM_PREFERRED_RNG, as documented by Windows.
    let status = unsafe { BCryptGenRandom(null_mut(), out.as_mut_ptr(), length, 2) };
    if status == 0 {
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_random_is_available_and_not_repeating() {
        let first = try_random_bytes(32).expect("OS random source");
        let second = try_random_bytes(32).expect("OS random source");
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        assert_ne!(first, second);
    }

    #[test]
    fn hex_and_array_have_the_requested_shape() {
        assert_eq!(random_hex(16).len(), 32);
        let array: [u8; 8] = random_array();
        assert_eq!(array.len(), 8);
        assert_eq!(secure_random_hex(16).len(), 32);
        assert_ne!(secure_random_hex(16), secure_random_hex(16));
        let array: [u8; 8] = secure_random_array();
        assert_eq!(array.len(), 8);
        assert!(secure_random_bytes(0).is_empty());
    }
}
