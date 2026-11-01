//! bcrypt verification and hashing.
//!
//! The Blowfish core is a direct implementation of the EksBlowfish construction
//! bcrypt is defined with; the P-array and S-boxes are the standard
//! public-domain Blowfish constants (the hexadecimal digits of pi). The cost is
//! bounded to [`MAX_VERIFY_COST`] before any work starts: bcrypt cost is
//! exponential, so a single damaged row with cost 31 would occupy a worker for
//! days.
//!
//! Only `$2y$`, `$2a$`, `$2b$` and `$2x$` are accepted. New hashes are written
//! as `$2y$` at [`DEFAULT_COST`].

use crate::constant_time_eq;
use crate::password::blowfish_consts::{P, S};
use fador_core::random::random_array;

const BCRYPT_B64: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The cost used when writing a new hash.
pub const DEFAULT_COST: u32 = 10;
/// The smallest accepted cost.
pub const MIN_COST: u32 = 4;
/// The highest cost accepted when verifying.
pub const MAX_VERIFY_COST: u32 = 16;
/// The longest password prefix bcrypt reads, including the NUL terminator.
pub const MAX_KEY_BYTES: usize = 72;

/// Hash a password with the default cost and a random salt.
pub fn hash(password: &str) -> String {
    hash_with_cost(password, DEFAULT_COST)
}

/// Hash a password with an explicit cost, clamped to
/// [`MIN_COST`]..=[`MAX_VERIFY_COST`].
pub fn hash_with_cost(password: &str, cost: u32) -> String {
    hash_with_salt(
        password,
        cost.clamp(MIN_COST, MAX_VERIFY_COST),
        random_array::<16>(),
    )
}

/// Hash a password with an explicit cost and salt.
pub fn hash_with_salt(password: &str, cost: u32, salt: [u8; 16]) -> String {
    let material = key_material(password);
    let output = bcrypt(cost, salt, &material);
    format!(
        "$2y${:02}${}{}",
        cost,
        encode_base64(&salt),
        encode_base64(&output[..23])
    )
}

/// Verify a password against a bcrypt hash.
pub fn verify(password: &str, hash: &str) -> bool {
    let Some(parts) = split_hash(hash) else {
        return false;
    };
    let Some(salt) = decode_base64(parts.salt, 16) else {
        return false;
    };
    let Some(expected) = decode_base64(parts.hash, 23) else {
        return false;
    };
    let Ok(salt) = <[u8; 16]>::try_from(salt.as_slice()) else {
        return false;
    };
    let output = bcrypt(parts.cost, salt, &key_material(password));
    constant_time_eq(&output[..23], &expected)
}

/// The cost of a bcrypt hash, if it parses and is inside the accepted range.
pub fn parse_cost(hash: &str) -> Option<u32> {
    let mut parts = hash.split('$').filter(|part| !part.is_empty());
    let version = parts.next()?;
    if !matches!(version, "2a" | "2b" | "2y" | "2x") {
        return None;
    }
    let cost: u32 = parts.next()?.parse().ok()?;
    (MIN_COST..=MAX_VERIFY_COST).contains(&cost).then_some(cost)
}

/// Whether a hash is weaker than `min_cost` or written with a legacy version
/// marker.
pub fn needs_rehash(hash: &str, min_cost: u32) -> bool {
    match parse_cost(hash) {
        Some(cost) => cost < min_cost || !hash.starts_with("$2y$"),
        None => true,
    }
}

fn key_material(password: &str) -> Vec<u8> {
    let mut material = password.as_bytes().to_vec();
    material.push(0);
    material.truncate(MAX_KEY_BYTES);
    material
}

/// Parse a bcrypt setting (`<cost>$<22-character salt>`), as used by the
/// chained combined-hash format.
pub(crate) fn parse_setting(setting: &str) -> Option<(u32, [u8; 16])> {
    let (cost, salt) = setting.split_once('$')?;
    let cost: u32 = cost.parse().ok()?;
    if !(MIN_COST..=MAX_VERIFY_COST).contains(&cost) || salt.len() != 22 {
        return None;
    }
    let decoded = decode_base64(salt, 16)?;
    Some((cost, decoded.try_into().ok()?))
}

struct Parts<'a> {
    cost: u32,
    salt: &'a str,
    hash: &'a str,
}

fn split_hash(hash: &str) -> Option<Parts<'_>> {
    let mut parts = hash.split('$').filter(|part| !part.is_empty());
    let version = parts.next()?;
    if !matches!(version, "2a" | "2b" | "2y" | "2x") {
        return None;
    }
    let cost: u32 = parts.next()?.parse().ok()?;
    if !(MIN_COST..=MAX_VERIFY_COST).contains(&cost) {
        return None;
    }
    let payload = parts.next()?;
    if parts.next().is_some() || payload.len() != 53 {
        return None;
    }
    // bcrypt's salt and digest are ASCII. Checking before slicing also keeps
    // `&payload[..22]` on a character boundary when a hostile row contains a
    // multi-byte character at that offset.
    if !payload.is_ascii() {
        return None;
    }
    Some(Parts {
        cost,
        salt: &payload[..22],
        hash: &payload[22..],
    })
}

fn encode_base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut index = 0usize;
    while index < data.len() {
        let chunk_len = (data.len() - index).min(3);
        let b0 = data[index] as u32;
        let b1 = *data.get(index + 1).unwrap_or(&0) as u32;
        let b2 = *data.get(index + 2).unwrap_or(&0) as u32;
        let value = (b0 << 16) | (b1 << 8) | b2;
        out.push(BCRYPT_B64[((value >> 18) & 63) as usize] as char);
        out.push(BCRYPT_B64[((value >> 12) & 63) as usize] as char);
        if chunk_len > 1 {
            out.push(BCRYPT_B64[((value >> 6) & 63) as usize] as char);
        }
        if chunk_len > 2 {
            out.push(BCRYPT_B64[(value & 63) as usize] as char);
        }
        index += chunk_len;
    }
    out
}

fn decode_base64(input: &str, expected_len: usize) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(expected_len);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let value = match byte {
            b'.' => 0,
            b'/' => 1,
            b'A'..=b'Z' => byte - b'A' + 2,
            b'a'..=b'z' => byte - b'a' + 28,
            b'0'..=b'9' => byte - b'0' + 54,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    (output.len() == expected_len).then_some(output)
}

struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Blowfish {
    fn new() -> Self {
        Self { p: P, s: S }
    }

    fn next_u32_wrap(buffer: &[u8], offset: &mut usize) -> u32 {
        let mut value = 0u32;
        for _ in 0..4 {
            if *offset >= buffer.len() {
                *offset = 0;
            }
            value = (value << 8) | buffer[*offset] as u32;
            *offset += 1;
        }
        value
    }

    fn expand_key(&mut self, key: &[u8]) {
        let mut position = 0usize;
        for item in &mut self.p {
            *item ^= Self::next_u32_wrap(key, &mut position);
        }
        let mut left = 0u32;
        let mut right = 0u32;
        for index in 0..9 {
            let (next_left, next_right) = self.encrypt(left, right);
            left = next_left;
            right = next_right;
            self.p[2 * index] = left;
            self.p[2 * index + 1] = right;
        }
        for block in 0..4 {
            for index in 0..128 {
                let (next_left, next_right) = self.encrypt(left, right);
                left = next_left;
                right = next_right;
                self.s[block][2 * index] = left;
                self.s[block][2 * index + 1] = right;
            }
        }
    }

    fn salted_expand_key(&mut self, salt: &[u8], key: &[u8]) {
        let mut key_pos = 0usize;
        for item in &mut self.p {
            *item ^= Self::next_u32_wrap(key, &mut key_pos);
        }
        let mut left = 0u32;
        let mut right = 0u32;
        let mut salt_pos = 0usize;
        for index in 0..9 {
            left ^= Self::next_u32_wrap(salt, &mut salt_pos);
            right ^= Self::next_u32_wrap(salt, &mut salt_pos);
            let (next_left, next_right) = self.encrypt(left, right);
            left = next_left;
            right = next_right;
            self.p[2 * index] = left;
            self.p[2 * index + 1] = right;
        }
        for block in 0..4 {
            for index in 0..64 {
                left ^= Self::next_u32_wrap(salt, &mut salt_pos);
                right ^= Self::next_u32_wrap(salt, &mut salt_pos);
                let (next_left, next_right) = self.encrypt(left, right);
                left = next_left;
                right = next_right;
                self.s[block][4 * index] = left;
                self.s[block][4 * index + 1] = right;

                left ^= Self::next_u32_wrap(salt, &mut salt_pos);
                right ^= Self::next_u32_wrap(salt, &mut salt_pos);
                let (next_left, next_right) = self.encrypt(left, right);
                left = next_left;
                right = next_right;
                self.s[block][4 * index + 2] = left;
                self.s[block][4 * index + 3] = right;
            }
        }
    }

    fn round(&self, value: u32) -> u32 {
        let a = self.s[0][(value >> 24) as usize];
        let b = self.s[1][((value >> 16) & 0xff) as usize];
        let c = self.s[2][((value >> 8) & 0xff) as usize];
        let d = self.s[3][(value & 0xff) as usize];
        (a.wrapping_add(b) ^ c).wrapping_add(d)
    }

    fn encrypt(&self, mut left: u32, mut right: u32) -> (u32, u32) {
        for index in 0..8 {
            left ^= self.p[2 * index];
            right ^= self.round(left);
            right ^= self.p[2 * index + 1];
            left ^= self.round(right);
        }
        left ^= self.p[16];
        right ^= self.p[17];
        (right, left)
    }
}

fn bcrypt(cost: u32, salt: [u8; 16], password: &[u8]) -> [u8; 24] {
    let cost = cost.min(MAX_VERIFY_COST);
    let mut state = Blowfish::new();
    state.salted_expand_key(&salt, password);
    for _ in 0..(1u32 << cost) {
        state.expand_key(password);
        state.expand_key(&salt);
    }
    let mut text = [
        0x4f727068u32,
        0x65616e42,
        0x65686f6c,
        0x64657253,
        0x63727944,
        0x6f756274,
    ];
    let mut output = [0u8; 24];
    for index in 0..3 {
        let offset = index * 2;
        for _ in 0..64 {
            let (left, right) = state.encrypt(text[offset], text[offset + 1]);
            text[offset] = left;
            text[offset + 1] = right;
        }
        output[offset * 4..offset * 4 + 4].copy_from_slice(&text[offset].to_be_bytes());
        output[(offset + 1) * 4..(offset + 1) * 4 + 4]
            .copy_from_slice(&text[offset + 1].to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &str = "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye";

    #[test]
    fn verifies_a_known_vector() {
        assert!(verify("secret", VECTOR));
        assert!(!verify("wrong", VECTOR));
        assert_eq!(parse_cost(VECTOR), Some(10));
        assert!(!needs_rehash(VECTOR, 10));
    }

    #[test]
    fn base64_roundtrips_known_bcrypt_parts() {
        let salt = "u/a4ZTIgnxqS1ATR8n2wNu";
        let hash = "nuxzZ5uhjnw9GmxNqStOompVzhBJwye";
        let salt_bytes = decode_base64(salt, 16).unwrap();
        let hash_bytes = decode_base64(hash, 23).unwrap();
        assert_eq!(encode_base64(&salt_bytes), salt);
        assert_eq!(encode_base64(&hash_bytes), hash);
    }

    #[test]
    fn hashes_and_verifies_roundtrip() {
        let hash = hash("Hyvää päivää");
        assert!(hash.starts_with("$2y$10$"));
        assert!(verify("Hyvää päivää", &hash));
        assert!(!verify("Hyvää päivää!", &hash));

        let cheap = hash_with_cost("secret", 4);
        assert!(cheap.starts_with("$2y$04$"));
        assert!(verify("secret", &cheap));
        assert_eq!(parse_cost(&cheap), Some(4));
        assert!(needs_rehash(&cheap, 10));
    }

    #[test]
    fn accepts_every_legacy_version_marker() {
        let salt = decode_base64("u/a4ZTIgnxqS1ATR8n2wNu", 16).unwrap();
        let salt: [u8; 16] = salt.try_into().unwrap();
        let payload = hash_with_salt("secret", 4, salt);
        for marker in ["$2a$", "$2b$", "$2x$"] {
            let legacy = payload.replacen("$2y$", marker, 1);
            assert!(verify("secret", &legacy), "rejected {marker}");
            assert!(needs_rehash(&legacy, 4));
        }
    }

    #[test]
    fn truncates_at_the_bcrypt_key_limit() {
        let long = "a".repeat(MAX_KEY_BYTES);
        let hash = hash_with_cost(&long, 4);
        assert!(verify(&long, &hash));
        // Anything after the first 72 key bytes is not read.
        let mut longer = long.clone();
        longer.push('b');
        assert!(verify(&longer, &hash));
        // A difference inside the window is still significant.
        let mut different = long[..MAX_KEY_BYTES - 1].to_string();
        different.push('b');
        assert!(!verify(&different, &hash));
    }

    #[test]
    fn rejects_malformed_hashes() {
        for hash in [
            "",
            "$2y$3$abc",
            "$2y$10$short",
            "$2y$17$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye",
            "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye-extra",
            "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwy\0",
            "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwy中",
            "nonsense",
        ] {
            assert!(!verify("x", hash), "accepted {hash:?}");
        }
        assert_eq!(parse_cost("$2y$31$abc"), None);
        assert_eq!(parse_cost("$2y$03$abc"), None);
    }
}
