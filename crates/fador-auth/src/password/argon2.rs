//! Argon2 password verification.
//!
//! PHP's `password_hash(PASSWORD_ARGON2ID)` produces a PHC string
//! (`$argon2id$v=19$m=...,t=...,p=...$salt$tag`). A board migrated from PHP can
//! contain those rows, so this module verifies them. New passwords are written
//! with bcrypt or PBKDF2, never Argon2, because writing an Argon2 hash needs a
//! memory-hard encoder and the verifier is all this crate needs.
//!
//! The implementation follows RFC 9106. Every parameter is bounded before any
//! memory is allocated, and the product `memory × time` is bounded as well, so a
//! hostile database row cannot exhaust the process.

use crate::constant_time_eq;
use fador_core::crypto::{base64_decode, blake2b};

const VERSION: u32 = 0x13;
const SYNC_POINTS: usize = 4;
const BLOCK_WORDS: usize = 128;
const ADDRESSES_IN_BLOCK: usize = 128;

/// Largest accepted memory size in KiB (256 MiB).
pub const MAX_MEMORY_KIB: u32 = 262_144;
/// Largest accepted time cost.
pub const MAX_TIME_COST: u32 = 16;
/// Largest accepted parallelism.
pub const MAX_PARALLELISM: u32 = 16;
/// Largest accepted `memory × time` product.
///
/// Both parameters are bounded on their own, but their product is the real
/// work: 256 MiB × 16 passes would keep a login worker busy for minutes. The
/// PHP default (64 MiB × 4) and the RFC vector stay below this ceiling.
pub const MAX_WORK: u64 = 1_048_576;

type Block = [u64; BLOCK_WORDS];

/// The Argon2 variant named by a PHC string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Kind {
    /// Data-dependent addressing.
    D,
    /// Data-independent addressing.
    I,
    /// Hybrid addressing, the recommended variant.
    Id,
}

impl Argon2Kind {
    fn code(self) -> u32 {
        match self {
            Self::D => 0,
            Self::I => 1,
            Self::Id => 2,
        }
    }

    /// The PHC identifier (`argon2d`, `argon2i`, `argon2id`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::D => "argon2d",
            Self::I => "argon2i",
            Self::Id => "argon2id",
        }
    }
}

/// The bounded parameters of a parsed PHC string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// The variant.
    pub kind: Argon2Kind,
    /// Memory size in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub time_cost: u32,
    /// Number of lanes.
    pub parallelism: u32,
    /// Digest length in bytes.
    pub tag_len: usize,
}

struct ParsedHash {
    kind: Argon2Kind,
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    salt: Vec<u8>,
    tag: Vec<u8>,
}

/// Verify a password against a PHC-formatted Argon2 hash.
pub fn verify(password: &str, hash: &str) -> bool {
    if password.len() > 4_096 || hash.len() > 1_024 {
        return false;
    }
    let Some(parsed) = parse(hash) else {
        return false;
    };
    let tag = argon2(
        password.as_bytes(),
        &parsed.salt,
        &[],
        &[],
        parsed.memory_kib,
        parsed.time_cost,
        parsed.parallelism,
        parsed.kind,
        parsed.tag.len(),
    );
    constant_time_eq(&tag, &parsed.tag)
}

/// The bounded parameters of a PHC string, without its salt and digest.
pub fn params(hash: &str) -> Option<Argon2Params> {
    if hash.len() > 1_024 {
        return None;
    }
    let parsed = parse(hash)?;
    Some(Argon2Params {
        kind: parsed.kind,
        memory_kib: parsed.memory_kib,
        time_cost: parsed.time_cost,
        parallelism: parsed.parallelism,
        tag_len: parsed.tag.len(),
    })
}

fn parse(hash: &str) -> Option<ParsedHash> {
    let mut parts = hash.split('$');
    if !parts.next()?.is_empty() {
        return None;
    }
    let kind = match parts.next()? {
        "argon2d" => Argon2Kind::D,
        "argon2i" => Argon2Kind::I,
        "argon2id" => Argon2Kind::Id,
        _ => return None,
    };
    let version = parts.next()?.strip_prefix("v=")?.parse::<u32>().ok()?;
    if version != VERSION {
        return None;
    }
    let mut memory_kib = None;
    let mut time_cost = None;
    let mut parallelism = None;
    for pair in parts.next()?.split(',') {
        let (key, value) = pair.split_once('=')?;
        let value = value.parse::<u32>().ok()?;
        match key {
            "m" => memory_kib = Some(value),
            "t" => time_cost = Some(value),
            "p" => parallelism = Some(value),
            _ => return None,
        }
    }
    let salt = base64_decode(parts.next()?)?;
    let tag = base64_decode(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    let memory_kib = memory_kib?;
    let time_cost = time_cost?;
    let parallelism = parallelism?;
    if !(8..=MAX_MEMORY_KIB).contains(&memory_kib)
        || !(1..=MAX_TIME_COST).contains(&time_cost)
        || !(1..=MAX_PARALLELISM).contains(&parallelism)
        || memory_kib < 8 * parallelism
        || u64::from(memory_kib) * u64::from(time_cost) > MAX_WORK
        || !(8..=64).contains(&salt.len())
        || !(4..=64).contains(&tag.len())
    {
        return None;
    }
    Some(ParsedHash {
        kind,
        memory_kib,
        time_cost,
        parallelism,
        salt,
        tag,
    })
}

#[allow(clippy::too_many_arguments)]
fn argon2(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated: &[u8],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    kind: Argon2Kind,
    out_len: usize,
) -> Vec<u8> {
    let lanes = parallelism as usize;
    let memory_blocks = (memory_kib as usize / (SYNC_POINTS * lanes)) * SYNC_POINTS * lanes;
    let lane_length = memory_blocks / lanes;
    let segment_length = lane_length / SYNC_POINTS;
    if segment_length < 2 || lane_length < 8 {
        return Vec::new();
    }

    let mut initial = Vec::with_capacity(128);
    push_u32(&mut initial, parallelism);
    push_u32(&mut initial, out_len as u32);
    push_u32(&mut initial, memory_kib);
    push_u32(&mut initial, time_cost);
    push_u32(&mut initial, VERSION);
    push_u32(&mut initial, kind.code());
    push_bytes(&mut initial, password);
    push_bytes(&mut initial, salt);
    push_bytes(&mut initial, secret);
    push_bytes(&mut initial, associated);
    let h0 = blake2b(&initial, 64);

    let mut memory = vec![[0u64; BLOCK_WORDS]; memory_blocks];
    for lane in 0..lanes {
        let mut input = Vec::with_capacity(72);
        input.extend_from_slice(&h0);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&(lane as u32).to_le_bytes());
        memory[lane * lane_length] = block_from_bytes(&h_prime(&input, 1024));
        input[64..68].copy_from_slice(&1u32.to_le_bytes());
        memory[lane * lane_length + 1] = block_from_bytes(&h_prime(&input, 1024));
    }

    for pass in 0..time_cost as usize {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                let data_independent =
                    kind == Argon2Kind::I || (kind == Argon2Kind::Id && pass == 0 && slice < 2);
                let mut address_block = [0u64; BLOCK_WORDS];
                let mut input_block = [0u64; BLOCK_WORDS];
                if data_independent {
                    input_block[0] = pass as u64;
                    input_block[1] = lane as u64;
                    input_block[2] = slice as u64;
                    input_block[3] = memory_blocks as u64;
                    input_block[4] = time_cost as u64;
                    input_block[5] = kind.code() as u64;
                }
                let starting_index = if pass == 0 && slice == 0 { 2 } else { 0 };
                if data_independent && pass == 0 && slice == 0 {
                    next_addresses(&mut address_block, &mut input_block);
                }
                for index in starting_index..segment_length {
                    let current = lane * lane_length + slice * segment_length + index;
                    let previous = if current.is_multiple_of(lane_length) {
                        current + lane_length - 1
                    } else {
                        current - 1
                    };
                    let pseudo_random = if data_independent {
                        if index % ADDRESSES_IN_BLOCK == 0 {
                            next_addresses(&mut address_block, &mut input_block);
                        }
                        address_block[index % ADDRESSES_IN_BLOCK]
                    } else {
                        memory[previous][0]
                    };
                    let mut reference_lane = ((pseudo_random >> 32) as usize) % lanes;
                    if pass == 0 && slice == 0 {
                        reference_lane = lane;
                    }
                    let reference_index = index_alpha(
                        pass,
                        slice,
                        index,
                        reference_lane == lane,
                        pseudo_random as u32,
                        lane_length,
                        segment_length,
                    );
                    let reference = memory[reference_lane * lane_length + reference_index];
                    let previous_block = memory[previous];
                    let old = if pass > 0 {
                        Some(memory[current])
                    } else {
                        None
                    };
                    memory[current] = fill_block(&previous_block, &reference, old.as_ref());
                }
            }
        }
    }

    let mut final_block = memory[lane_length - 1];
    for lane in 1..lanes {
        let last = memory[lane * lane_length + lane_length - 1];
        for (target, value) in final_block.iter_mut().zip(last) {
            *target ^= value;
        }
    }
    h_prime(&block_to_bytes(&final_block), out_len)
}

fn push_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes(buffer: &mut Vec<u8>, value: &[u8]) {
    push_u32(buffer, value.len() as u32);
    buffer.extend_from_slice(value);
}

fn next_addresses(address: &mut Block, input: &mut Block) {
    input[6] = input[6].wrapping_add(1);
    let zero = [0u64; BLOCK_WORDS];
    let first = fill_block(&zero, input, None);
    *address = fill_block(&zero, &first, None);
}

#[allow(clippy::too_many_arguments)]
fn index_alpha(
    pass: usize,
    slice: usize,
    index: usize,
    same_lane: bool,
    pseudo_random: u32,
    lane_length: usize,
    segment_length: usize,
) -> usize {
    let reference_area_size: i64 = if pass == 0 {
        if slice == 0 {
            index as i64 - 1
        } else if same_lane {
            (slice * segment_length + index) as i64 - 1
        } else {
            (slice * segment_length) as i64 + if index == 0 { -1 } else { 0 }
        }
    } else if same_lane {
        (lane_length - segment_length + index) as i64 - 1
    } else {
        (lane_length - segment_length) as i64 + if index == 0 { -1 } else { 0 }
    };
    if reference_area_size <= 0 {
        return 0;
    }
    let mut relative = pseudo_random as u64;
    relative = (relative * relative) >> 32;
    let relative = reference_area_size as u64 - 1 - ((reference_area_size as u64 * relative) >> 32);
    let start = if pass != 0 && slice != SYNC_POINTS - 1 {
        (slice + 1) * segment_length
    } else {
        0
    };
    (start + relative as usize) % lane_length
}

fn fill_block(previous: &Block, reference: &Block, old: Option<&Block>) -> Block {
    let mut block = [0u64; BLOCK_WORDS];
    for index in 0..BLOCK_WORDS {
        block[index] = previous[index] ^ reference[index];
    }
    let mut original = block;
    if let Some(old) = old {
        for (target, value) in original.iter_mut().zip(old) {
            *target ^= value;
        }
    }
    for row in 0..8 {
        let base = row * 16;
        round_at(
            &mut block,
            [
                base,
                base + 1,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7,
                base + 8,
                base + 9,
                base + 10,
                base + 11,
                base + 12,
                base + 13,
                base + 14,
                base + 15,
            ],
        );
    }
    for column in 0..8 {
        let base = 2 * column;
        let mut indices = [0usize; 16];
        for row in 0..8 {
            indices[row * 2] = base + row * 16;
            indices[row * 2 + 1] = base + row * 16 + 1;
        }
        round_at(&mut block, indices);
    }
    for (target, value) in block.iter_mut().zip(original) {
        *target ^= value;
    }
    block
}

fn round_at(block: &mut Block, indices: [usize; 16]) {
    let mut v = [0u64; 16];
    for (index, source) in indices.iter().enumerate() {
        v[index] = block[*source];
    }
    g(&mut v, 0, 4, 8, 12);
    g(&mut v, 1, 5, 9, 13);
    g(&mut v, 2, 6, 10, 14);
    g(&mut v, 3, 7, 11, 15);
    g(&mut v, 0, 5, 10, 15);
    g(&mut v, 1, 6, 11, 12);
    g(&mut v, 2, 7, 8, 13);
    g(&mut v, 3, 4, 9, 14);
    for (index, target) in indices.iter().enumerate() {
        block[*target] = v[index];
    }
}

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blamka(x: u64, y: u64) -> u64 {
    let low = (x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff);
    x.wrapping_add(y).wrapping_add(low.wrapping_mul(2))
}

fn h_prime(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(input.len() + 4);
    push_u32(&mut prefixed, out_len as u32);
    prefixed.extend_from_slice(input);
    if out_len <= 64 {
        return blake2b(&prefixed, out_len);
    }
    let rounds = out_len.div_ceil(32) - 2;
    let mut value = blake2b(&prefixed, 64);
    let mut out = Vec::with_capacity(out_len);
    out.extend_from_slice(&value[..32]);
    for _ in 1..rounds {
        value = blake2b(&value, 64);
        out.extend_from_slice(&value[..32]);
    }
    let last_len = out_len - 32 * rounds;
    out.extend_from_slice(&blake2b(&value, last_len));
    out
}

fn block_from_bytes(bytes: &[u8]) -> Block {
    let mut block = [0u64; BLOCK_WORDS];
    for (index, word) in block.iter_mut().enumerate() {
        let start = index * 8;
        *word = u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap_or_default());
    }
    block
}

fn block_to_bytes(block: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    for word in block {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fador_core::crypto::hex;

    const PHC: &str =
        "$argon2id$v=19$m=32,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE";

    #[test]
    fn matches_the_rfc9106_vector() {
        let password = [1u8; 32];
        let salt = [2u8; 16];
        let secret = [3u8; 8];
        let associated = [4u8; 12];
        let tag = argon2(
            &password,
            &salt,
            &secret,
            &associated,
            32,
            3,
            4,
            Argon2Kind::Id,
            32,
        );
        assert_eq!(
            hex(&tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn verifies_phc_strings() {
        assert!(verify("secret", PHC));
        assert!(!verify("wrong", PHC));
        assert!(verify(
            "password",
            "$argon2id$v=19$m=1024,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$+7dJuHPiovHaVjBbvoCRk/LMMK9tLvX6CdadmqChTXs"
        ));
        // A tag produced by one variant does not verify under another.
        assert!(!verify(
            "secret",
            "$argon2i$v=19$m=32,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE"
        ));
    }

    #[test]
    fn reports_bounded_parameters() {
        let parsed = params(PHC).unwrap();
        assert_eq!(parsed.kind, Argon2Kind::Id);
        assert_eq!(parsed.memory_kib, 32);
        assert_eq!(parsed.time_cost, 3);
        assert_eq!(parsed.parallelism, 4);
        assert_eq!(parsed.tag_len, 32);
        assert_eq!(parsed.kind.as_str(), "argon2id");
        assert_eq!(params(PHC).unwrap().memory_kib, 32);
    }

    #[test]
    fn rejects_malformed_or_oversized_hashes() {
        for hash in [
            "",
            "not-a-hash",
            "$argon2id$v=16$m=32,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE",
            "$argon2id$v=19$m=999999999,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE",
            "$argon2id$v=19$m=32,t=3,p=0$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE",
            "$argon2id$v=19$m=32,t=3,p=4$bad$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE",
            "$argon2id$v=19$m=262144,t=16,p=1$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE",
            "$argon2id$v=19$m=32,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE$extra",
            "$argon2id$v=19$m=32,t=3$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE",
            "$argon2id$v=19$m=32,t=3,p=4,x=1$c29tZXNhbHQxMjM0NTY3OA$bJaML8IJ8L4VjPwqhqG4vsyzyi0t+RLt+xvumLzLuJE",
        ] {
            assert!(!verify("secret", hash), "{hash}");
            assert!(params(hash).is_none(), "{hash}");
        }
        assert!(!verify("secret", &"$argon2id$v=19$".repeat(100)));
    }

    #[test]
    #[ignore = "64 MiB Argon2id is intentionally slow"]
    fn verifies_php_argon2id_64m() {
        assert!(verify(
            "secret",
            "$argon2id$v=19$m=65536,t=4,p=2$MDEyMzQ1Njc4OWFiY2RlZg$3jcZPNqt9+GKqnvGVGshKlkBzqUH6HY1mDtdFKa0Y4Y"
        ));
    }
}
