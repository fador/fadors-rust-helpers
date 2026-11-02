//! gzip/zlib/raw DEFLATE encoders using fixed-Huffman blocks.
//!
//! The encoder uses a bounded hash-chain LZ77 matcher. Fixed Huffman coding
//! keeps the encoder small (no dynamic code tables) while still shrinking
//! ordinary HTML, JavaScript, CSS, JSON and PNG IDAT data substantially. The
//! decoder in [`mod@crate::inflate`] is the test oracle.

use crate::checksum::{adler32, crc32};

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const MAX_DISTANCE: usize = 32_768;
const WINDOW_MASK: usize = MAX_DISTANCE - 1;
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN: usize = 32;

/// Compress `data` as a gzip member (RFC 1952).
///
/// The output has a zero modification time and no optional header fields, so
/// the same input always produces the same bytes. Inputs of 4 GiB or more are
/// rejected because the gzip ISIZE trailer is 32 bits.
pub fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let size = u32::try_from(data.len()).expect("gzip input must be smaller than 4 GiB");
    let mut out = Vec::with_capacity(data.len() / 3 + 64);
    // gzip header: magic, deflate, no flags, mtime 0, XFL 0, OS unknown.
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
    write_deflate(data, &mut out);
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out
}

/// Compress `data` as a zlib stream (RFC 1950).
///
/// This is the wrapper used by PNG IDAT chunks and by PHP's `gzcompress()`.
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 3 + 16);
    // CM=8, CINFO=7, FCHECK so that the 16-bit header is divisible by 31.
    out.extend_from_slice(&[0x78, 0x01]);
    write_deflate(data, &mut out);
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// Compress `data` as a raw DEFLATE stream (RFC 1951), with no wrapper.
///
/// This is what PHP's `gzdeflate()` produces.
pub fn deflate_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 3 + 16);
    write_deflate(data, &mut out);
    out
}

fn write_deflate(data: &[u8], out: &mut Vec<u8>) {
    let mut writer = BitWriter::new(out);
    // BFINAL=1, BTYPE=01 (fixed Huffman).
    writer.write_bits(1, 1);
    writer.write_bits(1, 2);
    compress_block(data, &mut writer);
    writer.write_literal(256);
    writer.flush();
}

fn compress_block(data: &[u8], writer: &mut BitWriter<'_>) {
    let mut head = vec![u32::MAX; HASH_SIZE];
    let mut previous = vec![u32::MAX; MAX_DISTANCE];
    let mut pos = 0usize;
    while pos < data.len() {
        let mut best_len = 0usize;
        let mut best_distance = 0usize;
        if pos + MIN_MATCH <= data.len() {
            let hash = hash3(data, pos);
            let mut candidate = head[hash];
            let mut links = 0usize;
            let limit = pos.saturating_sub(MAX_DISTANCE);
            let max_len = (data.len() - pos).min(MAX_MATCH);
            while candidate != u32::MAX && links < MAX_CHAIN {
                let cand = candidate as usize;
                if cand < limit || cand >= pos {
                    break;
                }
                if data[cand + best_len] == data[pos + best_len] {
                    let len = match_len(data, cand, pos, max_len);
                    if len > best_len {
                        best_len = len;
                        best_distance = pos - cand;
                        if len == max_len {
                            break;
                        }
                    }
                }
                candidate = previous[cand & WINDOW_MASK];
                links += 1;
            }
            previous[pos & WINDOW_MASK] = head[hash];
            head[hash] = pos as u32;
        }

        // A three-byte match that is far away costs more bits than three
        // literals.  Keep the short match only when its distance code is cheap.
        let worthwhile = best_len >= MIN_MATCH && !(best_len == MIN_MATCH && best_distance > 8_192);
        if worthwhile {
            writer.write_match(best_len, best_distance);
            for next in pos + 1..pos + best_len {
                if next + MIN_MATCH <= data.len() {
                    let hash = hash3(data, next);
                    previous[next & WINDOW_MASK] = head[hash];
                    head[hash] = next as u32;
                }
            }
            pos += best_len;
        } else {
            writer.write_literal(u32::from(data[pos]) as u16);
            pos += 1;
        }
    }
}

fn hash3(data: &[u8], pos: usize) -> usize {
    let value =
        (u32::from(data[pos]) << 16) | (u32::from(data[pos + 1]) << 8) | u32::from(data[pos + 2]);
    (value.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

fn match_len(data: &[u8], left: usize, right: usize, max: usize) -> usize {
    let mut len = 0usize;
    while len < max && data[left + len] == data[right + len] {
        len += 1;
    }
    len
}

struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    bits: u32,
    count: u8,
}

impl<'a> BitWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            out,
            bits: 0,
            count: 0,
        }
    }

    fn write_bits(&mut self, value: u32, count: u8) {
        if count == 0 {
            return;
        }
        let value = value & ((1u32 << count) - 1);
        self.bits |= value << self.count;
        self.count += count;
        while self.count >= 8 {
            self.out.push((self.bits & 0xff) as u8);
            self.bits >>= 8;
            self.count -= 8;
        }
    }

    /// Write a literal or length/end code.  The code is already bit-reversed.
    fn write_literal(&mut self, value: u16) {
        let (code, bits) = LITERAL_CODES[value as usize];
        self.write_bits(u32::from(code), bits);
    }

    fn write_match(&mut self, len: usize, distance: usize) {
        let (code, extra_bits, extra) = length_code(len);
        self.write_literal(code);
        self.write_bits(u32::from(extra), extra_bits);

        let (code, extra_bits, extra) = distance_code(distance);
        let (bits, count) = DISTANCE_CODES[code as usize];
        self.write_bits(u32::from(bits), count);
        self.write_bits(u32::from(extra), extra_bits);
    }

    fn flush(&mut self) {
        if self.count > 0 {
            self.out.push((self.bits & 0xff) as u8);
            self.bits = 0;
            self.count = 0;
        }
    }
}

fn length_code(len: usize) -> (u16, u8, u16) {
    let extra = |base: usize, _bits: u8| (len - base) as u16;
    match len {
        3..=10 => (257 + (len - 3) as u16, 0, 0),
        11..=12 => (265, 1, extra(11, 1)),
        13..=14 => (266, 1, extra(13, 1)),
        15..=16 => (267, 1, extra(15, 1)),
        17..=18 => (268, 1, extra(17, 1)),
        19..=22 => (269, 2, extra(19, 2)),
        23..=26 => (270, 2, extra(23, 2)),
        27..=30 => (271, 2, extra(27, 2)),
        31..=34 => (272, 2, extra(31, 2)),
        35..=42 => (273, 3, extra(35, 3)),
        43..=50 => (274, 3, extra(43, 3)),
        51..=58 => (275, 3, extra(51, 3)),
        59..=66 => (276, 3, extra(59, 3)),
        67..=82 => (277, 4, extra(67, 4)),
        83..=98 => (278, 4, extra(83, 4)),
        99..=114 => (279, 4, extra(99, 4)),
        115..=130 => (280, 4, extra(115, 4)),
        131..=162 => (281, 5, extra(131, 5)),
        163..=194 => (282, 5, extra(163, 5)),
        195..=226 => (283, 5, extra(195, 5)),
        227..=257 => (284, 5, extra(227, 5)),
        258 => (285, 0, 0),
        _ => (285, 0, 0),
    }
}

fn distance_code(distance: usize) -> (u8, u8, u16) {
    let extra = |base: usize, _bits: u8| (distance - base) as u16;
    match distance {
        1 => (0, 0, 0),
        2 => (1, 0, 0),
        3 => (2, 0, 0),
        4 => (3, 0, 0),
        5..=6 => (4, 1, extra(5, 1)),
        7..=8 => (5, 1, extra(7, 1)),
        9..=12 => (6, 2, extra(9, 2)),
        13..=16 => (7, 2, extra(13, 2)),
        17..=24 => (8, 3, extra(17, 3)),
        25..=32 => (9, 3, extra(25, 3)),
        33..=48 => (10, 4, extra(33, 4)),
        49..=64 => (11, 4, extra(49, 4)),
        65..=96 => (12, 5, extra(65, 5)),
        97..=128 => (13, 5, extra(97, 5)),
        129..=192 => (14, 6, extra(129, 6)),
        193..=256 => (15, 6, extra(193, 6)),
        257..=384 => (16, 7, extra(257, 7)),
        385..=512 => (17, 7, extra(385, 7)),
        513..=768 => (18, 8, extra(513, 8)),
        769..=1024 => (19, 8, extra(769, 8)),
        1025..=1536 => (20, 9, extra(1025, 9)),
        1537..=2048 => (21, 9, extra(1537, 9)),
        2049..=3072 => (22, 10, extra(2049, 10)),
        3073..=4096 => (23, 10, extra(3073, 10)),
        4097..=6144 => (24, 11, extra(4097, 11)),
        6145..=8192 => (25, 11, extra(6145, 11)),
        8193..=12288 => (26, 12, extra(8193, 12)),
        12289..=16384 => (27, 12, extra(12289, 12)),
        16385..=24576 => (28, 13, extra(16385, 13)),
        24577..=32768 => (29, 13, extra(24577, 13)),
        _ => (29, 13, 0),
    }
}

const fn reverse_bits(mut value: u16, count: u8) -> u16 {
    let mut out = 0u16;
    let mut index = 0u8;
    while index < count {
        out = (out << 1) | (value & 1);
        value >>= 1;
        index += 1;
    }
    out
}

const fn build_literal_codes() -> [(u16, u8); 288] {
    let mut table = [(0u16, 0u8); 288];
    let mut value = 0usize;
    while value < 288 {
        let (code, bits) = if value <= 143 {
            (0x30 + value as u16, 8u8)
        } else if value <= 255 {
            (0x190 + (value as u16 - 144), 9u8)
        } else if value <= 279 {
            (value as u16 - 256, 7u8)
        } else {
            (0xc0 + (value as u16 - 280), 8u8)
        };
        table[value] = (reverse_bits(code, bits), bits);
        value += 1;
    }
    table
}

const fn build_distance_codes() -> [(u16, u8); 30] {
    let mut table = [(0u16, 0u8); 30];
    let mut value = 0u8;
    while value < 30 {
        table[value as usize] = (reverse_bits(value as u16, 5), 5);
        value += 1;
    }
    table
}

static LITERAL_CODES: [(u16, u8); 288] = build_literal_codes();
static DISTANCE_CODES: [(u16, u8); 30] = build_distance_codes();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inflate::inflate;

    #[test]
    fn gzip_roundtrips_empty_and_text() {
        for input in [
            b"".as_slice(),
            b"hello",
            "Hyvää päivää, Naruto!".as_bytes(),
            &[0u8; 1024],
        ] {
            let compressed = gzip_compress(input);
            assert_eq!(compressed[..2], [0x1f, 0x8b]);
            let output = inflate(&compressed).unwrap();
            assert_eq!(output, input);
        }
    }

    #[test]
    fn gzip_roundtrips_deterministic_random_input() {
        let mut rng = crate::testutil::Rng::new(0xdef1_0001);
        for length in [1usize, 7, 64, 1024, 65_537] {
            let input = rng.bytes(length);
            let compressed = gzip_compress(&input);
            let output = inflate(&compressed).unwrap();
            assert_eq!(output, input, "length {length}");
        }
    }

    #[test]
    fn zlib_and_raw_deflate_roundtrip() {
        for input in [
            b"".as_slice(),
            b"hello",
            "Hyvää päivää, Naruto!".as_bytes(),
            &[0u8; 4096],
        ] {
            let zlib = zlib_compress(input);
            assert_eq!(zlib[..2], [0x78, 0x01]);
            assert_eq!(crate::inflate::zlib_decompress(&zlib).unwrap(), input);

            let raw = deflate_compress(input);
            assert_eq!(crate::inflate::inflate_raw(&raw).unwrap(), input);
        }
    }

    #[test]
    fn gzip_trailer_has_crc32_and_isize() {
        let input = b"hello hello hello";
        let compressed = gzip_compress(input);
        let trailer = &compressed[compressed.len() - 8..];
        assert_eq!(
            u32::from_le_bytes(trailer[..4].try_into().unwrap()),
            crate::checksum::crc32(input)
        );
        assert_eq!(
            u32::from_le_bytes(trailer[4..].try_into().unwrap()),
            input.len() as u32
        );
    }

    #[test]
    fn gzip_compresses_repetitive_markup() {
        let input =
            br#"<div class="post"><a href="./viewtopic.php?p=123#p123">reply</a></div>"#.repeat(64);
        let compressed = gzip_compress(&input);
        assert!(
            compressed.len() < input.len() / 3,
            "expected real compression, got {} from {}",
            compressed.len(),
            input.len()
        );
        assert_eq!(inflate(&compressed).unwrap(), input);
    }

    #[test]
    fn gzip_does_not_expand_incompressible_input_much() {
        let mut rng = crate::testutil::Rng::new(0xdef1_0002);
        let input = rng.bytes(4096);
        let compressed = gzip_compress(&input);
        assert!(
            compressed.len() <= input.len() + input.len() / 8 + 32,
            "unexpected expansion: {} from {}",
            compressed.len(),
            input.len()
        );
        assert_eq!(inflate(&compressed).unwrap(), input);
    }
}
