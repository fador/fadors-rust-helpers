//! A strict, bounded DEFLATE, gzip and zlib decoder.
//!
//! The decoder implements RFC 1951 (DEFLATE), RFC 1952 (gzip) and RFC 1950
//! (zlib). It verifies the gzip CRC32/ISIZE and zlib Adler-32 trailers and
//! rejects trailing bytes, so a truncated or corrupted stream is reported
//! instead of silently accepted.
//!
//! [`inflate`] auto-detects the wrapper. Use [`inflate_raw`] when the input is
//! known to be a raw DEFLATE stream, because a raw stream can coincidentally
//! begin with bytes that look like a valid zlib header.

use std::fmt;

use crate::checksum::{adler32, crc32};

/// Default upper bound for one decompressed output.
///
/// The limit is deliberately generous because the same decoder is used for
/// database backups. Callers that decompress untrusted input should pass a
/// smaller value to [`inflate_with_limit`].
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// A decoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input ended before the stream was complete.
    Truncated,
    /// The wrapper header is malformed.
    InvalidHeader(&'static str),
    /// A DEFLATE block header or stored-block length is invalid.
    InvalidBlock(&'static str),
    /// A Huffman code or code-length sequence is invalid.
    InvalidCode(&'static str),
    /// The decoded output would exceed the configured limit.
    OutputLimit,
    /// A gzip CRC32/ISIZE or zlib Adler-32 check failed.
    Checksum(&'static str),
    /// Bytes remain after the wrapper trailer.
    TrailingData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated compressed stream"),
            Self::InvalidHeader(reason) => write!(f, "invalid compressed header: {reason}"),
            Self::InvalidBlock(reason) => write!(f, "invalid DEFLATE block: {reason}"),
            Self::InvalidCode(reason) => write!(f, "invalid DEFLATE code: {reason}"),
            Self::OutputLimit => f.write_str("decompressed output exceeds the safety limit"),
            Self::Checksum(reason) => write!(f, "checksum mismatch: {reason}"),
            Self::TrailingData => f.write_str("trailing bytes after the compressed stream"),
        }
    }
}

impl std::error::Error for Error {}

/// Decompress a gzip, zlib or raw DEFLATE stream with the default limit.
pub fn inflate(data: &[u8]) -> Result<Vec<u8>, Error> {
    inflate_with_limit(data, DEFAULT_MAX_OUTPUT)
}

/// Decompress a gzip, zlib or raw DEFLATE stream with an explicit output limit.
///
/// A valid gzip magic or zlib header selects the corresponding strict wrapper;
/// anything else is treated as raw DEFLATE. The wrapper trailers are verified.
pub fn inflate_with_limit(data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        gzip_decompress_with_limit(data, max_output)
    } else if looks_like_zlib(data) {
        zlib_decompress_with_limit(data, max_output)
    } else {
        inflate_raw_with_limit(data, max_output)
    }
}

/// Decompress a gzip member or, when the gzip magic is absent, a raw DEFLATE
/// stream with the default limit.
///
/// This is the MediaWiki `old_flags` shape: the row is either gzip-wrapped or
/// raw DEFLATE, never zlib-wrapped. Use [`inflate`] when a zlib wrapper is also
/// possible.
pub fn inflate_gzip_or_raw(data: &[u8]) -> Result<Vec<u8>, Error> {
    inflate_gzip_or_raw_with_limit(data, DEFAULT_MAX_OUTPUT)
}

/// Decompress a gzip member or a raw DEFLATE stream with an explicit limit.
pub fn inflate_gzip_or_raw_with_limit(data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        gzip_decompress_with_limit(data, max_output)
    } else {
        inflate_raw_with_limit(data, max_output)
    }
}

/// Decompress a raw DEFLATE stream with the default limit.
pub fn inflate_raw(data: &[u8]) -> Result<Vec<u8>, Error> {
    inflate_raw_with_limit(data, DEFAULT_MAX_OUTPUT)
}

/// Decompress a raw DEFLATE stream with an explicit output limit.
pub fn inflate_raw_with_limit(data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let (out, consumed) = inflate_into(data, max_output)?;
    if consumed != data.len() {
        return Err(Error::TrailingData);
    }
    Ok(out)
}

/// Decompress a single gzip member with the default limit.
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    gzip_decompress_with_limit(data, DEFAULT_MAX_OUTPUT)
}

/// Decompress a single gzip member with an explicit output limit.
///
/// Concatenated gzip members are not supported; trailing bytes are rejected.
pub fn gzip_decompress_with_limit(data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if data.len() < 18 {
        return Err(Error::Truncated);
    }
    if data[0] != 0x1f || data[1] != 0x8b {
        return Err(Error::InvalidHeader("gzip magic"));
    }
    if data[2] != 8 {
        return Err(Error::InvalidHeader("gzip compression method"));
    }
    let flags = data[3];
    if flags & 0xe0 != 0 {
        return Err(Error::InvalidHeader("gzip reserved flags"));
    }

    let mut pos = 10usize;
    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return Err(Error::Truncated);
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos = pos
            .checked_add(2 + xlen)
            .ok_or(Error::InvalidHeader("gzip extra length"))?;
        if pos > data.len() {
            return Err(Error::Truncated);
        }
    }
    if flags & 0x08 != 0 {
        pos = skip_nul(data, pos)?;
    }
    if flags & 0x10 != 0 {
        pos = skip_nul(data, pos)?;
    }
    if flags & 0x02 != 0 {
        if pos + 2 > data.len() {
            return Err(Error::Truncated);
        }
        let expected = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if u16::try_from(crc32(&data[..pos]) & 0xffff).ok() != Some(expected) {
            return Err(Error::Checksum("gzip header CRC16"));
        }
        pos += 2;
    }

    let (out, consumed) = inflate_into(&data[pos..], max_output)?;
    let trailer = pos
        .checked_add(consumed)
        .ok_or(Error::InvalidHeader("gzip trailer offset"))?;
    if trailer + 8 > data.len() {
        return Err(Error::Truncated);
    }
    if trailer + 8 != data.len() {
        return Err(Error::TrailingData);
    }
    let expected_crc = u32::from_le_bytes(
        data[trailer..trailer + 4]
            .try_into()
            .expect("four-byte gzip CRC"),
    );
    let expected_size = u32::from_le_bytes(
        data[trailer + 4..trailer + 8]
            .try_into()
            .expect("four-byte gzip ISIZE"),
    );
    if crc32(&out) != expected_crc {
        return Err(Error::Checksum("gzip CRC32"));
    }
    let actual_size = u32::try_from(out.len()).map_err(|_| Error::Checksum("gzip ISIZE"))?;
    if actual_size != expected_size {
        return Err(Error::Checksum("gzip ISIZE"));
    }
    Ok(out)
}

/// Decompress a zlib stream with the default limit.
pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    zlib_decompress_with_limit(data, DEFAULT_MAX_OUTPUT)
}

/// Decompress a zlib stream with an explicit output limit.
///
/// Trailing bytes are rejected. A preset dictionary is not supported.
pub fn zlib_decompress_with_limit(data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if data.len() < 6 {
        return Err(Error::Truncated);
    }
    let cmf = data[0];
    let flg = data[1];
    if cmf & 0x0f != 8 {
        return Err(Error::InvalidHeader("zlib compression method"));
    }
    if cmf >> 4 > 7 {
        return Err(Error::InvalidHeader("zlib window size"));
    }
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Err(Error::InvalidHeader("zlib FCHECK"));
    }
    if flg & 0x20 != 0 {
        return Err(Error::InvalidHeader("zlib preset dictionary"));
    }

    let (out, consumed) = inflate_into(&data[2..], max_output)?;
    let trailer = 2usize
        .checked_add(consumed)
        .ok_or(Error::InvalidHeader("zlib trailer offset"))?;
    if trailer + 4 > data.len() {
        return Err(Error::Truncated);
    }
    if trailer + 4 != data.len() {
        return Err(Error::TrailingData);
    }
    let expected = u32::from_be_bytes(
        data[trailer..trailer + 4]
            .try_into()
            .expect("four-byte zlib Adler-32"),
    );
    if adler32(&out) != expected {
        return Err(Error::Checksum("zlib Adler-32"));
    }
    Ok(out)
}

fn looks_like_zlib(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }
    let cmf = data[0];
    let flg = data[1];
    cmf & 0x0f == 8
        && cmf >> 4 <= 7
        && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
        && flg & 0x20 == 0
}

fn skip_nul(data: &[u8], mut pos: usize) -> Result<usize, Error> {
    while pos < data.len() {
        if data[pos] == 0 {
            return Ok(pos + 1);
        }
        pos += 1;
    }
    Err(Error::Truncated)
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u64,
    bit_count: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    fn need(&mut self, count: u32) -> Result<(), Error> {
        while self.bit_count < count {
            if self.pos >= self.data.len() {
                return Err(Error::Truncated);
            }
            self.bit_buf |= u64::from(self.data[self.pos]) << self.bit_count;
            self.pos += 1;
            self.bit_count += 8;
        }
        Ok(())
    }

    fn bits(&mut self, count: u32) -> Result<u32, Error> {
        if count == 0 {
            return Ok(0);
        }
        if count > 32 {
            return Err(Error::InvalidCode("bit count"));
        }
        self.need(count)?;
        let value = (self.bit_buf & ((1u64 << count) - 1)) as u32;
        self.bit_buf >>= count;
        self.bit_count -= count;
        Ok(value)
    }

    fn align_byte(&mut self) {
        let drop = self.bit_count % 8;
        self.bit_buf >>= drop;
        self.bit_count -= drop;
    }

    fn read_u16_le(&mut self) -> Result<u16, Error> {
        self.align_byte();
        if self.bit_count >= 16 {
            let value = (self.bit_buf & 0xffff) as u16;
            self.bit_buf >>= 16;
            self.bit_count -= 16;
            return Ok(value);
        }
        let low = if self.bit_count >= 8 {
            let value = (self.bit_buf & 0xff) as u8;
            self.bit_buf >>= 8;
            self.bit_count -= 8;
            value
        } else {
            if self.pos >= self.data.len() {
                return Err(Error::Truncated);
            }
            let value = self.data[self.pos];
            self.pos += 1;
            value
        };
        if self.pos >= self.data.len() {
            return Err(Error::Truncated);
        }
        let high = self.data[self.pos];
        self.pos += 1;
        Ok(u16::from_le_bytes([low, high]))
    }

    fn copy_direct(
        &mut self,
        out: &mut Vec<u8>,
        len: usize,
        max_output: usize,
    ) -> Result<(), Error> {
        if out.len().saturating_add(len) > max_output {
            return Err(Error::OutputLimit);
        }
        let end = self.pos.checked_add(len).ok_or(Error::Truncated)?;
        if end > self.data.len() {
            return Err(Error::Truncated);
        }
        out.extend_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn from_lengths(lengths: &[u8]) -> Result<Self, Error> {
        let mut counts = [0u16; 16];
        for &length in lengths {
            if length as usize >= counts.len() {
                return Err(Error::InvalidCode("Huffman length"));
            }
            counts[length as usize] += 1;
        }
        counts[0] = 0;
        let mut left = 1i32;
        for &count in &counts[1..16] {
            left = (left << 1) - i32::from(count);
            if left < 0 {
                return Err(Error::InvalidCode("Huffman tree"));
            }
        }
        let mut offsets = [0u16; 16];
        for index in 1..16 {
            offsets[index] = offsets[index - 1] + counts[index - 1];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                let index = offsets[length as usize] as usize;
                if index >= symbols.len() {
                    return Err(Error::InvalidCode("Huffman tree"));
                }
                symbols[index] = symbol as u16;
                offsets[length as usize] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, Error> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for length in 1..16 {
            code |= reader.bits(1)? as i32;
            let count = self.counts[length] as i32;
            if code - first < count {
                let symbol_index = (index + code - first) as usize;
                return self
                    .symbols
                    .get(symbol_index)
                    .copied()
                    .ok_or(Error::InvalidCode("Huffman symbol"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::InvalidCode("Huffman code"))
    }
}

fn inflate_into(data: &[u8], max_output: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut reader = BitReader::new(data);
    let mut out = Vec::new();
    loop {
        if out.len() > max_output {
            return Err(Error::OutputLimit);
        }
        let final_block = reader.bits(1)? == 1;
        let block_type = reader.bits(2)?;
        match block_type {
            0 => stored_block(&mut reader, &mut out, max_output)?,
            1 => {
                let (literal, distance) = fixed_trees();
                compressed_block(&mut reader, &mut out, &literal, &distance, max_output)?;
            }
            2 => {
                let (literal, distance) = dynamic_trees(&mut reader)?;
                compressed_block(&mut reader, &mut out, &literal, &distance, max_output)?;
            }
            _ => return Err(Error::InvalidBlock("type")),
        }
        if final_block {
            break;
        }
    }
    reader.align_byte();
    let buffered_bytes = (reader.bit_count / 8) as usize;
    let consumed = reader.pos - buffered_bytes;
    Ok((out, consumed))
}

fn stored_block(
    reader: &mut BitReader<'_>,
    out: &mut Vec<u8>,
    max_output: usize,
) -> Result<(), Error> {
    reader.align_byte();
    let len = reader.read_u16_le()? as usize;
    let nlen = reader.read_u16_le()? as usize;
    if len != (!nlen & 0xffff) {
        return Err(Error::InvalidBlock("stored length"));
    }
    reader.copy_direct(out, len, max_output)
}

fn fixed_trees() -> (Huffman, Huffman) {
    let mut literal_lengths = [0u8; 288];
    literal_lengths[0..144].fill(8);
    literal_lengths[144..256].fill(9);
    literal_lengths[256..280].fill(7);
    literal_lengths[280..288].fill(8);
    let distance_lengths = [5u8; 32];
    (
        Huffman::from_lengths(&literal_lengths).expect("fixed literal tree"),
        Huffman::from_lengths(&distance_lengths).expect("fixed distance tree"),
    )
}

const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn dynamic_trees(reader: &mut BitReader<'_>) -> Result<(Huffman, Huffman), Error> {
    let hlit = reader.bits(5)? as usize + 257;
    let hdist = reader.bits(5)? as usize + 1;
    let hclen = reader.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(Error::InvalidBlock("dynamic header"));
    }
    let mut code_lengths = [0u8; 19];
    for &slot in CL_ORDER.iter().take(hclen) {
        code_lengths[slot] = reader.bits(3)? as u8;
    }
    let code_tree = Huffman::from_lengths(&code_lengths)?;

    let total = hlit + hdist;
    let mut lengths = vec![0u8; total];
    let mut index = 0;
    while index < total {
        let symbol = code_tree.decode(reader)?;
        match symbol {
            0..=15 => {
                lengths[index] = symbol as u8;
                index += 1;
            }
            16 => {
                if index == 0 {
                    return Err(Error::InvalidCode("repeat with no previous length"));
                }
                let previous = lengths[index - 1];
                let repeat = 3 + reader.bits(2)? as usize;
                if index + repeat > total {
                    return Err(Error::InvalidCode("code length repeat overflow"));
                }
                lengths[index..index + repeat].fill(previous);
                index += repeat;
            }
            17 => {
                let repeat = 3 + reader.bits(3)? as usize;
                if index + repeat > total {
                    return Err(Error::InvalidCode("zero repeat overflow"));
                }
                index += repeat;
            }
            18 => {
                let repeat = 11 + reader.bits(7)? as usize;
                if index + repeat > total {
                    return Err(Error::InvalidCode("long zero repeat overflow"));
                }
                index += repeat;
            }
            _ => return Err(Error::InvalidCode("code length symbol")),
        }
    }
    let literal = Huffman::from_lengths(&lengths[..hlit])?;
    let distance = Huffman::from_lengths(&lengths[hlit..])?;
    Ok((literal, distance))
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn compressed_block(
    reader: &mut BitReader<'_>,
    out: &mut Vec<u8>,
    literal: &Huffman,
    distance: &Huffman,
    max_output: usize,
) -> Result<(), Error> {
    loop {
        let symbol = literal.decode(reader)?;
        match symbol {
            0..=255 => {
                if out.len() >= max_output {
                    return Err(Error::OutputLimit);
                }
                out.push(symbol as u8);
            }
            256 => return Ok(()),
            257..=285 => {
                let index = (symbol - 257) as usize;
                let length = LENGTH_BASE[index] as usize
                    + reader.bits(u32::from(LENGTH_EXTRA[index]))? as usize;
                let distance_symbol = distance.decode(reader)? as usize;
                if distance_symbol >= 30 {
                    return Err(Error::InvalidCode("distance symbol"));
                }
                let distance = DIST_BASE[distance_symbol] as usize
                    + reader.bits(u32::from(DIST_EXTRA[distance_symbol]))? as usize;
                if distance == 0 || distance > out.len() {
                    return Err(Error::InvalidCode("back-reference distance"));
                }
                if out.len().saturating_add(length) > max_output {
                    return Err(Error::OutputLimit);
                }
                let start = out.len() - distance;
                for index in 0..length {
                    let byte = out[start + index];
                    out.push(byte);
                }
            }
            _ => return Err(Error::InvalidCode("literal/length symbol")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    const GZIP_HELLO: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0xc8, 0xc0, 0x4e, 0x02, 0x00, 0xf6, 0xd2, 0x53, 0x38, 0x1d, 0x00, 0x00, 0x00,
    ];
    const ZLIB_HELLO: &[u8] = &[
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0xc0, 0x4e, 0x02, 0x00, 0xa3, 0x10,
        0x0a, 0xe5,
    ];
    const RAW_HELLO: &[u8] = &[
        0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0xc0, 0x4e, 0x02, 0x00,
    ];
    const RAW_DYNAMIC: &[u8] = &[
        0xed, 0xca, 0xc1, 0x09, 0xc0, 0x30, 0x0c, 0x43, 0xd1, 0x55, 0xbc, 0x9a, 0x42, 0x4d, 0x53,
        0xb0, 0xdb, 0x40, 0x72, 0xca, 0xf4, 0xad, 0xb7, 0xe8, 0xe1, 0x1f, 0x24, 0x04, 0x7a, 0x8a,
        0xd1, 0x65, 0xcd, 0x97, 0xec, 0x54, 0xa6, 0xec, 0xf0, 0xf8, 0xb6, 0x8f, 0x79, 0xc5, 0x73,
        0xdb, 0xae, 0xa3, 0xb2, 0x7a, 0xb5, 0xd0, 0x68, 0x34, 0x1a, 0x8d, 0x46, 0xa3, 0xd1, 0xe8,
        0x5f, 0xe8, 0x17,
    ];

    #[test]
    fn known_gzip_vector() {
        assert_eq!(
            gzip_decompress(GZIP_HELLO).unwrap(),
            b"hello hello hello hello hello"
        );
    }

    #[test]
    fn gzip_or_raw_dispatch() {
        assert_eq!(
            inflate_gzip_or_raw(GZIP_HELLO).unwrap(),
            b"hello hello hello hello hello"
        );
        assert_eq!(
            inflate_gzip_or_raw(RAW_HELLO).unwrap(),
            b"hello hello hello hello hello"
        );
        assert!(inflate_gzip_or_raw(ZLIB_HELLO).is_err());
    }

    #[test]
    fn known_zlib_vector() {
        assert_eq!(
            zlib_decompress(ZLIB_HELLO).unwrap(),
            b"hello hello hello hello hello"
        );
    }

    #[test]
    fn known_raw_fixed_huffman_vector() {
        assert_eq!(
            inflate_raw(RAW_HELLO).unwrap(),
            b"hello hello hello hello hello"
        );
    }

    #[test]
    fn known_raw_dynamic_huffman_vector() {
        let expected = b"alpha beta gamma delta epsilon zeta eta theta ".repeat(60);
        assert_eq!(inflate_raw(RAW_DYNAMIC).unwrap(), expected);
    }

    #[test]
    fn rejects_corrupt_gzip_crc() {
        let mut data = GZIP_HELLO.to_vec();
        let last = data.len() - 8;
        data[last] ^= 1;
        assert!(matches!(
            gzip_decompress(&data),
            Err(Error::Checksum("gzip CRC32"))
        ));
    }

    #[test]
    fn rejects_corrupt_zlib_adler() {
        let mut data = ZLIB_HELLO.to_vec();
        let last = data.len() - 1;
        data[last] ^= 1;
        assert!(matches!(
            zlib_decompress(&data),
            Err(Error::Checksum("zlib Adler-32"))
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut gzip = GZIP_HELLO.to_vec();
        gzip.push(0);
        assert_eq!(gzip_decompress(&gzip), Err(Error::TrailingData));

        let mut zlib = ZLIB_HELLO.to_vec();
        zlib.push(0);
        assert_eq!(zlib_decompress(&zlib), Err(Error::TrailingData));

        let mut raw = RAW_HELLO.to_vec();
        raw.push(0);
        assert_eq!(inflate_raw(&raw), Err(Error::TrailingData));
    }

    #[test]
    fn rejects_oversubscribed_huffman_trees() {
        assert!(matches!(
            Huffman::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidCode("Huffman tree"))
        ));
    }

    #[test]
    fn respects_the_output_limit() {
        let input = vec![0u8; 100_000];
        let compressed = crate::deflate::gzip_compress(&input);
        assert_eq!(
            gzip_decompress_with_limit(&compressed, 1024),
            Err(Error::OutputLimit)
        );
    }

    #[test]
    fn stored_block_roundtrip() {
        let data = b"hello hello hello";
        let mut block = vec![0x01];
        block.extend_from_slice(&(data.len() as u16).to_le_bytes());
        block.extend_from_slice(&(!(data.len() as u16)).to_le_bytes());
        block.extend_from_slice(data);
        assert_eq!(inflate_raw(&block).unwrap(), data);
    }

    #[test]
    fn fuzz_inflate_never_panics_on_random_streams() {
        let mut rng = Rng::new(0x1afe_0001);
        for _ in 0..5_000 {
            let len = rng.below(256);
            let data = rng.bytes(len);
            if let Ok(out) = inflate(&data) {
                assert!(out.len() <= DEFAULT_MAX_OUTPUT);
            }
        }
        for _ in 0..1_000 {
            let len = rng.below(128);
            let mut data = vec![0x1f, 0x8b];
            data.extend(rng.bytes(len));
            if let Ok(out) = inflate(&data) {
                assert!(out.len() <= DEFAULT_MAX_OUTPUT);
            }
        }
        for flags in [0u8, 0x02, 0x04, 0x08, 0x10, 0xff] {
            let mut data = vec![0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 0];
            data.extend(rng.bytes(64));
            let _ = inflate(&data);
        }
    }
}
