//! Minimal 8-bit grayscale PNG writer.
//!
//! Only the encoder is implemented: the challenge image is generated from
//! scratch, so there is nothing to decode. Every row uses filter type 0 and the
//! single `IDAT` chunk is a zlib stream produced by
//! [`fador_compress::zlib_compress`]; the chunk CRCs come from
//! [`fador_core::crypto::crc32`].

use fador_compress::zlib_compress;
use fador_core::crypto::crc32;

/// The eight-byte PNG signature.
pub(crate) const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Largest image this writer accepts, in pixels.
const MAX_PIXELS: u64 = 1_000_000;

/// Encode an 8-bit grayscale image.
///
/// Returns `None` when the dimensions are zero, the pixel buffer does not
/// match them or the image is larger than the writer's bound.
pub(crate) fn encode_gray(width: u32, height: u32, pixels: &[u8]) -> Option<Vec<u8>> {
    if width == 0 || height == 0 {
        return None;
    }
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return None;
    }
    if pixels.len() != width as usize * height as usize {
        return None;
    }
    let mut out = Vec::with_capacity(pixels.len() / 2 + 128);
    out.extend_from_slice(SIGNATURE);
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 0, 0, 0, 0]);
    write_chunk(&mut out, b"IHDR", &header);
    let stride = width as usize;
    let mut raw = Vec::with_capacity((stride + 1) * height as usize);
    for row in pixels.chunks_exact(stride) {
        raw.push(0);
        raw.extend_from_slice(row);
    }
    write_chunk(&mut out, b"IDAT", &zlib_compress(&raw));
    write_chunk(&mut out, b"IEND", &[]);
    Some(out)
}

fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_inconsistent_input() {
        assert!(encode_gray(0, 1, &[]).is_none());
        assert!(encode_gray(1, 0, &[]).is_none());
        assert!(encode_gray(2, 2, &[0; 3]).is_none());
        assert!(encode_gray(2_000, 2_000, &[0; 4_000_000]).is_none());
    }

    #[test]
    fn writes_a_valid_single_pixel_png() {
        let png = encode_gray(1, 1, &[0x7f]).expect("png");
        assert_eq!(&png[..8], SIGNATURE);
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
        let position = png
            .windows(4)
            .position(|window| window == b"IDAT")
            .expect("IDAT");
        let length = u32::from_be_bytes(png[position - 4..position].try_into().unwrap()) as usize;
        let raw = fador_compress::zlib_decompress(&png[position + 4..position + 4 + length])
            .expect("zlib");
        assert_eq!(raw, vec![0, 0x7f]);
    }
}
