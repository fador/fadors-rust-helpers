//! Small format checks for uploaded raster images.
//!
//! Uploads are limited to PNG, JPEG and GIF.  We parse only enough to verify
//! the magic bytes and obtain dimensions for the `image` table; ImageMagick
//! remains responsible for actual thumbnail decoding.

/// Dimensions and media type of a supported image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// MediaWiki-style media type (`BITMAP`).
    pub media_type: &'static str,
    /// Top-level MIME type (`image`).
    pub major_mime: &'static str,
    /// File extension used as the minor MIME type (`png`, `jpeg`, `gif`).
    pub minor_mime: &'static str,
}

/// Inspect the header of a PNG, JPEG or GIF image.
///
/// Returns `None` for an unsupported extension, a malformed header, or
/// dimensions outside the sane bounds (100,000 px per side and 100 million
/// pixels total).
pub fn inspect(data: &[u8], filename: &str) -> Option<ImageInfo> {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())?;
    let (width, height, minor) = match ext.as_str() {
        "png" => png_size(data)?,
        "jpg" | "jpeg" => jpeg_size(data)?,
        "gif" => gif_size(data)?,
        _ => return None,
    };
    if width == 0
        || height == 0
        || width > 100_000
        || height > 100_000
        || u64::from(width) * u64::from(height) > 100_000_000
    {
        return None;
    }
    Some(ImageInfo {
        width,
        height,
        media_type: "BITMAP",
        major_mime: "image",
        minor_mime: minor,
    })
}

fn png_size(data: &[u8]) -> Option<(u32, u32, &'static str)> {
    if data.len() < 24 || &data[..8] != b"\x89PNG\r\n\x1a\n" || &data[12..16] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes(data[16..20].try_into().ok()?);
    let height = u32::from_be_bytes(data[20..24].try_into().ok()?);
    Some((width, height, "png"))
}

fn gif_size(data: &[u8]) -> Option<(u32, u32, &'static str)> {
    if data.len() < 10 || (&data[..6] != b"GIF87a" && &data[..6] != b"GIF89a") {
        return None;
    }
    let width = u16::from_le_bytes([data[6], data[7]]) as u32;
    let height = u16::from_le_bytes([data[8], data[9]]) as u32;
    Some((width, height, "gif"))
}

fn jpeg_size(data: &[u8]) -> Option<(u32, u32, &'static str)> {
    if data.len() < 4 || data[0] != 0xff || data[1] != 0xd8 {
        return None;
    }
    let mut pos = 2usize;
    while pos + 4 <= data.len() {
        if data[pos] != 0xff {
            return None;
        }
        while pos < data.len() && data[pos] == 0xff {
            pos += 1;
        }
        if pos >= data.len() {
            return None;
        }
        let marker = data[pos];
        pos += 1;
        if marker == 0xd9 || marker == 0xda {
            return None;
        }
        if (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            continue;
        }
        if pos + 2 > data.len() {
            return None;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        if len < 2 || pos + len > data.len() {
            return None;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            if len < 7 {
                return None;
            }
            let height = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as u32;
            let width = u16::from_be_bytes([data[pos + 5], data[pos + 6]]) as u32;
            return Some((width, height, "jpeg"));
        }
        pos += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    #[test]
    fn reads_known_headers() {
        let mut png = vec![0u8; 24];
        png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        png[12..16].copy_from_slice(b"IHDR");
        png[16..20].copy_from_slice(&640u32.to_be_bytes());
        png[20..24].copy_from_slice(&480u32.to_be_bytes());
        assert_eq!(inspect(&png, "x.png").unwrap().width, 640);

        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&320u16.to_le_bytes());
        gif.extend_from_slice(&200u16.to_le_bytes());
        assert_eq!(inspect(&gif, "x.gif").unwrap().height, 200);

        let jpeg = [
            0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x64, 0x00, 0xc8, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd9,
        ];
        let info = inspect(&jpeg, "x.jpg").unwrap();
        assert_eq!((info.width, info.height), (200, 100));
    }

    #[test]
    fn rejects_truncated_and_out_of_range_images() {
        assert!(inspect(b"not an image", "x.png").is_none());
        assert!(inspect(b"GIF89a", "x.gif").is_none());
        assert!(inspect(&[0xff, 0xd8, 0xff, 0xc0, 0, 2], "x.jpg").is_none());
        let mut png = vec![0u8; 24];
        png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        png[12..16].copy_from_slice(b"IHDR");
        png[16..20].copy_from_slice(&100_000u32.to_be_bytes());
        png[20..24].copy_from_slice(&100_000u32.to_be_bytes());
        assert!(inspect(&png, "x.png").is_none());
    }

    #[test]
    fn fuzz_image_headers_never_panic() {
        let mut rng = Rng::new(0x1a6e_0001);
        let extensions = ["png", "jpg", "jpeg", "gif", "webp", "php", ""];
        for _ in 0..5_000 {
            let len = rng.below(512);
            let data = rng.bytes(len);
            let ext = extensions[rng.below(extensions.len())];
            if let Some(info) = inspect(&data, &format!("x.{ext}")) {
                assert!(info.width > 0 && info.height > 0);
                assert!(info.width <= 100_000 && info.height <= 100_000);
            }
        }
    }
}
