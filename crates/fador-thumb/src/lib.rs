//! Bounded image thumbnail planning, rendering and atomic writing.
//!
//! `fador-thumb` is the reusable part of a phpBB-compatible attachment
//! thumbnail pipeline. It scales the longer side of an image to a configured
//! width, re-encodes the result in the source format (JPEG quality 90) and
//! writes it atomically next to the original. It knows nothing about boards,
//! attachment rows, permissions or database schemas: the caller supplies a
//! [`ThumbnailSettings`], the encoded source bytes and a destination directory.
//!
//! The rules mirror phpBB's `get_img_size_format()` and `create_thumbnail()`:
//!
//! - `max_width` is `img_max_thumb_width`; zero selects
//!   [`DEFAULT_MAX_THUMB_WIDTH`] (400 pixels).
//! - `min_filesize` is `img_min_thumb_filesize`; a file must be *strictly*
//!   larger than it, and an empty file is never thumbnailed.
//! - the longer side is scaled to `max_width`, the other side keeps the aspect
//!   ratio and is rounded half away from zero like PHP's `round()`.
//! - an image that would not actually become smaller is skipped.
//! - animated GIF and WebP inputs use their first frame, exactly like
//!   `imagecreatefromgif()` and `imagecreatefromwebp()`.
//!
//! Every decode is bounded before it allocates: no side may exceed
//! [`MAX_DIMENSION`] pixels and the decoder may not reserve more than
//! [`MAX_ALLOCATION`] bytes. A hostile or damaged payload is rejected with an
//! error, never with an allocation failure or a panic.
//!
//! # Pipeline
//!
//! [`scaled_size`] and [`plan`] are pure decisions and can run before any image
//! byte is read. [`render`] decodes, resizes and re-encodes one image in
//! memory, and [`write_atomic`] stores the result so a reader never sees a
//! partially written thumbnail.
//!
//! ```no_run
//! use fador_thumb::{plan, render, write_atomic, Format, ThumbnailSettings};
//!
//! let settings = ThumbnailSettings::new(true, 400, 12_000);
//! let source = std::fs::read("files/1_ab.jpg").unwrap();
//! let (width, height) = plan(&settings, source.len() as u64, 1920, 1080).unwrap();
//! let thumbnail = render(&source, Format::Jpeg, width, height).unwrap();
//! write_atomic(
//!     std::path::Path::new("files"),
//!     std::path::Path::new("files/thumb_1_ab.jpg"),
//!     &thumbnail,
//! )
//! .unwrap();
//! ```
//!
//! ```
//! use fador_thumb::scaled_size;
//!
//! assert_eq!(scaled_size(1920, 1080, 400), Some((400, 225)));
//! assert_eq!(scaled_size(300, 200, 400), None);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use image::codecs::gif::GifEncoder;
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::codecs::webp::WebPEncoder;
use image::imageops::FilterType;
use image::{DynamicImage, ExtendedColorType, ImageEncoder, ImageFormat, ImageReader, Limits};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Width used when [`ThumbnailSettings::max_width`] is zero.
///
/// phpBB falls back to 400 pixels in `get_img_size_format()`.
pub const DEFAULT_MAX_THUMB_WIDTH: u64 = 400;

/// Largest accepted width or height of a decoded image, in pixels.
///
/// This matches the reference board's header inspection limit and keeps a
/// decompression bomb from reaching the decoder.
pub const MAX_DIMENSION: u32 = 100_000;

/// Largest number of bytes the decoder may reserve for one image.
pub const MAX_ALLOCATION: u64 = 512 * 1024 * 1024;

/// JPEG re-encode quality, matching `imagejpeg($new_image, $destination, 90)`.
pub const JPEG_QUALITY: u8 = 90;

/// The image formats the pipeline can decode and re-encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// JPEG (`.jpg`, `.jpeg`, `image/jpeg`), re-encoded at [`JPEG_QUALITY`].
    Jpeg,
    /// PNG (`.png`, `image/png`), alpha preserved.
    Png,
    /// GIF (`.gif`, `image/gif`); only the first frame of an animation.
    Gif,
    /// WebP (`.webp`, `image/webp`), written losslessly; only the first frame.
    WebP,
}

impl Format {
    /// Map a stored attachment extension to an encoder.
    ///
    /// The comparison is case-insensitive and ignores surrounding whitespace.
    #[must_use]
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.trim().to_ascii_lowercase().as_str() {
            "jpg" | "jpeg" => Some(Self::Jpeg),
            "png" => Some(Self::Png),
            "gif" => Some(Self::Gif),
            "webp" => Some(Self::WebP),
            _ => None,
        }
    }

    /// Map a stored attachment MIME type to an encoder.
    ///
    /// The comparison is case-insensitive and ignores surrounding whitespace.
    #[must_use]
    pub fn from_mimetype(mimetype: &str) -> Option<Self> {
        match mimetype.trim().to_ascii_lowercase().as_str() {
            "image/jpeg" | "image/jpg" | "image/pjpeg" => Some(Self::Jpeg),
            "image/png" => Some(Self::Png),
            "image/gif" => Some(Self::Gif),
            "image/webp" => Some(Self::WebP),
            _ => None,
        }
    }

    fn image_format(self) -> ImageFormat {
        match self {
            Self::Jpeg => ImageFormat::Jpeg,
            Self::Png => ImageFormat::Png,
            Self::Gif => ImageFormat::Gif,
            Self::WebP => ImageFormat::WebP,
        }
    }
}

/// The three board settings that drive thumbnail creation.
///
/// The field names are the phpBB configuration keys, so a caller can copy them
/// from its settings table without any translation:
///
/// | field | phpBB key |
/// | --- | --- |
/// | [`enabled`](Self::enabled) | `img_create_thumbnail` |
/// | [`max_width`](Self::max_width) | `img_max_thumb_width` |
/// | [`min_filesize`](Self::min_filesize) | `img_min_thumb_filesize` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThumbnailSettings {
    /// Whether thumbnails are created at all (`img_create_thumbnail`).
    ///
    /// [`plan`] rejects a disabled configuration; the reference board checked
    /// this flag in the upload path instead.
    pub enabled: bool,
    /// The width the longer side is scaled to (`img_max_thumb_width`).
    ///
    /// Zero selects [`DEFAULT_MAX_THUMB_WIDTH`].
    pub max_width: u64,
    /// The minimum source file size (`img_min_thumb_filesize`).
    ///
    /// A file must be strictly larger than this value. Zero accepts any
    /// non-empty file.
    pub min_filesize: u64,
}

impl ThumbnailSettings {
    /// Build a settings value from the three phpBB keys.
    #[must_use]
    pub const fn new(enabled: bool, max_width: u64, min_filesize: u64) -> Self {
        Self {
            enabled,
            max_width,
            min_filesize,
        }
    }
}

impl Default for ThumbnailSettings {
    /// The phpBB defaults: thumbnails off, 400 pixels, no size threshold.
    fn default() -> Self {
        Self {
            enabled: false,
            max_width: DEFAULT_MAX_THUMB_WIDTH,
            min_filesize: 0,
        }
    }
}

/// phpBB skips an empty file and any file that is not strictly larger than
/// `img_min_thumb_filesize`.
fn large_enough(filesize: u64, min_filesize: u64) -> bool {
    filesize > 0 && filesize > min_filesize
}

/// Scale the longer side to `max_width`, mirroring `get_img_size_format()`:
/// PHP's `round()` (half away from zero) and the longer-side branch.
///
/// Returns `None` when the image is already small enough, when a dimension is
/// zero, or when the scale factor is not finite/useful.
///
/// The other side keeps the aspect ratio and is clamped to at least one pixel,
/// so a 1000x1 image becomes 400x1 rather than 400x0.
///
/// ```
/// use fador_thumb::scaled_size;
///
/// assert_eq!(scaled_size(800, 600, 400), Some((400, 300)));
/// assert_eq!(scaled_size(600, 800, 400), Some((300, 400)));
/// assert_eq!(scaled_size(500, 500, 400), Some((400, 400)));
/// assert_eq!(scaled_size(1000, 1, 400), Some((400, 1)));
/// ```
#[must_use]
pub fn scaled_size(width: u32, height: u32, max_width: u64) -> Option<(u32, u32)> {
    if width == 0 || height == 0 {
        return None;
    }
    let max_width = if max_width == 0 {
        DEFAULT_MAX_THUMB_WIDTH
    } else {
        max_width
    };
    let scale = if width > height {
        max_width as f64 / f64::from(width)
    } else {
        max_width as f64 / f64::from(height)
    };
    let new_width = (f64::from(width) * scale).round();
    let new_height = (f64::from(height) * scale).round();
    if !new_width.is_finite() || !new_height.is_finite() {
        return None;
    }
    // Do not create a thumbnail when the result would not actually be smaller.
    if new_width >= f64::from(width) && new_height >= f64::from(height) {
        return None;
    }
    let clamp = |value: f64| value.clamp(1.0, f64::from(u32::MAX)) as u32;
    Some((clamp(new_width), clamp(new_height)))
}

/// Decide whether a thumbnail should be created and at which size.
///
/// The checks run in the same order as the reference upload path:
///
/// 1. thumbnails must be enabled ([`ThumbnailSettings::enabled`]);
/// 2. the source must be non-empty and strictly larger than
///    [`ThumbnailSettings::min_filesize`];
/// 3. [`scaled_size`] must produce a smaller image.
///
/// The error is the reason string the caller should log; the upload itself is
/// never failed because a thumbnail was skipped.
///
/// ```
/// use fador_thumb::{plan, ThumbnailSettings};
///
/// let settings = ThumbnailSettings::new(true, 400, 12_000);
/// assert_eq!(plan(&settings, 12_001, 800, 600), Ok((400, 300)));
/// assert_eq!(
///     plan(&settings, 12_000, 800, 600),
///     Err("file is not larger than img_min_thumb_filesize")
/// );
/// ```
pub fn plan(
    settings: &ThumbnailSettings,
    filesize: u64,
    width: u32,
    height: u32,
) -> Result<(u32, u32), &'static str> {
    if !settings.enabled {
        return Err("thumbnails are disabled");
    }
    if !large_enough(filesize, settings.min_filesize) {
        return Err("file is not larger than img_min_thumb_filesize");
    }
    scaled_size(width, height, settings.max_width).ok_or("scaling would not make the image smaller")
}

/// Decode, resize and re-encode one image in the same format.
///
/// `data` is the complete encoded file and `format` selects both the decoder
/// and the encoder, so a PNG stays a PNG and a JPEG stays a JPEG at
/// [`JPEG_QUALITY`]. The function is free of filesystem and configuration
/// access, which makes it usable with in-memory images and unit tests.
///
/// The target size is not validated against the source: pass a size produced by
/// [`scaled_size`] or [`plan`]. Both dimensions must be non-zero.
///
/// # Errors
///
/// Returns a human-readable message when the payload is not a valid image of
/// the requested format, when the decoder's dimension or allocation limits are
/// exceeded, when the target size is empty, or when the encoder fails.
pub fn render(data: &[u8], format: Format, width: u32, height: u32) -> Result<Vec<u8>, String> {
    if width == 0 || height == 0 {
        return Err("target size is empty".to_string());
    }
    let mut reader = ImageReader::with_format(Cursor::new(data), format.image_format());
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_ALLOCATION);
    reader.limits(limits);
    let decoded = reader
        .decode()
        .map_err(|error| format!("decode failed: {error}"))?;
    if decoded.width() == 0 || decoded.height() == 0 {
        return Err("decoded image is empty".to_string());
    }
    // GD's imagecopyresampled is a bilinear resample; Lanczos3 is a good-quality
    // filter that also resamples the alpha channel.  Animated inputs use the
    // first frame, exactly like imagecreatefromgif/imagecreatefromwebp.
    let resized = decoded.resize_exact(width, height, FilterType::Lanczos3);
    encode(&resized, format)
}

fn encode(image: &DynamicImage, format: Format) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    match format {
        Format::Jpeg => {
            // JPEG has no alpha channel; `to_rgb8` drops it like GD does.
            let rgb = image.to_rgb8();
            JpegEncoder::new_with_quality(&mut output, JPEG_QUALITY)
                .write_image(
                    rgb.as_raw(),
                    rgb.width(),
                    rgb.height(),
                    ExtendedColorType::Rgb8,
                )
                .map_err(|error| format!("jpeg encode failed: {error}"))?;
        }
        Format::Png => {
            let rgba = image.to_rgba8();
            PngEncoder::new(&mut output)
                .write_image(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    ExtendedColorType::Rgba8,
                )
                .map_err(|error| format!("png encode failed: {error}"))?;
        }
        Format::Gif => {
            let rgba = image.to_rgba8();
            GifEncoder::new(&mut output)
                .encode(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    ExtendedColorType::Rgba8,
                )
                .map_err(|error| format!("gif encode failed: {error}"))?;
        }
        Format::WebP => {
            let rgba = image.to_rgba8();
            WebPEncoder::new_lossless(&mut output)
                .write_image(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    ExtendedColorType::Rgba8,
                )
                .map_err(|error| format!("webp encode failed: {error}"))?;
        }
    }
    if output.is_empty() {
        return Err("encoder produced no data".to_string());
    }
    Ok(output)
}

/// Write `data` to a temporary file in `dir`, then rename it onto
/// `destination`.
///
/// The temporary name starts with `.thumb-` and is unique per process and
/// call. The file is flushed to disk before the rename, so a reader either sees
/// the old destination or the complete new content, and the temporary file is
/// removed when any step fails.
///
/// `dir` must already exist. Keep `destination` inside `dir` (or at least on
/// the same filesystem), otherwise the rename is not atomic and may fail.
///
/// # Errors
///
/// Returns the underlying I/O error when the temporary file cannot be created
/// or written, when `sync_all` fails, or when the rename fails.
pub fn write_atomic(dir: &Path, destination: &Path, data: &[u8]) -> std::io::Result<()> {
    let temp = temp_path(dir);
    let result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// A process-unique, collision-resistant temporary name.
///
/// The pid makes names unique across processes sharing the directory, and the
/// nanosecond timestamp plus the atomic counter make them unique within a
/// process without pulling in a random-number dependency.
fn temp_path(dir: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    dir.join(format!(
        ".thumb-{:x}-{nanos:x}-{counter:x}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{AnimationDecoder, Rgba, RgbaImage};

    fn sample(width: u32, height: u32) -> DynamicImage {
        DynamicImage::ImageRgba8(RgbaImage::from_fn(width, height, |x, y| {
            Rgba([
                (x * 255 / width.max(1)) as u8,
                (y * 255 / height.max(1)) as u8,
                ((x + y) % 251) as u8,
                if x < width / 2 { 0 } else { 255 },
            ])
        }))
    }

    fn encode_sample(format: Format, width: u32, height: u32) -> Vec<u8> {
        encode(&sample(width, height), format).expect("sample encodes")
    }

    fn decode_dimensions(data: &[u8], format: Format) -> (u32, u32) {
        let image = image::load_from_memory_with_format(data, format.image_format())
            .expect("thumbnail decodes");
        (image.width(), image.height())
    }

    /// A private directory under the system temp directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("fador-thumb-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn scales_the_longest_side_to_the_configured_width() {
        assert_eq!(scaled_size(800, 600, 400), Some((400, 300)));
        assert_eq!(scaled_size(600, 800, 400), Some((300, 400)));
        assert_eq!(scaled_size(500, 500, 400), Some((400, 400)));
        assert_eq!(scaled_size(1000, 250, 400), Some((400, 100)));
        assert_eq!(scaled_size(401, 1, 400), Some((400, 1)));
        assert_eq!(scaled_size(1, 401, 400), Some((1, 400)));
        assert_eq!(scaled_size(1920, 1080, 300), Some((300, 169)));
    }

    #[test]
    fn zero_max_width_falls_back_to_400() {
        assert_eq!(scaled_size(800, 600, 0), scaled_size(800, 600, 400));
        assert_eq!(scaled_size(800, 600, 0), Some((400, 300)));
    }

    #[test]
    fn already_small_images_have_no_thumbnail_size() {
        assert_eq!(scaled_size(300, 200, 400), None);
        assert_eq!(scaled_size(400, 300, 400), None);
        assert_eq!(scaled_size(400, 400, 400), None);
        assert_eq!(scaled_size(1, 1, 400), None);
        assert_eq!(scaled_size(300, 1000, 400), Some((120, 400)));
    }

    #[test]
    fn empty_and_absurd_dimensions_are_rejected() {
        assert_eq!(scaled_size(0, 100, 400), None);
        assert_eq!(scaled_size(100, 0, 400), None);
        assert_eq!(scaled_size(0, 0, 400), None);
        assert_eq!(scaled_size(100, 100, u64::MAX), None);
        assert_eq!(scaled_size(u32::MAX, u32::MAX, u64::MAX), None);
        assert_eq!(scaled_size(u32::MAX, 1, 400), Some((400, 1)));
    }

    #[test]
    fn size_threshold_is_strictly_greater() {
        assert!(large_enough(12_001, 12_000));
        assert!(!large_enough(12_000, 12_000));
        assert!(!large_enough(0, 0));
        assert!(large_enough(1, 0));
        assert!(large_enough(5_000, 0));
        assert!(!large_enough(400, 12_000));
    }

    #[test]
    fn plan_explains_why_it_skips() {
        let settings = ThumbnailSettings::new(true, 400, 12_000);
        assert_eq!(plan(&settings, 12_001, 800, 600), Ok((400, 300)));
        assert_eq!(
            plan(&settings, 12_000, 800, 600),
            Err("file is not larger than img_min_thumb_filesize")
        );
        assert_eq!(
            plan(&settings, 20_000, 320, 240),
            Err("scaling would not make the image smaller")
        );
        assert_eq!(
            plan(&ThumbnailSettings::new(true, 0, 0), 1, 800, 600),
            Ok((400, 300))
        );
        assert_eq!(
            plan(&ThumbnailSettings::new(false, 400, 0), 20_000, 800, 600),
            Err("thumbnails are disabled")
        );
    }

    #[test]
    fn settings_default_to_the_phpbb_values() {
        let settings = ThumbnailSettings::default();
        assert!(!settings.enabled);
        assert_eq!(settings.max_width, DEFAULT_MAX_THUMB_WIDTH);
        assert_eq!(settings.min_filesize, 0);
        assert_eq!(
            settings,
            ThumbnailSettings {
                enabled: false,
                max_width: 400,
                min_filesize: 0,
            }
        );
    }

    #[test]
    fn maps_extensions_and_mimetypes() {
        assert_eq!(Format::from_extension("jpg"), Some(Format::Jpeg));
        assert_eq!(Format::from_extension("JPG"), Some(Format::Jpeg));
        assert_eq!(Format::from_extension(" jpeg "), Some(Format::Jpeg));
        assert_eq!(Format::from_extension("png"), Some(Format::Png));
        assert_eq!(Format::from_extension("gif"), Some(Format::Gif));
        assert_eq!(Format::from_extension("webp"), Some(Format::WebP));
        assert_eq!(Format::from_extension("bmp"), None);
        assert_eq!(Format::from_extension(""), None);
        assert_eq!(Format::from_mimetype("image/jpeg"), Some(Format::Jpeg));
        assert_eq!(Format::from_mimetype("image/jpg"), Some(Format::Jpeg));
        assert_eq!(Format::from_mimetype("image/pjpeg"), Some(Format::Jpeg));
        assert_eq!(Format::from_mimetype("IMAGE/PNG"), Some(Format::Png));
        assert_eq!(Format::from_mimetype("image/gif"), Some(Format::Gif));
        assert_eq!(Format::from_mimetype("image/webp"), Some(Format::WebP));
        assert_eq!(Format::from_mimetype("text/plain"), None);
    }

    #[test]
    fn renders_each_format_in_the_source_format() {
        let cases = [
            (Format::Jpeg, &b"\xff\xd8\xff"[..]),
            (Format::Png, &b"\x89PNG"[..]),
            (Format::Gif, &b"GIF8"[..]),
            (Format::WebP, &b"RIFF"[..]),
        ];
        for (format, magic) in cases {
            let source = encode_sample(format, 200, 100);
            let thumbnail = render(&source, format, 100, 50).expect("renders");
            assert!(
                thumbnail.starts_with(magic),
                "{format:?} thumbnail has the wrong magic bytes"
            );
            assert_eq!(decode_dimensions(&thumbnail, format), (100, 50));
        }
    }

    #[test]
    fn png_round_trip_through_render() {
        let source = encode_sample(Format::Png, 320, 200);
        let settings = ThumbnailSettings::new(true, 160, 0);
        let (width, height) =
            plan(&settings, source.len() as u64, 320, 200).expect("a thumbnail is planned");
        assert_eq!((width, height), (160, 100));
        let thumbnail = render(&source, Format::Png, width, height).expect("renders");
        assert!(thumbnail.starts_with(b"\x89PNG"));
        assert_eq!(decode_dimensions(&thumbnail, Format::Png), (160, 100));
    }

    #[test]
    fn jpeg_round_trip_through_render() {
        let source = encode_sample(Format::Jpeg, 320, 200);
        let settings = ThumbnailSettings::new(true, 160, 0);
        let (width, height) =
            plan(&settings, source.len() as u64, 320, 200).expect("a thumbnail is planned");
        let thumbnail = render(&source, Format::Jpeg, width, height).expect("renders");
        assert!(thumbnail.starts_with(b"\xff\xd8\xff"));
        assert_eq!(decode_dimensions(&thumbnail, Format::Jpeg), (160, 100));
    }

    #[test]
    fn jpeg_thumbnails_use_quality_90() {
        let source = encode_sample(Format::Jpeg, 200, 100);
        let low = render(&source, Format::Jpeg, 100, 50).unwrap();
        let reference = {
            let mut buffer = Vec::new();
            let image = image::load_from_memory_with_format(&source, ImageFormat::Jpeg)
                .unwrap()
                .resize_exact(100, 50, FilterType::Lanczos3);
            JpegEncoder::new_with_quality(&mut buffer, 90)
                .write_image(&image.to_rgb8(), 100, 50, ExtendedColorType::Rgb8)
                .unwrap();
            buffer
        };
        assert_eq!(low, reference);
        assert!(low.starts_with(b"\xff\xd8\xff"));
    }

    #[test]
    fn png_alpha_survives_the_thumbnail() {
        let source = encode_sample(Format::Png, 200, 100);
        let thumbnail = render(&source, Format::Png, 100, 50).unwrap();
        assert!(thumbnail.starts_with(b"\x89PNG"));
        let decoded = image::load_from_memory_with_format(&thumbnail, ImageFormat::Png)
            .unwrap()
            .to_rgba8();
        assert_eq!(decoded.get_pixel(2, 2)[3], 0);
        assert_eq!(decoded.get_pixel(97, 2)[3], 255);
    }

    #[test]
    fn animated_gifs_render_the_first_frame() {
        let mut animated = Vec::new();
        {
            let mut encoder = GifEncoder::new(&mut animated);
            for shade in [32u8, 224u8] {
                encoder
                    .encode_frame(image::Frame::new(RgbaImage::from_pixel(
                        120,
                        80,
                        Rgba([shade, shade, shade, 255]),
                    )))
                    .unwrap();
            }
        }
        let thumbnail = render(&animated, Format::Gif, 60, 40).unwrap();
        assert!(thumbnail.starts_with(b"GIF8"));
        assert_eq!(decode_dimensions(&thumbnail, Format::Gif), (60, 40));
        let frames = image::codecs::gif::GifDecoder::new(Cursor::new(&thumbnail))
            .unwrap()
            .into_frames()
            .collect_frames()
            .unwrap();
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn a_payload_that_does_not_match_the_format_is_rejected() {
        let png = encode_sample(Format::Png, 64, 64);
        assert!(render(&png, Format::Jpeg, 32, 32).is_err());
        assert!(render(b"not an image", Format::Png, 32, 32).is_err());
        assert!(render(&png, Format::Png, 0, 32).is_err());
        assert!(render(&png, Format::Png, 32, 0).is_err());
    }

    /// A PNG signature plus a valid IHDR chunk, an empty IDAT and IEND.
    fn png_with_dimensions(width: u32, height: u32) -> Vec<u8> {
        fn crc32(bytes: &[u8]) -> u32 {
            let mut crc = 0xffff_ffffu32;
            for &byte in bytes {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    let mask = (crc & 1).wrapping_neg();
                    crc = (crc >> 1) ^ (0xedb8_8320 & mask);
                }
            }
            !crc
        }

        fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
            let mut crc_input = Vec::with_capacity(4 + data.len());
            crc_input.extend_from_slice(kind);
            crc_input.extend_from_slice(data);
            let mut out = Vec::with_capacity(12 + data.len());
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(&crc_input);
            out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
            out
        }

        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&chunk(b"IHDR", &ihdr));
        png.extend_from_slice(&chunk(b"IDAT", &[]));
        png.extend_from_slice(&chunk(b"IEND", &[]));
        png
    }

    #[test]
    fn oversized_images_are_rejected_before_they_are_decoded() {
        // 100,001 pixels on the longer side is one over MAX_DIMENSION, while
        // the compressed payload stays tiny. The decoder must reject it from
        // the header, before it reserves the pixel buffer.
        let too_wide = png_with_dimensions(MAX_DIMENSION + 1, 1);
        let error = render(&too_wide, Format::Png, 400, 1).unwrap_err();
        assert!(error.contains("decode failed"), "{error}");
        assert!(error.contains("limit"), "{error}");

        let too_tall = png_with_dimensions(1, MAX_DIMENSION + 1);
        let error = render(&too_tall, Format::Png, 1, 400).unwrap_err();
        assert!(error.contains("limit"), "{error}");
    }

    #[test]
    fn write_atomic_replaces_the_destination_and_leaves_no_temporary_file() {
        let dir = TempDir::new("atomic");
        let destination = dir.path().join("thumb_1_abcdef.png");
        fs::write(&destination, b"old content").unwrap();
        write_atomic(dir.path(), &destination, b"new content").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new content");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "the temporary file must not survive a successful write"
        );
    }

    #[test]
    fn write_atomic_fails_cleanly_without_a_directory() {
        let dir = TempDir::new("missing");
        let missing = dir.path().join("nested");
        let destination = missing.join("thumb_1_abcdef.png");
        assert!(write_atomic(&missing, &destination, b"data").is_err());
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_rendered_thumbnail_is_written_atomically() {
        let dir = TempDir::new("roundtrip");
        let source = encode_sample(Format::Png, 320, 200);
        let (width, height) = plan(&ThumbnailSettings::new(true, 160, 0), 1, 320, 200).unwrap();
        let thumbnail = render(&source, Format::Png, width, height).unwrap();
        let destination = dir.path().join("thumb_7_deadbeef.png");
        write_atomic(dir.path(), &destination, &thumbnail).unwrap();
        let on_disk = fs::read(&destination).unwrap();
        assert_eq!(on_disk, thumbnail);
        assert_eq!(decode_dimensions(&on_disk, Format::Png), (160, 100));
    }

    #[test]
    fn random_payloads_are_rejected_without_panicking() {
        let mut rng = fador_testutil::Rng::new(0x7e55_1e55);
        let formats = [Format::Jpeg, Format::Png, Format::Gif, Format::WebP];
        for _ in 0..fador_testutil::iterations(200) {
            let len = rng.below(256);
            let data = rng.bytes(len);
            for format in formats {
                assert!(
                    render(&data, format, 32, 32).is_err(),
                    "{format:?} accepted {} random bytes",
                    data.len()
                );
            }
        }
        for payload in fador_testutil::MALICIOUS_STRINGS {
            for format in formats {
                assert!(render(payload.as_bytes(), format, 32, 32).is_err());
            }
        }
    }
}
