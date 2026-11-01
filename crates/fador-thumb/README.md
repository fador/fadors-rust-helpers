# fador-thumb

Bounded, phpBB-compatible image thumbnail planning, rendering and atomic
writing.

This is the reusable half of the attachment thumbnail pipeline: it decides the
target size, decodes the source, resizes it and re-encodes it in the source
format. It never reads board settings, attachment rows or permissions.

## What it preserves

The rules mirror phpBB's `get_img_size_format()` and `create_thumbnail()`:

| phpBB setting | `ThumbnailSettings` field | behaviour |
| --- | --- | --- |
| `img_create_thumbnail` | `enabled` | `plan` refuses a disabled configuration |
| `img_max_thumb_width` | `max_width` | the longer side is scaled to it; `0` means 400 |
| `img_min_thumb_filesize` | `min_filesize` | a file must be *strictly* larger; an empty file is skipped |

- The aspect ratio is kept and the shorter side is rounded half away from zero
  like PHP's `round()`, clamped to at least one pixel.
- An image that would not actually become smaller is skipped.
- The source format is kept: JPEG is re-encoded at quality 90, PNG keeps alpha,
  GIF and WebP write their first frame (matching
  `imagecreatefromgif()`/`imagecreatefromwebp()`).
- The decode is bounded to 100,000 pixels per side and a 512 MiB allocation,
  so a decompression bomb is rejected before it can reserve the pixel buffer.

## Usage

```rust
use fador_thumb::{plan, render, write_atomic, Format, ThumbnailSettings};

fn make_thumbnail(
    source_path: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    let settings = ThumbnailSettings::new(true, 400, 12_000);
    let source = std::fs::read(source_path)?;
    let (width, height) = match plan(&settings, source.len() as u64, 1920, 1080) {
        Ok(size) => size,
        Err(reason) => {
            eprintln!("thumbnail skipped: {reason}");
            return Ok(());
        }
    };
    let format = Format::from_extension("jpg").expect("a supported extension");
    let thumbnail = render(&source, format, width, height)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_atomic(
        destination.parent().expect("a parent directory"),
        destination,
        &thumbnail,
    )
}
```

The format can come from the stored extension or MIME type:

```rust
use fador_thumb::Format;

assert_eq!(Format::from_extension("JPG"), Some(Format::Jpeg));
assert_eq!(Format::from_mimetype("image/png"), Some(Format::Png));
assert_eq!(Format::from_extension("bmp"), None);
```

## API

| item | purpose |
| --- | --- |
| `ThumbnailSettings` | the three phpBB settings, with `new` and `Default` |
| `Format` | JPEG/PNG/GIF/WebP, plus `from_extension` and `from_mimetype` |
| `scaled_size` | pure size decision; `None` when no thumbnail is needed |
| `plan` | `scaled_size` plus the enabled and `min_filesize` checks |
| `render` | decode, resize and re-encode one image in memory |
| `write_atomic` | write a temp file in the upload directory, then rename |

`plan` returns a static reason string, `render` returns a human-readable
message and `write_atomic` returns `std::io::Error`. A skipped thumbnail is
never an upload failure: log the reason and keep the original file.

## Caller responsibilities

The crate deliberately does not do any of the following:

- read `img_create_thumbnail`, `img_max_thumb_width` or
  `img_min_thumb_filesize` from a database;
- validate an attachment record, an ACL or a quota;
- generate the `thumb_<physical_filename>` name or check that the physical name
  is a plain file name;
- reuse an existing thumbnail (forks share the physical file name);
- log a skip, count bytes or update the attachment row.

Those belong to the application that owns the upload path.

## Limits

| constant | value | meaning |
| --- | --- | --- |
| `DEFAULT_MAX_THUMB_WIDTH` | 400 | width used when `max_width` is zero |
| `MAX_DIMENSION` | 100,000 | maximum width or height of a decoded image |
| `MAX_ALLOCATION` | 512 MiB | maximum allocation the decoder may reserve |
| `JPEG_QUALITY` | 90 | JPEG re-encode quality |

`write_atomic` requires an existing `dir` and a `destination` on the same
filesystem. It flushes the temporary file before the rename and removes the
temporary file if any step fails.

## Dependency

The only external dependency is `image` 0.25 with `default-features = false`
and the `jpeg`, `png`, `gif` and `webp` features; everything else is `std`. The
crate is `#![deny(unsafe_code)]` and every public item is documented.

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
