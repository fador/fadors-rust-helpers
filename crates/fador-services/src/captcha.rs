//! Visual and audio challenges, plus third-party challenge verification.
//!
//! The image challenge is a grayscale PNG built from a built-in 5x7 bitmap
//! face. It does not need GD, a font file or an image crate: the pixels are
//! written by a local PNG encoder and compressed with
//! [`fador_compress::zlib_compress`]. The audio challenge is an 8-bit mono WAV
//! that plays one tone per character.
//!
//! The third-party path verifies a Turnstile or hCaptcha response token
//! against a **plain HTTP** verifier endpoint (TLS is terminated in front of
//! it, exactly like the mail relay). The policy is fail-closed: a verifier
//! that cannot be reached rejects the submission unless the caller explicitly
//! opts into `fail_open`, and a configuration error always rejects.
//!
//! ```no_run
//! use fador_services::captcha::{friendly_code, render_png, CaptchaOptions};
//!
//! let code = friendly_code();
//! let png = render_png(&code, &CaptchaOptions::new(1)).expect("captcha image");
//! assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
//! ```
//!
//! # Bounds
//!
//! | item | limit |
//! | --- | --- |
//! | code length | 4-7 characters |
//! | rendered glyphs | 8 |
//! | image | 64-1024 x 24-256 pixels, at most 1,000,000 pixels |
//! | WAV | 8 tones, 8,000 Hz mono, 8-bit |
//! | provider response | 16 KiB, 1-60 second timeout |

mod png;

use fador_core::json::Json;
use fador_core::random::random_bytes;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The characters a friendly code is drawn from: `A-Z` without `O`, and
/// `1-9` without `0`.
pub const FRIENDLY_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNPQRSTUVWXYZ123456789";
/// Shortest friendly code.
pub const MIN_CODE_LENGTH: usize = 4;
/// Longest friendly code.
pub const MAX_CODE_LENGTH: usize = 7;
/// Largest number of glyphs drawn into one image or played in one WAV.
pub const MAX_GLYPHS: usize = 8;
/// Default image width in pixels.
pub const DEFAULT_WIDTH: u32 = 320;
/// Default image height in pixels.
pub const DEFAULT_HEIGHT: u32 = 50;
/// Smallest image width accepted by [`render_png`].
pub const MIN_WIDTH: u32 = 64;
/// Largest image width accepted by [`render_png`].
pub const MAX_WIDTH: u32 = 1024;
/// Smallest image height accepted by [`render_png`].
pub const MIN_HEIGHT: u32 = 24;
/// Largest image height accepted by [`render_png`].
pub const MAX_HEIGHT: u32 = 256;

const MAX_PIXELS: u64 = 1_000_000;
const GLYPH_WIDTH: usize = 5;
const GLYPH_HEIGHT: usize = 7;
const WAV_SAMPLE_RATE: u32 = 8_000;
const WAV_TONE_SAMPLES: usize = 1_600;
const WAV_GAP_SAMPLES: usize = 400;
const VERIFY_RESPONSE_LIMIT: usize = 16 * 1024;

/// How much noise and distortion the image challenge carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Difficulty {
    /// Black glyphs on a white background with a frame.
    VerySimple,
    /// Coloured glyphs, light noise, a frame.
    #[default]
    Simple,
    /// Light background noise and per-glyph jitter.
    Medium,
    /// Dense noise, shear and mirrored glyphs.
    Hard,
    /// The densest noise, the strongest shear, the largest palette.
    Extreme,
}

impl Difficulty {
    /// The 1-5 level the old board stored as `visual_verification_type`.
    pub const fn level(self) -> u8 {
        match self {
            Self::VerySimple => 1,
            Self::Simple => 2,
            Self::Medium => 3,
            Self::Hard => 4,
            Self::Extreme => 5,
        }
    }

    /// Clamp a stored level into the supported range.
    pub const fn from_level(level: i64) -> Self {
        match level {
            i64::MIN..=1 => Self::VerySimple,
            2 => Self::Simple,
            3 => Self::Medium,
            4 => Self::Hard,
            _ => Self::Extreme,
        }
    }
}

/// Image challenge settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptchaOptions {
    /// Image width; clamped to [`MIN_WIDTH`]..=[`MAX_WIDTH`].
    pub width: u32,
    /// Image height; clamped to [`MIN_HEIGHT`]..=[`MAX_HEIGHT`].
    pub height: u32,
    /// Noise and distortion level.
    pub difficulty: Difficulty,
    /// Seed for the deterministic noise generator.
    pub seed: u64,
}

impl CaptchaOptions {
    /// Default-sized options with the given seed.
    pub const fn new(seed: u64) -> Self {
        Self {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            difficulty: Difficulty::Simple,
            seed,
        }
    }

    /// Set the image size.
    #[must_use]
    pub const fn size(mut self, width: u32, height: u32) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    /// Set the difficulty.
    #[must_use]
    pub const fn difficulty(mut self, difficulty: Difficulty) -> Self {
        self.difficulty = difficulty;
        self
    }
}

impl Default for CaptchaOptions {
    fn default() -> Self {
        Self::new(1)
    }
}

/// Draw a friendly code from the operating system random source.
pub fn friendly_code() -> String {
    let bytes = random_bytes(MAX_CODE_LENGTH + 1);
    friendly_code_from(&bytes)
}

/// Draw a friendly code from caller-supplied bytes.
///
/// The first byte selects the length and the remaining bytes select the
/// characters, so a test can pin the result. Empty input yields an empty
/// string.
pub fn friendly_code_from(bytes: &[u8]) -> String {
    let Some(first) = bytes.first() else {
        return String::new();
    };
    let length = MIN_CODE_LENGTH + usize::from(*first) % (MAX_CODE_LENGTH - MIN_CODE_LENGTH + 1);
    (0..length)
        .map(|index| {
            let byte = bytes[(index + 1) % bytes.len()];
            FRIENDLY_ALPHABET[usize::from(byte) % FRIENDLY_ALPHABET.len()] as char
        })
        .collect()
}

/// Render `code` as a grayscale PNG.
///
/// Characters without a glyph are skipped; a code with no drawable character
/// returns `None`. The same code, options and seed always produce the same
/// bytes.
pub fn render_png(code: &str, options: &CaptchaOptions) -> Option<Vec<u8>> {
    let width = options.width.clamp(MIN_WIDTH, MAX_WIDTH);
    let height = options.height.clamp(MIN_HEIGHT, MAX_HEIGHT);
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return None;
    }
    let glyphs = code
        .chars()
        .filter_map(glyph)
        .take(MAX_GLYPHS)
        .collect::<Vec<_>>();
    if glyphs.is_empty() {
        return None;
    }
    let level = options.difficulty.level();
    let mut rng = Rng::new(options.seed);
    let mut pixels = vec![0u8; width as usize * height as usize];
    for pixel in &mut pixels {
        *pixel = 140 + (rng.next() % 116) as u8;
    }

    let margin = 4u32;
    let scale = ((height.saturating_sub(margin * 2)) / GLYPH_HEIGHT as u32).max(1);
    let glyph_width = GLYPH_WIDTH as u32 * scale;
    let spacing = (scale / 2).max(1);
    let total_width = glyphs.len() as u32 * glyph_width + (glyphs.len() as u32 - 1) * spacing;
    let offset_x = if total_width < width {
        rng.below(width - total_width)
    } else {
        0
    };
    let offset_y = (height.saturating_sub(GLYPH_HEIGHT as u32 * scale)) / 2;
    let mut canvas = Canvas {
        pixels: &mut pixels,
        width,
        height,
    };

    if level <= 2 {
        for x in 0..width {
            canvas.put(i64::from(x), 0, 96);
            canvas.put(i64::from(x), i64::from(height) - 1, 96);
        }
        for y in 0..height {
            canvas.put(0, i64::from(y), 96);
            canvas.put(i64::from(width) - 1, i64::from(y), 96);
        }
    }
    if level >= 3 {
        let dots = 60 * u32::from(level - 2);
        for _ in 0..dots {
            let x = rng.range(0, i64::from(width) - 1);
            let y = rng.range(0, i64::from(height) - 1);
            let shade = rng.below(110) as u8;
            canvas.put(x, y, shade);
        }
        for _ in 0..level.saturating_sub(3) {
            let x0 = rng.range(0, i64::from(width) - 1);
            let y0 = rng.range(0, i64::from(height) - 1);
            let x1 = rng.range(0, i64::from(width) - 1);
            let y1 = rng.range(0, i64::from(height) - 1);
            let shade = rng.below(110) as u8;
            canvas.line(x0, y0, x1, y1, shade);
        }
    }

    for (index, rows) in glyphs.iter().enumerate() {
        let shade = if level <= 2 { 0 } else { rng.below(80) as u8 };
        let alpha = if level <= 3 { 200 } else { 255 };
        let slope = if level >= 4 { rng.range(-1, 1) } else { 0 };
        let jitter_x = if level >= 2 { rng.range(-1, 1) } else { 0 };
        let jitter_y = if level >= 2 { rng.range(-1, 1) } else { 0 };
        let reversed = level >= 4 && index % 2 == 0;
        let base_x = i64::from(offset_x + index as u32 * (glyph_width + spacing)) + jitter_x;
        let base_y = i64::from(offset_y) + jitter_y;
        for (row, bits) in rows.iter().enumerate() {
            let bits = if reversed {
                rows[GLYPH_HEIGHT - 1 - row]
            } else {
                *bits
            };
            for column in 0..GLYPH_WIDTH {
                let mask = 1u8 << (GLYPH_WIDTH - 1 - column);
                if bits & mask == 0 {
                    continue;
                }
                for dy in 0..i64::from(scale) {
                    for dx in 0..i64::from(scale) {
                        let x = base_x
                            + i64::from(column as u32 * scale)
                            + slope * (row as i64 - 3)
                            + dx;
                        let y = base_y + i64::from(row as u32 * scale) + dy;
                        canvas.blend(x, y, shade, alpha);
                    }
                }
            }
        }
    }
    png::encode_gray(width, height, &pixels)
}

/// Render `code` as an 8-bit mono WAV with one tone per character.
///
/// At most [`MAX_GLYPHS`] characters are played. An empty code yields one gap
/// of silence, so the result is always a complete WAV document.
pub fn render_wav(code: &str) -> Vec<u8> {
    let mut samples = Vec::new();
    for character in code.chars().take(MAX_GLYPHS) {
        let step = u32::from(character).wrapping_sub(u32::from('A'));
        let frequency = 300.0 + f64::from(step % 20) * 40.0;
        for index in 0..WAV_TONE_SAMPLES {
            let time = index as f64 / f64::from(WAV_SAMPLE_RATE);
            let sample = (2.0 * std::f64::consts::PI * frequency * time).sin();
            samples.push((128.0 + 64.0 * sample) as u8);
        }
        samples.extend(std::iter::repeat_n(128u8, WAV_GAP_SAMPLES));
    }
    if samples.is_empty() {
        samples.extend(std::iter::repeat_n(128u8, WAV_GAP_SAMPLES));
    }
    let data_length = samples.len() as u32;
    let mut out = Vec::with_capacity(samples.len() + 44);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_length).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&WAV_SAMPLE_RATE.to_le_bytes());
    out.extend_from_slice(&WAV_SAMPLE_RATE.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_length.to_le_bytes());
    out.extend_from_slice(&samples);
    out
}

/// A supported third-party challenge provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// Cloudflare Turnstile.
    Turnstile,
    /// hCaptcha.
    HCaptcha,
}

impl Provider {
    /// Resolve the provider name used in configuration.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "turnstile" => Some(Self::Turnstile),
            "hcaptcha" => Some(Self::HCaptcha),
            _ => None,
        }
    }

    /// The configuration name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Turnstile => "turnstile",
            Self::HCaptcha => "hcaptcha",
        }
    }

    /// The browser script URL. The server never contacts it.
    pub const fn script_url(self) -> &'static str {
        match self {
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/api.js",
            Self::HCaptcha => "https://js.hcaptcha.com/1/api.js",
        }
    }

    /// The widget container class the script scans for.
    pub const fn widget_class(self) -> &'static str {
        match self {
            Self::Turnstile => "cf-turnstile",
            Self::HCaptcha => "h-captcha",
        }
    }

    /// The hidden form field the widget fills with the response token.
    pub const fn response_field(self) -> &'static str {
        match self {
            Self::Turnstile => "cf-turnstile-response",
            Self::HCaptcha => "h-captcha-response",
        }
    }
}

/// A resolved provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    /// Which provider verifies the token.
    pub provider: Provider,
    /// The provider secret. It is never logged and never appears in an error.
    pub secret_key: String,
    /// Plain `http://` verifier endpoint.
    pub verify_url: String,
    /// Connect, read and write timeout, clamped to 1-60 seconds.
    pub timeout: Duration,
    /// Accept a submission when the verifier cannot be reached.
    ///
    /// This never applies to a rejected token or a configuration error; it
    /// only covers a transport failure.
    pub fail_open: bool,
}

impl ProviderConfig {
    /// A fail-closed configuration with a 10-second timeout.
    pub fn new(
        provider: Provider,
        secret_key: impl Into<String>,
        verify_url: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            secret_key: secret_key.into(),
            verify_url: verify_url.into(),
            timeout: Duration::from_secs(10),
            fail_open: false,
        }
    }

    /// Set the timeout. It is clamped when the request is made.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Accept a transport failure instead of rejecting the submission.
    #[must_use]
    pub fn fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }
}

/// A provider verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The form carried no response token, or a token above 8 KiB.
    MissingToken,
    /// The verifier could not be reached, timed out or answered garbage.
    Unavailable(String),
    /// The verifier URL or secret is unusable.
    Config(&'static str),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingToken => write!(formatter, "the challenge response token is missing"),
            Self::Unavailable(reason) => {
                write!(formatter, "the challenge verifier is unavailable: {reason}")
            }
            Self::Config(reason) => write!(
                formatter,
                "invalid challenge verifier configuration: {reason}"
            ),
        }
    }
}

impl std::error::Error for ProviderError {}

/// `http://host[:port][/path]` with no control character and a real host.
pub fn is_plain_http_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    if rest.is_empty() || rest.starts_with('/') {
        return false;
    }
    if url
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or("");
    !authority.is_empty()
}

/// Verify a provider response token.
///
/// Returns `Ok(true)` for a token the verifier accepted, `Ok(false)` for a
/// token it rejected, and an error when the verifier could not be asked. Use
/// [`accepts`] for the documented fail-closed policy.
pub fn verify_provider(
    config: &ProviderConfig,
    token: &str,
    remote_ip: &str,
) -> Result<bool, ProviderError> {
    if token.is_empty() || token.len() > 8_192 {
        return Err(ProviderError::MissingToken);
    }
    if config.secret_key.is_empty() {
        return Err(ProviderError::Config("the secret key is empty"));
    }
    if !is_plain_http_url(&config.verify_url) {
        return Err(ProviderError::Config(
            "the verifier URL is not a plain HTTP URL",
        ));
    }
    let body = format!(
        "secret={}&response={}&remoteip={}",
        url_encode(&config.secret_key),
        url_encode(token),
        url_encode(remote_ip)
    );
    let (status, payload) = post_plain_http(config, &body)?;
    if status != 200 {
        return Err(ProviderError::Unavailable(format!(
            "the verifier answered HTTP {status}"
        )));
    }
    match fador_core::json::parse(&payload) {
        Ok(Json::Object(fields)) => Ok(fields
            .iter()
            .find(|(name, _)| name == "success")
            .is_some_and(|(_, value)| matches!(value, Json::Bool(true)))),
        _ => Err(ProviderError::Unavailable(
            "the verifier did not answer a JSON object".into(),
        )),
    }
}

/// Apply the fail-closed policy to [`verify_provider`].
///
/// A rejected token is always rejected. A transport failure is accepted only
/// when [`ProviderConfig::fail_open`] is set, and a configuration error is
/// never accepted.
pub fn accepts(config: &ProviderConfig, token: &str, remote_ip: &str) -> bool {
    match verify_provider(config, token, remote_ip) {
        Ok(passed) => passed,
        Err(ProviderError::Unavailable(_)) => config.fail_open,
        Err(_) => false,
    }
}

fn post_plain_http(config: &ProviderConfig, body: &str) -> Result<(u16, String), ProviderError> {
    let url = config.verify_url.trim();
    let rest = url
        .strip_prefix("http://")
        .ok_or(ProviderError::Config("the verifier URL is not plain HTTP"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let (host, port) = split_authority(authority)
        .ok_or(ProviderError::Config("the verifier authority is invalid"))?;
    if host.is_empty() {
        return Err(ProviderError::Config("the verifier has no host"));
    }
    if host
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || path
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ProviderError::Config(
            "the verifier URL has a control character",
        ));
    }
    let timeout = config
        .timeout
        .clamp(Duration::from_secs(1), Duration::from_secs(60));
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|_| ProviderError::Unavailable("cannot resolve the verifier".into()))?
        .next()
        .ok_or_else(|| ProviderError::Unavailable("the verifier has no address".into()))?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|_| ProviderError::Unavailable("cannot reach the verifier".into()))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let host_header = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| ProviderError::Unavailable("the verifier write failed".into()))?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 4_096];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|_| ProviderError::Unavailable("the verifier read failed".into()))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if response.len() >= VERIFY_RESPONSE_LIMIT {
            return Err(ProviderError::Unavailable(
                "the verifier answer was too large".into(),
            ));
        }
    }
    let text = String::from_utf8(response)
        .map_err(|_| ProviderError::Unavailable("the verifier answer is not text".into()))?;
    let (head, payload) = text.split_once("\r\n\r\n").ok_or_else(|| {
        ProviderError::Unavailable("the verifier answer has no header block".into())
    })?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| ProviderError::Unavailable("the verifier status is invalid".into()))?;
    Ok((status, payload.to_string()))
}

fn split_authority(authority: &str) -> Option<(&str, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = if tail.is_empty() {
            80
        } else {
            tail.strip_prefix(':')?.parse().ok()?
        };
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?)),
        None => Some((authority, 80)),
    }
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A five by seven bitmap font for `A-Z` and `0-9`.
const GLYPHS: &[(u8, [u8; GLYPH_HEIGHT])] = &[
    (
        b'A',
        [
            0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
    ),
    (
        b'B',
        [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110,
        ],
    ),
    (
        b'C',
        [
            0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110,
        ],
    ),
    (
        b'D',
        [
            0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110,
        ],
    ),
    (
        b'E',
        [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
        ],
    ),
    (
        b'F',
        [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
    ),
    (
        b'G',
        [
            0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01111,
        ],
    ),
    (
        b'H',
        [
            0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
    ),
    (
        b'I',
        [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b11111,
        ],
    ),
    (
        b'J',
        [
            0b00111, 0b00010, 0b00010, 0b00010, 0b00010, 0b10010, 0b01100,
        ],
    ),
    (
        b'K',
        [
            0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001,
        ],
    ),
    (
        b'L',
        [
            0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111,
        ],
    ),
    (
        b'M',
        [
            0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001,
        ],
    ),
    (
        b'N',
        [
            0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001,
        ],
    ),
    (
        b'O',
        [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
    ),
    (
        b'P',
        [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
    ),
    (
        b'Q',
        [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101,
        ],
    ),
    (
        b'R',
        [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001,
        ],
    ),
    (
        b'S',
        [
            0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110,
        ],
    ),
    (
        b'T',
        [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
    ),
    (
        b'U',
        [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
    ),
    (
        b'V',
        [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100,
        ],
    ),
    (
        b'W',
        [
            0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001,
        ],
    ),
    (
        b'X',
        [
            0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001,
        ],
    ),
    (
        b'Y',
        [
            0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
    ),
    (
        b'Z',
        [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111,
        ],
    ),
    (
        b'0',
        [
            0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110,
        ],
    ),
    (
        b'1',
        [
            0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
    ),
    (
        b'2',
        [
            0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111,
        ],
    ),
    (
        b'3',
        [
            0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110,
        ],
    ),
    (
        b'4',
        [
            0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010,
        ],
    ),
    (
        b'5',
        [
            0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110,
        ],
    ),
    (
        b'6',
        [
            0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110,
        ],
    ),
    (
        b'7',
        [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000,
        ],
    ),
    (
        b'8',
        [
            0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110,
        ],
    ),
    (
        b'9',
        [
            0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100,
        ],
    ),
];

fn glyph(character: char) -> Option<&'static [u8; GLYPH_HEIGHT]> {
    let upper = character.to_ascii_uppercase();
    GLYPHS
        .iter()
        .find(|(known, _)| char::from(*known) == upper)
        .map(|(_, rows)| rows)
}

/// A bounded grayscale drawing surface.
struct Canvas<'a> {
    pixels: &'a mut [u8],
    width: u32,
    height: u32,
}

impl Canvas<'_> {
    fn put(&mut self, x: i64, y: i64, shade: u8) {
        if x < 0 || y < 0 || x >= i64::from(self.width) || y >= i64::from(self.height) {
            return;
        }
        let index = y as usize * self.width as usize + x as usize;
        self.pixels[index] = shade;
    }

    fn blend(&mut self, x: i64, y: i64, shade: u8, alpha: u8) {
        if x < 0 || y < 0 || x >= i64::from(self.width) || y >= i64::from(self.height) {
            return;
        }
        let index = y as usize * self.width as usize + x as usize;
        let mix = u32::from(alpha);
        let rest = 255 - mix;
        self.pixels[index] =
            ((u32::from(shade) * mix + u32::from(self.pixels[index]) * rest) / 255) as u8;
    }

    fn line(&mut self, x0: i64, y0: i64, x1: i64, y1: i64, shade: u8) {
        let steps = (x1 - x0).abs().max((y1 - y0).abs()).max(1);
        for step in 0..=steps {
            let x = x0 + (x1 - x0) * step / steps;
            let y = y0 + (y1 - y0) * step / steps;
            self.put(x, y, shade);
        }
    }
}

/// A small deterministic generator so a test can pin the picture.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    fn next(&mut self) -> u32 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        (value.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }

    fn below(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            0
        } else {
            self.next() % bound
        }
    }

    fn range(&mut self, low: i64, high: i64) -> i64 {
        if high <= low {
            return low;
        }
        low + i64::from(self.next()) % (high - low + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn friendly_codes_use_the_safe_alphabet() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let code = friendly_code();
            assert!((MIN_CODE_LENGTH..=MAX_CODE_LENGTH).contains(&code.len()));
            assert!(code
                .chars()
                .all(|character| { character.is_ascii_uppercase() || character.is_ascii_digit() }));
            assert!(!code.contains('O') && !code.contains('0'));
            seen.insert(code);
        }
        assert!(seen.len() > 150, "codes repeat too often");
    }

    #[test]
    fn friendly_code_from_bytes_is_deterministic() {
        assert_eq!(friendly_code_from(&[0]), "AAAA");
        assert_eq!(friendly_code_from(&[0, 0, 1, 2, 3]), "ABCD");
        assert_eq!(friendly_code_from(&[]), "");
        let long = vec![255u8; 16];
        let code = friendly_code_from(&long);
        assert_eq!(code.len(), MAX_CODE_LENGTH);
    }

    #[test]
    fn every_friendly_character_has_a_glyph() {
        for character in FRIENDLY_ALPHABET {
            assert!(
                glyph(char::from(*character)).is_some(),
                "missing {}",
                char::from(*character)
            );
        }
        assert!(glyph('o').is_some(), "lowercase letters map to uppercase");
        assert!(glyph('!').is_none());
    }

    fn chunks(png: &[u8]) -> Vec<(String, Vec<u8>)> {
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let mut position = 8usize;
        let mut out = Vec::new();
        while position + 12 <= png.len() {
            let length =
                u32::from_be_bytes(png[position..position + 4].try_into().unwrap()) as usize;
            let kind = &png[position + 4..position + 8];
            let data = &png[position + 8..position + 8 + length];
            let crc = u32::from_be_bytes(
                png[position + 8 + length..position + 12 + length]
                    .try_into()
                    .unwrap(),
            );
            let mut crc_input = Vec::new();
            crc_input.extend_from_slice(kind);
            crc_input.extend_from_slice(data);
            assert_eq!(crc, fador_core::crypto::crc32(&crc_input), "chunk CRC");
            out.push((String::from_utf8_lossy(kind).to_string(), data.to_vec()));
            position += 12 + length;
        }
        assert_eq!(position, png.len(), "trailing bytes");
        out
    }

    #[test]
    fn png_has_the_expected_signature_and_dimensions() {
        let png = render_png("ABCD", &CaptchaOptions::new(12_345)).expect("png");
        let chunks = chunks(&png);
        assert_eq!(chunks[0].0, "IHDR");
        let header = &chunks[0].1;
        assert_eq!(u32::from_be_bytes(header[0..4].try_into().unwrap()), 320);
        assert_eq!(u32::from_be_bytes(header[4..8].try_into().unwrap()), 50);
        assert_eq!(header[8], 8, "bit depth");
        assert_eq!(header[9], 0, "grayscale colour type");
        assert_eq!(header[10], 0);
        assert_eq!(header[11], 0);
        assert_eq!(header[12], 0);
        assert_eq!(chunks.last().map(|chunk| chunk.0.as_str()), Some("IEND"));
        let idat = chunks.iter().find(|chunk| chunk.0 == "IDAT").expect("IDAT");
        let raw = fador_compress::zlib_decompress(&idat.1).expect("zlib");
        assert_eq!(raw.len(), (320 + 1) * 50);
        assert!(raw.chunks(321).all(|row| row[0] == 0));
        assert!(
            raw.iter().any(|byte| *byte < 80),
            "the image has no dark glyph pixels"
        );
        assert!(
            raw.iter().any(|byte| *byte > 200),
            "the image has no light background pixels"
        );
    }

    #[test]
    fn png_is_deterministic_for_a_seed() {
        let options = CaptchaOptions::new(7).size(200, 60);
        let first = render_png("TEST12", &options).expect("first");
        let second = render_png("TEST12", &options).expect("second");
        assert_eq!(first, second);
        let other = render_png("TEST12", &CaptchaOptions::new(8).size(200, 60)).expect("other");
        assert_ne!(first, other);
    }

    #[test]
    fn png_rejects_codes_without_glyphs_and_clamps_sizes() {
        assert!(render_png("", &CaptchaOptions::default()).is_none());
        assert!(render_png("!!!", &CaptchaOptions::default()).is_none());
        let png = render_png("AB", &CaptchaOptions::new(1).size(1, 1_000_000)).expect("clamped");
        let chunks = chunks(&png);
        let header = &chunks[0].1;
        assert_eq!(
            u32::from_be_bytes(header[0..4].try_into().unwrap()),
            MIN_WIDTH
        );
        assert_eq!(
            u32::from_be_bytes(header[4..8].try_into().unwrap()),
            MAX_HEIGHT
        );
    }

    #[test]
    fn png_handles_every_difficulty() {
        for level in 1..=5 {
            let options = CaptchaOptions::new(level as u64)
                .difficulty(Difficulty::from_level(level))
                .size(180, 44);
            assert!(render_png("ABC123", &options).is_some(), "level {level}");
        }
        assert_eq!(Difficulty::from_level(0), Difficulty::VerySimple);
        assert_eq!(Difficulty::from_level(99), Difficulty::Extreme);
        assert_eq!(Difficulty::Extreme.level(), 5);
    }

    #[test]
    fn wav_header_is_well_formed() {
        let wav = render_wav("ABCD");
        assert_eq!(&wav[..4], b"RIFF");
        assert_eq!(
            u32::from_le_bytes(wav[4..8].try_into().unwrap()) as usize,
            wav.len() - 8
        );
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
        assert_eq!(u32::from_le_bytes(wav[16..20].try_into().unwrap()), 16);
        assert_eq!(u16::from_le_bytes(wav[20..22].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(wav[22..24].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(wav[24..28].try_into().unwrap()),
            WAV_SAMPLE_RATE
        );
        assert_eq!(
            u32::from_le_bytes(wav[28..32].try_into().unwrap()),
            WAV_SAMPLE_RATE
        );
        assert_eq!(u16::from_le_bytes(wav[32..34].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(wav[34..36].try_into().unwrap()), 8);
        assert_eq!(&wav[36..40], b"data");
        assert_eq!(
            u32::from_le_bytes(wav[40..44].try_into().unwrap()) as usize,
            wav.len() - 44
        );
        assert_eq!(wav.len() - 44, 4 * (WAV_TONE_SAMPLES + WAV_GAP_SAMPLES));
    }

    #[test]
    fn wav_is_bounded_and_never_empty() {
        let wav = render_wav("");
        assert_eq!(wav.len() - 44, WAV_GAP_SAMPLES);
        let long = render_wav(&"A".repeat(1_000));
        assert_eq!(
            long.len() - 44,
            MAX_GLYPHS * (WAV_TONE_SAMPLES + WAV_GAP_SAMPLES)
        );
        assert_eq!(render_wav("ABCD"), render_wav("ABCD"));
    }

    #[test]
    fn challenge_renderers_survive_hostile_codes() {
        let mut rng = fador_testutil::Rng::new(0xc0ffee);
        let small = CaptchaOptions::new(1).size(64, 24);
        for text in fador_testutil::MALICIOUS_STRINGS {
            let _ = render_png(text, &small);
            let _ = render_wav(text);
            let _ = friendly_code_from(text.as_bytes());
        }
        for _ in 0..fador_testutil::iterations(60) {
            let length = 1 + rng.below(40);
            let text = rng.text(length);
            let seed = rng.next_u64();
            let _ = render_png(&text, &CaptchaOptions::new(seed).size(64, 24));
            let _ = render_wav(&text);
        }
    }

    #[test]
    fn provider_metadata_is_stable() {
        assert_eq!(Provider::from_name("turnstile"), Some(Provider::Turnstile));
        assert_eq!(Provider::from_name("hcaptcha"), Some(Provider::HCaptcha));
        assert_eq!(Provider::from_name("recaptcha"), None);
        assert_eq!(
            Provider::Turnstile.response_field(),
            "cf-turnstile-response"
        );
        assert_eq!(Provider::HCaptcha.widget_class(), "h-captcha");
        assert_eq!(
            Provider::HCaptcha.script_url(),
            "https://js.hcaptcha.com/1/api.js"
        );
        assert!(is_plain_http_url("http://127.0.0.1:8080/verify"));
        assert!(!is_plain_http_url("https://example.test/verify"));
        assert!(!is_plain_http_url("http:///verify"));
        assert!(!is_plain_http_url("http://host/verify\r\n"));
    }

    /// One scripted verifier. Returns the port and the received request text.
    fn verifier(response: &'static str) -> (u16, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let mut request = Vec::new();
            let mut buffer = [0u8; 4_096];
            let mut body_length = 0usize;
            loop {
                let read = stream.read(&mut buffer).expect("read");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(position) = find_bytes(&request, b"\r\n\r\n") {
                    if body_length == 0 {
                        body_length = content_length(&request[..position]).unwrap_or(0);
                    }
                    if request.len() >= position + 4 + body_length {
                        break;
                    }
                }
            }
            stream.write_all(response.as_bytes()).expect("write");
            String::from_utf8_lossy(&request).to_string()
        });
        (port, handle)
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn content_length(head: &[u8]) -> Option<usize> {
        let text = String::from_utf8_lossy(head);
        text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
    }

    fn config(port: u16) -> ProviderConfig {
        ProviderConfig::new(
            Provider::Turnstile,
            "s3cr3t",
            format!("http://127.0.0.1:{port}/verify"),
        )
        .timeout(Duration::from_secs(5))
    }

    #[test]
    fn provider_accepts_a_successful_verification() {
        let (port, server) = verifier(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: 16\r\nConnection: close\r\n\r\n{\"success\":true}",
        );
        assert_eq!(
            verify_provider(&config(port), "token value", "127.0.0.1"),
            Ok(true)
        );
        let request = server.join().expect("server");
        assert!(request.starts_with("POST /verify HTTP/1.1\r\n"));
        assert!(request.contains("Host: 127.0.0.1:"));
        assert!(request.contains("secret=s3cr3t"));
        assert!(request.contains("response=token+value"));
        assert!(request.contains("remoteip=127.0.0.1"));
    }

    #[test]
    fn provider_rejects_a_failed_verification() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Connection: close\r\n\r\n{\"success\":false}";
        let (port, server) = verifier(response);
        assert_eq!(
            verify_provider(&config(port), "token", "127.0.0.1"),
            Ok(false)
        );
        let _ = server.join();
        let (port, server) = verifier(response);
        assert!(!accepts(&config(port), "token", "127.0.0.1"));
        let _ = server.join();
    }

    #[test]
    fn provider_reports_garbage_and_http_errors() {
        let (port, server) = verifier("HTTP/1.1 200 OK\r\n\r\nnot json");
        assert!(matches!(
            verify_provider(&config(port), "token", "127.0.0.1"),
            Err(ProviderError::Unavailable(_))
        ));
        let _ = server.join();

        let (port, server) = verifier("HTTP/1.1 500 Internal Server Error\r\n\r\n");
        assert!(matches!(
            verify_provider(&config(port), "token", "127.0.0.1"),
            Err(ProviderError::Unavailable(_))
        ));
        let _ = server.join();
    }

    #[test]
    fn provider_fails_closed_when_the_verifier_is_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().expect("accept");
                drop(stream);
            }
        });
        let closed = config(port);
        assert!(matches!(
            verify_provider(&closed, "token", "127.0.0.1"),
            Err(ProviderError::Unavailable(_))
        ));
        assert!(!accepts(&closed, "token", "127.0.0.1"));
        let open = closed.clone().fail_open(true);
        assert!(accepts(&open, "token", "127.0.0.1"));
        server.join().expect("server");
        // A configuration error is never accepted, even with fail_open.
        let broken =
            ProviderConfig::new(Provider::HCaptcha, "secret", "https://example.test/verify")
                .fail_open(true);
        assert!(!accepts(&broken, "token", "127.0.0.1"));
    }

    #[test]
    fn provider_requires_a_token_and_a_secret() {
        let config =
            ProviderConfig::new(Provider::Turnstile, "secret", "http://127.0.0.1:9/verify");
        assert_eq!(
            verify_provider(&config, "", "127.0.0.1"),
            Err(ProviderError::MissingToken)
        );
        assert_eq!(
            verify_provider(&config, &"x".repeat(9_000), "127.0.0.1"),
            Err(ProviderError::MissingToken)
        );
        let empty_secret =
            ProviderConfig::new(Provider::Turnstile, "", "http://127.0.0.1:9/verify");
        assert!(matches!(
            verify_provider(&empty_secret, "token", "127.0.0.1"),
            Err(ProviderError::Config(_))
        ));
        assert!(!accepts(&empty_secret, "token", "127.0.0.1"));
    }
}
