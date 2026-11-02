//! Small, dependency-free helpers shared by the rest of the server.
//!
//! Everything in here is deliberately allocation-conscious: the HTTP and
//! wikitext hot paths call these functions many times per request.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

/// Escape text for use in HTML text and quoted attribute values.
///
/// MediaWiki's Sanitizer escapes the same five characters.  `'` is encoded as
/// `&#039;` which is what MediaWiki emits for attributes.
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#039;"),
            _ => out.push(ch),
        }
    }
    out
}

/// SMF-compatible `htmlspecialchars($value, ENT_COMPAT)`.
/// Single quotes are deliberately left alone; using [`html_escape`] for stored
/// board text would change every apostrophe in the rendered output.
pub fn html_escape_compat(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\0' => out.push('\u{fffd}'),
            _ => out.push(ch),
        }
    }
    out
}

/// SMF's `un_htmlspecialchars()`: the inverse of [`html_escape`].
pub fn html_unescape_compat(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#039;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// Escape a string for a JavaScript string literal.  Only the fuzz tests need
/// this helper; production JavaScript comes from the original assets.
#[cfg(test)]
/// Escape a string for a single-quoted JavaScript literal.
pub fn js_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003C"),
            '>' => out.push_str("\\u003E"),
            '&' => out.push_str("\\u0026"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            _ => out.push(ch),
        }
    }
    out
}

/// Percent-encode a title the way MediaWiki does for local URLs.
///
/// Spaces become underscores, slashes and colons are kept (so subpages and
/// namespaces work), and all other non-ASCII bytes are percent encoded.
pub fn encode_title(title: &str) -> String {
    let mut out = String::with_capacity(title.len() + 8);
    for ch in title.chars() {
        match ch {
            ' ' => out.push('_'),
            '_' | '-' | '.' | ':' | '/' | '~' | ';' | '@' | '$' | '!' | '*' | '(' | ')' | ',' => {
                out.push(ch)
            }
            c if c.is_ascii_alphanumeric() => out.push(c),
            c if c.is_ascii() => {
                let b = c as u8;
                push_pct(&mut out, b);
            }
            c => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).as_bytes() {
                    push_pct(&mut out, *b);
                }
            }
        }
    }
    out
}

fn push_pct(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 0xf) as usize] as char);
}

/// Percent-decode a URL component.  Invalid escapes are passed through.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((a << 4) | b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// RFC 3986 percent encoding, matching PHP's `rawurlencode`.
pub fn rawurlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX_UPPER[(byte >> 4) as usize] as char);
            out.push(HEX_UPPER[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

/// PHP-compatible `urlencode` (spaces become `+`).
pub fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            out.push(byte as char);
        } else if byte == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(HEX_UPPER[(byte >> 4) as usize] as char);
            out.push(HEX_UPPER[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Decode one hexadecimal digit.
pub fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a `application/x-www-form-urlencoded` body into key/value pairs.
///
/// The field count is capped even though request bodies are already bounded:
/// a body made only of `&` separators would otherwise create a large number of
/// tiny allocations for no legitimate reason.
pub fn parse_form(input: &[u8]) -> Vec<(String, String)> {
    const MAX_FORM_FIELDS: usize = 4_096;
    let text = String::from_utf8_lossy(input);
    let mut out = Vec::new();
    for pair in text.split('&').take(MAX_FORM_FIELDS) {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.push((
            percent_decode(&k.replace('+', " ")),
            percent_decode(&v.replace('+', " ")),
        ));
    }
    out
}

/// Normalize a title the way MediaWiki's Title class does for the common
/// cases we care about: trim, underscores, collapse whitespace, capitalize
/// the first character and reject characters that cannot be in a title.
pub fn normalize_title_text(input: &str) -> Option<String> {
    let mut s = input.trim().replace('_', " ");
    // Collapse runs of whitespace to a single space.
    let mut collapsed = String::with_capacity(s.len());
    let mut last_space = false;
    for ch in s.drain(..) {
        if ch.is_whitespace() {
            if !last_space {
                collapsed.push(' ');
                last_space = true;
            }
        } else {
            collapsed.push(ch);
            last_space = false;
        }
    }
    let mut out = collapsed.trim().to_string();
    // Remove invisible formatting characters rather than rejecting titles such
    // as "Tiedosto:Kyuubi.jpg\u{200e}" which the old editor inserted.
    out.retain(|ch| {
        !matches!(
            ch,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
                | '\u{00ad}'
        )
    });
    let mut out = out.trim().to_string();
    if out.is_empty() {
        return None;
    }
    if out.len() > 255 {
        return None;
    }
    for ch in out.chars() {
        if ch.is_control() || matches!(ch, '#' | '<' | '>' | '[' | ']' | '{' | '}' | '|') {
            return None;
        }
    }
    // MediaWiki uppercases the first character (Unicode-aware).
    let mut chars = out.chars();
    if let Some(first) = chars.next() {
        let mut result = String::with_capacity(out.len());
        for c in first.to_uppercase() {
            result.push(c);
        }
        result.push_str(chars.as_str());
        out = result;
    }
    Some(out)
}

/// Normalize browser and legacy line endings to MediaWiki's `\n`.
///
/// Browsers submit `<textarea>` contents with CRLF line endings even when the
/// document used LF.  Storing that text verbatim makes every line differ from
/// the previous revision, so diffs show the whole page as changed.
pub fn normalize_line_endings(text: &str) -> Cow<'_, str> {
    if !text.contains('\r') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

/// Convert a display title to the canonical database form (underscores).
pub fn title_to_db(title: &str) -> String {
    title.replace(' ', "_")
}

/// Build an HTML5-safe fragment identifier.
pub fn anchor_html5(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            ' ' => out.push('_'),
            c if c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') => out.push(c),
            _ => {}
        }
    }
    if out.is_empty() {
        "section".into()
    } else {
        out
    }
}

const CP1252_HIGH: [(u8, char); 27] = [
    (0x80, '\u{20ac}'),
    (0x82, '\u{201a}'),
    (0x83, '\u{0192}'),
    (0x84, '\u{201e}'),
    (0x85, '\u{2026}'),
    (0x86, '\u{2020}'),
    (0x87, '\u{2021}'),
    (0x88, '\u{02c6}'),
    (0x89, '\u{2030}'),
    (0x8a, '\u{0160}'),
    (0x8b, '\u{2039}'),
    (0x8c, '\u{0152}'),
    (0x8e, '\u{017d}'),
    (0x91, '\u{2018}'),
    (0x92, '\u{2019}'),
    (0x93, '\u{201c}'),
    (0x94, '\u{201d}'),
    (0x95, '\u{2022}'),
    (0x96, '\u{2013}'),
    (0x97, '\u{2014}'),
    (0x98, '\u{02dc}'),
    (0x99, '\u{2122}'),
    (0x9a, '\u{0161}'),
    (0x9b, '\u{203a}'),
    (0x9c, '\u{0153}'),
    (0x9e, '\u{017e}'),
    (0x9f, '\u{0178}'),
];

fn cp1252_char(b: u8) -> char {
    for (byte, ch) in CP1252_HIGH {
        if byte == b {
            return ch;
        }
    }
    char::from(b)
}

fn cp1252_byte(ch: char) -> Option<u8> {
    for (byte, mapped) in CP1252_HIGH {
        if mapped == ch {
            return Some(byte);
        }
    }
    let cp = ch as u32;
    if cp <= 0xff {
        Some(cp as u8)
    } else {
        None
    }
}

/// Interpret the UTF-8 bytes of `s` as Windows-1252 characters.  This is the
/// corruption produced by old Latin-1/UTF-8 double-encoding.
fn encode_as_cp1252_chars(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if (0x80..=0x9f).contains(&b) && !CP1252_HIGH.iter().any(|(x, _)| *x == b) {
            return None;
        }
        out.push(cp1252_char(b));
    }
    Some(out)
}

fn decode_cp1252_chars(s: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(s.len());
    for ch in s.chars() {
        bytes.push(cp1252_byte(ch)?);
    }
    String::from_utf8(bytes).ok()
}

/// Repair common MediaWiki mojibake (`KylÃ¤t` -> `Kylät`).  It only transforms
/// when the characters form a valid UTF-8 sequence, so ordinary Finnish text
/// is left alone.
pub fn repair_mojibake(s: &str) -> String {
    let mut text = s.to_string();
    for _ in 0..4 {
        if text.is_ascii() {
            break;
        }
        let Some(decoded) = decode_cp1252_chars(&text) else {
            break;
        };
        if decoded == text
            || decoded.contains('\u{fffd}')
            || decoded
                .chars()
                .any(|c| (c as u32) < 0x20 && c != '\n' && c != '\t')
        {
            break;
        }
        text = decoded;
    }
    text
}

/// Variants of a correct title, encoded the way the legacy database may have
/// stored it (`Kylät`, `KylÃ¤t`, `KylÃƒÂ¤t`).
pub fn mojibake_variants(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = s.to_string();
    if !out.contains(&current) {
        out.push(current.clone());
    }
    for _ in 0..3 {
        let Some(next) = encode_as_cp1252_chars(&current) else {
            break;
        };
        if next == current || out.contains(&next) {
            break;
        }
        out.push(next.clone());
        current = next;
    }
    out
}

/// Percent-encode a fragment identifier.
pub fn anchor_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            ' ' => out.push('_'),
            c if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') => out.push(c),
            c => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    out.push('.');
                    out.push_str(&format!("{b:02X}"));
                }
            }
        }
    }
    if out.is_empty() {
        "section".into()
    } else {
        out
    }
}

/// Days since Unix epoch to a civil date (Howard Hinnant's algorithm).
pub fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((y + if m <= 2 { 1 } else { 0 }) as i32, m, d)
}

/// Days since Unix epoch from a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = i64::from(year) - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = i64::from(month);
    let d = i64::from(day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe as i64 * 365 + yoe as i64 / 4 - yoe as i64 / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Day of the week for a Unix day: 0 = Sunday through 6 = Saturday.
pub fn weekday_from_days(days: i64) -> usize {
    (days + 4).rem_euclid(7) as usize
}

/// Return the current UTC date and time parts.
pub fn now_parts() -> (i32, u32, u32, u32, u32, u32, u64) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
        secs,
    )
}

/// Current UTC time in MediaWiki's 14-digit timestamp format.
pub fn mw_timestamp_now() -> String {
    let (y, m, d, h, min, s, _) = now_parts();
    format!("{y:04}{m:02}{d:02}{h:02}{min:02}{s:02}")
}

/// UTC time `seconds` in the future in MediaWiki's 14-digit format.
pub fn mw_timestamp_after(seconds: u64) -> String {
    let (_, _, _, _, _, _, now) = now_parts();
    let (y, m, d, h, min, s) = timestamp_parts(now.saturating_add(seconds));
    format!("{y:04}{m:02}{d:02}{h:02}{min:02}{s:02}")
}

fn timestamp_parts(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

/// RFC 7231 IMF-fixdate, e.g. `Thu, 22 Oct 2026 11:07:32 GMT`.
pub fn http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // 1970-01-01 was a Thursday.
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    let wd = ((days % 7 + 7) % 7) as usize;
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[wd],
        d,
        MONTHS[(m - 1) as usize],
        y,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Current time as HTTP date.
pub fn now_http_date() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    http_date(secs)
}

/// Parse the HTTP date formats used by browsers for conditional requests.
pub fn parse_http_date(input: &str) -> Option<u64> {
    let input = input.trim();
    // IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
    if let Some(rest) = input.split_once(", ") {
        let parts: Vec<&str> = rest.1.split_whitespace().collect();
        if parts.len() == 5 && parts[4] == "GMT" {
            let day = parts[0].parse::<u32>().ok()?;
            let month = month_number(parts[1])?;
            let year = parts[2].parse::<i32>().ok()?;
            let (hour, minute, second) = parse_clock(parts[3])?;
            return civil_to_epoch(year, month, day, hour, minute, second);
        }
    }
    // RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
    if let Some((_, rest)) = input.split_once(", ") {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() == 3 && parts[2] == "GMT" {
            let date_parts: Vec<&str> = parts[0].split('-').collect();
            if date_parts.len() == 3 {
                let day = date_parts[0].parse::<u32>().ok()?;
                let month = month_number(date_parts[1])?;
                let mut year = date_parts[2].parse::<i32>().ok()?;
                if year < 100 {
                    year += if year < 70 { 2000 } else { 1900 };
                }
                let (hour, minute, second) = parse_clock(parts[1])?;
                return civil_to_epoch(year, month, day, hour, minute, second);
            }
        }
    }
    // asctime: Sun Nov  6 08:49:37 1994
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() == 5 {
        let month = month_number(parts[1])?;
        let day = parts[2].parse::<u32>().ok()?;
        let (hour, minute, second) = parse_clock(parts[3])?;
        let year = parts[4].parse::<i32>().ok()?;
        return civil_to_epoch(year, month, day, hour, minute, second);
    }
    None
}

fn month_number(name: &str) -> Option<u32> {
    Some(match name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn parse_clock(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

fn civil_to_epoch(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = month as i32 + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as i64 * 146_097 + doe as i64 - 719_468;
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// MediaWiki timestamp (`YYYYMMDDHHMMSS`) to (year, month, day, hour, min, sec).
pub fn parse_mw_timestamp(ts: &str) -> Option<(i32, u32, u32, u32, u32, u32)> {
    if ts.len() < 14 || !ts.as_bytes()[..14].iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((
        ts[0..4].parse().ok()?,
        ts[4..6].parse().ok()?,
        ts[6..8].parse().ok()?,
        ts[8..10].parse().ok()?,
        ts[10..12].parse().ok()?,
        ts[12..14].parse().ok()?,
    ))
}

#[cfg(test)]
/// Truncate a string at a UTF-8 boundary and at most `max` bytes.
pub fn truncate_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Convert a UTF-8 string to a filesystem-safe representation.  Test-only:
/// uploads use the stricter `normalize_upload_name` in `app.rs`.
#[cfg(test)]
/// Replace unsafe file-name characters with `_`.
pub fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ' ') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

/// The default binary byte units.
pub const BINARY_UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
/// The Finnish byte units used by the original boards.
pub const FINNISH_UNITS: [&str; 5] = ["tavua", "kt", "Mt", "Gt", "Tt"];

/// Format a byte count with binary units (B, KiB, MiB, GiB, TiB).
pub fn format_bytes(n: u64) -> String {
    format_bytes_with_units(n, &BINARY_UNITS)
}

/// Format a byte count with caller-supplied binary units.
///
/// The units are ordered from bytes to terabytes and must contain five entries.
pub fn format_bytes_with_units(n: u64, units: &[&str; 5]) -> String {
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", n, units[0])
    } else if value >= 100.0 {
        format!("{:.0} {}", value, units[unit])
    } else if value >= 10.0 {
        format!("{:.1} {}", value, units[unit])
    } else {
        format!("{:.2} {}", value, units[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rng, MALICIOUS_STRINGS};

    fn assert_html_escaped(input: &str) -> String {
        let output = html_escape(input);
        assert!(!output.contains('<'), "raw '<' in {output:?}");
        assert!(!output.contains('>'), "raw '>' in {output:?}");
        assert!(!output.contains('"'), "raw quote in {output:?}");
        assert!(!output.contains('\''), "raw apostrophe in {output:?}");
        let bytes = output.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'&' {
                assert!(
                    output[i..].starts_with("&amp;")
                        || output[i..].starts_with("&lt;")
                        || output[i..].starts_with("&gt;")
                        || output[i..].starts_with("&quot;")
                        || output[i..].starts_with("&#039;"),
                    "unescaped ampersand in {output:?}"
                );
            }
            i += 1;
        }
        output
    }

    #[test]
    fn fuzz_html_and_javascript_escaping() {
        let mut rng = Rng::new(0xfeed_0001);
        for _ in 0..2_000 {
            let len = rng.below(120);
            let input = rng.text(len);
            assert_html_escaped(&input);
            let js = js_escape(&input);
            assert!(!js.contains('<') && !js.contains('>') && !js.contains('&'));
            assert!(!js.contains("</script"), "{js:?}");
        }
        for input in MALICIOUS_STRINGS {
            assert_html_escaped(input);
            let js = js_escape(input);
            assert!(!js.to_ascii_lowercase().contains("</script"));
        }
    }

    #[test]
    fn fuzz_title_url_roundtrip() {
        let mut rng = Rng::new(0xfeed_0002);
        for _ in 0..2_000 {
            let len = rng.below(120);
            let input = rng.text(len);
            let encoded = encode_title(&input);
            assert!(
                encoded.is_ascii(),
                "encode_title produced non-ASCII output for {input:?}"
            );
            assert_eq!(
                percent_decode(&encoded),
                input.replace(' ', "_"),
                "title URL roundtrip failed for {input:?}"
            );
        }
        for input in MALICIOUS_STRINGS {
            let encoded = encode_title(input);
            assert!(encoded.is_ascii());
            assert_eq!(percent_decode(&encoded), input.replace(' ', "_"));
        }
    }

    #[test]
    fn fuzz_title_normalization_never_returns_unsafe_text() {
        let mut rng = Rng::new(0xfeed_0003);
        let check = |input: &str| {
            if let Some(out) = normalize_title_text(input) {
                assert!(!out.is_empty());
                assert!(out.len() <= 255);
                assert_eq!(out, out.trim());
                assert!(!out.chars().any(char::is_control));
                assert!(!out
                    .chars()
                    .any(|c| matches!(c, '#' | '<' | '>' | '[' | ']' | '{' | '}' | '|')));
                let first = out.chars().next().unwrap();
                let uppercase: String = first.to_uppercase().collect();
                assert!(
                    out.starts_with(&uppercase),
                    "first character was not uppercased: {out:?}"
                );
            }
        };
        for _ in 0..2_000 {
            let len = rng.below(320);
            let input = rng.text(len);
            check(&input);
        }
        for input in MALICIOUS_STRINGS {
            check(input);
        }
    }

    #[test]
    fn fuzz_other_text_helpers_never_emit_unsafe_paths() {
        let mut rng = Rng::new(0xfeed_0004);
        for _ in 0..1_000 {
            let len = rng.below(160);
            let input = rng.text(len);
            let anchor = anchor_encode(&input);
            assert!(!anchor.is_empty());
            assert!(anchor.is_ascii());
            assert!(!anchor.chars().any(char::is_control));

            let filename = sanitize_filename(&input);
            assert!(filename
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ')));

            let max = rng.below(input.len() + 1);
            let truncated = truncate_bytes(&input, max);
            assert!(truncated.len() <= max);
            assert!(input.starts_with(truncated));

            let repaired = repair_mojibake(&input);
            assert!(!repaired.chars().any(|c| c == '\u{fffd}'));
        }
        for input in MALICIOUS_STRINGS {
            let _ = anchor_encode(input);
            let _ = sanitize_filename(input);
            let _ = repair_mojibake(input);
        }
    }

    #[test]
    fn fuzz_form_parser_accepts_arbitrary_bytes() {
        let mut rng = Rng::new(0xfeed_0005);
        for _ in 0..2_000 {
            let len = rng.below(512);
            let input = rng.bytes(len);
            let pairs = parse_form(&input);
            assert!(pairs.len() <= 4_096);
            for (key, value) in pairs {
                assert!(key.len() <= input.len().saturating_mul(3) + 3);
                assert!(value.len() <= input.len().saturating_mul(3) + 3);
            }
        }
        let flood = "a=1&".repeat(20_000);
        assert_eq!(parse_form(flood.as_bytes()).len(), 4_096);
    }

    #[test]
    fn escapes_html() {
        assert_eq!(
            html_escape("<a href=\"x\">'&"),
            "&lt;a href=&quot;x&quot;&gt;&#039;&amp;"
        );
    }

    #[test]
    fn compat_escape_matches_ent_compat() {
        assert_eq!(
            html_escape_compat("<a href=\"x\">'&"),
            "&lt;a href=&quot;x&quot;&gt;'&amp;"
        );
    }

    #[test]
    fn compat_escape_normalises_nul() {
        assert_eq!(html_escape_compat("a\0b"), "a\u{fffd}b");
    }

    #[test]
    fn formats_bytes_with_either_unit_set() {
        assert_eq!(format_bytes(1536), "1.50 KiB");
        assert_eq!(format_bytes_with_units(1536, &FINNISH_UNITS), "1.50 kt");
        assert_eq!(format_bytes_with_units(0, &FINNISH_UNITS), "0 tavua");
    }

    #[test]
    fn encodes_titles() {
        assert_eq!(encode_title("Naruto Uzumaki"), "Naruto_Uzumaki");
        assert_eq!(encode_title("Luokka:Naruto"), "Luokka:Naruto");
        assert_eq!(encode_title("Ääkkösiä"), "%C3%84%C3%A4kk%C3%B6si%C3%A4");
    }

    #[test]
    fn normalizes_titles() {
        assert_eq!(
            normalize_title_text("  naruto   uzumaki  ").as_deref(),
            Some("Naruto uzumaki")
        );
        assert!(normalize_title_text("a|b").is_none());
        assert_eq!(
            normalize_title_text("Kyuubi.jpg\u{200e}").as_deref(),
            Some("Kyuubi.jpg")
        );
    }

    #[test]
    fn normalizes_line_endings() {
        assert_eq!(normalize_line_endings("a\r\nb\rc\nd"), "a\nb\nc\nd");
        assert_eq!(normalize_line_endings("a\r\r\nb"), "a\n\nb");
        assert_eq!(normalize_line_endings("\r\n\r"), "\n\n");
        assert_eq!(normalize_line_endings("no breaks"), "no breaks");
        assert_eq!(normalize_line_endings(""), "");
    }

    #[test]
    fn date_conversion() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        for days in [-10_000i64, -1, 0, 1, 7_300, 20_000] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
        assert_eq!(weekday_from_days(0), 4); // Thursday
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(parse_http_date("not a date"), None);
        assert_eq!(parse_http_date("Thu, 31 Feb 2026 00:00:00 GMT"), None);
    }

    #[test]
    fn repairs_double_encoded_finnish() {
        let variants = mojibake_variants("Kylät");
        assert_eq!(variants[0], "Kylät");
        assert!(variants.len() >= 3);
        let last = variants.last().unwrap();
        assert_eq!(repair_mojibake(last), "Kylät");
        assert_eq!(repair_mojibake(&variants[1]), "Kylät");
        assert_eq!(repair_mojibake("Sisältö"), "Sisältö");
    }
}
