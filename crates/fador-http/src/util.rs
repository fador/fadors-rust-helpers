//! Small HTTP-local helpers.
//!
//! Keeping these here makes the server crate depend only on `std`, so it can be
//! reused without pulling in an application.

use crate::FormSeparators;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hard upper bound on the number of fields one form body may produce.
const MAX_FORM_FIELDS: usize = 4_096;

/// Percent-decode a URL component. Invalid escapes are preserved literally.
pub(crate) fn percent_decode(input: &str) -> String {
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

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse `application/x-www-form-urlencoded` data with a bounded field count.
///
/// Only `&` separates fields; use [`parse_form_with`] for the legacy PHP
/// `arg_separator.input` behaviour that also splits on `;`. Repeated names are
/// preserved in order and a pair without `=` yields an empty value.
pub fn parse_form(input: &[u8]) -> Vec<(String, String)> {
    parse_form_with(input, FormSeparators::default())
}

/// Parse urlencoded data with the caller's separator policy.
pub fn parse_form_with(input: &[u8], separators: FormSeparators) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(input);
    let mut out = Vec::new();
    let split =
        |ch: char| (ch == '&' && separators.ampersand) || (ch == ';' && separators.semicolon);
    for pair in text.split(split).take(MAX_FORM_FIELDS) {
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

/// Parse a bounded `multipart/form-data` body into its text fields.
///
/// File parts (`Content-Disposition` with a `filename` parameter) are skipped;
/// upload handlers parse them separately from [`Request::body`]. A missing,
/// empty or malformed boundary yields an empty vector, never a panic, and the
/// number of returned fields is capped at 4,096.
///
/// [`Request::body`]: crate::Request::body
pub(crate) fn parse_multipart_form(content_type: &str, body: &[u8]) -> Vec<(String, String)> {
    let Some(boundary) = multipart_boundary(content_type) else {
        return Vec::new();
    };
    if boundary.is_empty()
        || boundary.len() > 70
        || boundary.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
    {
        return Vec::new();
    }
    let mut delimiter = Vec::with_capacity(boundary.len() + 4);
    delimiter.extend_from_slice(b"--");
    delimiter.extend_from_slice(boundary.as_bytes());
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while out.len() < MAX_FORM_FIELDS {
        let Some(relative) = find_bytes(&body[cursor..], &delimiter) else {
            break;
        };
        let mut part_start = cursor + relative + delimiter.len();
        if body.get(part_start..part_start + 2) == Some(b"--") {
            break;
        }
        if body.get(part_start..part_start + 2) == Some(b"\r\n") {
            part_start += 2;
        } else if body.get(part_start..part_start + 1) == Some(b"\n") {
            part_start += 1;
        }
        let Some(header_end) = find_bytes(&body[part_start..], b"\r\n\r\n") else {
            break;
        };
        let header_block = String::from_utf8_lossy(&body[part_start..part_start + header_end]);
        let value_start = part_start + header_end + 4;
        let Some(next) = find_bytes(&body[value_start..], &delimiter) else {
            break;
        };
        let mut value_end = value_start + next;
        if value_end > value_start && body[value_end - 1] == b'\n' {
            value_end -= 1;
            if value_end > value_start && body[value_end - 1] == b'\r' {
                value_end -= 1;
            }
        }
        let mut name = None;
        let mut is_file = false;
        for line in header_block.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if !key.trim().eq_ignore_ascii_case("content-disposition") {
                continue;
            }
            for piece in value.split(';') {
                let piece = piece.trim();
                if let Some(rest) = piece.strip_prefix("name=") {
                    name = Some(rest.trim_matches('"').to_string());
                } else if piece.starts_with("filename=") {
                    is_file = true;
                }
            }
        }
        if let Some(name) = name {
            if !is_file && !name.is_empty() && name.len() <= 255 {
                out.push((
                    name,
                    String::from_utf8_lossy(&body[value_start..value_end]).to_string(),
                ));
            }
        }
        cursor = value_start + next;
    }
    out
}

/// Extract the `boundary` parameter of a `multipart/form-data` content type.
fn multipart_boundary(content_type: &str) -> Option<String> {
    for piece in content_type.split(';').skip(1) {
        let Some((key, value)) = piece.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or(value);
        return Some(value.to_string());
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((y + if m <= 2 { 1 } else { 0 }) as i32, m, d)
}

/// RFC 7231 IMF-fixdate, e.g. `Thu, 22 Oct 2026 11:07:32 GMT`.
pub(crate) fn http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
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

pub(crate) fn now_http_date() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    http_date(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multipart_fields_and_ignores_files() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"group_name\"\r\n\r\nTestiryhm\xc3\xa4\r\n--XyZ\r\nContent-Disposition: form-data; name=\"group_desc\"\r\n\r\nHei\r\nmaailma\r\n--XyZ\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n--XyZ--\r\n";
        let fields = parse_multipart_form("multipart/form-data; boundary=XyZ", body);
        assert_eq!(
            fields,
            vec![
                ("group_name".to_string(), "Testiryhm\u{e4}".to_string()),
                ("group_desc".to_string(), "Hei\r\nmaailma".to_string()),
            ]
        );
    }

    #[test]
    fn preserves_intentional_trailing_newlines_in_multipart_fields() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"message\"\r\n\r\nline1\r\n\r\n\r\n--XyZ--\r\n";
        let fields = parse_multipart_form("multipart/form-data; boundary=XyZ", body);
        assert_eq!(fields, vec![("message".to_string(), "line1\r\n\r\n".to_string())]);
    }

    #[test]
    fn accepts_a_quoted_or_unquoted_multipart_boundary() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--XyZ--\r\n";
        for content_type in [
            "multipart/form-data; boundary=XyZ",
            "multipart/form-data; boundary=\"XyZ\"",
            "multipart/form-data; charset=utf-8; Boundary = XyZ",
        ] {
            assert_eq!(
                parse_multipart_form(content_type, body),
                vec![("a".to_string(), "1".to_string())],
                "{content_type}"
            );
        }
    }

    #[test]
    fn rejects_multipart_without_boundary() {
        assert!(parse_multipart_form("multipart/form-data", b"x").is_empty());
        assert!(parse_multipart_form("multipart/form-data; boundary=", b"x").is_empty());
    }

    #[test]
    fn decodes_forms_and_preserves_bad_escapes() {
        assert_eq!(
            parse_form(b"a=b%20c&x=1&plus=a+b"),
            vec![
                ("a".into(), "b c".into()),
                ("x".into(), "1".into()),
                ("plus".into(), "a b".into()),
            ]
        );
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn formats_http_dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 GMT");
    }
}
