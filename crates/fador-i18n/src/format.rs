//! A bounded `sprintf` subset for language strings.
//!
//! phpBB passes every message through `vsprintf()`, so a pack may use
//! positional arguments (`%1$s`), integer, float and hexadecimal conversions,
//! precision (`%.2f`), width and flags. This module implements that subset and
//! keeps an unknown or malformed conversion verbatim, so a broken translation
//! is visible in the page instead of losing text.

use std::borrow::Cow;

/// Largest width or precision the formatter honours.
///
/// A hostile format string such as `%999999999d` would otherwise allocate
/// without limit. Wider requests are clamped instead of rejected. The bound is
/// the largest precision the standard formatting machinery accepts, so the
/// same limit applies to every conversion.
pub const MAX_PADDING: usize = 65_535;

/// Replace `sprintf`-style placeholders in `format` with `args`.
///
/// Supported conversions are `%s`, `%d`, `%u`, `%f`/`%F`, `%x`, `%X` and
/// `%%`. An optional argument number (`%1$s`, 1-based), flags (`-`, `+`, `0`,
/// space), width (`%5s`, `%05d`) and precision (`%.2f`, `%.3s`) are honoured.
/// A missing argument renders as an empty string for `%s` and as zero for the
/// numeric conversions, and an unknown conversion is copied through unchanged.
///
/// ```
/// use fador_i18n::format_placeholders;
///
/// let args = vec!["Ada".to_string(), "3".to_string()];
/// assert_eq!(
///     format_placeholders("Hi %1$s, you have %2$d messages", &args),
///     "Hi Ada, you have 3 messages"
/// );
/// assert_eq!(format_placeholders("%.2f", &["3.14159".to_string()]), "3.14");
/// assert_eq!(format_placeholders("%05d", &["42".to_string()]), "00042");
/// assert_eq!(format_placeholders("100%%", &[]), "100%");
/// ```
#[must_use]
pub fn format_placeholders(format: &str, args: &[String]) -> String {
    let chars: Vec<char> = format.chars().collect();
    let mut out = String::with_capacity(format.len() + 16);
    let mut sequential = 0usize;
    let mut index = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if ch != '%' {
            out.push(ch);
            index += 1;
            continue;
        }
        let spec_start = index + 1;
        index += 1;
        if index >= chars.len() {
            out.push('%');
            break;
        }
        if chars[index] == '%' {
            out.push('%');
            index += 1;
            continue;
        }

        // `%12$s`: digits followed by `$` are a 1-based argument number.
        let digits_start = index;
        let mut number = 0usize;
        while index < chars.len() && chars[index].is_ascii_digit() {
            number = number
                .saturating_mul(10)
                .saturating_add(chars[index] as usize - '0' as usize);
            index += 1;
        }
        let positional = if index > digits_start && chars.get(index) == Some(&'$') {
            index += 1;
            Some(number.saturating_sub(1))
        } else {
            index = digits_start;
            None
        };

        let mut left = false;
        let mut plus = false;
        let mut zero = false;
        let mut space = false;
        loop {
            match chars.get(index) {
                Some('-') => left = true,
                Some('+') => plus = true,
                Some('0') => zero = true,
                Some(' ') => space = true,
                _ => break,
            }
            index += 1;
        }

        let width_start = index;
        let mut width = 0usize;
        while index < chars.len() && chars[index].is_ascii_digit() {
            width = width
                .saturating_mul(10)
                .saturating_add(chars[index] as usize - '0' as usize)
                .min(MAX_PADDING);
            index += 1;
        }
        let width = if index > width_start { width } else { 0 };

        let mut precision = None;
        if chars.get(index) == Some(&'.') {
            index += 1;
            let precision_start = index;
            let mut value = 0usize;
            while index < chars.len() && chars[index].is_ascii_digit() {
                value = value
                    .saturating_mul(10)
                    .saturating_add(chars[index] as usize - '0' as usize)
                    .min(MAX_PADDING);
                index += 1;
            }
            precision = Some(if index > precision_start { value } else { 0 });
        }

        let Some(&conversion) = chars.get(index) else {
            out.push('%');
            out.extend(chars[spec_start..].iter());
            break;
        };
        index += 1;

        let argument = positional.unwrap_or_else(|| {
            let current = sequential;
            sequential += 1;
            current
        });
        let value = args.get(argument).map_or("", String::as_str);

        let handled = match conversion {
            's' => {
                let text: Cow<'_, str> = match precision {
                    Some(limit) => Cow::Owned(value.chars().take(limit).collect()),
                    None => Cow::Borrowed(value),
                };
                push_padded(&mut out, &text, "", width, left, zero);
                true
            }
            'd' => {
                let number = parse_int_prefix(value);
                let negative = number < 0;
                let mut digits = number.unsigned_abs().to_string();
                if let Some(precision) = precision {
                    if digits.len() < precision {
                        digits.insert_str(0, &"0".repeat(precision - digits.len()));
                    }
                }
                let sign = if negative {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                push_padded(
                    &mut out,
                    &digits,
                    sign,
                    width,
                    left,
                    zero && precision.is_none(),
                );
                true
            }
            'u' => {
                let mut digits = (parse_int_prefix(value) as u64).to_string();
                if let Some(precision) = precision {
                    if digits.len() < precision {
                        digits.insert_str(0, &"0".repeat(precision - digits.len()));
                    }
                }
                push_padded(
                    &mut out,
                    &digits,
                    "",
                    width,
                    left,
                    zero && precision.is_none(),
                );
                true
            }
            'x' | 'X' => {
                let number = parse_int_prefix(value) as u64;
                let mut digits = if conversion == 'x' {
                    format!("{number:x}")
                } else {
                    format!("{number:X}")
                };
                if let Some(precision) = precision {
                    if digits.len() < precision {
                        digits.insert_str(0, &"0".repeat(precision - digits.len()));
                    }
                }
                push_padded(
                    &mut out,
                    &digits,
                    "",
                    width,
                    left,
                    zero && precision.is_none(),
                );
                true
            }
            'f' | 'F' => {
                let body = format_float(parse_float_prefix(value), precision.unwrap_or(6));
                let (sign, digits) = match body.strip_prefix('-') {
                    Some(rest) => ("-", rest),
                    None if plus => ("+", body.as_str()),
                    None if space => (" ", body.as_str()),
                    None => ("", body.as_str()),
                };
                push_padded(&mut out, digits, sign, width, left, zero);
                true
            }
            _ => false,
        };
        if !handled {
            out.push('%');
            out.extend(chars[spec_start..index].iter());
        }
    }
    out
}

/// Append `body` with `sign` in front, padded to `width`.
fn push_padded(out: &mut String, body: &str, sign: &str, width: usize, left: bool, zero: bool) {
    let used = sign.chars().count() + body.chars().count();
    let padding = width.saturating_sub(used);
    if left {
        out.push_str(sign);
        out.push_str(body);
        for _ in 0..padding {
            out.push(' ');
        }
    } else if zero {
        out.push_str(sign);
        for _ in 0..padding {
            out.push('0');
        }
        out.push_str(body);
    } else {
        for _ in 0..padding {
            out.push(' ');
        }
        out.push_str(sign);
        out.push_str(body);
    }
}

/// `printf`-style float rendering, including PHP's spellings for non-finite
/// values.
fn format_float(value: f64, precision: usize) -> String {
    if value.is_nan() {
        return "NAN".to_string();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-INF".to_string()
        } else {
            "INF".to_string()
        };
    }
    format!("{value:.precision$}")
}

/// Integer value of a string, following PHP's `(int)` cast: a full parse
/// first, then the longest numeric prefix, then truncation of a float.
fn parse_int_prefix(value: &str) -> i64 {
    let text = value.trim();
    if let Ok(number) = text.parse::<i64>() {
        return number;
    }
    let bytes = text.as_bytes();
    let mut index = usize::from(matches!(bytes.first().copied(), Some(b'+' | b'-')));
    let start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index > start {
        if matches!(bytes.get(index).copied(), Some(b'.' | b'e' | b'E')) {
            return parse_float_prefix(text).trunc() as i64;
        }
        return text[..index].parse::<i64>().unwrap_or(0);
    }
    0
}

/// Float value of a string, following PHP's `(float)` cast.
fn parse_float_prefix(value: &str) -> f64 {
    let text = value.trim();
    if let Ok(number) = text.parse::<f64>() {
        return number;
    }
    let bytes = text.as_bytes();
    let mut index = usize::from(matches!(bytes.first().copied(), Some(b'+' | b'-')));
    let mut seen_digit = false;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
        seen_digit = true;
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
            seen_digit = true;
        }
    }
    if !seen_digit {
        return 0.0;
    }
    if matches!(bytes.get(index).copied(), Some(b'e' | b'E')) {
        let mut exponent = index + 1;
        if matches!(bytes.get(exponent).copied(), Some(b'+' | b'-')) {
            exponent += 1;
        }
        let start = exponent;
        while exponent < bytes.len() && bytes[exponent].is_ascii_digit() {
            exponent += 1;
        }
        if exponent > start {
            index = exponent;
        }
    }
    text[..index].parse::<f64>().unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fador_testutil::{iterations, Rng};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn replaces_sequential_and_positional_arguments() {
        assert_eq!(format_placeholders("%s", &args(&["a"])), "a");
        assert_eq!(format_placeholders("%s %s", &args(&["a", "b"])), "a b");
        assert_eq!(format_placeholders("%2$s %1$s", &args(&["a", "b"])), "b a");
        assert_eq!(format_placeholders("%1$s %1$s", &args(&["a"])), "a a");
        // A positional conversion does not advance the sequential counter.
        assert_eq!(
            format_placeholders("%s %1$s %s", &args(&["a", "b"])),
            "a a b"
        );
        assert_eq!(format_placeholders("%s", &[]), "");
        assert_eq!(format_placeholders("%9$s", &args(&["a"])), "");
    }

    #[test]
    fn formats_integers_and_hexadecimal() {
        assert_eq!(format_placeholders("%d", &args(&["42"])), "42");
        assert_eq!(format_placeholders("%d", &args(&["-7"])), "-7");
        assert_eq!(format_placeholders("%d", &args(&[" 42 "])), "42");
        assert_eq!(format_placeholders("%d", &args(&["42abc"])), "42");
        assert_eq!(format_placeholders("%d", &args(&["3.9"])), "3");
        assert_eq!(format_placeholders("%d", &args(&["abc"])), "0");
        assert_eq!(
            format_placeholders("%u", &args(&["-1"])),
            u64::MAX.to_string()
        );
        assert_eq!(format_placeholders("%x", &args(&["255"])), "ff");
        assert_eq!(format_placeholders("%X", &args(&["255"])), "FF");
        assert_eq!(
            format_placeholders("%x", &args(&["-1"])),
            format!("{:x}", u64::MAX)
        );
        assert_eq!(
            format_placeholders("%d", &args(&["999999999999999999999"])),
            "0"
        );
    }

    #[test]
    fn formats_floats_with_php_precision() {
        assert_eq!(format_placeholders("%f", &args(&["3.5"])), "3.500000");
        assert_eq!(format_placeholders("%.2f", &args(&["3.14159"])), "3.14");
        assert_eq!(format_placeholders("%.0f", &args(&["3.6"])), "4");
        assert_eq!(format_placeholders("%F", &args(&["-2.5"])), "-2.500000");
        assert_eq!(format_placeholders("%.1f", &args(&["abc"])), "0.0");
        assert_eq!(format_placeholders("%f", &args(&["1e3"])), "1000.000000");
        assert_eq!(format_placeholders("%f", &args(&["NaN"])), "NAN");
        assert_eq!(format_placeholders("%f", &args(&["-inf"])), "-INF");
    }

    #[test]
    fn honours_flags_width_and_precision() {
        assert_eq!(format_placeholders("%05d", &args(&["42"])), "00042");
        assert_eq!(format_placeholders("%-5d|", &args(&["42"])), "42   |");
        assert_eq!(format_placeholders("%5d|", &args(&["42"])), "   42|");
        assert_eq!(format_placeholders("%+d", &args(&["42"])), "+42");
        assert_eq!(format_placeholders("% d", &args(&["42"])), " 42");
        assert_eq!(format_placeholders("%+d", &args(&["-42"])), "-42");
        assert_eq!(
            format_placeholders("%08.2f", &args(&["-3.14159"])),
            "-0003.14"
        );
        assert_eq!(format_placeholders("%5.2f", &args(&["3.14159"])), " 3.14");
        assert_eq!(format_placeholders("%.3s", &args(&["abcdef"])), "abc");
        assert_eq!(format_placeholders("%05s", &args(&["ab"])), "000ab");
        assert_eq!(format_placeholders("%-4s|", &args(&["ab"])), "ab  |");
        assert_eq!(format_placeholders("%.3d", &args(&["7"])), "007");
        assert_eq!(format_placeholders("%.3x", &args(&["15"])), "00f");
        // Width and precision are clamped instead of allocating without bound.
        let wide = format_placeholders("%999999999d", &args(&["1"]));
        assert_eq!(wide.len(), MAX_PADDING);
        let precise = format_placeholders("%.999999999f", &args(&["1"]));
        assert!(precise.len() <= MAX_PADDING + 2);
    }

    #[test]
    fn keeps_unknown_and_truncated_conversions_verbatim() {
        assert_eq!(format_placeholders("100%%", &[]), "100%");
        assert_eq!(format_placeholders("%%s", &args(&["a"])), "%s");
        assert_eq!(format_placeholders("%q", &args(&["a"])), "%q");
        assert_eq!(format_placeholders("%5q", &args(&["a"])), "%5q");
        assert_eq!(format_placeholders("%1$q", &args(&["a"])), "%1$q");
        assert_eq!(format_placeholders("trailing %", &[]), "trailing %");
        assert_eq!(format_placeholders("%5", &[]), "%5");
        assert_eq!(format_placeholders("%", &[]), "%");
        assert_eq!(format_placeholders("Ä%sö", &args(&["x"])), "Äxö");
        assert_eq!(format_placeholders("", &[]), "");
    }

    #[test]
    fn parses_numeric_prefixes_like_php() {
        assert_eq!(parse_int_prefix("  12  "), 12);
        assert_eq!(parse_int_prefix("+3"), 3);
        assert_eq!(parse_int_prefix("-0"), 0);
        assert_eq!(parse_int_prefix("1e3"), 1000);
        assert_eq!(parse_int_prefix(".5"), 0);
        assert_eq!(parse_int_prefix("0x10"), 0);
        assert_eq!(parse_float_prefix("1.5e2x"), 150.0);
        assert_eq!(parse_float_prefix("-0.25"), -0.25);
        assert_eq!(parse_float_prefix("."), 0.0);
        assert_eq!(parse_float_prefix("-.5"), -0.5);
    }

    #[test]
    fn fuzz_format_placeholders_does_not_panic() {
        let mut rng = Rng::new(0x10f0_0001);
        let cases = iterations(500);
        let pool = args(&["0", "1", "-1", "3.5", "abc", "", " 42", "1e3"]);
        for _ in 0..cases {
            let length = rng.below(40);
            let format = rng.text(length);
            let argument_count = rng.below(5);
            let mut values = Vec::with_capacity(argument_count);
            for _ in 0..argument_count {
                values.push(pool[rng.below(pool.len())].clone());
            }
            let _ = format_placeholders(&format, &values);
        }
        for hostile in fador_testutil::MALICIOUS_STRINGS {
            let _ = format_placeholders(hostile, &args(&["%s", "%%"]));
        }
    }
}
