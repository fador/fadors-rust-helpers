//! The PHP standard functions a template may call.
//!
//! These are the functions the evaluator provides by itself, without any
//! application host: string and number formatting, array inspection, and the
//! few helpers the templates use to build output. Everything is a pure
//! function of its arguments except `time()`, which reads the system clock.
//!
//! The set is a fixed allow-list. A name outside it is an error, so a template
//! can never reach a function the embedder did not choose to expose. Functions
//! that mutate their argument (`array_pop`, `ksort`) are handled by the
//! evaluator itself, because PHP passes the array by reference and the value
//! copy a normal call receives would be lost.

use crate::eval::{EvalError, Evaluator};
use crate::value::{Key, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// Every PHP standard function a template can call, lower case.
///
/// The list is alphabetical so it reads like the PHP manual; the lookup is a
/// linear scan over a few dozen entries. `array_pop` and `ksort` are listed
/// because `function_exists()` reports them, but the evaluator dispatches them
/// itself: PHP passes their array by reference, and a normal call would only
/// receive a copy.
const BUILTINS: &[&str] = &[
    "abs",
    "addcslashes",
    "addslashes",
    "array_pop",
    "array_reverse",
    "base64_encode",
    "ceil",
    "count",
    "floor",
    "function_exists",
    "htmlspecialchars",
    "implode",
    "in_array",
    "intval",
    "is_array",
    "is_float",
    "ksort",
    "max",
    "min",
    "nl2br",
    "number_format",
    "preg_replace",
    "round",
    "sprintf",
    "str_repeat",
    "str_replace",
    "strip_tags",
    "strpos",
    "strtolower",
    "strtoupper",
    "strtr",
    "strval",
    "substr",
    "time",
    "trim",
    "ucfirst",
    "urlencode",
];

impl Evaluator {
    /// Whether `name` is one of the PHP standard functions implemented here.
    ///
    /// `name` is already lower case and has the `smf_` alias prefix removed.
    pub(crate) fn has_builtin(name: &str) -> bool {
        BUILTINS.contains(&name)
    }

    /// Call a PHP standard function.
    ///
    /// `None` means the name is not a builtin; the caller then tries the host.
    /// `array_pop` and `ksort` never reach this function because the evaluator
    /// handles their by-reference argument itself.
    pub(crate) fn call_builtin(
        &mut self,
        name: &str,
        args: &[Value],
    ) -> Option<Result<Value, EvalError>> {
        let result = match name {
            "count" => Ok(Value::Int(match args.first() {
                Some(Value::Array(array)) => array.borrow().len() as i64,
                Some(Value::Null) | None => 0,
                Some(_) => 1,
            })),
            "is_array" => Ok(Value::Bool(
                args.first().is_some_and(|value| value.is_array()),
            )),
            "is_float" => Ok(Value::Bool(
                args.first().is_some_and(|value| value.is_float()),
            )),
            "function_exists" => {
                let name = args.first().map(Value::to_php_string).unwrap_or_default();
                let lower = name.to_ascii_lowercase();
                let bare = lower.strip_prefix("smf_").unwrap_or(&lower);
                Ok(Value::Bool(
                    self.has_function(&lower) || Self::has_builtin(bare) || self.host_has(bare),
                ))
            }
            "implode" => {
                let empty = Value::Null;
                let (glue, array) = if args.len() >= 2 {
                    (args[0].to_php_string(), &args[1])
                } else {
                    (String::new(), args.first().unwrap_or(&empty))
                };
                let Some(array) = array.as_array() else {
                    return Some(Ok(Value::Str(String::new())));
                };
                let values = array
                    .borrow()
                    .values()
                    .iter()
                    .map(Value::to_php_string)
                    .collect::<Vec<_>>();
                self.bounded_string(values.join(&glue), "implode")
            }
            "in_array" => {
                let needle = args.first().cloned().unwrap_or(Value::Null);
                let haystack = args.get(1).cloned().unwrap_or(Value::Null);
                let strict = args.get(2).is_some_and(Value::to_bool);
                let Some(array) = haystack.as_array() else {
                    return Some(Ok(Value::Bool(false)));
                };
                let found = array.borrow().values().iter().any(|value| {
                    if strict {
                        value.strict_eq(&needle)
                    } else {
                        value.loose_eq(&needle)
                    }
                });
                Ok(Value::Bool(found))
            }
            "sprintf" => {
                let format = args.first().map(Value::to_php_string).unwrap_or_default();
                self.bounded_string(php_sprintf(&format, &args[1..]), "sprintf")
            }
            "str_repeat" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                let count = args.get(1).map(Value::to_int).unwrap_or(0).max(0) as usize;
                if text.len().saturating_mul(count) > self.limits().max_string_bytes {
                    return Some(Err(self.error("str_repeat result exceeds the string limit")));
                }
                Ok(Value::Str(text.repeat(count)))
            }
            "str_replace" => {
                let search = args.first().map(Value::to_php_string).unwrap_or_default();
                let replace = args.get(1).map(Value::to_php_string).unwrap_or_default();
                let subject = args.get(2).map(Value::to_php_string).unwrap_or_default();
                self.bounded_string(subject.replace(&search, &replace), "str_replace")
            }
            "strtr" => {
                let subject = args.first().map(Value::to_php_string).unwrap_or_default();
                // `strtr($string, array('from' => 'to'))` walks the string once,
                // preferring the longest matching key at each position.
                if let Some(array) = args.get(1).and_then(Value::as_array) {
                    let pairs = {
                        let array = array.borrow();
                        array
                            .entries()
                            .into_iter()
                            .map(|(key, value)| {
                                let from = match key {
                                    Key::Int(number) => number.to_string(),
                                    Key::Str(text) => text,
                                };
                                (from, value.borrow().to_php_string())
                            })
                            .collect::<Vec<_>>()
                    };
                    let mut pairs = pairs;
                    pairs.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
                    let mut out = String::with_capacity(subject.len());
                    let mut index = 0usize;
                    'outer: while index < subject.len() {
                        for (from, to) in &pairs {
                            if !from.is_empty() && subject[index..].starts_with(from.as_str()) {
                                out.push_str(to);
                                index += from.len();
                                continue 'outer;
                            }
                        }
                        let character = subject[index..].chars().next().unwrap();
                        out.push(character);
                        index += character.len_utf8();
                    }
                    return Some(self.bounded_string(out, "strtr"));
                }
                let from = args.get(1).map(Value::to_php_string).unwrap_or_default();
                let to = args.get(2).map(Value::to_php_string).unwrap_or_default();
                if from.is_empty() {
                    return Some(Ok(Value::Str(subject)));
                }
                let mut out = String::with_capacity(subject.len());
                let mut index = 0usize;
                while index < subject.len() {
                    if subject[index..].starts_with(from.as_str()) {
                        out.push_str(&to);
                        index += from.len();
                    } else {
                        let character = subject[index..].chars().next().unwrap();
                        out.push(character);
                        index += character.len_utf8();
                    }
                }
                self.bounded_string(out, "strtr")
            }
            "substr" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                let start = args.get(1).map(Value::to_int).unwrap_or(0);
                let length = args.get(2).map(Value::to_int);
                Ok(Value::Str(php_substr(&text, start, length)))
            }
            "strpos" => {
                let haystack = args.first().map(Value::to_php_string).unwrap_or_default();
                let needle = args.get(1).map(Value::to_php_string).unwrap_or_default();
                Ok(Value::Int(
                    haystack
                        .find(&needle)
                        .map(|index| haystack[..index].chars().count() as i64)
                        .unwrap_or(-1),
                ))
            }
            "strtolower" => Ok(Value::Str(
                args.first()
                    .map(Value::to_php_string)
                    .unwrap_or_default()
                    .to_lowercase(),
            )),
            "strtoupper" => Ok(Value::Str(
                args.first()
                    .map(Value::to_php_string)
                    .unwrap_or_default()
                    .to_uppercase(),
            )),
            "ucfirst" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                let mut chars = text.chars();
                let first = chars
                    .next()
                    .map(|c| c.to_uppercase().collect::<String>())
                    .unwrap_or_default();
                Ok(Value::Str(first + chars.as_str()))
            }
            "addslashes" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                Ok(Value::Str(
                    text.replace('\\', "\\\\")
                        .replace('\'', "\\'")
                        .replace('"', "\\\"")
                        .replace('\0', "\\0"),
                ))
            }
            "addcslashes" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                let chars = args.get(1).map(Value::to_php_string).unwrap_or_default();
                let mut out = String::with_capacity(text.len());
                for c in text.chars() {
                    if chars.contains(c) {
                        out.push('\\');
                    }
                    out.push(c);
                }
                Ok(Value::Str(out))
            }
            "strip_tags" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                Ok(Value::Str(strip_tags(&text)))
            }
            "preg_replace" => {
                let pattern = args.first().map(Value::to_php_string).unwrap_or_default();
                let replacement = args.get(1).map(Value::to_php_string).unwrap_or_default();
                let subject = args.get(2).map(Value::to_php_string).unwrap_or_default();
                match preg_replace(&pattern, &replacement, &subject) {
                    Ok(text) => Ok(Value::Str(text)),
                    Err(error) => Err(error),
                }
            }
            "base64_encode" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                Ok(Value::Str(base64_encode(text.as_bytes())))
            }
            "htmlspecialchars" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                Ok(Value::Str(fador_core::util::html_escape_compat(&text)))
            }
            "number_format" => {
                let value = args.first().map(Value::to_float).unwrap_or(0.0);
                let decimals = args.get(1).map(Value::to_int).unwrap_or(0).clamp(0, 20) as usize;
                let dec_point = args
                    .get(2)
                    .map(Value::to_php_string)
                    .unwrap_or_else(|| ".".into());
                let thousands = args
                    .get(3)
                    .map(Value::to_php_string)
                    .unwrap_or_else(|| ",".into());
                Ok(Value::Str(number_format(
                    value, decimals, &dec_point, &thousands,
                )))
            }
            "round" => {
                let value = args.first().map(Value::to_float).unwrap_or(0.0);
                let precision = args.get(1).map(Value::to_int).unwrap_or(0);
                let factor = 10f64.powi(precision as i32);
                Ok(Value::Float((value * factor).round() / factor))
            }
            "ceil" => Ok(Value::Float(
                args.first().map(Value::to_float).unwrap_or(0.0).ceil(),
            )),
            "floor" => Ok(Value::Float(
                args.first().map(Value::to_float).unwrap_or(0.0).floor(),
            )),
            "abs" => {
                let value = args.first().cloned().unwrap_or(Value::Null);
                Ok(match value {
                    Value::Int(value) => Value::Int(value.wrapping_abs()),
                    other => Value::Float(other.to_float().abs()),
                })
            }
            "max" | "min" => {
                let values = if args.len() == 1 {
                    args[0]
                        .as_array()
                        .map(|array| array.borrow().values())
                        .unwrap_or_default()
                } else {
                    args.to_vec()
                };
                let mut iter = values.into_iter();
                let Some(mut best) = iter.next() else {
                    return Some(Ok(Value::Bool(false)));
                };
                for value in iter {
                    let ordering = value.compare(&best);
                    if (name == "max" && ordering.is_gt()) || (name == "min" && ordering.is_lt()) {
                        best = value;
                    }
                }
                Ok(best)
            }
            "array_reverse" => {
                let Value::Array(array) = args.first().cloned().unwrap_or(Value::Null) else {
                    return Some(Ok(Value::Null));
                };
                let preserve = args.get(1).is_some_and(Value::to_bool);
                let mut copy = array.borrow().deep_clone();
                copy.reverse(preserve);
                Ok(Value::from_array(copy))
            }
            "intval" => Ok(Value::Int(args.first().map(Value::to_int).unwrap_or(0))),
            "strval" => Ok(Value::Str(
                args.first().map(Value::to_php_string).unwrap_or_default(),
            )),
            "trim" => Ok(Value::Str(
                args.first()
                    .map(Value::to_php_string)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            )),
            "nl2br" => Ok(Value::Str(
                args.first()
                    .map(Value::to_php_string)
                    .unwrap_or_default()
                    .replace('\n', "<br />\n"),
            )),
            "urlencode" => Ok(Value::Str(urlencode(
                &args.first().map(Value::to_php_string).unwrap_or_default(),
            ))),
            "time" => Ok(Value::Int(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs() as i64)
                    .unwrap_or(0),
            )),
            _ => return None,
        };
        Some(result)
    }
}

/// PHP `substr()`: character based, with negative offsets and lengths.
fn php_substr(text: &str, start: i64, length: Option<i64>) -> String {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len() as i64;
    let start = if start < 0 {
        (len + start).max(0)
    } else {
        start.min(len)
    };
    let end = match length {
        Some(length) if length < 0 => (len + length).max(start),
        Some(length) => (start + length).min(len),
        None => len,
    };
    chars[start as usize..end.max(start) as usize]
        .iter()
        .collect()
}

/// PHP `strip_tags()` without an allow-list: drop everything between `<` and
/// `>`.
fn strip_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    for c in text.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Standard base64 encoding, as PHP's `base64_encode()`.
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b1 = chunk[0];
        let b2 = chunk.get(1).copied().unwrap_or(0);
        let b3 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b1 >> 2) as usize] as char);
        out.push(TABLE[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b3 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// PHP `urlencode()`: spaces become `+`, everything outside `[A-Za-z0-9-_.]`
/// becomes `%XX`.
pub(crate) fn urlencode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() + 8);
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            out.push(byte as char);
        } else if byte == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

/// `number_format()` with an explicit decimal point and thousands separator.
pub(crate) fn number_format(value: f64, decimals: usize, decimal: &str, thousands: &str) -> String {
    let formatted = format!("{value:.decimals$}");
    let (integer, fraction) = formatted
        .split_once('.')
        .unwrap_or((formatted.as_str(), ""));
    let mut grouped = String::new();
    let digits = integer.strip_prefix('-').unwrap_or(integer);
    for (index, c) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push_str(thousands);
        }
        grouped.push(c);
    }
    if integer.starts_with('-') {
        grouped.insert(0, '-');
    }
    if decimals > 0 {
        format!("{grouped}{decimal}{fraction}")
    } else {
        grouped
    }
}

/// The `preg_replace()` patterns the templates use, matched by hand.
///
/// A general PCRE engine is out of scope and would be a denial-of-service
/// risk, so only these three exact patterns are accepted; anything else is an
/// error instead of a silent no-op.
fn preg_replace(pattern: &str, replacement: &str, subject: &str) -> Result<String, EvalError> {
    if pattern == "~%[df\\.\\d]+~" {
        let mut out = String::new();
        let mut chars = subject.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            let mut removed = false;
            while chars
                .peek()
                .is_some_and(|c| c.is_ascii_digit() || *c == '.' || *c == 'd' || *c == 'f')
            {
                chars.next();
                removed = true;
            }
            if !removed {
                out.push(c);
            }
        }
        return Ok(out);
    }
    if pattern == "~[^A-Za-z0-9_\\-=:]~" {
        return Ok(subject
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '=' | ':') {
                    c.to_string()
                } else {
                    replacement.to_string()
                }
            })
            .collect());
    }
    if pattern == "~<div class=\"(?:quote|code)header\">(.+?)</div>~" {
        let mut out = String::new();
        let mut rest = subject;
        while let Some(start) = rest.find("<div class=\"") {
            let header = if rest[start..].starts_with("<div class=\"quoteheader\">") {
                "quoteheader"
            } else if rest[start..].starts_with("<div class=\"codeheader\">") {
                "codeheader"
            } else {
                out.push_str(&rest[..start + 1]);
                rest = &rest[start + 1..];
                continue;
            };
            let prefix = format!("<div class=\"{header}\">");
            let body_start = start + prefix.len();
            let Some(end) = rest[body_start..].find("</div>") else {
                break;
            };
            out.push_str(&rest[..start]);
            let capture = &rest[body_start..body_start + end];
            out.push_str(&replacement.replace("$1", capture));
            rest = &rest[body_start + end + "</div>".len()..];
        }
        out.push_str(rest);
        return Ok(out);
    }
    Err(EvalError {
        message: format!("unsupported preg_replace pattern {pattern:?}"),
    })
}

/// The `sprintf` subset the language strings use: positional arguments,
/// width, precision and the `s`, `d`, `i`, `u`, `f`, `F`, `e`, `E`, `x`, `X`,
/// `o`, `b` and `c` conversions.
pub(crate) fn php_sprintf(format: &str, args: &[Value]) -> String {
    let mut out = String::with_capacity(format.len());
    let chars: Vec<char> = format.chars().collect();
    let mut index = 0;
    let mut next_arg = 0usize;
    while index < chars.len() {
        if chars[index] != '%' {
            out.push(chars[index]);
            index += 1;
            continue;
        }
        index += 1;
        if chars.get(index) == Some(&'%') {
            out.push('%');
            index += 1;
            continue;
        }
        let start = index;
        while chars.get(index).is_some_and(|c| c.is_ascii_digit()) {
            index += 1;
        }
        let mut arg_index = None;
        if chars.get(index) == Some(&'$') && index > start {
            let text: String = chars[start..index].iter().collect();
            arg_index = text
                .parse::<usize>()
                .ok()
                .map(|value| value.saturating_sub(1));
            index += 1;
        } else {
            index = start;
        }
        let mut left = false;
        let mut zero = false;
        let mut plus = false;
        let mut space = false;
        while let Some(flag) = chars.get(index) {
            match flag {
                '-' => left = true,
                '0' => zero = true,
                '+' => plus = true,
                ' ' => space = true,
                _ => break,
            }
            index += 1;
        }
        let width_start = index;
        while chars.get(index).is_some_and(|c| c.is_ascii_digit()) {
            index += 1;
        }
        let width = chars[width_start..index]
            .iter()
            .collect::<String>()
            .parse::<usize>()
            .ok()
            .map(|w| w.min(65_535));
        let mut precision = None;
        if chars.get(index) == Some(&'.') {
            index += 1;
            let precision_start = index;
            while chars.get(index).is_some_and(|c| c.is_ascii_digit()) {
                index += 1;
            }
            precision = chars[precision_start..index]
                .iter()
                .collect::<String>()
                .parse::<usize>()
                .ok()
                .map(|p| p.min(65_535));
        }
        let Some(spec) = chars.get(index).copied() else {
            break;
        };
        index += 1;
        let arg = if let Some(arg_index) = arg_index {
            args.get(arg_index).cloned().unwrap_or(Value::Null)
        } else {
            let value = args.get(next_arg).cloned().unwrap_or(Value::Null);
            next_arg += 1;
            value
        };
        let mut text = match spec {
            's' => {
                let mut value = arg.to_php_string();
                if let Some(precision) = precision {
                    value = value.chars().take(precision).collect();
                }
                value
            }
            'd' | 'i' => {
                let mut value = arg.to_int().to_string();
                if plus && arg.to_int() >= 0 {
                    value.insert(0, '+');
                } else if space && arg.to_int() >= 0 {
                    value.insert(0, ' ');
                }
                value
            }
            'u' => (arg.to_int() as u64).to_string(),
            'f' | 'F' => format!("{:.*}", precision.unwrap_or(6), arg.to_float()),
            'e' | 'E' => format!("{:.*e}", precision.unwrap_or(6), arg.to_float()),
            'x' => format!("{:x}", arg.to_int()),
            'X' => format!("{:X}", arg.to_int()),
            'o' => format!("{:o}", arg.to_int()),
            'b' => format!("{:b}", arg.to_int()),
            'c' => char::from_u32(arg.to_int() as u32)
                .map(|c| c.to_string())
                .unwrap_or_default(),
            other => {
                out.push('%');
                out.push(other);
                continue;
            }
        };
        if let Some(width) = width {
            if text.len() < width {
                let pad = width - text.len();
                if left {
                    text.push_str(&" ".repeat(pad));
                } else if zero {
                    let sign = text.starts_with('-') || text.starts_with('+');
                    if sign {
                        let first = text.remove(0);
                        text = format!("{first}{}{}", "0".repeat(pad), text);
                    } else {
                        text = format!("{}{}", "0".repeat(pad), text);
                    }
                } else {
                    text = format!("{}{}", " ".repeat(pad), text);
                }
            }
        }
        out.push_str(&text);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sprintf_handles_positional_width_and_precision() {
        let text = [Value::Str("a".into()), Value::Int(7)];
        assert_eq!(php_sprintf("%s-%d", &text), "a-7");
        assert_eq!(php_sprintf("%2$d %1$s", &text), "7 a");
        assert_eq!(
            php_sprintf("%05d|%-3d|", &[Value::Int(7), Value::Int(7)]),
            "00007|7  |"
        );
        assert_eq!(php_sprintf("%.2f", &[Value::Float(2.5)]), "2.50");
        assert_eq!(
            php_sprintf(
                "%x %X %o %b",
                &[
                    Value::Int(255),
                    Value::Int(255),
                    Value::Int(255),
                    Value::Int(255)
                ]
            ),
            "ff FF 377 11111111"
        );
        assert_eq!(php_sprintf("%c", &[Value::Int(0xff)]), "\u{ff}");
        assert_eq!(php_sprintf("%% %s", &text), "% a");
        assert_eq!(php_sprintf("%q", &text), "%q");
        assert_eq!(php_sprintf("%1$s", &[]), "");
    }

    #[test]
    fn substr_matches_php_offsets() {
        assert_eq!(php_substr("abcdef", 1, Some(2)), "bc");
        assert_eq!(php_substr("abcdef", -2, None), "ef");
        assert_eq!(php_substr("abcdef", 0, Some(-2)), "abcd");
        assert_eq!(php_substr("abcdef", 10, None), "");
        assert_eq!(php_substr("äöä", 1, Some(1)), "ö");
    }

    #[test]
    fn urlencode_and_base64_match_php() {
        assert_eq!(urlencode("a b&c/d"), "a+b%26c%2Fd");
        assert_eq!(urlencode("ä"), "%C3%A4");
        assert_eq!(
            base64_encode(b"any carnal pleasure."),
            "YW55IGNhcm5hbCBwbGVhc3VyZS4="
        );
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
    }

    #[test]
    fn number_format_groups_thousands() {
        assert_eq!(number_format(1234.5, 2, ".", ","), "1,234.50");
        assert_eq!(number_format(-1234567.0, 0, ",", "."), "-1.234.567");
        assert_eq!(number_format(0.0, 0, ".", ","), "0");
    }

    #[test]
    fn preg_replace_only_accepts_the_known_patterns() {
        assert_eq!(
            preg_replace("~%[df\\.\\d]+~", "", "100%1.5f done 100%").unwrap(),
            "100 done 100%"
        );
        assert_eq!(
            preg_replace("~[^A-Za-z0-9_\\-=:]~", "-", "a b!").unwrap(),
            "a-b-"
        );
        assert_eq!(
            preg_replace(
                "~<div class=\"(?:quote|code)header\">(.+?)</div>~",
                "[$1]",
                "<div class=\"quoteheader\">x</div>"
            )
            .unwrap(),
            "[x]"
        );
        assert!(preg_replace("~.*~", "", "x").is_err());
    }

    #[test]
    fn strip_tags_removes_markup() {
        assert_eq!(strip_tags("<b>a</b> <i>b"), "a b");
        assert_eq!(strip_tags("a < b"), "a ");
    }
}
