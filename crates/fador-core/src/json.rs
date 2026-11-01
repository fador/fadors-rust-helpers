//! Minimal JSON reader used for MediaWiki i18n files and small API payloads.

use std::collections::HashMap;

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A JSON number. Numbers are stored as `f64`, so integers above 2^53 lose
    /// precision.
    Number(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object. Insertion order is preserved so a read-modify-write round
    /// trip keeps the original layout.
    Object(Vec<(String, Json)>),
}

/// Parse one JSON document with a bounded nesting depth.
pub fn parse(input: &str) -> Result<Json, String> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(format!("trailing data at byte {}", p.pos));
    }
    Ok(v)
}

/// Serialise a [`Json`] document. Object key order is the parse order, so a
/// read-modify-write round trip keeps the pack layout stable.
pub fn write(value: &Json) -> String {
    let mut out = String::new();
    write_value(value, 0, &mut out);
    out
}

/// The same document on one line. Used where whitespace would change a token.
pub fn write_compact(value: &Json) -> String {
    let mut out = String::new();
    write_compact_value(value, &mut out);
    out
}

/// A JSON string literal, including the quotes.
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    write_string(value, &mut out);
    out
}

fn indent(depth: usize, out: &mut String) {
    out.push('\n');
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(value: f64, out: &mut String) {
    if value.is_finite() {
        // JSON has no integers; keep whole numbers without a fractional part so
        // a round trip does not rewrite `1` as `1.0`.
        if value.fract() == 0.0 && value.abs() < 1e15 {
            out.push_str(&format!("{}", value as i64));
            return;
        }
        out.push_str(&format!("{value}"));
    } else {
        out.push_str("null");
    }
}

fn write_value(value: &Json, depth: usize, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(number) => write_number(*number, out),
        Json::String(text) => write_string(text, out),
        Json::Array(items) if items.is_empty() => out.push_str("[]"),
        Json::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                indent(depth + 1, out);
                write_value(item, depth + 1, out);
            }
            indent(depth, out);
            out.push(']');
        }
        Json::Object(fields) if fields.is_empty() => out.push_str("{}"),
        Json::Object(fields) => {
            out.push('{');
            for (index, (key, item)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                indent(depth + 1, out);
                write_string(key, out);
                out.push_str(": ");
                write_value(item, depth + 1, out);
            }
            indent(depth, out);
            out.push('}');
        }
    }
}

fn write_compact_value(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(number) => write_number(*number, out),
        Json::String(text) => write_string(text, out),
        Json::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_compact_value(item, out);
            }
            out.push(']');
        }
        Json::Object(fields) => {
            out.push('{');
            for (index, (key, item)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_compact_value(item, out);
            }
            out.push('}');
        }
    }
}

/// Parse a JSON object whose top-level values are strings into a map.
pub fn parse_string_map(input: &str) -> Result<HashMap<String, String>, String> {
    let json = parse(input)?;
    let mut out = HashMap::new();
    if let Json::Object(items) = json {
        for (k, v) in items {
            if let Json::String(s) = v {
                out.insert(k, s);
            }
        }
    }
    Ok(out)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: u32,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\n' | b'\r' | b'\t')
        {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.depth += 1;
        if self.depth > 128 {
            return Err("JSON nesting too deep".into());
        }
        self.skip_ws();
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| "unexpected end of JSON".to_string())?;
        let result = match b {
            b'n' => {
                self.expect_literal("null")?;
                Ok(Json::Null)
            }
            b't' => {
                self.expect_literal("true")?;
                Ok(Json::Bool(true))
            }
            b'f' => {
                self.expect_literal("false")?;
                Ok(Json::Bool(false))
            }
            b'"' => Ok(Json::String(self.string()?)),
            b'[' => self.array(),
            b'{' => self.object(),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(format!("unexpected byte {:?} at {}", b as char, self.pos)),
        };
        self.depth -= 1;
        result
    }

    fn expect_literal(&mut self, lit: &str) -> Result<(), String> {
        if self.pos <= self.bytes.len() && self.bytes[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(format!("expected {lit} at {}", self.pos))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err("expected string".into());
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = *self
                        .bytes
                        .get(self.pos)
                        .ok_or_else(|| "unterminated escape".to_string())?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.bytes.get(self.pos) == Some(&b'\\')
                                    && self.bytes.get(self.pos + 1) == Some(&b'u')
                                {
                                    self.pos += 2;
                                    let low = self.hex4()?;
                                    if (0xDC00..=0xDFFF).contains(&low) {
                                        let c = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                                        out.push(
                                            char::from_u32(c)
                                                .ok_or_else(|| "invalid surrogate".to_string())?,
                                        );
                                    } else {
                                        return Err("invalid surrogate pair".into());
                                    }
                                } else {
                                    return Err("lone surrogate".into());
                                }
                            } else {
                                out.push(
                                    char::from_u32(cp)
                                        .ok_or_else(|| "invalid unicode escape".to_string())?,
                                );
                            }
                        }
                        _ => return Err(format!("invalid escape \\{}", esc as char)),
                    }
                }
                b => {
                    // Copy a full UTF-8 sequence.
                    let start = self.pos;
                    let len = utf8_len(b);
                    self.pos = (self.pos + len).min(self.bytes.len());
                    out.push_str(&String::from_utf8_lossy(&self.bytes[start..self.pos]));
                }
            }
        }
        Err("unterminated string".into())
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated unicode escape".into());
        }
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.bytes[self.pos];
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err("invalid unicode escape".into()),
            };
            v = (v << 4) | d as u32;
            self.pos += 1;
        }
        Ok(v)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.bytes[self.pos] == b'-' {
            self.pos += 1;
        }
        while self.pos < self.bytes.len()
            && matches!(
                self.bytes[self.pos],
                b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
            )
        {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| "bad number")?;
        s.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| format!("invalid number {s}"))
    }

    fn array(&mut self) -> Result<Json, String> {
        self.pos += 1;
        let mut out = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Json::Array(out));
        }
        loop {
            out.push(self.value()?);
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(out));
                }
                _ => return Err(format!("expected , or ] at {}", self.pos)),
            }
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.pos += 1;
        let mut out = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Json::Object(out));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err(format!("expected : at {}", self.pos));
            }
            self.pos += 1;
            let value = self.value()?;
            out.push((key, value));
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(out));
                }
                _ => return Err(format!("expected , or }} at {}", self.pos)),
            }
        }
    }
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    #[test]
    fn fuzz_json_parser_with_hostile_text() {
        let mut rng = Rng::new(0x1500_0001);
        let tokens = [
            "{", "}", "[", "]", ":", ",", "\"", "\\", "u", "0", "1", "9", ".", "-", "+", "e", "E",
            "true", "false", "null", " ", "\n", "\t", "\0", "💣", "ä", "<script>",
        ];
        for _ in 0..3_000 {
            let mut input = String::new();
            for _ in 0..rng.below(80) {
                input.push_str(tokens[rng.below(tokens.len())]);
            }
            let _ = parse(&input);
            let _ = parse_string_map(&input);
        }
        for _ in 0..1_000 {
            let len = rng.below(256);
            let input = rng.text(len);
            let _ = parse(&input);
        }
        assert!(parse(&"[".repeat(10_000)).is_err());
        assert!(parse(&"{\"a\":".repeat(1_000)).is_err());
    }

    #[test]
    fn fuzz_json_bytes_truncation_and_deep_nesting() {
        let mut rng = Rng::new(0x1500_0002);
        // Arbitrary bytes, lossily decoded exactly like an HTTP body would be.
        for _ in 0..2_000 {
            let len = rng.below(256);
            let bytes = rng.bytes(len);
            let input = String::from_utf8_lossy(&bytes).into_owned();
            let _ = parse(&input);
            let _ = parse_string_map(&input);
        }
        // Every truncation of a valid document, which must never panic or
        // allocate past the nesting limit.
        let document = r#"{"a":[1,2,{"b":"c"}],"d":null,"e":-1.5e3,"f":"\u00e4"}"#;
        for cut in 0..document.len() {
            let _ = parse(&document[..cut]);
        }
        // Deep nesting is bounded, not stack-recursive without a limit.
        for depth in [200usize, 512, 10_000] {
            assert!(parse(&"[".repeat(depth)).is_err(), "depth {depth}");
            assert!(
                parse(&format!("{}{}", "[".repeat(depth), "]".repeat(depth))).is_err(),
                "balanced depth {depth}"
            );
        }
        // Huge numbers and escapes stay bounded.
        let _ = parse(&format!("{{\"n\":{}1}}", "9".repeat(5_000)));
        let _ = parse(&format!("\"{}\"", "\\u".repeat(5_000)));
    }

    #[test]
    fn parses_i18n_shape() {
        let s = r#"{"@metadata":{"authors":["x"]},"tagline":"{{GRAMMAR:elative|{{SITENAME}}}}","x":"\u00e4"}"#;
        let m = parse_string_map(s).unwrap();
        assert_eq!(
            m.get("tagline").unwrap(),
            "{{GRAMMAR:elative|{{SITENAME}}}}"
        );
        assert_eq!(m.get("x").unwrap(), "ä");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("{").is_err());
        assert!(parse("[] trailing").is_err());
    }

    #[test]
    fn writes_what_it_reads() {
        let source = r#"{"code":"fi","messages":{"a":"Hei \"maailma\"","b":"rivit\nkaksi"},"n":[1,2.5,true,null],"files":{"Admin":{"lang":{},"help":{}}}}"#;
        let parsed = parse(source).unwrap();
        let written = write(&parsed);
        assert_eq!(parse(&written).unwrap(), parsed);
        assert!(written.contains("\"a\": \"Hei \\\"maailma\\\"\""));
        assert!(written.contains("\"b\": \"rivit\\nkaksi\""));
        assert!(written.contains("\"n\": [\n"));
        assert!(written.contains("\"files\": {\n"));
        // Whole numbers stay integers, fractions keep their point.
        assert!(written.contains("\n    1,"), "{written}");
        assert!(written.contains("\n    2.5,"), "{written}");
        assert_eq!(
            write_compact(&parsed),
            write_compact(&parse(&write_compact(&parsed)).unwrap())
        );
    }

    #[test]
    fn quotes_control_characters() {
        assert_eq!(quote("a\u{1}b"), "\"a\\u0001b\"");
        assert_eq!(quote("\t"), "\"\\t\"");
    }
}
