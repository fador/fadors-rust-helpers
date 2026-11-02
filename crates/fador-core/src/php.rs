//! A bounded PHP serialisation reader and writer.
//!
//! Only the value types a session or settings row can contain are supported:
//! `null`, booleans, integers, floats, strings and arrays. Objects, references
//! and custom serialised classes are rejected. The reader has a byte, depth and
//! entry cap, so a hostile database row cannot exhaust a worker.

use std::collections::HashSet;
use std::fmt;

/// Maximum accepted serialised input in bytes.
pub const MAX_SERIALIZED_BYTES: usize = 1024 * 1024;
/// Maximum array nesting depth.
pub const MAX_SERIALIZED_DEPTH: usize = 32;
/// Maximum entries in one serialised array.
pub const MAX_SERIALIZED_ENTRIES: usize = 4096;

/// A PHP value that can be serialised.
#[derive(Debug, Clone, PartialEq)]
pub enum PhpValue {
    /// `N;`
    Null,
    /// `b:0;` or `b:1;`
    Bool(bool),
    /// `i:...;`
    Int(i64),
    /// `d:...;`
    Float(f64),
    /// `s:<length>:"...";`
    Str(String),
    /// `a:<count>:{...}`
    Array(Vec<(PhpKey, PhpValue)>),
}

/// A PHP array key: an integer or a string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PhpKey {
    /// Integer key.
    Int(i64),
    /// String key.
    Str(String),
}

/// A scalar-only PHP value for flat settings maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhpScalar {
    /// `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A string.
    Str(String),
}

impl PhpScalar {
    /// Return the string value, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }

    /// Return the integer value, if this is an integer.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            _ => None,
        }
    }

    /// Return the boolean value, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    fn to_value(&self) -> PhpValue {
        match self {
            Self::Null => PhpValue::Null,
            Self::Bool(value) => PhpValue::Bool(*value),
            Self::Int(value) => PhpValue::Int(*value),
            Self::Str(value) => PhpValue::Str(value.clone()),
        }
    }
}

/// A serialisation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhpError {
    /// The value is malformed or contains an unsupported type.
    Format(String),
    /// A size, depth or entry limit was exceeded.
    Limit(String),
}

impl fmt::Display for PhpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(message) => write!(f, "PHP serialisation format: {message}"),
            Self::Limit(message) => write!(f, "PHP serialisation limit: {message}"),
        }
    }
}

impl std::error::Error for PhpError {}

impl PhpValue {
    /// Look up an array entry by key.
    pub fn get(&self, key: &PhpKey) -> Option<&PhpValue> {
        match self {
            Self::Array(items) => items
                .iter()
                .find(|(item, _)| item == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// Look up an array entry by integer index.
    pub fn get_index(&self, index: usize) -> Option<&PhpValue> {
        self.get(&PhpKey::Int(index as i64))
    }

    /// Look up a string value by key.
    pub fn get_str(&self, key: &PhpKey) -> Option<&str> {
        self.get(key)?.as_str()
    }

    /// Look up an integer value by key.
    pub fn get_i64(&self, key: &PhpKey) -> Option<i64> {
        self.get(key)?.as_i64()
    }

    /// Look up a boolean value by key.
    pub fn get_bool(&self, key: &PhpKey) -> Option<bool> {
        self.get(key)?.as_bool()
    }

    /// Return the string value, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }

    /// Return the integer value, if this is an integer.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            _ => None,
        }
    }

    /// Return the float value, if this is a float.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float(value) => Some(*value),
            _ => None,
        }
    }

    /// Return the boolean value, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Return the array entries, if this is an array.
    pub fn as_array(&self) -> Option<&[(PhpKey, PhpValue)]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Build an associative array from string keys.
    pub fn assoc<I, K>(items: I) -> Self
    where
        I: IntoIterator<Item = (K, PhpValue)>,
        K: Into<String>,
    {
        Self::Array(
            items
                .into_iter()
                .map(|(key, value)| (PhpKey::Str(key.into()), value))
                .collect(),
        )
    }
}

/// Serialise a value to PHP's `serialize()` format.
///
/// Returns an error for non-finite floats and for arrays nested deeper than
/// [`MAX_SERIALIZED_DEPTH`].
pub fn serialize(value: &PhpValue) -> Result<String, PhpError> {
    let mut out = String::new();
    write_value(&mut out, value, 0)?;
    Ok(out)
}

fn write_value(out: &mut String, value: &PhpValue, depth: usize) -> Result<(), PhpError> {
    if depth > MAX_SERIALIZED_DEPTH {
        return Err(PhpError::Limit("serialised nesting is too deep".into()));
    }
    match value {
        PhpValue::Null => out.push_str("N;"),
        PhpValue::Bool(true) => out.push_str("b:1;"),
        PhpValue::Bool(false) => out.push_str("b:0;"),
        PhpValue::Int(value) => {
            out.push_str("i:");
            out.push_str(&value.to_string());
            out.push(';');
        }
        PhpValue::Float(value) => {
            if !value.is_finite() {
                return Err(PhpError::Format("non-finite float".into()));
            }
            out.push_str("d:");
            out.push_str(&value.to_string());
            out.push(';');
        }
        PhpValue::Str(value) => {
            out.push_str("s:");
            out.push_str(&value.len().to_string());
            out.push_str(":\"");
            out.push_str(value);
            out.push_str("\";");
        }
        PhpValue::Array(items) => {
            out.push_str("a:");
            out.push_str(&items.len().to_string());
            out.push_str(":{");
            for (key, value) in items {
                match key {
                    PhpKey::Int(value) => {
                        out.push_str("i:");
                        out.push_str(&value.to_string());
                        out.push(';');
                    }
                    PhpKey::Str(value) => {
                        out.push_str("s:");
                        out.push_str(&value.len().to_string());
                        out.push_str(":\"");
                        out.push_str(value);
                        out.push_str("\";");
                    }
                }
                write_value(out, value, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Parse a PHP `serialize()` value.
///
/// The input is capped at [`MAX_SERIALIZED_BYTES`], nesting at
/// [`MAX_SERIALIZED_DEPTH`] and array size at [`MAX_SERIALIZED_ENTRIES`].
/// Trailing bytes, duplicate keys, objects, references and invalid UTF-8 are
/// rejected.
pub fn unserialize(input: &str) -> Result<PhpValue, PhpError> {
    unserialize_with_budget(input, MAX_SERIALIZED_BYTES)
}

/// Parse a PHP value with an explicit input budget.
///
/// The budget is clamped to `1..=16 MiB`; the depth and entry caps are the
/// same as [`unserialize`].
pub fn unserialize_with_budget(input: &str, max_bytes: usize) -> Result<PhpValue, PhpError> {
    let max_bytes = max_bytes.clamp(1, 16 * 1024 * 1024);
    if input.len() > max_bytes {
        return Err(PhpError::Limit("serialised value is too large".into()));
    }
    let mut parser = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
        entries: 0,
    };
    let value = parser.value()?;
    if parser.pos != parser.bytes.len() {
        return Err(PhpError::Format("trailing serialised data".into()));
    }
    Ok(value)
}

/// Parse a flat PHP array whose keys are strings and whose values are scalars.
///
/// This is the shape of a board settings row. Nested arrays and floats are
/// rejected.
pub fn parse_scalar_map(
    input: &str,
    max_bytes: usize,
) -> Result<Vec<(String, PhpScalar)>, PhpError> {
    let value = unserialize_with_budget(input, max_bytes)?;
    let PhpValue::Array(items) = value else {
        return Err(PhpError::Format("expected a serialised array".into()));
    };
    let mut out = Vec::with_capacity(items.len());
    for (key, value) in items {
        let PhpKey::Str(key) = key else {
            return Err(PhpError::Format("scalar map keys must be strings".into()));
        };
        let value = match value {
            PhpValue::Null => PhpScalar::Null,
            PhpValue::Bool(value) => PhpScalar::Bool(value),
            PhpValue::Int(value) => PhpScalar::Int(value),
            PhpValue::Str(value) => PhpScalar::Str(value),
            PhpValue::Float(_) => {
                return Err(PhpError::Format(
                    "scalar map values must not be floats".into(),
                ))
            }
            PhpValue::Array(_) => {
                return Err(PhpError::Format(
                    "scalar map values must not be arrays".into(),
                ))
            }
        };
        out.push((key, value));
    }
    Ok(out)
}

/// Serialise a flat scalar map as a PHP array.
pub fn serialize_scalar_map(items: &[(String, PhpScalar)]) -> Result<String, PhpError> {
    let value = PhpValue::Array(
        items
            .iter()
            .map(|(key, value)| (PhpKey::Str(key.clone()), value.to_value()))
            .collect(),
    );
    serialize(&value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
    entries: usize,
}

impl Parser<'_> {
    fn value(&mut self) -> Result<PhpValue, PhpError> {
        self.depth += 1;
        if self.depth > MAX_SERIALIZED_DEPTH {
            return Err(PhpError::Limit("serialised nesting is too deep".into()));
        }
        let tag = self.take(1)?[0];
        let value = match tag {
            b'N' => {
                self.expect(b';')?;
                PhpValue::Null
            }
            b'b' => {
                self.expect(b':')?;
                let value = match self.take(1)?[0] {
                    b'0' => false,
                    b'1' => true,
                    _ => return Err(PhpError::Format("invalid boolean".into())),
                };
                self.expect(b';')?;
                PhpValue::Bool(value)
            }
            b'i' => {
                self.expect(b':')?;
                let text = self.until(b';')?;
                PhpValue::Int(
                    text.parse()
                        .map_err(|_| PhpError::Format("invalid integer".into()))?,
                )
            }
            b'd' => {
                self.expect(b':')?;
                let text = self.until(b';')?;
                let value = text
                    .parse::<f64>()
                    .map_err(|_| PhpError::Format("invalid float".into()))?;
                if !value.is_finite() {
                    return Err(PhpError::Format("non-finite float".into()));
                }
                PhpValue::Float(value)
            }
            b's' => {
                self.expect(b':')?;
                let length = self
                    .until(b':')?
                    .parse::<usize>()
                    .map_err(|_| PhpError::Format("invalid string length".into()))?;
                self.expect(b'"')?;
                let bytes = self.take(length)?;
                let value = std::str::from_utf8(bytes)
                    .map_err(|_| PhpError::Format("invalid UTF-8 string".into()))?;
                let value = value.to_string();
                self.expect(b'"')?;
                self.expect(b';')?;
                PhpValue::Str(value)
            }
            b'a' => {
                self.expect(b':')?;
                let count = self
                    .until(b':')?
                    .parse::<usize>()
                    .map_err(|_| PhpError::Format("invalid array length".into()))?;
                self.entries = self.entries.saturating_add(count);
                if count > MAX_SERIALIZED_ENTRIES || self.entries > MAX_SERIALIZED_ENTRIES {
                    return Err(PhpError::Limit("serialised array is too large".into()));
                }
                self.expect(b'{')?;
                let initial_cap = count.min((self.bytes.len() - self.pos) / 4).min(64);
                let mut items = Vec::with_capacity(initial_cap);
                let mut seen = HashSet::with_capacity(initial_cap);
                for _ in 0..count {
                    let key = match self.take(1)?[0] {
                        b'i' => {
                            self.expect(b':')?;
                            PhpKey::Int(
                                self.until(b';')?
                                    .parse()
                                    .map_err(|_| PhpError::Format("invalid array key".into()))?,
                            )
                        }
                        b's' => {
                            self.expect(b':')?;
                            let length = self
                                .until(b':')?
                                .parse::<usize>()
                                .map_err(|_| PhpError::Format("invalid key length".into()))?;
                            self.expect(b'"')?;
                            let bytes = self.take(length)?;
                            let value = std::str::from_utf8(bytes)
                                .map_err(|_| PhpError::Format("invalid key UTF-8".into()))?
                                .to_string();
                            self.expect(b'"')?;
                            self.expect(b';')?;
                            PhpKey::Str(value)
                        }
                        _ => return Err(PhpError::Format("invalid array key type".into())),
                    };
                    if !seen.insert(key.clone()) {
                        return Err(PhpError::Format("duplicate key in serialised array".into()));
                    }
                    items.push((key, self.value()?));
                }
                self.expect(b'}')?;
                PhpValue::Array(items)
            }
            b'O' | b'C' | b'R' | b'r' => {
                return Err(PhpError::Format(
                    "objects and references are not allowed".into(),
                ))
            }
            _ => return Err(PhpError::Format("unsupported serialised type".into())),
        };
        self.depth -= 1;
        Ok(value)
    }

    fn take(&mut self, len: usize) -> Result<&[u8], PhpError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| PhpError::Format("serialised length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(PhpError::Format("truncated serialised value".into()));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn expect(&mut self, byte: u8) -> Result<(), PhpError> {
        let actual = self.take(1)?[0];
        if actual != byte {
            return Err(PhpError::Format("unexpected serialised delimiter".into()));
        }
        Ok(())
    }

    fn until(&mut self, byte: u8) -> Result<&str, PhpError> {
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos] != byte {
            self.pos += 1;
        }
        if self.pos >= self.bytes.len() {
            return Err(PhpError::Format("unterminated serialised value".into()));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| PhpError::Format("invalid serialised UTF-8".into()))?;
        self.pos += 1;
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(serialize(&PhpValue::Null).unwrap(), "N;");
        assert_eq!(serialize(&PhpValue::Bool(true)).unwrap(), "b:1;");
        assert_eq!(serialize(&PhpValue::Int(-7)).unwrap(), "i:-7;");
        assert_eq!(serialize(&PhpValue::Float(1.5)).unwrap(), "d:1.5;");
        assert_eq!(
            serialize(&PhpValue::Str("hei".into())).unwrap(),
            "s:3:\"hei\";"
        );
        assert_eq!(
            serialize(&PhpValue::assoc([("a", PhpValue::Int(1))])).unwrap(),
            "a:1:{s:1:\"a\";i:1;}"
        );
    }

    #[test]
    fn scalar_maps_roundtrip() {
        let items = vec![
            ("enabled".to_string(), PhpScalar::Bool(true)),
            ("count".to_string(), PhpScalar::Int(7)),
            ("name".to_string(), PhpScalar::Str("board".to_string())),
            ("none".to_string(), PhpScalar::Null),
        ];
        let encoded = serialize_scalar_map(&items).unwrap();
        assert_eq!(parse_scalar_map(&encoded, 4096).unwrap(), items);
    }

    #[test]
    fn scalar_maps_reject_nested_and_float_values() {
        let nested = serialize(&PhpValue::assoc([(
            "a",
            PhpValue::Array(vec![(PhpKey::Int(0), PhpValue::Int(1))]),
        )]))
        .unwrap();
        assert!(parse_scalar_map(&nested, 4096).is_err());

        let float = serialize(&PhpValue::assoc([("a", PhpValue::Float(1.5))])).unwrap();
        assert!(parse_scalar_map(&float, 4096).is_err());
    }

    #[test]
    fn explicit_budget_is_enforced() {
        let encoded = serialize(&PhpValue::Str("x".repeat(64))).unwrap();
        assert!(unserialize_with_budget(&encoded, encoded.len()).is_ok());
        assert!(unserialize_with_budget(&encoded, encoded.len() - 1).is_err());
    }

    #[test]
    fn roundtrips_nested_values() {
        let value = PhpValue::Array(vec![
            (PhpKey::Int(0), PhpValue::Str("x".into())),
            (
                PhpKey::Str("list".into()),
                PhpValue::Array(vec![
                    (PhpKey::Int(0), PhpValue::Bool(false)),
                    (PhpKey::Int(1), PhpValue::Float(2.25)),
                ]),
            ),
        ]);
        let encoded = serialize(&value).unwrap();
        assert_eq!(unserialize(&encoded).unwrap(), value);
    }

    #[test]
    fn rejects_objects_references_and_trailing_data() {
        assert!(unserialize("O:8:\"stdClass\":0:{}").is_err());
        assert!(unserialize("R:1;").is_err());
        assert!(unserialize("N;x").is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert!(unserialize("a:2:{i:0;N;i:0;N;}").is_err());
    }

    #[test]
    fn rejects_invalid_utf8_slices() {
        // The declared length splits the two-byte `ä`.
        assert!(unserialize("s:1:\"ä\";").is_err());
    }

    #[test]
    fn rejects_non_finite_floats() {
        assert!(serialize(&PhpValue::Float(f64::NAN)).is_err());
        assert!(serialize(&PhpValue::Float(f64::INFINITY)).is_err());
        assert!(unserialize("d:NAN;").is_err());
    }

    #[test]
    fn enforces_depth_and_entry_limits() {
        let mut value = PhpValue::Null;
        for _ in 0..(MAX_SERIALIZED_DEPTH + 1) {
            value = PhpValue::Array(vec![(PhpKey::Int(0), value)]);
        }
        assert!(serialize(&value).is_err());

        let mut input = String::new();
        for _ in 0..(MAX_SERIALIZED_DEPTH + 1) {
            input.push_str("a:1:{i:0;");
        }
        input.push_str("N;");
        for _ in 0..(MAX_SERIALIZED_DEPTH + 1) {
            input.push('}');
        }
        assert!(unserialize(&input).is_err());

        // Cumulative entries across nested arrays cannot exceed MAX_SERIALIZED_ENTRIES.
        let mut cumulative = format!("a:2:{{i:0;a:{MAX_SERIALIZED_ENTRIES}:{{");
        for i in 0..MAX_SERIALIZED_ENTRIES {
            cumulative.push_str(&format!("i:{i};N;"));
        }
        cumulative.push_str("}i:1;N;}");
        assert!(matches!(unserialize(&cumulative), Err(PhpError::Limit(_))));
    }
}
