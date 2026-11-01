use std::collections::BTreeMap;

/// A template value: the data a [`crate::Context`] holds and expressions
/// produce.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Absent or null. Renders as an empty string and is falsy.
    Null,
    /// Boolean. Renders as `1` or an empty string, like phpBB.
    Bool(bool),
    /// Signed integer.
    Int(i64),
    /// Floating-point number. Integral values render without a decimal point.
    Float(f64),
    /// UTF-8 string. Inserted raw by default; escape at the template.
    Str(String),
    /// Ordered list. Renders as `Array` if emitted directly.
    Array(Vec<Value>),
    /// String-keyed map. Renders as `Object` if emitted directly.
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// Build an object from `(key, value)` pairs.
    pub fn object(entries: impl IntoIterator<Item = (String, Value)>) -> Self {
        Self::Object(entries.into_iter().collect())
    }

    /// phpBB/Twig truthiness: null, `false`, `0`, `"0"`, `""` and empty
    /// collections are false.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(value) => *value,
            Value::Int(value) => *value != 0,
            Value::Float(value) => *value != 0.0,
            Value::Str(value) => !value.is_empty() && value != "0",
            Value::Array(values) => !values.is_empty(),
            Value::Object(values) => !values.is_empty(),
        }
    }

    /// Whether `|default` and `is empty` treat the value as absent.
    ///
    /// Unlike [`Value::truthy`], the string `"0"` is not empty and numeric zero
    /// is not empty.
    pub fn is_empty_value(&self) -> bool {
        match self {
            Value::Null => true,
            Value::Bool(value) => !*value,
            Value::Str(value) => value.is_empty(),
            Value::Array(values) => values.is_empty(),
            Value::Object(values) => values.is_empty(),
            Value::Int(_) | Value::Float(_) => false,
        }
    }

    /// The string inside a [`Value::Str`], if any.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(value) => Some(value),
            _ => None,
        }
    }

    /// Coerce to an integer: strings are trimmed and parsed, floats truncate,
    /// booleans become `0`/`1`.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(value) => Some(*value),
            Value::Float(value) if value.is_finite() => Some(*value as i64),
            Value::Bool(value) => Some(i64::from(*value)),
            Value::Str(value) => value.trim().parse().ok(),
            _ => None,
        }
    }

    /// Coerce to a number with the same rules as [`Value::as_i64`].
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(value) => Some(*value as f64),
            Value::Float(value) => Some(*value),
            Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
            Value::Str(value) => value.trim().parse().ok(),
            _ => None,
        }
    }

    /// Length in Unicode scalar values for strings, in elements for
    /// collections, and zero for scalars.
    pub fn len(&self) -> usize {
        match self {
            Value::Str(value) => value.chars().count(),
            Value::Array(values) => values.len(),
            Value::Object(values) => values.len(),
            _ => 0,
        }
    }

    /// Whether [`Value::len`] is zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read a member of an object or an element of an array by numeric index.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(values) => values.get(key),
            Value::Array(values) => key
                .parse::<usize>()
                .ok()
                .and_then(|index| values.get(index)),
            _ => None,
        }
    }

    /// The elements of an array, if the value is one.
    pub fn array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(values) => Some(values),
            _ => None,
        }
    }

    /// Render the value the way a template output expression does.
    ///
    /// This does not escape. Escaping is a template decision (`|e`).
    pub fn to_output(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Bool(value) => {
                if *value {
                    "1".to_string()
                } else {
                    String::new()
                }
            }
            Value::Int(value) => value.to_string(),
            Value::Float(value) => format_float(*value),
            Value::Str(value) => value.clone(),
            Value::Array(_) => "Array".to_string(),
            Value::Object(_) => "Object".to_string(),
        }
    }
}

fn format_float(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        format!("{}", value as i64)
    } else {
        let text = format!("{value}");
        if text.contains('.') {
            text
        } else {
            format!("{text}.0")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthiness_matches_template_expectations() {
        assert!(!Value::Null.truthy());
        assert!(!Value::Bool(false).truthy());
        assert!(Value::Int(1).truthy());
        assert!(!Value::Str("0".into()).truthy());
        assert!(Value::Str("x".into()).truthy());
        assert!(Value::Array(vec![Value::Int(1)]).truthy());
    }

    #[test]
    fn output_and_length_are_codepoint_based() {
        assert_eq!(Value::Str("äö".into()).len(), 2);
        assert_eq!(Value::Bool(true).to_output(), "1");
        assert_eq!(Value::Bool(false).to_output(), "");
        assert_eq!(Value::Float(2.5).to_output(), "2.5");
    }
}
