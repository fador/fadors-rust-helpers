//! PHP-like values and arrays used by the template evaluator.
//!
//! The types mirror PHP's semantics where the templates can observe them:
//! arrays keep insertion order and share their cells, `to_php_string()` uses
//! PHP's precision for floats, and comparisons follow PHP's numeric-then-string
//! rules. Nothing here allocates without a bound; the evaluator applies its
//! own limits before it builds a value.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

/// A host callback exposed to a template as a callable value.
///
/// Templates call callbacks the way SMF does with `$context['get_message']()`.
/// The callback owns its state (rendered rows, cursors) and never receives
/// access to the database, the filesystem or the network.
pub type NativeFunction = dyn FnMut(Vec<Value>) -> Result<Value, String>;

/// A callable value stored in a [`Value::Function`].
///
/// The callback is shared, so cloning a function value does not copy its
/// state. A callback that is already running is rejected instead of
/// panicking on a double borrow.
#[derive(Clone)]
pub struct FunctionValue(Rc<RefCell<NativeFunction>>);

impl FunctionValue {
    /// Wrap a closure as a callable value.
    pub fn new<F>(function: F) -> Self
    where
        F: FnMut(Vec<Value>) -> Result<Value, String> + 'static,
    {
        Self(Rc::new(RefCell::new(function)))
    }

    /// Invoke the callback. Re-entrant calls are rejected instead of panicking
    /// on a double borrow.
    ///
    /// # Errors
    ///
    /// Returns the callback's own error message, or a message when the
    /// callback is already running.
    pub fn call(&self, args: Vec<Value>) -> Result<Value, String> {
        let mut function = self
            .0
            .try_borrow_mut()
            .map_err(|_| "callback is already running".to_string())?;
        function(args)
    }

    /// Whether both values wrap the same callback.
    pub fn is_same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for FunctionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Function")
    }
}

/// A PHP-like value: null, bool, int, float, string, array or callable.
///
/// Arrays are reference-counted and mutable, so two variables can share one
/// array the way PHP does after `$a = &$b`. Use [`Value::deep_clone`] to copy
/// a value the way a plain PHP assignment would.
#[derive(Debug, Clone)]
pub enum Value {
    /// PHP `null`.
    Null,
    /// PHP `bool`.
    Bool(bool),
    /// PHP `int`.
    Int(i64),
    /// PHP `float`.
    Float(f64),
    /// PHP `string`.
    Str(String),
    /// A PHP array, shared by reference.
    Array(Rc<RefCell<PhpArray>>),
    /// A callable value; templates call it as `$context['get_message']()`.
    Function(FunctionValue),
}

/// An array key: an integer or a string, exactly like PHP.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    /// An integer key.
    Int(i64),
    /// A string key.
    Str(String),
}

/// A PHP array: insertion-ordered entries with int or string keys.
///
/// Entries hold their value in a shared cell, so a reference taken from the
/// array (`$row = &$context['row']`) stays valid when the array is reordered.
/// Arrays larger than 16 entries build a lazy key index; mutating the array
/// drops it again.
#[derive(Debug, Clone, Default)]
pub struct PhpArray {
    entries: Vec<(Key, Rc<RefCell<Value>>)>,
    /// Lazily built key -> position lookup for the large arrays (`$txt` has
    /// ~5,000 keys and every template lookup would otherwise scan it).
    index: OnceCell<HashMap<Key, usize>>,
}

/// Arrays below this size are faster to scan than to index.
const INDEX_THRESHOLD: usize = 16;

const MAX_ARRAY_DEPTH: usize = 64;

impl PhpArray {
    /// An empty array.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an array from entries whose keys are already unique and in their
    /// final order. This is the linear-time counterpart of repeated `insert`
    /// calls for the language and settings maps, which have thousands of keys.
    pub fn from_entries(entries: Vec<(Key, Value)>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(key, value)| (key, Rc::new(RefCell::new(value))))
                .collect(),
            index: OnceCell::new(),
        }
    }

    /// Number of entries, the value PHP's `count()` returns.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the array has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Position lookup that never builds the lazily cached index. Mutating
    /// callers use this so appending a large array cannot rebuild the index
    /// (and invalidate it again) on every insert.
    fn existing_position(&self, key: &Key) -> Option<usize> {
        if let Some(index) = self.index.get() {
            return index.get(key).copied();
        }
        self.entries.iter().position(|(entry, _)| entry == key)
    }

    fn position(&self, key: &Key) -> Option<usize> {
        if let Some(index) = self.index.get() {
            return index.get(key).copied();
        }
        if self.entries.len() < INDEX_THRESHOLD {
            return self.entries.iter().position(|(entry, _)| entry == key);
        }
        let index = self.index.get_or_init(|| {
            let mut map = HashMap::with_capacity(self.entries.len());
            for (position, (entry, _)) in self.entries.iter().enumerate() {
                map.entry(entry.clone()).or_insert(position);
            }
            map
        });
        index.get(key).copied()
    }

    /// The shared cell stored under `key`, if the key exists.
    pub fn get(&self, key: &Key) -> Option<Rc<RefCell<Value>>> {
        self.position(key)
            .map(|position| Rc::clone(&self.entries[position].1))
    }

    /// Store `value` under `key`, replacing an existing entry in place so the
    /// insertion order is unchanged.
    pub fn insert(&mut self, key: Key, value: Value) {
        if let Some(position) = self.existing_position(&key) {
            *self.entries[position].1.borrow_mut() = value;
            return;
        }
        self.entries.push((key, Rc::new(RefCell::new(value))));
        self.index = OnceCell::new();
    }

    /// Bind `key` to an existing cell, which is what `$a[$k] = &$b` does.
    pub fn set_cell(&mut self, key: Key, cell: Rc<RefCell<Value>>) {
        if let Some(position) = self.existing_position(&key) {
            self.entries[position].1 = cell;
            return;
        }
        self.entries.push((key, cell));
        self.index = OnceCell::new();
    }

    /// Append `value` under the next integer key, and return that key.
    ///
    /// The next key is one past the largest integer key, exactly like PHP, so
    /// an array built from `array(1 => 'a')` continues at 2.
    pub fn push(&mut self, value: Value) -> Key {
        let next = self
            .entries
            .iter()
            .filter_map(|(key, _)| match key {
                Key::Int(value) => Some(value.saturating_add(1)),
                Key::Str(_) => None,
            })
            .max()
            .unwrap_or(0);
        let key = Key::Int(next);
        self.entries
            .push((key.clone(), Rc::new(RefCell::new(value))));
        self.index = OnceCell::new();
        key
    }

    /// Remove `key` and return its cell, or `None` when the key is absent.
    pub fn remove(&mut self, key: &Key) -> Option<Rc<RefCell<Value>>> {
        let index = self.entries.iter().position(|(entry, _)| entry == key)?;
        self.index = OnceCell::new();
        Some(self.entries.remove(index).1)
    }

    /// A snapshot of the entries, in order, with shared value cells.
    pub fn entries(&self) -> Vec<(Key, Rc<RefCell<Value>>)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.clone(), Rc::clone(value)))
            .collect()
    }

    /// The keys, in insertion order.
    pub fn keys(&self) -> Vec<Key> {
        self.entries.iter().map(|(key, _)| key.clone()).collect()
    }

    /// Deep copies of the values, in insertion order.
    pub fn values(&self) -> Vec<Value> {
        self.entries
            .iter()
            .map(|(_, value)| value.borrow().deep_clone())
            .collect()
    }

    /// Sort the entries by key, like PHP's `ksort()`.
    pub fn ksort(&mut self) {
        self.entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        self.index = OnceCell::new();
    }

    /// Reverse the entry order, like PHP's `array_reverse()`.
    ///
    /// When `preserve_keys` is false the keys are renumbered from zero.
    pub fn reverse(&mut self, preserve_keys: bool) {
        self.entries.reverse();
        if !preserve_keys {
            for (index, (key, _)) in self.entries.iter_mut().enumerate() {
                *key = Key::Int(index as i64);
            }
        }
        self.index = OnceCell::new();
    }

    /// A recursive copy: mutating the copy never changes this array.
    pub fn deep_clone(&self) -> Self {
        self.deep_clone_bounded(0)
    }

    fn deep_clone_bounded(&self, depth: usize) -> Self {
        let mut out = PhpArray::new();
        if depth > MAX_ARRAY_DEPTH {
            return out;
        }
        for (key, value) in &self.entries {
            out.entries.push((
                key.clone(),
                Rc::new(RefCell::new(value.borrow().deep_clone_bounded(depth + 1))),
            ));
        }
        out
    }
}

impl Value {
    /// A new empty array value.
    pub fn array() -> Self {
        Value::Array(Rc::new(RefCell::new(PhpArray::new())))
    }

    /// Wrap an existing array as a value.
    pub fn from_array(array: PhpArray) -> Self {
        Value::Array(Rc::new(RefCell::new(array)))
    }

    /// The shared array, when this value is an array.
    pub fn as_array(&self) -> Option<&Rc<RefCell<PhpArray>>> {
        match self {
            Value::Array(array) => Some(array),
            _ => None,
        }
    }

    /// Wrap a closure as a callable value.
    pub fn from_function<F>(function: F) -> Self
    where
        F: FnMut(Vec<Value>) -> Result<Value, String> + 'static,
    {
        Value::Function(FunctionValue::new(function))
    }

    /// The callable, when this value is a function.
    pub fn as_function(&self) -> Option<&FunctionValue> {
        match self {
            Value::Function(function) => Some(function),
            _ => None,
        }
    }

    /// Whether this is PHP `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Whether this is an array.
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }

    /// Whether this is a float.
    pub fn is_float(&self) -> bool {
        matches!(self, Value::Float(_))
    }

    /// A recursive copy of the value.
    ///
    /// Scalars and callables are copied as they are; an array is copied
    /// recursively, so the copy can be mutated without affecting the original.
    pub fn deep_clone(&self) -> Value {
        self.deep_clone_bounded(0)
    }

    pub(crate) fn deep_clone_bounded(&self, depth: usize) -> Value {
        if depth > MAX_ARRAY_DEPTH {
            return Value::Null;
        }
        match self {
            Value::Null => Value::Null,
            Value::Bool(value) => Value::Bool(*value),
            Value::Int(value) => Value::Int(*value),
            Value::Float(value) => Value::Float(*value),
            Value::Str(value) => Value::Str(value.clone()),
            Value::Array(array) => {
                Value::from_array(array.borrow().deep_clone_bounded(depth + 1))
            }
            Value::Function(function) => Value::Function(function.clone()),
        }
    }

    /// PHP truthiness.
    ///
    /// `null`, `false`, `0`, `0.0`, `""`, `"0"` and the empty array are false;
    /// everything else, including a callable, is true.
    pub fn to_bool(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(value) => *value,
            Value::Int(value) => *value != 0,
            Value::Float(value) => *value != 0.0,
            Value::Str(value) => !value.is_empty() && value != "0",
            Value::Array(array) => !array.borrow().is_empty(),
            Value::Function(_) => true,
        }
    }

    /// PHP integer conversion. A string yields its leading number, or zero.
    pub fn to_int(&self) -> i64 {
        match self {
            Value::Null => 0,
            Value::Bool(value) => i64::from(*value),
            Value::Int(value) => *value,
            Value::Float(value) => *value as i64,
            Value::Str(value) => parse_leading_number(value).map_or(0, |n| n as i64),
            Value::Array(_) | Value::Function(_) => 0,
        }
    }

    /// PHP float conversion. A string yields its leading number, or zero.
    pub fn to_float(&self) -> f64 {
        match self {
            Value::Null => 0.0,
            Value::Bool(value) => f64::from(u8::from(*value)),
            Value::Int(value) => *value as f64,
            Value::Float(value) => *value,
            Value::Str(value) => parse_leading_number(value).unwrap_or(0.0),
            Value::Array(_) | Value::Function(_) => 0.0,
        }
    }

    /// PHP string conversion, as `echo` performs it.
    ///
    /// `true` is `"1"`, `false` and `null` are empty, an array is `"Array"`,
    /// and a float uses PHP's 14-digit precision.
    pub fn to_php_string(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Bool(true) => "1".into(),
            Value::Bool(false) => String::new(),
            Value::Int(value) => value.to_string(),
            Value::Float(value) => php_float_string(*value),
            Value::Str(value) => value.clone(),
            Value::Array(_) => "Array".into(),
            Value::Function(_) => String::new(),
        }
    }

    /// PHP's name for this type, as `gettype()` reports it.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "NULL",
            Value::Bool(_) => "boolean",
            Value::Int(_) => "integer",
            Value::Float(_) => "double",
            Value::Str(_) => "string",
            Value::Array(_) => "array",
            Value::Function(_) => "object",
        }
    }

    /// Loose comparison (`==`): numeric when both sides are numeric,
    /// otherwise PHP's type-juggling rules.
    pub fn loose_eq(&self, other: &Value) -> bool {
        if let (Some(a), Some(b)) = (self.numeric(), other.numeric()) {
            return a == b;
        }
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Array(_), Value::Array(_)) => self.strict_eq(other),
            (Value::Function(a), Value::Function(b)) => a.is_same(b),
            _ => self.to_php_string() == other.to_php_string(),
        }
    }

    /// Strict comparison (`===`): same type and same value.
    pub fn strict_eq(&self, other: &Value) -> bool {
        self.strict_eq_bounded(other, 0)
    }

    fn strict_eq_bounded(&self, other: &Value, depth: usize) -> bool {
        if depth > MAX_ARRAY_DEPTH {
            return false;
        }
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Function(a), Value::Function(b)) => a.is_same(b),
            (Value::Array(a), Value::Array(b)) => {
                if Rc::ptr_eq(a, b) {
                    return true;
                }
                let a = a.borrow();
                let b = b.borrow();
                if a.len() != b.len() {
                    return false;
                }
                for (key, value) in &a.entries {
                    let Some(other) = b.get(key) else {
                        return false;
                    };
                    if !value
                        .borrow()
                        .strict_eq_bounded(&other.borrow(), depth + 1)
                    {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Ordering used by `<`, `>`, `<=`, `>=` and `<=>`.
    pub fn compare(&self, other: &Value) -> std::cmp::Ordering {
        if let (Some(a), Some(b)) = (self.numeric(), other.numeric()) {
            return a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal);
        }
        self.to_php_string().cmp(&other.to_php_string())
    }

    fn numeric(&self) -> Option<f64> {
        match self {
            Value::Null => Some(0.0),
            Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
            Value::Int(value) => Some(*value as f64),
            Value::Float(value) => Some(*value),
            Value::Str(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else if is_numeric(trimmed) {
                    trimmed.parse::<f64>().ok()
                } else {
                    None
                }
            }
            Value::Array(_) | Value::Function(_) => None,
        }
    }
}

/// Convert a value to an array key the way PHP does.
///
/// A canonical integer string (`"12"`, `"-3"`) becomes an integer key; a
/// float is truncated; `null` becomes the empty string.
pub fn key_from_value(value: &Value) -> Key {
    match value {
        Value::Null => Key::Str(String::new()),
        Value::Bool(value) => Key::Int(i64::from(*value)),
        Value::Int(value) => Key::Int(*value),
        Value::Float(value) => Key::Int(*value as i64),
        Value::Str(value) => {
            if is_canonical_int(value) {
                Key::Int(value.parse().unwrap_or(0))
            } else {
                Key::Str(value.clone())
            }
        }
        Value::Array(_) => Key::Str("Array".into()),
        Value::Function(_) => Key::Str(String::new()),
    }
}

/// Whether the trimmed string is a PHP numeric string.
///
/// Leading and trailing whitespace is ignored; `""`, `"0x1f"` and `"1 2"` are
/// not numeric.
pub fn is_numeric(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    let mut chars = value.chars().peekable();
    if matches!(chars.peek(), Some('+') | Some('-')) {
        chars.next();
    }
    let mut digits = 0;
    let mut dot = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            digits += 1;
        } else if c == '.' && !dot {
            dot = true;
        } else if matches!(c, 'e' | 'E') && digits > 0 {
            if matches!(chars.peek(), Some('+') | Some('-')) {
                chars.next();
            }
            let mut exp_digits = 0;
            for next in chars.by_ref() {
                if next.is_ascii_digit() {
                    exp_digits += 1;
                } else {
                    return false;
                }
            }
            return exp_digits > 0;
        } else {
            return false;
        }
    }
    digits > 0
}

fn is_canonical_int(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    if value.starts_with('0') || value.starts_with('+') {
        return false;
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn parse_leading_number(value: &str) -> Option<f64> {
    let value = value.trim_start();
    let mut end = 0;
    let mut seen_digit = false;
    let mut seen_dot = false;
    let mut seen_exp = false;
    let bytes = value.as_bytes();
    let mut index = 0;
    if matches!(bytes.first(), Some(b'+') | Some(b'-')) {
        index += 1;
    }
    while index < bytes.len() {
        let b = bytes[index];
        if b.is_ascii_digit() {
            seen_digit = true;
            index += 1;
            end = index;
        } else if b == b'.' && !seen_dot && !seen_exp {
            seen_dot = true;
            index += 1;
        } else if matches!(b, b'e' | b'E') && !seen_exp && seen_digit {
            seen_exp = true;
            index += 1;
            if matches!(bytes.get(index), Some(b'+') | Some(b'-')) {
                index += 1;
            }
        } else {
            break;
        }
    }
    if !seen_digit {
        return None;
    }
    value[..end].parse().ok()
}

/// PHP's `echo` float conversion uses `precision=14` significant digits.
/// Render a float the way PHP's `echo` does with `precision = 14`.
///
/// An integral float below 1e15 is printed without a decimal point, `NAN`
/// and `INF` are spelled that way, and trailing zeros are dropped.
pub fn php_float_string(value: f64) -> String {
    if value == 0.0 {
        return "0".into();
    }
    if !value.is_finite() {
        return if value.is_nan() {
            "NAN".into()
        } else if value.is_sign_negative() {
            "-INF".into()
        } else {
            "INF".into()
        };
    }
    if value.fract() == 0.0 && value.abs() < 1.0e15 {
        return format!("{value:.0}");
    }
    let exponent = value.abs().log10().floor() as i32;
    let decimals = (13 - exponent).clamp(0, 40) as usize;
    let mut out = format!("{value:.decimals$}");
    if out.contains('.') {
        while out.ends_with('0') {
            out.pop();
        }
        if out.ends_with('.') {
            out.pop();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthiness_and_strings_match_php() {
        assert!(!Value::Str("0".into()).to_bool());
        assert!(!Value::Str(String::new()).to_bool());
        assert!(Value::Str("0.0".into()).to_bool());
        assert_eq!(Value::Bool(true).to_php_string(), "1");
        assert_eq!(Value::Null.to_php_string(), "");
        assert_eq!(Value::Float(2.0).to_php_string(), "2");
    }

    #[test]
    fn arrays_preserve_order_and_keys() {
        let mut array = PhpArray::new();
        array.insert(Key::Str("b".into()), Value::Int(2));
        array.insert(Key::Str("a".into()), Value::Int(1));
        array.push(Value::Int(3));
        assert_eq!(array.keys()[0], Key::Str("b".into()));
        assert_eq!(array.keys()[2], Key::Int(0));
        array.ksort();
        assert_eq!(array.keys()[0], Key::Int(0));
    }

    #[test]
    fn float_output_uses_php_precision() {
        assert_eq!(Value::Float(8.780000000000001).to_php_string(), "8.78");
        assert_eq!(Value::Float(4.78).to_php_string(), "4.78");
        assert_eq!(Value::Float(100.0).to_php_string(), "100");
        assert_eq!(
            Value::Float(0.007318348144276007).to_php_string(),
            "0.007318348144276"
        );
    }

    #[test]
    fn loose_comparison_is_numeric_when_possible() {
        assert!(Value::Str("10".into()).loose_eq(&Value::Int(10)));
        assert!(Value::Bool(false).loose_eq(&Value::Str("0".into())));
        assert!(!Value::Str("10".into()).strict_eq(&Value::Int(10)));
    }

    #[test]
    fn indexed_lookup_stays_correct_after_mutation() {
        let mut array = PhpArray::new();
        for index in 0..40 {
            array.insert(Key::Str(format!("k{index}")), Value::Int(index));
        }
        // Build the lazy index, then keep mutating the same array.
        assert_eq!(
            array
                .get(&Key::Str("k20".into()))
                .unwrap()
                .borrow()
                .to_int(),
            20
        );
        array.insert(Key::Str("k20".into()), Value::Int(200));
        array.insert(Key::Str("new".into()), Value::Int(999));
        assert_eq!(
            array
                .get(&Key::Str("k20".into()))
                .unwrap()
                .borrow()
                .to_int(),
            200
        );
        assert_eq!(
            array
                .get(&Key::Str("new".into()))
                .unwrap()
                .borrow()
                .to_int(),
            999
        );
        assert!(array.get(&Key::Str("missing".into())).is_none());

        array.remove(&Key::Str("k0".into()));
        assert!(array.get(&Key::Str("k0".into())).is_none());
        assert_eq!(
            array
                .get(&Key::Str("k39".into()))
                .unwrap()
                .borrow()
                .to_int(),
            39
        );

        array.ksort();
        let keys = array.keys();
        assert_eq!(keys.first(), Some(&Key::Str("k1".into())));
        assert_eq!(
            array
                .get(&Key::Str("k39".into()))
                .unwrap()
                .borrow()
                .to_int(),
            39
        );
    }

    #[test]
    fn from_entries_keeps_order_and_lookup() {
        let entries = (0..100)
            .map(|index| (Key::Int(index), Value::Int(index * 2)))
            .collect();
        let array = PhpArray::from_entries(entries);
        assert_eq!(array.len(), 100);
        assert_eq!(array.get(&Key::Int(42)).unwrap().borrow().to_int(), 84);
        assert_eq!(array.entries()[0].0, Key::Int(0));
    }
}
