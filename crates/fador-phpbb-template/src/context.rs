use crate::value::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) struct LoopFrame {
    pub name: String,
    pub path: String,
    pub row: BTreeMap<String, Value>,
    pub meta: BTreeMap<String, Value>,
    /// A scalar row from `for x in ['a', 'b']`.  Object rows leave this empty.
    pub scalar: Option<Value>,
}

/// The data a template renders against.
///
/// A context holds global values (`set`), local values (`set_local`, written by
/// `{% set %}` and `{% DEFINE %}`) and the loop frames the renderer pushes while
/// it walks a block. Lookups are case-sensitive and follow phpBB's rules:
/// `{$NAME}` falls back from a definition to a global, `definition.NAME` reads
/// either scope, `loop.*` exposes the current loop metadata and the innermost
/// loop row wins for `forumrow.NAME` and bare `NAME` paths.
///
/// ```
/// use fador_phpbb_template::{Context, Value};
///
/// let mut context = Context::new();
/// context.set("NAME", Value::Str("Naruto".into()));
/// assert!(context.is_defined("NAME"));
/// assert_eq!(context.get("NAME"), Some(Value::Str("Naruto".into())));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Context {
    values: BTreeMap<String, Value>,
    locals: BTreeMap<String, Value>,
    pub(crate) loops: Vec<LoopFrame>,
}

impl Context {
    /// Create an empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a global template value.
    pub fn set(&mut self, name: impl Into<String>, value: Value) {
        self.values.insert(name.into(), value);
    }

    /// Set a local (definition) value, the scope `{% set %}` writes to.
    pub fn set_local(&mut self, name: impl Into<String>, value: Value) {
        self.locals.insert(name.into(), value);
    }

    pub(crate) fn remove_local(&mut self, name: &str) {
        self.locals.remove(name);
    }

    /// Read a dotted path such as `forumrow.NAME` or `loop.index`.
    pub fn get(&self, path: &str) -> Option<Value> {
        self.lookup(path)
    }

    /// Whether a path resolves to any value, including null.
    pub fn is_defined(&self, path: &str) -> bool {
        self.lookup(path).is_some()
    }

    /// Whether a legacy block array exists and would render at least once.
    ///
    /// A leading dot (`.forumrow.subforum`) is accepted because that is how a
    /// nested block is referenced from a template.
    pub fn block_exists(&self, path: &str) -> bool {
        let path = path.strip_prefix('.').unwrap_or(path);
        self.lookup(path)
            .map(|value| match value {
                Value::Array(values) => !values.is_empty(),
                Value::Object(values) => !values.is_empty(),
                other => other.truthy(),
            })
            .unwrap_or(false)
    }

    pub(crate) fn lookup(&self, path: &str) -> Option<Value> {
        if path.is_empty() {
            return None;
        }
        if let Some(name) = path.strip_prefix("definition.") {
            if let Some(value) = self.locals.get(name) {
                return Some(value.clone());
            }
            if let Some(value) = self.values.get(name) {
                return Some(value.clone());
            }
        }
        if let Some(value) = self.locals.get(path) {
            return Some(value.clone());
        }
        // `{$NAME}` first means a DEFINE'd local variable.  phpBB also allows
        // the same syntax for global template variables whose name is
        // assigned without the dollar sign (for example `SCRIPTS`).
        if let Some(name) = path.strip_prefix('$') {
            if let Some(value) = self.values.get(name) {
                return Some(value.clone());
            }
        }
        if path == "loop" {
            return self
                .loops
                .last()
                .map(|frame| Value::Object(frame.meta.clone()));
        }
        if let Some(rest) = path.strip_prefix("loop.") {
            let frame = self.loops.last()?;
            return frame.meta.get(rest).cloned();
        }

        // Innermost loop paths win.  This is what makes both
        // `forumrow.subforum.NAME` and `subforum.NAME` work inside nested
        // loops.
        for frame in self.loops.iter().rev() {
            if path == frame.path {
                return frame
                    .scalar
                    .clone()
                    .or_else(|| Some(Value::Object(frame.row.clone())));
            }
            if let Some(rest) = path.strip_prefix(&format!("{}.", frame.path)) {
                return lookup_in(&Value::Object(frame.row.clone()), rest);
            }
            let first = path.split('.').next().unwrap_or("");
            if first == frame.name {
                let rest = path.strip_prefix(&frame.name).unwrap_or("");
                let rest = rest.strip_prefix('.').unwrap_or(rest);
                if rest.is_empty() {
                    return frame
                        .scalar
                        .clone()
                        .or_else(|| Some(Value::Object(frame.row.clone())));
                }
                return lookup_in(&Value::Object(frame.row.clone()), rest);
            }
        }

        if let Some(value) = self.values.get(path) {
            return Some(value.clone());
        }
        if let Some((first, rest)) = path.split_once('.') {
            if let Some(value) = self.values.get(first) {
                return lookup_in(value, rest);
            }
        }
        None
    }

    pub(crate) fn resolve_block(&self, name: &str) -> (Vec<Value>, String) {
        // A dotted path is always explicit.
        if name.contains('.') {
            let rows = match self.lookup(name) {
                Some(Value::Array(values)) => values,
                _ => Vec::new(),
            };
            return (rows, name.to_string());
        }

        // Nested block arrays live on the current row.  Walk outward so the
        // innermost row wins.
        for frame in self.loops.iter().rev() {
            if let Some(Value::Array(values)) = frame.row.get(name) {
                return (values.clone(), format!("{}.{}", frame.path, name));
            }
        }

        if let Some(Value::Array(values)) = self.locals.get(name) {
            return (values.clone(), name.to_string());
        }
        if let Some(Value::Array(values)) = self.values.get(name) {
            return (values.clone(), name.to_string());
        }
        (Vec::new(), name.to_string())
    }

    pub(crate) fn push_loop(
        &mut self,
        name: &str,
        path: &str,
        rows: &[Value],
        index: usize,
    ) -> bool {
        let Some(value) = rows.get(index).cloned() else {
            return false;
        };
        let (mut row, scalar) = match value {
            Value::Object(row) => (row, None),
            other => (BTreeMap::new(), Some(other)),
        };
        let len = rows.len();
        let first = index == 0;
        let last = index + 1 == len;
        row.insert("S_ROW_COUNT".into(), Value::Int(index as i64));
        row.insert("S_ROW_NUM".into(), Value::Int(index as i64 + 1));
        row.insert("S_FIRST_ROW".into(), Value::Bool(first));
        row.insert("S_LAST_ROW".into(), Value::Bool(last));
        row.insert("S_NUM_ROWS".into(), Value::Int(len as i64));

        let mut meta = BTreeMap::new();
        meta.insert("index".into(), Value::Int(index as i64));
        meta.insert("index0".into(), Value::Int(index as i64));
        meta.insert("revindex".into(), Value::Int((len - index) as i64));
        meta.insert("revindex0".into(), Value::Int((len - index - 1) as i64));
        meta.insert("first".into(), Value::Bool(first));
        meta.insert("last".into(), Value::Bool(last));
        meta.insert("length".into(), Value::Int(len as i64));
        meta.insert("parent".into(), Value::Null);

        self.loops.push(LoopFrame {
            name: name.to_string(),
            path: path.to_string(),
            row,
            meta,
            scalar,
        });
        true
    }

    pub(crate) fn pop_loop(&mut self) {
        self.loops.pop();
    }
}

fn lookup_in(value: &Value, path: &str) -> Option<Value> {
    let mut current = value.clone();
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        current = match current {
            Value::Object(values) => values.get(segment)?.clone(),
            Value::Array(values) => {
                let index: usize = segment.parse().ok()?;
                values.get(index)?.clone()
            }
            _ => return None,
        };
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(entries: &[(&str, Value)]) -> Value {
        Value::object(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone())),
        )
    }

    #[test]
    fn nested_block_paths_resolve_to_the_current_row() {
        let mut ctx = Context::new();
        let subforum = object(&[("SUBFORUM_NAME", Value::Str("Sub".into()))]);
        let forum = object(&[
            ("FORUM_NAME", Value::Str("Forum".into())),
            ("subforum", Value::Array(vec![subforum])),
        ]);
        ctx.set("forumrow", Value::Array(vec![forum]));
        let (rows, path) = ctx.resolve_block("forumrow");
        assert!(ctx.push_loop("forumrow", &path, &rows, 0));
        assert_eq!(
            ctx.lookup("forumrow.FORUM_NAME")
                .and_then(|v| v.as_str().map(str::to_string)),
            Some("Forum".into())
        );
        assert!(ctx.block_exists(".forumrow.subforum"));
        let (subs, sub_path) = ctx.resolve_block("subforum");
        assert_eq!(sub_path, "forumrow.subforum");
        assert!(ctx.push_loop("subforum", &sub_path, &subs, 0));
        assert_eq!(
            ctx.lookup("forumrow.subforum.SUBFORUM_NAME")
                .and_then(|v| v.as_str().map(str::to_string)),
            Some("Sub".into())
        );
        assert_eq!(
            ctx.lookup("subforum.S_LAST_ROW").and_then(|v| match v {
                Value::Bool(b) => Some(b),
                _ => None,
            }),
            Some(true)
        );
    }
}
