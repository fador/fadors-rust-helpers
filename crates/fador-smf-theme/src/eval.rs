//! Sandboxed PHP-subset evaluator.
//!
//! Values are PHP-like, arrays preserve insertion order, references are
//! explicit cells, and every execution is bounded by step, depth, output and
//! collection limits. The evaluator has no filesystem, network, process,
//! object system or database access.
//!
//! Two function sets are callable from a template:
//!
//! 1. the PHP standard functions implemented in [`crate::builtins`]
//!    (`count`, `implode`, `sprintf`, `substr`, ...), which every evaluator
//!    provides; and
//! 2. the host functions an application installs with
//!    [`Evaluator::set_host`] — for the SMF theme dialect that is
//!    [`crate::SmfFunctions`].
//!
//! A template function always wins over a builtin of the same name, and
//! nothing outside those two sets is callable: an unknown name is an error,
//! never a dynamic lookup.

use crate::host::{HostContext, HostFunctions};
use crate::value::{key_from_value, Key, PhpArray, Value};
use crate::{AssignOp, BinOp, CastType, Expr, Param, ParseError, Stmt, UnOp};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;
use std::sync::atomic::Ordering;

type Cell = Rc<RefCell<Value>>;

/// Benchmark attribution: statement and function timings, disabled unless the
/// benchmark enables them with [`set_profiling`].
static PROFILING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Enable or disable the process-wide statement and call profiler.
pub fn set_profiling(enabled: bool) {
    PROFILING.store(enabled, Ordering::Relaxed);
}

/// Whether the profiler is enabled.
pub fn profiling() -> bool {
    PROFILING.load(Ordering::Relaxed)
}

type ProfileMap = HashMap<String, (u64, u64)>;

fn profile_map() -> &'static std::sync::Mutex<ProfileMap> {
    static MAP: std::sync::OnceLock<std::sync::Mutex<ProfileMap>> = std::sync::OnceLock::new();
    MAP.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn record_profile(key: &str, nanos: u64) {
    if let Ok(mut map) = profile_map().lock() {
        let entry = map.entry(key.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += nanos;
    }
}

/// Collected timings as `(name, calls, total nanoseconds)`, sorted by total
/// time descending.
///
/// Names are `stmt:<kind>` for statements and `call:<name>` for calls.
pub fn profile_results() -> Vec<(String, u64, u64)> {
    let Ok(map) = profile_map().lock() else {
        return Vec::new();
    };
    let mut entries = map
        .iter()
        .map(|(name, (calls, nanos))| (name.clone(), *calls, *nanos))
        .collect::<Vec<_>>();
    entries.sort_by_key(|left| std::cmp::Reverse(left.2));
    entries
}

/// Drop every collected timing.
pub fn reset_profile() {
    if let Ok(mut map) = profile_map().lock() {
        map.clear();
    }
}

fn stmt_name(stmt: &Stmt) -> &'static str {
    match stmt {
        Stmt::Text(_) => "text",
        Stmt::Echo(_) => "echo",
        Stmt::Expr(_) => "expr",
        Stmt::If { .. } => "if",
        Stmt::Foreach { .. } => "foreach",
        Stmt::For { .. } => "for",
        Stmt::While { .. } => "while",
        Stmt::Switch { .. } => "switch",
        Stmt::Break(_) => "break",
        Stmt::Continue(_) => "continue",
        Stmt::Return(_) => "return",
        Stmt::Function { .. } => "function",
        Stmt::Global(_) => "global",
        Stmt::Unset(_) => "unset",
        Stmt::Block(_) => "block",
        Stmt::Nop => "nop",
    }
}

/// The bounds one template execution may not exceed.
///
/// A template is untrusted input: it can loop, recurse, concatenate and build
/// arrays, so every dimension that can grow is capped. Exceeding a bound is an
/// [`EvalError`], never a panic or an allocation without limit.
#[derive(Debug, Clone)]
pub struct EvalLimits {
    /// Statements plus expressions evaluated per execution.
    pub max_steps: u64,
    /// Nested template-function calls.
    pub max_call_depth: usize,
    /// Total bytes of rendered output.
    pub max_output_bytes: usize,
    /// Bytes of a single string value or string-producing function result.
    pub max_string_bytes: usize,
    /// Entries of a single array.
    pub max_array_entries: usize,
}

impl Default for EvalLimits {
    fn default() -> Self {
        Self {
            max_steps: 10_000_000,
            max_call_depth: 64,
            max_output_bytes: 16 * 1024 * 1024,
            max_string_bytes: 4 * 1024 * 1024,
            max_array_entries: 100_000,
        }
    }
}

/// A template that failed to evaluate, or exceeded a limit.
#[derive(Debug, Clone)]
pub struct EvalError {
    /// Human-readable diagnostic. It never contains rendered output.
    pub message: String,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EvalError {}

impl From<ParseError> for EvalError {
    fn from(error: ParseError) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct FunctionDef {
    params: Vec<Param>,
    body: Vec<Stmt>,
}

#[derive(Default)]
struct Scope {
    vars: HashMap<String, Cell>,
}

enum Flow {
    Normal,
    Break,
    Continue,
    Return(Value),
}

/// A sandboxed interpreter for one template execution.
///
/// Create it with [`Evaluator::new`], seed the template globals with
/// [`Evaluator::set_global`], register the top-level statements with
/// [`Evaluator::execute`] (which defines the template's functions) and call a
/// function with [`Evaluator::call`]. Rendered text accumulates in the
/// evaluator and is drained with [`Evaluator::take_output`].
pub struct Evaluator {
    functions: HashMap<String, Rc<FunctionDef>>,
    globals: HashMap<String, Cell>,
    constants: HashMap<String, Value>,
    host: Option<Box<dyn HostFunctions>>,
    limits: EvalLimits,
    steps: u64,
    depth: usize,
    output: String,
}

impl Evaluator {
    /// A fresh evaluator with no globals, functions or host.
    pub fn new(limits: EvalLimits) -> Self {
        Self {
            functions: HashMap::new(),
            globals: HashMap::new(),
            constants: HashMap::new(),
            host: None,
            limits,
            steps: 0,
            depth: 0,
            output: String::new(),
        }
    }

    /// Install the application's host functions.
    ///
    /// Replaces a previously installed host. Without one, only the PHP
    /// standard functions the evaluator implements are callable.
    pub fn set_host(&mut self, host: Box<dyn HostFunctions>) {
        self.host = Some(host);
    }

    /// Remove and return the installed host, if any.
    pub fn take_host(&mut self) -> Option<Box<dyn HostFunctions>> {
        self.host.take()
    }

    /// Whether a host is installed.
    pub fn has_host(&self) -> bool {
        self.host.is_some()
    }

    /// Define a constant a template can read by name.
    ///
    /// The host may provide more through
    /// [`HostFunctions::constant`](crate::HostFunctions::constant); a constant
    /// registered here wins.
    pub fn set_constant(&mut self, name: &str, value: Value) {
        self.constants.insert(name.to_string(), value);
    }

    /// Set a global the template can reach through `global $name`.
    pub fn set_global(&mut self, name: &str, value: Value) {
        self.globals
            .insert(name.to_string(), Rc::new(RefCell::new(value)));
    }

    /// A deep copy of a global's current value.
    pub fn global(&self, name: &str) -> Option<Value> {
        self.globals
            .get(name)
            .map(|cell| cell.borrow().deep_clone())
    }

    /// Remove and return the accumulated template output.
    pub fn take_output(&mut self) -> String {
        std::mem::take(&mut self.output)
    }

    /// Whether the template declared a function with this name (any case).
    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(&name.to_ascii_lowercase())
    }

    /// Sandbox steps consumed so far. Used by the benchmark to spot a loop
    /// or expression that scales unexpectedly.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Evaluate top-level statements, registering function definitions.
    pub fn execute(&mut self, statements: &[Stmt]) -> Result<String, EvalError> {
        let mut scope = Scope::default();
        self.exec_block(statements, &mut scope)?;
        Ok(std::mem::take(&mut self.output))
    }

    /// Evaluate top-level statements with pre-seeded variables. The variables
    /// become globals too, so a `global $txt` in a language file aliases the
    /// same cell. Returns the final local/global variable set.
    pub fn execute_with_variables(
        &mut self,
        statements: &[Stmt],
        variables: Vec<(String, Value)>,
    ) -> Result<HashMap<String, Value>, EvalError> {
        let mut scope = Scope::default();
        for (name, value) in variables {
            let cell = Rc::new(RefCell::new(value));
            self.globals.insert(name.clone(), Rc::clone(&cell));
            scope.vars.insert(name, cell);
        }
        self.exec_block(statements, &mut scope)?;
        Ok(scope
            .vars
            .into_iter()
            .map(|(name, cell)| (name, cell.borrow().deep_clone()))
            .collect())
    }

    /// Call a defined template function by name.
    pub fn call(&mut self, name: &str, args: Vec<Value>) -> Result<Value, EvalError> {
        let cells = args
            .into_iter()
            .map(|value| Rc::new(RefCell::new(value)))
            .collect::<Vec<_>>();
        self.call_user_or_host(name, cells)
    }

    /// The bounds this evaluator enforces.
    pub(crate) fn limits(&self) -> &EvalLimits {
        &self.limits
    }

    /// Whether the installed host provides a function with this name.
    pub(crate) fn host_has(&self, name: &str) -> bool {
        self.host.as_ref().is_some_and(|host| host.has(name))
    }

    /// Return a string value only when it fits `max_string_bytes`; a template
    /// loop that doubles a value must fail instead of allocating without limit.
    pub(crate) fn bounded_string(&self, text: String, what: &str) -> Result<Value, EvalError> {
        if text.len() > self.limits.max_string_bytes {
            return Err(self.error(format!("{what} result exceeds the string limit")));
        }
        Ok(Value::Str(text))
    }

    fn tick(&mut self) -> Result<(), EvalError> {
        self.steps += 1;
        if self.steps > self.limits.max_steps {
            return Err(self.error("template execution step limit exceeded"));
        }
        Ok(())
    }

    /// Build an [`EvalError`] with this evaluator's formatting.
    pub(crate) fn error(&self, message: impl Into<String>) -> EvalError {
        EvalError {
            message: message.into(),
        }
    }

    fn exec_block(&mut self, statements: &[Stmt], scope: &mut Scope) -> Result<Flow, EvalError> {
        for statement in statements {
            match self.exec_statement(statement, scope)? {
                Flow::Normal => {}
                other => return Ok(other),
            }
        }
        Ok(Flow::Normal)
    }

    fn exec_statement(&mut self, statement: &Stmt, scope: &mut Scope) -> Result<Flow, EvalError> {
        if !profiling() {
            return self.exec_statement_inner(statement, scope);
        }
        let start = std::time::Instant::now();
        let result = self.exec_statement_inner(statement, scope);
        record_profile(
            &format!("stmt:{}", stmt_name(statement)),
            start.elapsed().as_nanos() as u64,
        );
        result
    }

    fn exec_statement_inner(
        &mut self,
        statement: &Stmt,
        scope: &mut Scope,
    ) -> Result<Flow, EvalError> {
        self.tick()?;
        match statement {
            Stmt::Text(text) => {
                self.push_output(text)?;
                Ok(Flow::Normal)
            }
            Stmt::Echo(values) => {
                for value in values {
                    let value = self.eval(value, scope)?;
                    self.push_output(&value.to_php_string())?;
                }
                Ok(Flow::Normal)
            }
            Stmt::Expr(expr) => {
                self.eval(expr, scope)?;
                Ok(Flow::Normal)
            }
            Stmt::If { branches } => {
                for (condition, body) in branches {
                    let matches = match condition {
                        Some(condition) => self.eval(condition, scope)?.to_bool(),
                        None => true,
                    };
                    if matches {
                        return self.exec_block(body, scope);
                    }
                }
                Ok(Flow::Normal)
            }
            Stmt::Foreach {
                subject,
                key,
                value,
                by_ref,
                body,
            } => {
                let subject = self.eval(subject, scope)?;
                let entries = match subject {
                    Value::Array(array) => array.borrow().entries(),
                    Value::Null => Vec::new(),
                    _ => return Err(self.error("foreach subject is not an array")),
                };
                for (entry_key, entry_value) in entries {
                    if let Some(key_name) = key {
                        scope.vars.insert(
                            key_name.clone(),
                            Rc::new(RefCell::new(key_value(&entry_key))),
                        );
                    }
                    if *by_ref {
                        scope.vars.insert(value.clone(), entry_value);
                    } else {
                        let cloned = entry_value.borrow().deep_clone();
                        scope
                            .vars
                            .insert(value.clone(), Rc::new(RefCell::new(cloned)));
                    }
                    match self.exec_block(body, scope)? {
                        Flow::Normal => {}
                        Flow::Continue => continue,
                        Flow::Break => break,
                        Flow::Return(value) => return Ok(Flow::Return(value)),
                    }
                }
                Ok(Flow::Normal)
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                for expr in init {
                    self.eval(expr, scope)?;
                }
                loop {
                    self.tick()?;
                    if !cond.is_empty() {
                        let mut result = true;
                        for expr in cond {
                            result = self.eval(expr, scope)?.to_bool();
                        }
                        if !result {
                            break;
                        }
                    }
                    match self.exec_block(body, scope)? {
                        Flow::Normal => {}
                        Flow::Continue => {}
                        Flow::Break => break,
                        Flow::Return(value) => return Ok(Flow::Return(value)),
                    }
                    for expr in step {
                        self.eval(expr, scope)?;
                    }
                }
                Ok(Flow::Normal)
            }
            Stmt::While { cond, body } => {
                loop {
                    self.tick()?;
                    if !self.eval(cond, scope)?.to_bool() {
                        break;
                    }
                    match self.exec_block(body, scope)? {
                        Flow::Normal => {}
                        Flow::Continue => {}
                        Flow::Break => break,
                        Flow::Return(value) => return Ok(Flow::Return(value)),
                    }
                }
                Ok(Flow::Normal)
            }
            Stmt::Switch { subject, cases } => {
                let subject = self.eval(subject, scope)?;
                let mut start = None;
                let mut default = None;
                for (index, (case, _)) in cases.iter().enumerate() {
                    match case {
                        Some(case) => {
                            if self.eval(case, scope)?.loose_eq(&subject) {
                                start = Some(index);
                                break;
                            }
                        }
                        None => default = Some(index),
                    }
                }
                let Some(mut index) = start.or(default) else {
                    return Ok(Flow::Normal);
                };
                while index < cases.len() {
                    match self.exec_block(&cases[index].1, scope)? {
                        Flow::Normal => {}
                        Flow::Break => return Ok(Flow::Normal),
                        Flow::Continue => return Ok(Flow::Normal),
                        Flow::Return(value) => return Ok(Flow::Return(value)),
                    }
                    index += 1;
                }
                Ok(Flow::Normal)
            }
            Stmt::Break(_) => Ok(Flow::Break),
            Stmt::Continue(_) => Ok(Flow::Continue),
            Stmt::Return(value) => {
                let value = match value {
                    Some(value) => self.eval(value, scope)?,
                    None => Value::Null,
                };
                Ok(Flow::Return(value))
            }
            Stmt::Function { name, params, body } => {
                self.functions.insert(
                    name.to_ascii_lowercase(),
                    Rc::new(FunctionDef {
                        params: params.clone(),
                        body: body.clone(),
                    }),
                );
                Ok(Flow::Normal)
            }
            Stmt::Global(names) => {
                for name in names {
                    let cell = self
                        .globals
                        .entry(name.clone())
                        .or_insert_with(|| Rc::new(RefCell::new(Value::Null)))
                        .clone();
                    scope.vars.insert(name.clone(), cell);
                }
                Ok(Flow::Normal)
            }
            Stmt::Unset(values) => {
                for value in values {
                    self.unset(value, scope)?;
                }
                Ok(Flow::Normal)
            }
            Stmt::Block(body) => self.exec_block(body, scope),
            Stmt::Nop => Ok(Flow::Normal),
        }
    }

    fn eval(&mut self, expr: &Expr, scope: &mut Scope) -> Result<Value, EvalError> {
        self.tick()?;
        match expr {
            Expr::Null => Ok(Value::Null),
            Expr::Bool(value) => Ok(Value::Bool(*value)),
            Expr::Int(value) => Ok(Value::Int(*value)),
            Expr::Float(value) => Ok(Value::Float(*value)),
            Expr::Str { raw, single } => {
                let value = self.interpolate(raw, *single, scope)?;
                self.check_string(&value)?;
                Ok(Value::Str(value))
            }
            Expr::Variable(name) => Ok(self.read_variable(scope, name)),
            Expr::Array(items) => {
                if items.len() > self.limits.max_array_entries {
                    return Err(self.error("array literal exceeds the entry limit"));
                }
                let mut array = PhpArray::new();
                let mut next = 0i64;
                for (key, value) in items {
                    let value = self.eval(value, scope)?;
                    if let Some(key) = key {
                        let key = key_from_value(&self.eval(key, scope)?);
                        if let Key::Int(index) = key {
                            // PHP advances the implicit index past the
                            // largest explicit non-negative integer key.
                            if index >= next {
                                next = index + 1;
                            }
                            array.insert(Key::Int(index), value);
                        } else {
                            array.insert(key, value);
                        }
                    } else {
                        array.insert(Key::Int(next), value);
                        next += 1;
                    }
                }
                Ok(Value::from_array(array))
            }
            Expr::Index(base, key) => {
                // A template indexes `$context` and `$txt` hundreds of times
                // per page. Read through the existing cell instead of
                // evaluating the base variable to a deep copy of the whole
                // array; only the selected entry is copied.
                if let Some(cell) = self.read_cell(base, scope)? {
                    let key = key_from_value(&self.eval(key, scope)?);
                    return self.index_cell_value(&cell, &key);
                }
                let base = self.eval(base, scope)?;
                let key = key_from_value(&self.eval(key, scope)?);
                match base {
                    Value::Array(array) => Ok(array
                        .borrow()
                        .get(&key)
                        .map(|cell| cell.borrow().deep_clone())
                        .unwrap_or(Value::Null)),
                    Value::Str(value) => Ok(value
                        .chars()
                        .nth(key_to_usize(&key))
                        .map(|c| Value::Str(c.to_string()))
                        .unwrap_or(Value::Null)),
                    Value::Null => Ok(Value::Null),
                    _ => Err(self.error("cannot index this value")),
                }
            }
            Expr::Append(_) => Err(self.error("cannot read an append expression")),
            Expr::Call(name, args) => {
                let (_, cells) = self.eval_args(args, scope)?;
                self.call_user_or_host(name, cells)
            }
            Expr::DynamicCall(target, args) => {
                let target = self.eval(target, scope)?;
                let (values, cells) = self.eval_args(args, scope)?;
                if let Value::Function(function) = &target {
                    return function
                        .call(values)
                        .map_err(|message| self.error(format!("callback failed: {message}")));
                }
                let name = target.to_php_string();
                self.call_user_or_host(&name, cells)
            }
            Expr::Constant(name) => {
                if let Some(value) = self.constants.get(name) {
                    return Ok(value.deep_clone());
                }
                if let Some(value) = self.host.as_ref().and_then(|host| host.constant(name)) {
                    return Ok(value);
                }
                Err(self.error(format!("unknown constant {name:?}")))
            }
            Expr::Unary(op, value) => {
                let value = self.eval(value, scope)?;
                Ok(match op {
                    UnOp::Not => Value::Bool(!value.to_bool()),
                    UnOp::Neg => match value {
                        Value::Int(value) => Value::Int(-value),
                        _ => Value::Float(-value.to_float()),
                    },
                    UnOp::Pos => match value {
                        Value::Int(value) => Value::Int(value),
                        _ => Value::Float(value.to_float()),
                    },
                    UnOp::BitNot => Value::Int(!value.to_int()),
                })
            }
            Expr::Binary(op, left, right) => self.eval_binary(*op, left, right, scope),
            Expr::Assign { target, op, value } => {
                let cell = self.resolve_cell(target, scope)?;
                if *op == AssignOp::Assign {
                    if let Expr::Reference(source) = value.as_ref() {
                        let source = self.resolve_cell(source, scope)?;
                        self.replace_cell(target, source, scope)?;
                        return Ok(cell.borrow().deep_clone());
                    }
                    let value = self.eval(value, scope)?;
                    *cell.borrow_mut() = value.deep_clone();
                    // PHP assignment is an expression: `while ($row = next())`.
                    return Ok(cell.borrow().deep_clone());
                }
                let rhs = self.eval(value, scope)?;
                let mut current = cell.borrow().deep_clone();
                current = self.apply_assign(*op, current, rhs)?;
                *cell.borrow_mut() = current.deep_clone();
                Ok(current)
            }
            Expr::PreInc(value) => {
                let cell = self.resolve_cell(value, scope)?;
                let next = match &*cell.borrow() {
                    Value::Int(value) => Value::Int(value + 1),
                    other => Value::Float(other.to_float() + 1.0),
                };
                *cell.borrow_mut() = next.clone();
                Ok(next)
            }
            Expr::PreDec(value) => {
                let cell = self.resolve_cell(value, scope)?;
                let next = match &*cell.borrow() {
                    Value::Int(value) => Value::Int(value - 1),
                    other => Value::Float(other.to_float() - 1.0),
                };
                *cell.borrow_mut() = next.clone();
                Ok(next)
            }
            Expr::PostInc(value) => {
                let cell = self.resolve_cell(value, scope)?;
                let previous = cell.borrow().deep_clone();
                *cell.borrow_mut() = match &previous {
                    Value::Int(value) => Value::Int(value + 1),
                    other => Value::Float(other.to_float() + 1.0),
                };
                Ok(previous)
            }
            Expr::PostDec(value) => {
                let cell = self.resolve_cell(value, scope)?;
                let previous = cell.borrow().deep_clone();
                *cell.borrow_mut() = match &previous {
                    Value::Int(value) => Value::Int(value - 1),
                    other => Value::Float(other.to_float() - 1.0),
                };
                Ok(previous)
            }
            Expr::Ternary {
                cond,
                then,
                otherwise,
            } => {
                let condition = self.eval(cond, scope)?;
                if condition.to_bool() {
                    match then {
                        Some(value) => self.eval(value, scope),
                        None => Ok(condition),
                    }
                } else {
                    self.eval(otherwise, scope)
                }
            }
            Expr::Isset(values) => {
                for value in values {
                    if !self.is_set(value, scope)? {
                        return Ok(Value::Bool(false));
                    }
                }
                Ok(Value::Bool(true))
            }
            Expr::Empty(value) => {
                if !self.is_set(value, scope)? {
                    return Ok(Value::Bool(true));
                }
                Ok(Value::Bool(!self.eval(value, scope)?.to_bool()))
            }
            Expr::Reference(value) => {
                let cell = self.resolve_cell(value, scope)?;
                let value = cell.borrow().deep_clone();
                Ok(value)
            }
            Expr::Cast(kind, value) => {
                let value = self.eval(value, scope)?;
                Ok(match kind {
                    CastType::Int => Value::Int(value.to_int()),
                    CastType::Float => Value::Float(value.to_float()),
                    CastType::String => Value::Str(value.to_php_string()),
                    CastType::Bool => Value::Bool(value.to_bool()),
                    CastType::Array => match value {
                        Value::Array(_) => value,
                        Value::Null => Value::array(),
                        other => {
                            let mut array = PhpArray::new();
                            array.insert(Key::Int(0), other);
                            Value::from_array(array)
                        }
                    },
                })
            }
            Expr::Suppressed(value) => match self.eval(value, scope) {
                Ok(value) => Ok(value),
                Err(_) => Ok(Value::Null),
            },
        }
    }

    fn eval_binary(
        &mut self,
        op: BinOp,
        left: &Expr,
        right: &Expr,
        scope: &mut Scope,
    ) -> Result<Value, EvalError> {
        match op {
            BinOp::And => {
                let left = self.eval(left, scope)?;
                if !left.to_bool() {
                    return Ok(Value::Bool(false));
                }
                return Ok(Value::Bool(self.eval(right, scope)?.to_bool()));
            }
            BinOp::Or => {
                let left = self.eval(left, scope)?;
                if left.to_bool() {
                    return Ok(Value::Bool(true));
                }
                return Ok(Value::Bool(self.eval(right, scope)?.to_bool()));
            }
            BinOp::Coalesce => {
                let left = self.eval(left, scope)?;
                if !left.is_null() {
                    return Ok(left);
                }
                return self.eval(right, scope);
            }
            _ => {}
        }
        let left = self.eval(left, scope)?;
        let right = self.eval(right, scope)?;
        if matches!(op, BinOp::Concat) {
            let mut text = left.to_php_string();
            text.push_str(&right.to_php_string());
            return self.bounded_string(text, "concatenation");
        }
        Ok(match op {
            BinOp::Add => numeric_op(left, right, |a, b| a + b, |a, b| a + b),
            BinOp::Sub => numeric_op(left, right, |a, b| a - b, |a, b| a - b),
            BinOp::Mul => numeric_op(left, right, |a, b| a * b, |a, b| a * b),
            BinOp::Div => match (&left, &right) {
                (Value::Int(a), Value::Int(b)) if *b != 0 => {
                    if a % b == 0 {
                        Value::Int(a / b)
                    } else {
                        Value::Float(*a as f64 / *b as f64)
                    }
                }
                _ => Value::Float(left.to_float() / right.to_float()),
            },
            BinOp::Mod => Value::Int(left.to_int() % right.to_int().max(1)),
            BinOp::Concat => unreachable!(),
            BinOp::BitAnd => Value::Int(left.to_int() & right.to_int()),
            BinOp::BitOr => Value::Int(left.to_int() | right.to_int()),
            BinOp::BitXor => Value::Int(left.to_int() ^ right.to_int()),
            BinOp::ShiftLeft => Value::Int(left.to_int() << (right.to_int().clamp(0, 63) as u32)),
            BinOp::ShiftRight => Value::Int(left.to_int() >> (right.to_int().clamp(0, 63) as u32)),
            BinOp::Equal => Value::Bool(left.loose_eq(&right)),
            BinOp::NotEqual => Value::Bool(!left.loose_eq(&right)),
            BinOp::Identical => Value::Bool(left.strict_eq(&right)),
            BinOp::NotIdentical => Value::Bool(!left.strict_eq(&right)),
            BinOp::Less => Value::Bool(left.compare(&right).is_lt()),
            BinOp::LessEqual => Value::Bool(!left.compare(&right).is_gt()),
            BinOp::Greater => Value::Bool(left.compare(&right).is_gt()),
            BinOp::GreaterEqual => Value::Bool(!left.compare(&right).is_lt()),
            BinOp::Spaceship => Value::Int(match left.compare(&right) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }),
            BinOp::And | BinOp::Or | BinOp::Xor | BinOp::Coalesce => unreachable!(),
        })
    }

    fn apply_assign(&self, op: AssignOp, current: Value, rhs: Value) -> Result<Value, EvalError> {
        if matches!(op, AssignOp::Concat) {
            let mut text = current.to_php_string();
            text.push_str(&rhs.to_php_string());
            return self.bounded_string(text, "concatenation");
        }
        Ok(match op {
            AssignOp::Assign => rhs.deep_clone(),
            AssignOp::Add => numeric_op(current, rhs, |a, b| a + b, |a, b| a + b),
            AssignOp::Sub => numeric_op(current, rhs, |a, b| a - b, |a, b| a - b),
            AssignOp::Mul => numeric_op(current, rhs, |a, b| a * b, |a, b| a * b),
            AssignOp::Div => Value::Float(current.to_float() / rhs.to_float()),
            AssignOp::Mod => Value::Int(current.to_int() % rhs.to_int().max(1)),
            AssignOp::Concat => unreachable!(),
            AssignOp::BitAnd => Value::Int(current.to_int() & rhs.to_int()),
            AssignOp::BitOr => Value::Int(current.to_int() | rhs.to_int()),
            AssignOp::BitXor => Value::Int(current.to_int() ^ rhs.to_int()),
            AssignOp::ShiftLeft => {
                Value::Int(current.to_int() << (rhs.to_int().clamp(0, 63) as u32))
            }
            AssignOp::ShiftRight => {
                Value::Int(current.to_int() >> (rhs.to_int().clamp(0, 63) as u32))
            }
            AssignOp::Coalesce => {
                if current.is_null() {
                    rhs
                } else {
                    current
                }
            }
        })
    }

    fn eval_args(
        &mut self,
        args: &[Expr],
        scope: &mut Scope,
    ) -> Result<(Vec<Value>, Vec<Cell>), EvalError> {
        let mut values = Vec::with_capacity(args.len());
        let mut cells = Vec::with_capacity(args.len());
        for arg in args {
            let cell = if matches!(arg, Expr::Variable(_) | Expr::Index(_, _) | Expr::Append(_)) {
                self.resolve_cell(arg, scope)?
            } else {
                let value = self.eval(arg, scope)?;
                Rc::new(RefCell::new(value))
            };
            values.push(cell.borrow().deep_clone());
            cells.push(cell);
        }
        Ok((values, cells))
    }

    fn call_user_or_host(&mut self, name: &str, cells: Vec<Cell>) -> Result<Value, EvalError> {
        if !profiling() {
            return self.call_user_or_host_inner(name, cells);
        }
        let start = std::time::Instant::now();
        let result = self.call_user_or_host_inner(name, cells);
        record_profile(&format!("call:{name}"), start.elapsed().as_nanos() as u64);
        result
    }

    fn call_user_or_host_inner(
        &mut self,
        name: &str,
        cells: Vec<Cell>,
    ) -> Result<Value, EvalError> {
        let lower = name.to_ascii_lowercase();
        if let Some(function) = self.functions.get(&lower).cloned() {
            return self.call_user(&function, cells);
        }
        // PHP passes these by reference; mutate the caller's cell instead of
        // the value copy `call_host` receives.
        match lower.as_str() {
            "array_pop" => {
                let Some(cell) = cells.first() else {
                    return Ok(Value::Null);
                };
                let value = cell.borrow_mut();
                let Value::Array(array) = &*value else {
                    return Ok(Value::Null);
                };
                let mut array = array.borrow_mut();
                let key = array.keys().last().cloned();
                return Ok(key
                    .and_then(|key| array.remove(&key))
                    .map(|cell| cell.borrow().deep_clone())
                    .unwrap_or(Value::Null));
            }
            "ksort" => {
                if let Some(cell) = cells.first() {
                    let value = cell.borrow();
                    if let Value::Array(array) = &*value {
                        array.borrow_mut().ksort();
                    }
                }
                return Ok(Value::Bool(true));
            }
            // `template_show_settings()` dispatches its `callback` rows this
            // way. Only functions already declared by the template can be
            // reached, so the sandbox stays closed.
            "call_user_func" => {
                let name = cells
                    .first()
                    .map(|cell| cell.borrow().to_php_string())
                    .unwrap_or_default();
                let lower = name.to_ascii_lowercase();
                let Some(function) = self.functions.get(&lower).cloned() else {
                    return Err(
                        self.error(format!("call_user_func target {name:?} is not defined"))
                    );
                };
                let arguments = cells
                    .iter()
                    .skip(1)
                    .map(|cell| Rc::new(RefCell::new(cell.borrow().deep_clone())))
                    .collect::<Vec<_>>();
                return self.call_user(&function, arguments);
            }
            _ => {}
        }
        let values = cells
            .iter()
            .map(|cell| cell.borrow().deep_clone())
            .collect::<Vec<_>>();
        if let Some(result) = self.call_builtin(&lower, &values) {
            return result;
        }
        self.call_host(&lower, values)
    }

    fn call_user(&mut self, function: &FunctionDef, cells: Vec<Cell>) -> Result<Value, EvalError> {
        if self.depth >= self.limits.max_call_depth {
            return Err(self.error("template call depth limit exceeded"));
        }
        self.depth += 1;
        let mut scope = Scope::default();
        let mut arguments = cells.into_iter();
        let mut failure = None;
        for param in &function.params {
            let cell = match arguments.next() {
                Some(cell) => cell,
                None => {
                    // A parameter without an argument takes its declared
                    // default, evaluated in the function's own scope like PHP.
                    let value = match &param.default {
                        Some(default) => match self.eval(default, &mut scope) {
                            Ok(value) => value,
                            Err(error) => {
                                failure = Some(error);
                                break;
                            }
                        },
                        None => Value::Null,
                    };
                    Rc::new(RefCell::new(value))
                }
            };
            if param.by_ref {
                scope.vars.insert(param.name.clone(), cell);
            } else {
                let value = cell.borrow().deep_clone();
                scope
                    .vars
                    .insert(param.name.clone(), Rc::new(RefCell::new(value)));
            }
        }
        let result = match failure {
            Some(error) => Err(error),
            None => self.exec_block(&function.body, &mut scope),
        };
        self.depth -= 1;
        let flow = result?;
        Ok(match flow {
            Flow::Return(value) => value,
            _ => Value::Null,
        })
    }

    fn read_variable(&mut self, scope: &mut Scope, name: &str) -> Value {
        scope
            .vars
            .get(name)
            .map(|cell| cell.borrow().deep_clone())
            .unwrap_or(Value::Null)
    }

    fn named_cell(&self, scope: &Scope, name: &str) -> Option<Cell> {
        scope.vars.get(name).cloned()
    }

    /// Resolve a variable or index chain to its existing cell, without
    /// copying the container and without creating missing keys.
    ///
    /// `None` means the expression is not a plain variable/index chain; the
    /// caller then falls back to evaluating it as a value.
    fn read_cell(&mut self, expr: &Expr, scope: &mut Scope) -> Result<Option<Cell>, EvalError> {
        match expr {
            Expr::Variable(name) => Ok(self.named_cell(scope, name)),
            Expr::Index(base, key) => {
                let Some(base) = self.read_cell(base, scope)? else {
                    return Ok(None);
                };
                let key = key_from_value(&self.eval(key, scope)?);
                let child = {
                    let borrowed = base.borrow();
                    match &*borrowed {
                        Value::Array(array) => array.borrow().get(&key),
                        _ => None,
                    }
                };
                Ok(child)
            }
            _ => Ok(None),
        }
    }

    fn index_cell_value(&self, cell: &Cell, key: &Key) -> Result<Value, EvalError> {
        let borrowed = cell.borrow();
        match &*borrowed {
            Value::Array(array) => Ok(array
                .borrow()
                .get(key)
                .map(|cell| cell.borrow().deep_clone())
                .unwrap_or(Value::Null)),
            Value::Str(value) => Ok(value
                .chars()
                .nth(key_to_usize(key))
                .map(|c| Value::Str(c.to_string()))
                .unwrap_or(Value::Null)),
            Value::Null => Ok(Value::Null),
            _ => Err(self.error("cannot index this value")),
        }
    }

    fn resolve_cell(&mut self, expr: &Expr, scope: &mut Scope) -> Result<Cell, EvalError> {
        match expr {
            Expr::Variable(name) => Ok(scope
                .vars
                .entry(name.clone())
                .or_insert_with(|| Rc::new(RefCell::new(Value::Null)))
                .clone()),
            Expr::Index(base, key) => {
                let base = self.resolve_cell(base, scope)?;
                let key = key_from_value(&self.eval(key, scope)?);
                let mut borrow = base.borrow_mut();
                if matches!(&*borrow, Value::Null) {
                    *borrow = Value::array();
                }
                let array = match &mut *borrow {
                    Value::Array(array) => Rc::clone(array),
                    _ => return Err(self.error("cannot use this value as an array")),
                };
                if array.borrow().get(&key).is_none() {
                    if array.borrow().len() >= self.limits.max_array_entries {
                        return Err(self.error("array exceeds the entry limit"));
                    }
                    array.borrow_mut().insert(key.clone(), Value::Null);
                }
                let cell = array.borrow().get(&key).unwrap();
                Ok(cell)
            }
            Expr::Append(base) => {
                let base = self.resolve_cell(base, scope)?;
                let mut borrow = base.borrow_mut();
                if matches!(&*borrow, Value::Null) {
                    *borrow = Value::array();
                }
                let array = match &mut *borrow {
                    Value::Array(array) => Rc::clone(array),
                    _ => return Err(self.error("cannot append to this value")),
                };
                if array.borrow().len() >= self.limits.max_array_entries {
                    return Err(self.error("array exceeds the entry limit"));
                }
                let key = array.borrow_mut().push(Value::Null);
                let cell = array.borrow().get(&key).unwrap();
                Ok(cell)
            }
            _ => Err(self.error("expression is not assignable")),
        }
    }

    fn replace_cell(
        &mut self,
        target: &Expr,
        source: Cell,
        scope: &mut Scope,
    ) -> Result<(), EvalError> {
        match target {
            Expr::Variable(name) => {
                scope.vars.insert(name.clone(), source);
                Ok(())
            }
            Expr::Index(base, key) => {
                let base = self.resolve_cell(base, scope)?;
                let key = key_from_value(&self.eval(key, scope)?);
                let mut borrow = base.borrow_mut();
                let array = match &mut *borrow {
                    Value::Array(array) => Rc::clone(array),
                    _ => return Err(self.error("cannot use this value as an array")),
                };
                array.borrow_mut().set_cell(key, source);
                Ok(())
            }
            Expr::Append(base) => {
                let base = self.resolve_cell(base, scope)?;
                let mut borrow = base.borrow_mut();
                let array = match &mut *borrow {
                    Value::Array(array) => Rc::clone(array),
                    _ => return Err(self.error("cannot append to this value")),
                };
                let key = array.borrow_mut().push(Value::Null);
                array.borrow_mut().set_cell(key, source);
                Ok(())
            }
            _ => Err(self.error("invalid reference target")),
        }
    }

    fn unset(&mut self, expr: &Expr, scope: &mut Scope) -> Result<(), EvalError> {
        match expr {
            Expr::Variable(name) => {
                scope.vars.remove(name);
                Ok(())
            }
            Expr::Index(base, key) => {
                let base = self.resolve_cell(base, scope)?;
                let key = key_from_value(&self.eval(key, scope)?);
                if let Value::Array(array) = &mut *base.borrow_mut() {
                    array.borrow_mut().remove(&key);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn is_set(&mut self, expr: &Expr, scope: &mut Scope) -> Result<bool, EvalError> {
        match expr {
            Expr::Variable(name) => Ok(scope
                .vars
                .get(name)
                .is_some_and(|cell| !cell.borrow().is_null())),
            Expr::Index(base, key) => {
                let base = self.eval(base, scope)?;
                let key = key_from_value(&self.eval(key, scope)?);
                Ok(match base {
                    Value::Array(array) => array
                        .borrow()
                        .get(&key)
                        .is_some_and(|cell| !cell.borrow().is_null()),
                    _ => false,
                })
            }
            _ => Ok(false),
        }
    }

    fn push_output(&mut self, text: &str) -> Result<(), EvalError> {
        if self.output.len() + text.len() > self.limits.max_output_bytes {
            return Err(self.error("template output limit exceeded"));
        }
        self.output.push_str(text);
        Ok(())
    }

    fn check_string(&self, text: &str) -> Result<(), EvalError> {
        if text.len() > self.limits.max_string_bytes {
            return Err(self.error("template string limit exceeded"));
        }
        Ok(())
    }

    fn interpolate(
        &mut self,
        raw: &str,
        single: bool,
        scope: &mut Scope,
    ) -> Result<String, EvalError> {
        let mut out = String::with_capacity(raw.len());
        let chars: Vec<char> = raw.chars().collect();
        let mut index = 0;
        while index < chars.len() {
            let c = chars[index];
            if c == '\\' {
                if let Some(next) = chars.get(index + 1).copied() {
                    if single {
                        if next == '\\' || next == '\'' {
                            out.push(next);
                            index += 2;
                            continue;
                        }
                    } else {
                        match next {
                            'n' => {
                                out.push('\n');
                                index += 2;
                                continue;
                            }
                            'r' => {
                                out.push('\r');
                                index += 2;
                                continue;
                            }
                            't' => {
                                out.push('\t');
                                index += 2;
                                continue;
                            }
                            '0' => {
                                out.push('\0');
                                index += 2;
                                continue;
                            }
                            '\\' | '"' | '$' => {
                                out.push(next);
                                index += 2;
                                continue;
                            }
                            _ => {}
                        }
                    }
                }
                out.push(c);
                index += 1;
                continue;
            }
            if single {
                out.push(c);
                index += 1;
                continue;
            }
            if c == '{' && chars.get(index + 1) == Some(&'$') {
                let mut end = index + 2;
                while end < chars.len() && chars[end] != '}' {
                    end += 1;
                }
                if end < chars.len() {
                    let inner: String = chars[index + 1..end].iter().collect();
                    let value = self.eval_inline_expression(&inner, scope)?;
                    out.push_str(&value.to_php_string());
                    index = end + 1;
                    continue;
                }
            }
            if c == '$' {
                let mut end = index + 1;
                while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
                    end += 1;
                }
                if end > index + 1 {
                    let name: String = chars[index + 1..end].iter().collect();
                    let mut cell = self.named_cell(scope, &name);
                    let value;
                    loop {
                        if chars.get(end) != Some(&'[') {
                            value = cell
                                .as_ref()
                                .map(|cell| cell.borrow().deep_clone())
                                .unwrap_or(Value::Null);
                            break;
                        }
                        let close = chars[end..]
                            .iter()
                            .position(|c| *c == ']')
                            .map(|offset| end + offset);
                        let Some(close) = close else {
                            value = cell
                                .as_ref()
                                .map(|cell| cell.borrow().deep_clone())
                                .unwrap_or(Value::Null);
                            break;
                        };
                        let key_text: String = chars[end + 1..close].iter().collect();
                        let key_value = self.eval_inline_key(&key_text, scope)?;
                        let key = key_from_value(&key_value);
                        cell = cell.as_ref().and_then(|cell| {
                            let borrowed = cell.borrow();
                            match &*borrowed {
                                Value::Array(array) => array.borrow().get(&key),
                                _ => None,
                            }
                        });
                        end = close + 1;
                    }
                    out.push_str(&value.to_php_string());
                    index = end;
                    continue;
                }
            }
            out.push(c);
            index += 1;
        }
        Ok(out)
    }

    fn eval_inline_expression(
        &mut self,
        inner: &str,
        scope: &mut Scope,
    ) -> Result<Value, EvalError> {
        let snippets = crate::parse(&format!("<?php {inner}; ?>"))?;
        for statement in snippets {
            if let Stmt::Expr(expr) = statement {
                return self.eval(&expr, scope);
            }
        }
        Ok(Value::Null)
    }

    fn eval_inline_key(&mut self, text: &str, scope: &mut Scope) -> Result<Value, EvalError> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(Value::Null);
        }
        if (text.starts_with('\'') && text.ends_with('\''))
            || (text.starts_with('"') && text.ends_with('"'))
        {
            return Ok(Value::Str(text[1..text.len() - 1].to_string()));
        }
        if let Ok(value) = text.parse::<i64>() {
            return Ok(Value::Int(value));
        }
        if let Some(name) = text.strip_prefix('$') {
            return Ok(self.read_variable(scope, name));
        }
        Ok(Value::Str(text.to_string()))
    }

    /// Dispatch a call to the installed host functions.
    ///
    /// The host is moved out of the evaluator for the duration of the call, so
    /// a callback can call back into the template (SMF's
    /// `theme_inline_permissions()` renders another template function) without
    /// two mutable borrows of the evaluator. It is put back before this
    /// function returns, so the next call sees the same instance.
    fn call_host(&mut self, name: &str, args: Vec<Value>) -> Result<Value, EvalError> {
        let Some(host) = self.host.take() else {
            return Err(self.error(unknown_function(name)));
        };
        let mut context = EvalHostContext {
            evaluator: self,
            host: Some(host),
        };
        let outcome = context.dispatch(name, args);
        let host = context.host.take();
        self.host = host;
        match outcome {
            Some(Ok(value)) => Ok(value),
            Some(Err(message)) => Err(self.error(message)),
            None => Err(self.error(unknown_function(name))),
        }
    }
}

fn unknown_function(name: &str) -> String {
    format!("function {name:?} is not in the template allow-list")
}

/// The [`HostContext`] a host function sees: read and write access to the
/// template globals, and a way to call a template function.
struct EvalHostContext<'a> {
    evaluator: &'a mut Evaluator,
    /// `None` only while the host callback itself is running.
    host: Option<Box<dyn HostFunctions>>,
}

impl EvalHostContext<'_> {
    fn dispatch(&mut self, name: &str, args: Vec<Value>) -> Option<Result<Value, String>> {
        let mut host = self.host.take()?;
        let outcome = host.call(name, args, self);
        self.host = Some(host);
        outcome
    }
}

impl HostContext for EvalHostContext<'_> {
    fn global(&self, name: &str) -> Option<Value> {
        self.evaluator.global(name)
    }

    fn global_field(&self, name: &str, key: &str) -> Option<Value> {
        self.evaluator.globals.get(name).and_then(|cell| {
            let borrowed = cell.borrow();
            array_value(&borrowed, key)
        })
    }

    fn set_global_field(&mut self, name: &str, key: &str, value: Value) -> bool {
        let Some(cell) = self.evaluator.globals.get(name) else {
            return false;
        };
        let mut borrowed = cell.borrow_mut();
        let Value::Array(array) = &mut *borrowed else {
            return false;
        };
        array.borrow_mut().insert(Key::Str(key.to_string()), value);
        true
    }

    fn call_template(&mut self, name: &str, args: Vec<Value>) -> Result<Value, String> {
        // Hand the host to the evaluator so the callee can use host functions
        // too, then take it back for the rest of this callback.
        self.evaluator.host = self.host.take();
        let result = self.evaluator.call(name, args);
        self.host = self.evaluator.host.take();
        result.map_err(|error| error.to_string())
    }
}

fn key_value(key: &Key) -> Value {
    match key {
        Key::Int(value) => Value::Int(*value),
        Key::Str(value) => Value::Str(value.clone()),
    }
}

fn array_value(root: &Value, key: &str) -> Option<Value> {
    let array = root.as_array()?;
    array
        .borrow()
        .get(&Key::Str(key.to_string()))
        .map(|cell| cell.borrow().deep_clone())
}

fn key_to_usize(key: &Key) -> usize {
    match key {
        Key::Int(value) => (*value).max(0) as usize,
        Key::Str(value) => value.parse().unwrap_or(0),
    }
}

fn numeric_op(
    left: Value,
    right: Value,
    int_op: impl Fn(i64, i64) -> i64,
    float_op: impl Fn(f64, f64) -> f64,
) -> Value {
    match (&left, &right) {
        (Value::Int(a), Value::Int(b)) => Value::Int(int_op(*a, *b)),
        _ => Value::Float(float_op(left.to_float(), right.to_float())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostContext;
    use crate::parse;

    fn evaluator() -> Evaluator {
        let mut evaluator = Evaluator::new(EvalLimits::default());
        let mut txt = PhpArray::new();
        txt.insert(Key::Str("title".into()), Value::Str("Hello".into()));
        txt.insert(Key::Str("count".into()), Value::Str("%1$d items".into()));
        evaluator.set_global("txt", Value::from_array(txt));
        let mut context = PhpArray::new();
        let mut items = PhpArray::new();
        items.insert(Key::Int(0), Value::Str("a".into()));
        items.insert(Key::Int(1), Value::Str("b".into()));
        context.insert(Key::Str("items".into()), Value::from_array(items));
        context.insert(Key::Str("total".into()), Value::Int(2));
        evaluator.set_global("context", Value::from_array(context));
        evaluator
    }

    /// Parse `code`, register it and call `function`, returning its output.
    fn render(evaluator: &mut Evaluator, code: &str, function: &str) -> String {
        let statements = parse(code).unwrap();
        evaluator.execute(&statements).unwrap();
        let _ = evaluator.take_output();
        evaluator.call(function, Vec::new()).unwrap();
        evaluator.take_output()
    }

    #[test]
    fn renders_echo_loops_and_sprintf() {
        let mut eval = evaluator();
        let code = r#"<?php
function template_main() {
    global $context, $txt;
    echo '<h1>', $txt['title'], '</h1>';
    foreach ($context['items'] as $item) {
        echo '<li>', $item, '</li>';
    }
    echo sprintf($txt['count'], $context['total']);
}
?>"#;
        assert_eq!(
            render(&mut eval, code, "template_main"),
            "<h1>Hello</h1><li>a</li><li>b</li>2 items"
        );
    }

    #[test]
    fn handles_references_and_arrays() {
        let mut eval = evaluator();
        let code = r#"<?php
function template_main() {
    global $context;
    $data = &$context['items'];
    $data[] = 'c';
    echo count($context['items']), ':', implode(',', $context['items']);
}
?>"#;
        assert_eq!(render(&mut eval, code, "template_main"), "3:a,b,c");
    }

    #[test]
    fn array_pop_and_ksort_modify_by_reference() {
        let mut eval = evaluator();
        let code = r#"<?php
function template_main() {
    $data = array('b' => 1, 'a' => 2, 'c' => 3);
    $last = array_pop($data);
    ksort($data);
    foreach ($data as $key => $value)
        echo $key;
    echo ':', $last, ':', count($data);
}
?>"#;
        assert_eq!(render(&mut eval, code, "template_main"), "ab:3:2");
    }

    #[test]
    fn assignment_expressions_yield_the_assigned_value() {
        let mut eval = evaluator();
        let code = r#"<?php
function template_main() {
    $items = array('a', 'b');
    $i = 0;
    while ($item = $items[$i]) {
        echo $item;
        $i++;
    }
    $n = $i += 2;
    echo ':', $n, ':', $i;
}
?>"#;
        assert_eq!(render(&mut eval, code, "template_main"), "ab:4:4");
    }

    #[test]
    fn php_array_auto_index_follows_explicit_keys() {
        let mut eval = evaluator();
        let code = r#"<?php
function template_main() {
    $months = array(1 => 'January', 'February', 'March');
    echo $months[1], ',', $months[2], ',', $months[3], ',', count($months);
}
?>"#;
        assert_eq!(
            render(&mut eval, code, "template_main"),
            "January,February,March,3"
        );
    }

    #[test]
    fn evaluates_expressions_like_php() {
        let mut eval = evaluator();
        let code = r#"<?php
function template_main() {
    echo 1 + 2 * 3, '|', 7 % 4, '|', 7 / 2, '|', 8 / 2, '|';
    echo 'a' . 1 + 2, '|', (int) '12abc', '|', (string) 1.5, '|';
    echo 1 == '1' ? 'eq' : 'ne', '|', 1 === '1' ? 'eq' : 'ne', '|';
    echo isset($missing) ? 'set' : 'unset', '|', empty($missing) ? 'empty' : 'full', '|';
    echo $missing ?? 'fallback', '|', 3 <=> 2, '|', !0 ? 'true' : 'false';
}
?>"#;
        assert_eq!(
            render(&mut eval, code, "template_main"),
            "7|3|3.5|4|2|12|1.5|eq|ne|unset|empty|fallback|1|true"
        );
    }

    #[test]
    fn evaluates_functions_defaults_and_recursion() {
        let mut eval = evaluator();
        let code = r#"<?php
function add($a, $b = 10) { return $a + $b; }
function bump(&$value) { $value++; }
function factorial($n) { return $n <= 1 ? 1 : $n * factorial($n - 1); }
function template_main() {
    global $total;
    $x = 1;
    bump($x);
    $total = 5;
    echo add($x), '|', add($x, 1), '|', factorial(5), '|', $total;
}
?>"#;
        assert_eq!(render(&mut eval, code, "template_main"), "12|3|120|5");
        assert_eq!(eval.global("total").unwrap().to_int(), 5);
    }

    #[test]
    fn switch_break_and_continue_follow_php() {
        let mut eval = evaluator();
        let code = r#"<?php
function template_main() {
    for ($i = 0; $i < 5; $i++) {
        if ($i == 1) { continue; }
        if ($i == 4) { break; }
        switch ($i) {
            case 0: echo 'zero'; break;
            case 2: echo 'two';
            case 3: echo 'three'; break;
            default: echo 'other';
        }
        echo ',';
    }
}
?>"#;
        // `case 2` falls through into `case 3`, exactly like PHP.
        assert_eq!(
            render(&mut eval, code, "template_main"),
            "zero,twothree,three,"
        );
    }

    #[test]
    fn interpolation_reads_arrays_and_braces() {
        let mut eval = evaluator();
        let code = r#"<?php
function template_main() {
    global $context, $txt;
    $name = 'world';
    echo "hello $name {$txt['title']} $context[total] \$name\n";
    echo 'single $name', '|', strtr('abc', array('a' => '1', 'bc' => '2'));
}
?>"#;
        assert_eq!(
            render(&mut eval, code, "template_main"),
            "hello world Hello 2 $name\nsingle $name|12"
        );
    }

    #[test]
    fn callbacks_stored_in_context_are_callable() {
        let mut eval = evaluator();
        let context = eval.global("context").unwrap();
        let mut index = 0;
        let value = Value::from_function(move |_args| {
            index += 1;
            Ok(Value::Str(format!("row{index}")))
        });
        let array = context.as_array().unwrap();
        array.borrow_mut().insert(Key::Str("next".into()), value);
        eval.set_global("context", context);
        let code = r#"<?php
function template_main() {
    global $context;
    echo $context['next'](), ',', $context['next']();
}
?>"#;
        assert_eq!(render(&mut eval, code, "template_main"), "row1,row2");
    }

    #[test]
    fn suppressed_errors_become_null() {
        let mut eval = evaluator();
        let code = "<?php function template_main() { echo @$missing[1], '|', 'ok'; } ?>";
        assert_eq!(render(&mut eval, code, "template_main"), "|ok");
    }

    struct TestHost;

    impl HostFunctions for TestHost {
        fn has(&self, name: &str) -> bool {
            matches!(name, "greet" | "context_value" | "call_other")
        }

        fn constant(&self, name: &str) -> Option<Value> {
            (name == "ANSWER").then_some(Value::Int(42))
        }

        fn call(
            &mut self,
            name: &str,
            args: Vec<Value>,
            context: &mut dyn HostContext,
        ) -> Option<Result<Value, String>> {
            match name {
                "greet" => Some(Ok(Value::Str(format!(
                    "hi {}",
                    args.first().map(Value::to_php_string).unwrap_or_default()
                )))),
                "context_value" => Some(Ok(context
                    .global_field("context", "total")
                    .unwrap_or(Value::Null))),
                "call_other" => Some(context.call_template("template_other", Vec::new())),
                _ => None,
            }
        }
    }

    #[test]
    fn host_functions_are_an_allow_list() {
        let mut eval = evaluator();
        eval.set_host(Box::new(TestHost));
        let code = r#"<?php
function template_main() {
    echo greet('you'), '|', context_value(), '|', function_exists('greet') ? 'yes' : 'no';
    echo '|', function_exists('system') ? 'yes' : 'no', '|', ANSWER;
}
?>"#;
        assert_eq!(
            render(&mut eval, code, "template_main"),
            "hi you|2|yes|no|42"
        );
        // A name the host does not provide is an error, not a call.
        let error = eval
            .call("system", vec![Value::Str("ls".into())])
            .unwrap_err();
        assert!(error.message.contains("allow-list"), "{}", error.message);
    }

    #[test]
    fn function_exists_reports_template_builtins_and_host_functions() {
        let mut eval = evaluator();
        let code = "<?php function my_helper() {} function template_main() { \
                    echo function_exists('my_helper') ? 'y' : 'n', \
                    function_exists('array_pop') ? 'y' : 'n', \
                    function_exists('create_button') ? 'y' : 'n'; } ?>";
        assert_eq!(render(&mut eval, code, "template_main"), "yyn");
        eval.set_host(Box::new(crate::SmfFunctions));
        assert_eq!(render(&mut eval, code, "template_main"), "yyy");
    }

    #[test]
    fn host_functions_can_call_template_functions() {
        let mut eval = evaluator();
        eval.set_host(Box::new(TestHost));
        let code = r#"<?php
function template_other() { echo 'other'; }
function template_main() { echo 'main-', call_other(); }
?>"#;
        assert_eq!(render(&mut eval, code, "template_main"), "main-other");
    }

    #[test]
    fn embedder_constants_win_over_the_host() {
        let mut eval = evaluator();
        eval.set_host(Box::new(TestHost));
        eval.set_constant("ANSWER", Value::Str("local".into()));
        let code = "<?php function template_main() { echo ANSWER; } ?>";
        assert_eq!(render(&mut eval, code, "template_main"), "local");
        // The constant is the embedder's, so it survives removing the host.
        eval.take_host();
        assert_eq!(render(&mut eval, code, "template_main"), "local");
    }

    #[test]
    fn unknown_constants_are_errors() {
        let mut eval = evaluator();
        let statements = parse("<?php function template_main() { echo MISSING; } ?>").unwrap();
        eval.execute(&statements).unwrap();
        let error = eval.call("template_main", Vec::new()).unwrap_err();
        assert!(
            error.message.contains("unknown constant"),
            "{}",
            error.message
        );
    }

    #[test]
    fn limits_stop_runaway_programs() {
        let cases: &[(&str, EvalLimits)] = &[
            (
                "<?php while (true) { } ?>",
                EvalLimits {
                    max_steps: 1_000,
                    ..EvalLimits::default()
                },
            ),
            (
                "<?php function f() { return f(); } f(); ?>",
                EvalLimits {
                    max_call_depth: 8,
                    ..EvalLimits::default()
                },
            ),
            (
                "<?php $s = 'x'; for ($i = 0; $i < 100; $i++) { $s .= $s; } ?>",
                EvalLimits {
                    max_string_bytes: 4_096,
                    ..EvalLimits::default()
                },
            ),
            (
                "<?php $a = array(); for ($i = 0; $i < 10_000; $i++) { $a[] = $i; } ?>",
                EvalLimits {
                    max_array_entries: 64,
                    ..EvalLimits::default()
                },
            ),
        ];
        for (code, limits) in cases {
            let statements = parse(code).unwrap();
            let mut evaluator = Evaluator::new(limits.clone());
            let result = evaluator.execute(&statements);
            assert!(result.is_err(), "finished: {code}");
        }
    }

    #[test]
    fn output_limit_stops_endless_echo() {
        let statements =
            parse("<?php for ($i = 0; $i < 1000; $i++) { echo 'xxxxxxxxxx'; } ?>").unwrap();
        let mut evaluator = Evaluator::new(EvalLimits {
            max_output_bytes: 128,
            ..EvalLimits::default()
        });
        let error = evaluator.execute(&statements).unwrap_err();
        assert!(error.message.contains("output"), "{}", error.message);
    }

    #[test]
    fn steps_are_counted() {
        let statements = parse("<?php echo 1 + 1; ?>").unwrap();
        let mut evaluator = Evaluator::new(EvalLimits::default());
        evaluator.execute(&statements).unwrap();
        assert!(evaluator.steps() > 0);
    }

    #[test]
    fn fuzz_random_programs_stay_bounded() {
        use fador_testutil::{iterations, Rng};

        const TOKENS: &[&str] = &[
            "<?php", "?>", "$x", "$y", "=", "==", "+", "-", ".", "*", "/", "%", "(", ")", "{", "}",
            "[", "]", ";", ",", "echo", "if", "else", "while", "for", "foreach", "as", "function",
            "return", "break", "continue", "global", "array", "'a'", "\"b\"", "1", "0", "true",
            "false", "null", "count", "implode", "sprintf", "&", "&&", "||", "!", "++", "--", "=>",
            "isset", "empty", "unset", "@",
        ];
        let mut rng = Rng::new(0x6576_0001);
        let limits = EvalLimits {
            max_steps: 2_000,
            max_call_depth: 16,
            max_output_bytes: 16 * 1024,
            max_string_bytes: 16 * 1024,
            max_array_entries: 256,
        };
        for _ in 0..iterations(500) {
            let mut code = String::new();
            for _ in 0..rng.below(40) {
                code.push_str(TOKENS[rng.below(TOKENS.len())]);
            }
            if let Ok(statements) = parse(&code) {
                let mut evaluator = Evaluator::new(limits.clone());
                let _ = evaluator.execute(&statements);
                let _ = evaluator.call("template_main", Vec::new());
            }
        }
    }
}
