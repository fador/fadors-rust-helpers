use crate::context::Context;
use crate::value::Value;
use crate::Runtime;

/// A binary operator in a template expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    /// `||`, `or`.
    Or,
    /// `&&`, `and`.
    And,
    /// `==`, `eq`.
    Equal,
    /// `!=`, `<>`, `ne`, `neq`.
    NotEqual,
    /// `===`.
    StrictEqual,
    /// `!==`.
    StrictNotEqual,
    /// `<`, `lt`.
    Less,
    /// `>`, `gt`.
    Greater,
    /// `<=`, `lte`, `le`.
    LessEqual,
    /// `>=`, `gte`, `ge`.
    GreaterEqual,
    /// `in`.
    In,
    /// `~`.
    Concat,
    /// `+`.
    Add,
    /// `-`.
    Subtract,
    /// `*`.
    Multiply,
    /// `/`.
    Divide,
    /// `%`.
    Modulo,
}

/// A prefix operator in a template expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// `!` or `not`.
    Not,
    /// Unary `-`.
    Negate,
    /// Unary `+`.
    Positive,
}

/// A Twig `is` test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestOp {
    /// `is odd`.
    Odd,
    /// `is even`.
    Even,
    /// `is defined`.
    Defined,
    /// `is empty`.
    Empty,
    /// `is none` / `is null`.
    None,
    /// `is iterable`.
    Iterable,
}

/// A compiled expression.
///
/// Expressions are produced by the parser and evaluated by the renderer. The
/// variants are public so callers can inspect a compiled [`crate::Node`] tree.
#[derive(Debug, Clone)]
pub enum Expr {
    /// A constant.
    Literal(Value),
    /// A context path such as `forumrow.NAME`.
    Path(String),
    /// `.block` / `.a.b`: true when the block array exists and is not empty.
    BlockExists(String),
    /// A prefix operator and its operand.
    Unary(UnaryOp, Box<Expr>),
    /// A binary operator and its operands.
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
    /// `condition ? then : else`.
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    /// `value|filter(args)`.
    Filter(Box<Expr>, String, Vec<Expr>),
    /// `name(args)` such as `lang('KEY')`.
    Function(String, Vec<Expr>),
    /// `value is test`; the flag records `is not`.
    Test(Box<Expr>, TestOp, bool),
    /// A `[...]` literal.
    Array(Vec<Expr>),
    /// A `{ key: value }` literal.
    Object(Vec<(String, Expr)>),
}

impl Expr {
    /// Evaluate the expression against a context and the host services.
    ///
    /// Missing paths evaluate to [`Value::Null`] rather than an error, matching
    /// phpBB's tolerance for optional template variables.
    pub fn eval(&self, ctx: &mut Context, runtime: &dyn Runtime) -> Value {
        match self {
            Expr::Literal(value) => value.clone(),
            Expr::Path(path) => ctx.lookup(path).unwrap_or(Value::Null),
            Expr::BlockExists(path) => Value::Bool(ctx.block_exists(path)),
            Expr::Unary(op, inner) => {
                let value = inner.eval(ctx, runtime);
                match op {
                    UnaryOp::Not => Value::Bool(!value.truthy()),
                    UnaryOp::Negate => number_value(-value.as_f64().unwrap_or(0.0)),
                    UnaryOp::Positive => number_value(value.as_f64().unwrap_or(0.0)),
                }
            }
            Expr::Binary(op, left, right) => {
                if *op == BinaryOp::And {
                    return Value::Bool(
                        left.eval(ctx, runtime).truthy() && right.eval(ctx, runtime).truthy(),
                    );
                }
                if *op == BinaryOp::Or {
                    return Value::Bool(
                        left.eval(ctx, runtime).truthy() || right.eval(ctx, runtime).truthy(),
                    );
                }
                let left = left.eval(ctx, runtime);
                let right = right.eval(ctx, runtime);
                eval_binary(*op, left, right)
            }
            Expr::Ternary(condition, then_value, else_value) => {
                if condition.eval(ctx, runtime).truthy() {
                    then_value.eval(ctx, runtime)
                } else {
                    else_value.eval(ctx, runtime)
                }
            }
            Expr::Filter(inner, name, args) => {
                let value = inner.eval(ctx, runtime);
                let args: Vec<Value> = args.iter().map(|arg| arg.eval(ctx, runtime)).collect();
                eval_filter(value, name, &args)
            }
            Expr::Function(name, args) => {
                let args: Vec<Value> = args.iter().map(|arg| arg.eval(ctx, runtime)).collect();
                eval_function(name, &args, ctx, runtime)
            }
            Expr::Test(inner, test, negated) => {
                let value = inner.eval(ctx, runtime);
                let result = match test {
                    TestOp::Odd => value.as_i64().is_some_and(|n| n % 2 != 0),
                    TestOp::Even => value.as_i64().is_some_and(|n| n % 2 == 0),
                    TestOp::Defined => match inner.as_ref() {
                        Expr::Path(path) => ctx.is_defined(path),
                        Expr::BlockExists(path) => ctx.block_exists(path),
                        _ => !matches!(value, Value::Null),
                    },
                    TestOp::Empty => value.is_empty_value(),
                    TestOp::None => matches!(value, Value::Null),
                    TestOp::Iterable => matches!(value, Value::Array(_) | Value::Object(_)),
                };
                Value::Bool(if *negated { !result } else { result })
            }
            Expr::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| value.eval(ctx, runtime))
                    .collect(),
            ),
            Expr::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), value.eval(ctx, runtime)))
                    .collect(),
            ),
        }
    }
}

fn number_value(value: f64) -> Value {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        Value::Int(value as i64)
    } else {
        Value::Float(value)
    }
}

fn eval_binary(op: BinaryOp, left: Value, right: Value) -> Value {
    match op {
        BinaryOp::Equal => Value::Bool(loose_equal(&left, &right)),
        BinaryOp::NotEqual => Value::Bool(!loose_equal(&left, &right)),
        BinaryOp::StrictEqual => Value::Bool(left == right),
        BinaryOp::StrictNotEqual => Value::Bool(left != right),
        BinaryOp::Less | BinaryOp::Greater | BinaryOp::LessEqual | BinaryOp::GreaterEqual => {
            let ordering = compare_values(&left, &right);
            let result = match op {
                BinaryOp::Less => ordering < 0,
                BinaryOp::Greater => ordering > 0,
                BinaryOp::LessEqual => ordering <= 0,
                BinaryOp::GreaterEqual => ordering >= 0,
                _ => false,
            };
            Value::Bool(result)
        }
        BinaryOp::In => Value::Bool(match &right {
            Value::Array(values) => values.iter().any(|value| loose_equal(&left, value)),
            Value::Object(values) => left.as_str().is_some_and(|key| values.contains_key(key)),
            Value::Str(text) => left.as_str().is_some_and(|needle| text.contains(needle)),
            _ => false,
        }),
        BinaryOp::Concat => Value::Str(format!("{}{}", left.to_output(), right.to_output())),
        BinaryOp::Add => arithmetic(left, right, |a, b| a + b),
        BinaryOp::Subtract => arithmetic(left, right, |a, b| a - b),
        BinaryOp::Multiply => arithmetic(left, right, |a, b| a * b),
        BinaryOp::Divide => arithmetic(left, right, |a, b| if b == 0.0 { 0.0 } else { a / b }),
        BinaryOp::Modulo => arithmetic(left, right, |a, b| if b == 0.0 { 0.0 } else { a % b }),
        BinaryOp::And | BinaryOp::Or => unreachable!("short-circuit handled by caller"),
    }
}

fn arithmetic(left: Value, right: Value, f: impl Fn(f64, f64) -> f64) -> Value {
    let left_number = left.as_f64().unwrap_or(0.0);
    let right_number = right.as_f64().unwrap_or(0.0);
    number_value(f(left_number, right_number))
}

fn loose_equal(left: &Value, right: &Value) -> bool {
    if matches!(left, Value::Null) && matches!(right, Value::Null) {
        return true;
    }
    if let (Some(a), Some(b)) = (left.as_f64(), right.as_f64()) {
        return (a - b).abs() < f64::EPSILON;
    }
    match (left, right) {
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => a == b,
        (Value::Object(a), Value::Object(b)) => a == b,
        (Value::Bool(value), Value::Str(text)) | (Value::Str(text), Value::Bool(value)) => {
            value.to_string() == *text
        }
        _ => false,
    }
}

fn compare_values(left: &Value, right: &Value) -> i32 {
    if let (Some(a), Some(b)) = (left.as_f64(), right.as_f64()) {
        return a.partial_cmp(&b).map_or(0, |ordering| match ordering {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        });
    }
    left.to_output().cmp(&right.to_output()) as i32
}

fn eval_filter(value: Value, name: &str, args: &[Value]) -> Value {
    match name {
        "e" | "escape" => {
            let strategy = args.first().and_then(Value::as_str).unwrap_or("html");
            Value::Str(match strategy {
                "js" => js_escape(&value.to_output()),
                "html_attr" => html_attr_escape(&value.to_output()),
                _ => html_escape(&value.to_output()),
            })
        }
        "default" => {
            if value.is_empty_value() {
                args.first().cloned().unwrap_or(Value::Null)
            } else {
                value
            }
        }
        "join" => {
            let separator = args
                .first()
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            match value {
                Value::Array(values) => Value::Str(
                    values
                        .iter()
                        .map(Value::to_output)
                        .collect::<Vec<_>>()
                        .join(&separator),
                ),
                other => Value::Str(other.to_output()),
            }
        }
        "length" => Value::Int(value.len() as i64),
        "upper" => Value::Str(value.to_output().to_uppercase()),
        "lower" => Value::Str(value.to_output().to_lowercase()),
        "int" => Value::Int(value.as_i64().unwrap_or(0)),
        "float" => Value::Float(value.as_f64().unwrap_or(0.0)),
        "addslashes" => Value::Str(
            value
                .to_output()
                .replace('\\', "\\\\")
                .replace('\'', "\\'")
                .replace('"', "\\\"")
                .replace('\0', "\\0"),
        ),
        "subset" => {
            let start = args.first().and_then(Value::as_i64).unwrap_or(0).max(0) as usize;
            let length = args.get(1).and_then(Value::as_i64);
            match value {
                Value::Array(values) => {
                    let end = length
                        .map(|length| start.saturating_add(length.max(0) as usize))
                        .unwrap_or(values.len())
                        .min(values.len());
                    Value::Array(
                        values
                            .into_iter()
                            .skip(start)
                            .take(end.saturating_sub(start))
                            .collect(),
                    )
                }
                other => other,
            }
        }
        _ => value,
    }
}

fn eval_function(name: &str, args: &[Value], ctx: &Context, runtime: &dyn Runtime) -> Value {
    match name {
        "lang" => {
            let key = args.first().and_then(Value::as_str).unwrap_or("");
            if let Some(value) = ctx.get(&format!("L_{key}")) {
                return Value::Str(value.to_output());
            }
            Value::Str(runtime.lang(key, &args[1..]))
        }
        "lang_defined" => {
            let key = args.first().and_then(Value::as_str).unwrap_or("");
            Value::Bool(ctx.is_defined(&format!("L_{key}")) || runtime.lang_defined(key))
        }
        "lang_js" => {
            let key = args.first().and_then(Value::as_str).unwrap_or("");
            let text = ctx
                .get(&format!("L_{key}"))
                .map(|value| value.to_output())
                .unwrap_or_else(|| runtime.lang(key, &args[1..]));
            Value::Str(js_escape(&text))
        }
        "path" => {
            let route = args.first().and_then(Value::as_str).unwrap_or("");
            let params = args.get(1).cloned().unwrap_or(Value::Null);
            Value::Str(runtime.path(route, &params))
        }
        "url" => {
            let route = args.first().and_then(Value::as_str).unwrap_or("");
            let params = args.get(1).cloned().unwrap_or(Value::Null);
            Value::Str(runtime.url(route, &params))
        }
        "attribute" => {
            let base = args.first().cloned().unwrap_or(Value::Null);
            let name = args.get(1).and_then(Value::as_str).unwrap_or("");
            match base {
                Value::Object(map) => map.get(name).cloned().unwrap_or(Value::Null),
                Value::Array(items) => name
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| items.get(index).cloned())
                    .unwrap_or(Value::Null),
                _ => Value::Null,
            }
        }
        "get_class" => Value::Str(String::new()),
        _ => Value::Null,
    }
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#039;"),
            '\0' => out.push('\u{fffd}'),
            _ => out.push(ch),
        }
    }
    out
}

/// Twig's `e('html_attr')` strategy: named entities for `"&<>`, hexadecimal
/// entities for everything except `[A-Za-z0-9,.-_]`.
fn html_attr_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            ch if ch.is_ascii_alphanumeric()
                || ch == ','
                || ch == '.'
                || ch == '-'
                || ch == '_' =>
            {
                out.push(ch);
            }
            ch => out.push_str(&format!("&#x{:X};", ch as u32)),
        }
    }
    out
}

pub(crate) fn js_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
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

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Int(i64),
    Float(f64),
    Str(String),
    Op(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Pipe,
    Dot,
    Question,
    End,
}

pub fn parse_expression(input: &str) -> Result<Expr, String> {
    let tokens = tokenize(input)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let expr = parser.parse_expr(0)?;
    if parser.peek() != &Tok::End {
        return Err(format!("unexpected token {:?}", parser.peek()));
    }
    Ok(expr)
}

/// Deepest expression nesting accepted.  The recursive-descent parser and the
/// evaluator both recurse, so a hostile expression such as thousands of nested
/// parentheses must be rejected before it can exhaust the stack.
const MAX_EXPR_DEPTH: usize = 64;
/// Most tokens accepted in one expression.  Real templates use a few dozen.
const MAX_EXPR_TOKENS: usize = 4_096;

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if out.len() >= MAX_EXPR_TOKENS {
            return Err("template expression is too long".into());
        }
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' {
            let quote = b;
            i += 1;
            let mut value = String::new();
            while i < bytes.len() {
                let current = bytes[i];
                if current == quote {
                    i += 1;
                    break;
                }
                if current == b'\\' {
                    i += 1;
                    if i >= bytes.len() {
                        return Err("unterminated string escape".into());
                    }
                    match bytes[i] {
                        b'n' => value.push('\n'),
                        b'r' => value.push('\r'),
                        b't' => value.push('\t'),
                        b'\\' => value.push('\\'),
                        b'\'' => value.push('\''),
                        b'"' => value.push('"'),
                        other => value.push(other as char),
                    }
                    i += 1;
                    continue;
                }
                let ch = input[i..]
                    .chars()
                    .next()
                    .ok_or_else(|| "invalid utf-8 in string".to_string())?;
                value.push(ch);
                i += ch.len_utf8();
            }
            out.push(Tok::Str(value));
            continue;
        }
        if b.is_ascii_digit() || (b == b'.' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit())
        {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let mut is_float = false;
            if i < bytes.len() && bytes[i] == b'.' {
                is_float = true;
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let text = &input[start..i];
            if is_float {
                out.push(Tok::Float(
                    text.parse().map_err(|_| "invalid float".to_string())?,
                ));
            } else {
                out.push(Tok::Int(
                    text.parse().map_err(|_| "invalid integer".to_string())?,
                ));
            }
            continue;
        }
        if b.is_ascii_alphabetic() || b == b'_' || b == b'$' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            out.push(Tok::Ident(input[start..i].to_string()));
            continue;
        }
        let rest = &input[i..];
        // Operator prefixes are ASCII.  Comparing with `starts_with` keeps the
        // scan on a character boundary; slicing `&rest[..3]` panics when the
        // next character is multi-byte (for example `ää`).
        if let Some(op) = ["===", "!=="]
            .into_iter()
            .find(|operator| rest.starts_with(operator))
        {
            out.push(Tok::Op(op.to_string()));
            i += op.len();
            continue;
        }
        if let Some(op) = ["==", "!=", "<=", ">=", "&&", "||", "<>"]
            .into_iter()
            .find(|operator| rest.starts_with(operator))
        {
            out.push(Tok::Op(op.to_string()));
            i += op.len();
            continue;
        }
        match b {
            b'(' => out.push(Tok::LParen),
            b')' => out.push(Tok::RParen),
            b'[' => out.push(Tok::LBracket),
            b']' => out.push(Tok::RBracket),
            b'{' => out.push(Tok::LBrace),
            b'}' => out.push(Tok::RBrace),
            b',' => out.push(Tok::Comma),
            b':' => out.push(Tok::Colon),
            b'|' => out.push(Tok::Pipe),
            b'.' => out.push(Tok::Dot),
            b'?' => out.push(Tok::Question),
            b'!' | b'~' | b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>' => {
                out.push(Tok::Op((b as char).to_string()))
            }
            _ => return Err(format!("unexpected character {:?}", b as char)),
        }
        i += 1;
    }
    out.push(Tok::End);
    Ok(out)
}

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        self.tokens.get(self.pos).unwrap_or(&Tok::End)
    }

    fn next(&mut self) -> Tok {
        let token = self.peek().clone();
        self.pos += 1;
        token
    }

    fn eat(&mut self, token: &Tok) -> bool {
        if self.peek() == token {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, token: &Tok) -> Result<(), String> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(format!("expected {token:?}, got {:?}", self.peek()))
        }
    }

    fn parse_expr(&mut self, min_bp: u8) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err("template expression is nested too deeply".into());
        }
        let result = self.parse_expr_inner(min_bp);
        self.depth -= 1;
        result
    }

    fn parse_expr_inner(&mut self, min_bp: u8) -> Result<Expr, String> {
        let mut left = self.parse_prefix()?;
        loop {
            // Postfix filters bind tighter than binary operators.
            if self.peek() == &Tok::Pipe && 70 >= min_bp {
                self.next();
                let name = match self.next() {
                    Tok::Ident(name) => name,
                    other => return Err(format!("expected filter name, got {other:?}")),
                };
                let args = if self.eat(&Tok::LParen) {
                    self.parse_arguments()?
                } else {
                    Vec::new()
                };
                left = Expr::Filter(Box::new(left), name, args);
                continue;
            }

            if self.peek() == &Tok::Question && 5 >= min_bp {
                self.next();
                if self.eat(&Tok::Colon) {
                    let else_value = self.parse_expr(5)?;
                    left =
                        Expr::Ternary(Box::new(left.clone()), Box::new(left), Box::new(else_value));
                    continue;
                }
                let then_value = self.parse_expr(0)?;
                let else_value = if self.eat(&Tok::Colon) {
                    self.parse_expr(5)?
                } else {
                    Expr::Literal(Value::Null)
                };
                left = Expr::Ternary(Box::new(left), Box::new(then_value), Box::new(else_value));
                continue;
            }

            let (op, left_bp, right_bp) = match self.peek() {
                Tok::Op(op) if op == "||" => (BinaryOp::Or, 10, 11),
                Tok::Ident(op) if op == "or" => (BinaryOp::Or, 10, 11),
                Tok::Op(op) if op == "&&" => (BinaryOp::And, 15, 16),
                Tok::Ident(op) if op == "and" => (BinaryOp::And, 15, 16),
                Tok::Op(op) if op == "==" => (BinaryOp::Equal, 20, 21),
                Tok::Op(op) if op == "!=" => (BinaryOp::NotEqual, 20, 21),
                Tok::Op(op) if op == "===" => (BinaryOp::StrictEqual, 20, 21),
                Tok::Op(op) if op == "!==" => (BinaryOp::StrictNotEqual, 20, 21),
                Tok::Op(op) if op == "<>" => (BinaryOp::NotEqual, 20, 21),
                Tok::Op(op) if op == "<" => (BinaryOp::Less, 20, 21),
                Tok::Op(op) if op == ">" => (BinaryOp::Greater, 20, 21),
                Tok::Op(op) if op == "<=" => (BinaryOp::LessEqual, 20, 21),
                Tok::Op(op) if op == ">=" => (BinaryOp::GreaterEqual, 20, 21),
                Tok::Ident(op) if op == "eq" => (BinaryOp::Equal, 20, 21),
                Tok::Ident(op) if op == "ne" || op == "neq" => (BinaryOp::NotEqual, 20, 21),
                Tok::Ident(op) if op == "gt" => (BinaryOp::Greater, 20, 21),
                Tok::Ident(op) if op == "gte" || op == "ge" => (BinaryOp::GreaterEqual, 20, 21),
                Tok::Ident(op) if op == "lt" => (BinaryOp::Less, 20, 21),
                Tok::Ident(op) if op == "lte" || op == "le" => (BinaryOp::LessEqual, 20, 21),
                Tok::Ident(op) if op == "in" => (BinaryOp::In, 20, 21),
                Tok::Op(op) if op == "~" => (BinaryOp::Concat, 30, 31),
                Tok::Op(op) if op == "+" => (BinaryOp::Add, 40, 41),
                Tok::Op(op) if op == "-" => (BinaryOp::Subtract, 40, 41),
                Tok::Op(op) if op == "*" => (BinaryOp::Multiply, 50, 51),
                Tok::Op(op) if op == "/" => (BinaryOp::Divide, 50, 51),
                Tok::Op(op) if op == "%" => (BinaryOp::Modulo, 50, 51),
                Tok::Ident(op) if op == "is" => {
                    if 20 < min_bp {
                        break;
                    }
                    self.next();
                    let negated = if let Tok::Ident(value) = self.peek() {
                        if value == "not" {
                            self.next();
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    let name = match self.next() {
                        Tok::Ident(name) => name,
                        other => return Err(format!("expected test name, got {other:?}")),
                    };
                    let test = match name.as_str() {
                        "odd" => TestOp::Odd,
                        "even" => TestOp::Even,
                        "defined" => TestOp::Defined,
                        "empty" => TestOp::Empty,
                        "none" | "null" => TestOp::None,
                        "iterable" => TestOp::Iterable,
                        other => return Err(format!("unsupported test {other:?}")),
                    };
                    left = Expr::Test(Box::new(left), test, negated);
                    continue;
                }
                _ => break,
            };
            if left_bp < min_bp {
                break;
            }
            self.next();
            let right = self.parse_expr(right_bp)?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_prefix(&mut self) -> Result<Expr, String> {
        match self.next() {
            Tok::Int(value) => Ok(Expr::Literal(Value::Int(value))),
            Tok::Float(value) => Ok(Expr::Literal(Value::Float(value))),
            Tok::Str(value) => Ok(Expr::Literal(Value::Str(value))),
            Tok::Ident(name) => match name.as_str() {
                "true" => Ok(Expr::Literal(Value::Bool(true))),
                "false" => Ok(Expr::Literal(Value::Bool(false))),
                "null" | "none" => Ok(Expr::Literal(Value::Null)),
                "not" => {
                    let value = self.parse_expr(60)?;
                    Ok(Expr::Unary(UnaryOp::Not, Box::new(value)))
                }
                _ => {
                    if self.eat(&Tok::LParen) {
                        let args = self.parse_arguments()?;
                        Ok(Expr::Function(name, args))
                    } else {
                        let mut path = name;
                        let mut has_dot = false;
                        while self.eat(&Tok::Dot) {
                            let segment = match self.next() {
                                Tok::Ident(segment) => segment,
                                Tok::Int(segment) => segment.to_string(),
                                other => {
                                    return Err(format!(
                                        "expected path segment after '.', got {other:?}"
                                    ))
                                }
                            };
                            path.push('.');
                            path.push_str(&segment);
                            has_dot = true;
                        }
                        if has_dot && self.eat(&Tok::LParen) {
                            let args = self.parse_arguments()?;
                            Ok(Expr::Function(path, args))
                        } else {
                            Ok(Expr::Path(path))
                        }
                    }
                }
            },
            Tok::Op(op) if op == "!" => {
                let value = self.parse_expr(60)?;
                Ok(Expr::Unary(UnaryOp::Not, Box::new(value)))
            }
            Tok::Op(op) if op == "-" => {
                let value = self.parse_expr(60)?;
                Ok(Expr::Unary(UnaryOp::Negate, Box::new(value)))
            }
            Tok::Op(op) if op == "+" => {
                let value = self.parse_expr(60)?;
                Ok(Expr::Unary(UnaryOp::Positive, Box::new(value)))
            }
            Tok::LParen => {
                let value = self.parse_expr(0)?;
                self.expect(&Tok::RParen)?;
                Ok(value)
            }
            Tok::LBracket => {
                let mut values = Vec::new();
                while self.peek() != &Tok::RBracket {
                    values.push(self.parse_expr(0)?);
                    if !self.eat(&Tok::Comma) {
                        break;
                    }
                }
                self.expect(&Tok::RBracket)?;
                Ok(Expr::Array(values))
            }
            Tok::LBrace => {
                let mut values = Vec::new();
                while self.peek() != &Tok::RBrace {
                    let key = match self.next() {
                        Tok::Ident(key) | Tok::Str(key) => key,
                        other => return Err(format!("expected object key, got {other:?}")),
                    };
                    self.expect(&Tok::Colon)?;
                    let value = self.parse_expr(0)?;
                    values.push((key, value));
                    if !self.eat(&Tok::Comma) {
                        break;
                    }
                }
                self.expect(&Tok::RBrace)?;
                Ok(Expr::Object(values))
            }
            Tok::Dot => {
                let mut path = String::new();
                while self.peek() != &Tok::End {
                    match self.next() {
                        Tok::Ident(segment) => {
                            if !path.is_empty() {
                                path.push('.');
                            }
                            path.push_str(&segment);
                        }
                        Tok::Dot => continue,
                        other => return Err(format!("unexpected token in block path: {other:?}")),
                    }
                    if !self.eat(&Tok::Dot) {
                        break;
                    }
                }
                Ok(Expr::BlockExists(path))
            }
            other => Err(format!("unexpected token in expression: {other:?}")),
        }
    }

    fn parse_arguments(&mut self) -> Result<Vec<Expr>, String> {
        let mut args = Vec::new();
        if self.eat(&Tok::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.parse_expr(0)?);
            if self.eat(&Tok::Comma) {
                continue;
            }
            self.expect(&Tok::RParen)?;
            break;
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Context;
    use crate::Runtime;

    struct TestRuntime;

    impl Runtime for TestRuntime {
        fn lang(&self, key: &str, _args: &[Value]) -> String {
            match key {
                "COLON" => ":".into(),
                "HELLO" => "Hei".into(),
                _ => key.into(),
            }
        }

        fn lang_defined(&self, key: &str) -> bool {
            key == "HELLO"
        }

        fn path(&self, route: &str, params: &Value) -> String {
            let id = params.get("forum_id").and_then(Value::as_i64).unwrap_or(0);
            format!("/app.php/{route}/{id}")
        }

        fn url(&self, route: &str, _params: &Value) -> String {
            format!("/{route}")
        }
    }

    fn eval(input: &str, ctx: &mut Context) -> Value {
        parse_expression(input).unwrap().eval(ctx, &TestRuntime)
    }

    #[test]
    fn parses_template_expressions() {
        let mut ctx = Context::new();
        ctx.set("S_IS_BOT", Value::Bool(false));
        ctx.set("COUNT", Value::Int(3));
        ctx.set(
            "row",
            Value::object([
                ("NAME".into(), Value::Str("Naruto".into())),
                ("S_ROW_COUNT".into(), Value::Int(2)),
            ]),
        );
        assert!(eval("not S_IS_BOT and COUNT > 1", &mut ctx).truthy());
        assert_eq!(eval("row.NAME", &mut ctx).to_output(), "Naruto");
        assert!(matches!(
            eval("row.S_ROW_COUNT is even", &mut ctx),
            Value::Bool(true)
        ));
        assert_eq!(
            eval("lang('HELLO') ~ lang('COLON')", &mut ctx).to_output(),
            "Hei:"
        );
        assert_eq!(
            eval("path('feed', { forum_id : row.S_ROW_COUNT })", &mut ctx).to_output(),
            "/app.php/feed/2"
        );
        assert_eq!(eval("S_IS_BOT ? 'yes' : 'no'", &mut ctx).to_output(), "no");
        assert_eq!(eval("'x'|e", &mut ctx).to_output(), "x");
        assert_eq!(eval("['a','b']|join('-')", &mut ctx).to_output(), "a-b");
        assert_eq!(eval("'aBc'|upper", &mut ctx).to_output(), "ABC");
        assert_eq!(eval("'aBc'|lower", &mut ctx).to_output(), "abc");
    }

    #[test]
    fn attribute_reads_object_and_array() {
        let mut ctx = Context::new();
        ctx.set(
            "loops",
            Value::object([
                ("enabled".into(), Value::Array(vec![Value::Str("x".into())])),
                ("empty".into(), Value::Array(Vec::new())),
            ]),
        );
        assert_eq!(
            eval("attribute(loops, 'enabled')|length", &mut ctx).to_output(),
            "1"
        );
        assert_eq!(
            eval("attribute(loops, 'empty')|length", &mut ctx).to_output(),
            "0"
        );
        assert_eq!(
            eval("attribute(loops, 'missing')|length", &mut ctx).to_output(),
            "0"
        );
    }
}
