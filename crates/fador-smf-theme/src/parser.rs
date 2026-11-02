//! Parser for the PHP subset the SMF theme templates are written in.
//!
//! The grammar is intentionally limited to what the installed templates use:
//! inline HTML, `echo`, `if`/`elseif`/`else`, `foreach`, `for`, `while`,
//! `switch`, function declarations, `global`, `return`/`break`/`continue`,
//! arrays, strings, variables, calls and the usual operators. There is no
//! object system, no `include`, no namespace, no class and no filesystem or
//! network access.
//!
//! Parsing is bounded: the token list is produced by [`crate::tokenize`], the
//! parser is a single pass over it, and nesting is limited by the input size.
//! A rejected template is a [`ParseError`], never a panic.

use crate::lexer::{tokenize, Token, TokenKind};
use std::fmt;

/// One statement of a template.
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// Literal inline HTML.
    Text(String),
    /// `echo a, b, c;`
    Echo(Vec<Expr>),
    /// An expression evaluated for its side effects.
    Expr(Expr),
    /// `if`/`elseif`/`else`. The last branch has a `None` condition and is the
    /// `else` arm.
    If {
        /// Condition and body of every arm, in source order.
        branches: Vec<(Option<Expr>, Vec<Stmt>)>,
    },
    /// `foreach ($subject as $key => $value)`.
    Foreach {
        /// The expression being iterated.
        subject: Expr,
        /// Variable receiving the key, when the loop names one.
        key: Option<String>,
        /// Variable receiving the value.
        value: String,
        /// Whether the value variable is bound to the array cell itself.
        by_ref: bool,
        /// Loop body.
        body: Vec<Stmt>,
    },
    /// `for (init; cond; step)`.
    For {
        /// Expressions run once before the loop.
        init: Vec<Expr>,
        /// Conditions; an empty list means "forever".
        cond: Vec<Expr>,
        /// Expressions run after every iteration.
        step: Vec<Expr>,
        /// Loop body.
        body: Vec<Stmt>,
    },
    /// `while (cond)`.
    While {
        /// Loop condition.
        cond: Expr,
        /// Loop body.
        body: Vec<Stmt>,
    },
    /// `switch ($subject) { case ...: ... }`.
    Switch {
        /// Value compared against every `case`.
        subject: Expr,
        /// `(Some(case value), body)` for a `case`, `(None, body)` for
        /// `default`, in source order.
        cases: Vec<(Option<Expr>, Vec<Stmt>)>,
    },
    /// `break;` or `break n;`.
    Break(Option<Expr>),
    /// `continue;` or `continue n;`.
    Continue(Option<Expr>),
    /// `return;` or `return value;`.
    Return(Option<Expr>),
    /// A named function declaration.
    Function {
        /// Function name as written; calls match it case-insensitively.
        name: String,
        /// Declared parameters.
        params: Vec<Param>,
        /// Function body.
        body: Vec<Stmt>,
    },
    /// `global $a, $b;` — bind the named globals into the current scope.
    Global(Vec<String>),
    /// `unset($a, $b[0]);`
    Unset(Vec<Expr>),
    /// A bare `{ ... }` block.
    Block(Vec<Stmt>),
    /// An empty statement (`;`).
    Nop,
}

/// One declared function parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    /// Parameter name without the `$`.
    pub name: String,
    /// Whether the parameter is declared `&$name`.
    pub by_ref: bool,
    /// Default value expression, when the parameter has one.
    pub default: Option<Expr>,
}

/// One expression of a template.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// An integer literal.
    Int(i64),
    /// A floating-point literal.
    Float(f64),
    /// A quoted string literal, before escape processing and interpolation.
    Str {
        /// The string body exactly as written, escapes included.
        raw: String,
        /// Whether the literal used single quotes.
        single: bool,
    },
    /// `$name`
    Variable(String),
    /// `array(...)` or `[...]`; entries keep `(key, value)` order.
    Array(Vec<(Option<Expr>, Expr)>),
    /// `$base[$key]`
    Index(Box<Expr>, Box<Expr>),
    /// `$base[]`, only valid as an assignment target.
    Append(Box<Expr>),
    /// A call to a named function.
    Call(String, Vec<Expr>),
    /// A call through a value, such as a callback stored in a variable.
    DynamicCall(Box<Expr>, Vec<Expr>),
    /// A bare identifier used as a constant.
    Constant(String),
    /// A unary operator and its operand.
    Unary(UnOp, Box<Expr>),
    /// A binary operator and its two operands.
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// An assignment; the expression yields the assigned value.
    Assign {
        /// Assignment target: variable, index or append.
        target: Box<Expr>,
        /// Assignment operator.
        op: AssignOp,
        /// Right-hand side.
        value: Box<Expr>,
    },
    /// `++$x`
    PreInc(Box<Expr>),
    /// `--$x`
    PreDec(Box<Expr>),
    /// `$x++`
    PostInc(Box<Expr>),
    /// `$x--`
    PostDec(Box<Expr>),
    /// `cond ? then : otherwise`, with `then` omitted for `cond ?: otherwise`.
    Ternary {
        /// The condition.
        cond: Box<Expr>,
        /// The value when the condition is true; `None` means "the condition".
        then: Option<Box<Expr>>,
        /// The value when the condition is false.
        otherwise: Box<Expr>,
    },
    /// `isset($a, $b['c'])`
    Isset(Vec<Expr>),
    /// `empty($a)`
    Empty(Box<Expr>),
    /// `&$x`, used as an assignment source to alias another cell.
    Reference(Box<Expr>),
    /// `(int)`, `(float)`, `(string)`, `(bool)` or `(array)`.
    Cast(CastType, Box<Expr>),
    /// `@expr`: an error inside the operand yields `null` instead.
    Suppressed(Box<Expr>),
}

/// A unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    /// Logical not (`!`).
    Not,
    /// Arithmetic negation (`-`).
    Neg,
    /// Unary plus (`+`).
    Pos,
    /// Bitwise complement (`~`).
    BitNot,
}

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Mod,
    /// `.`
    Concat,
    /// `&&` and the low-precedence `and`
    And,
    /// `||` and the low-precedence `or`
    Or,
    /// `xor`
    Xor,
    /// `&`
    BitAnd,
    /// `|`
    BitOr,
    /// `^`
    BitXor,
    /// `<<`
    ShiftLeft,
    /// `>>`
    ShiftRight,
    /// `==`
    Equal,
    /// `!=` and `<>`
    NotEqual,
    /// `===`
    Identical,
    /// `!==`
    NotIdentical,
    /// `<`
    Less,
    /// `<=`
    LessEqual,
    /// `>`
    Greater,
    /// `>=`
    GreaterEqual,
    /// `<=>`
    Spaceship,
    /// `??`
    Coalesce,
}

/// A compound assignment operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOp {
    /// `=`
    Assign,
    /// `+=`
    Add,
    /// `-=`
    Sub,
    /// `*=`
    Mul,
    /// `/=`
    Div,
    /// `%=`
    Mod,
    /// `.=`
    Concat,
    /// `&=`
    BitAnd,
    /// `|=`
    BitOr,
    /// `^=`
    BitXor,
    /// `<<=`
    ShiftLeft,
    /// `>>=`
    ShiftRight,
    /// `??=`
    Coalesce,
}

/// A cast target type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastType {
    /// `(int)` / `(integer)`
    Int,
    /// `(float)` / `(double)`
    Float,
    /// `(string)`
    String,
    /// `(bool)` / `(boolean)`
    Bool,
    /// `(array)`
    Array,
}

/// A template that could not be tokenized or parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    /// Human-readable diagnostic; it never contains file contents.
    pub message: String,
    /// One-based line of the offending token.
    pub line: usize,
    /// One-based column of the offending token.
    pub column: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}, column {}: {}",
            self.line, self.column, self.message
        )
    }
}

impl std::error::Error for ParseError {}

/// Parse a whole template into statements.
///
/// # Errors
///
/// Returns the first [`ParseError`] the lexer or parser finds.
pub fn parse(input: &str) -> Result<Vec<Stmt>, ParseError> {
    let tokens = tokenize(input)?;
    Parser::new(tokens).parse_program()
}

const MAX_PARSE_DEPTH: usize = 64;

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            depth: 0,
        }
    }

    fn enter_depth(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            Err(self.error_here("nesting depth exceeded"))
        } else {
            Ok(())
        }
    }

    fn leave_depth(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_program(&mut self) -> Result<Vec<Stmt>, ParseError> {
        let mut statements = Vec::new();
        while self.pos < self.tokens.len() {
            if let Some(text) = self.take_text() {
                statements.push(Stmt::Text(text));
                continue;
            }
            if self.at_eof() {
                break;
            }
            statements.push(self.parse_statement()?);
        }
        Ok(statements)
    }

    fn take_text(&mut self) -> Option<String> {
        if let Some(Token {
            kind: TokenKind::InlineHtml(text),
            ..
        }) = self.tokens.get(self.pos)
        {
            let text = text.clone();
            self.pos += 1;
            return Some(text);
        }
        None
    }

    fn parse_statement(&mut self) -> Result<Stmt, ParseError> {
        self.enter_depth()?;
        let res = self.parse_statement_inner();
        self.leave_depth();
        res
    }

    fn parse_statement_inner(&mut self) -> Result<Stmt, ParseError> {
        if let Some(text) = self.take_text() {
            return Ok(Stmt::Text(text));
        }
        if self.eat_symbol(";") {
            return Ok(Stmt::Nop);
        }
        if self.eat_symbol("{") {
            let body = self.parse_statements_until("}")?;
            return Ok(Stmt::Block(body));
        }
        if self.eat_keyword("if") {
            return self.parse_if();
        }
        if self.eat_keyword("foreach") {
            return self.parse_foreach();
        }
        if self.eat_keyword("for") {
            return self.parse_for();
        }
        if self.eat_keyword("while") {
            return self.parse_while();
        }
        if self.eat_keyword("switch") {
            return self.parse_switch();
        }
        if self.eat_keyword("function") {
            return self.parse_function();
        }
        if self.eat_keyword("global") {
            return self.parse_global();
        }
        if self.eat_keyword("echo") {
            let values = self.parse_expression_list_until_statement_end()?;
            if values.is_empty() {
                return Err(self.error_here("expected an expression after echo"));
            }
            self.consume_statement_end();
            return Ok(Stmt::Echo(values));
        }
        if self.eat_keyword("break") {
            let value = if self.at_statement_end() {
                None
            } else {
                Some(self.parse_expression()?)
            };
            self.consume_statement_end();
            return Ok(Stmt::Break(value));
        }
        if self.eat_keyword("continue") {
            let value = if self.at_statement_end() {
                None
            } else {
                Some(self.parse_expression()?)
            };
            self.consume_statement_end();
            return Ok(Stmt::Continue(value));
        }
        if self.eat_keyword("return") {
            let value = if self.at_statement_end() {
                None
            } else {
                Some(self.parse_expression()?)
            };
            self.consume_statement_end();
            return Ok(Stmt::Return(value));
        }
        if self.eat_keyword("unset") {
            self.expect_symbol("(")?;
            let values = self.parse_expression_list(")")?;
            self.expect_symbol(")")?;
            self.consume_statement_end();
            return Ok(Stmt::Unset(values));
        }
        let expr = self.parse_expression()?;
        self.consume_statement_end();
        Ok(Stmt::Expr(expr))
    }

    fn parse_statements_until(&mut self, end: &str) -> Result<Vec<Stmt>, ParseError> {
        let mut statements = Vec::new();
        while self.pos < self.tokens.len() && !self.check_symbol(end) {
            if let Some(text) = self.take_text() {
                statements.push(Stmt::Text(text));
                continue;
            }
            statements.push(self.parse_statement()?);
        }
        self.expect_symbol(end)?;
        Ok(statements)
    }

    fn parse_if(&mut self) -> Result<Stmt, ParseError> {
        self.expect_symbol("(")?;
        let cond = self.parse_expression()?;
        self.expect_symbol(")")?;
        let body = self.parse_statement()?;
        let mut branches = vec![(Some(cond), block_of(body))];
        loop {
            if self.eat_keyword("elseif") {
                self.expect_symbol("(")?;
                let cond = self.parse_expression()?;
                self.expect_symbol(")")?;
                let body = self.parse_statement()?;
                branches.push((Some(cond), block_of(body)));
            } else if self.eat_keyword("else") {
                let body = self.parse_statement()?;
                branches.push((None, block_of(body)));
                break;
            } else {
                break;
            }
        }
        Ok(Stmt::If { branches })
    }

    fn parse_foreach(&mut self) -> Result<Stmt, ParseError> {
        self.expect_symbol("(")?;
        let subject = self.parse_expression()?;
        self.expect_keyword("as")?;
        let by_ref = self.eat_symbol("&");
        let first = self.expect_variable()?;
        let (key, value, by_ref) = if self.eat_symbol("=>") {
            let value_by_ref = self.eat_symbol("&");
            let second = self.expect_variable()?;
            (Some(first), second, value_by_ref)
        } else {
            (None, first, by_ref)
        };
        self.expect_symbol(")")?;
        let body = self.parse_statement()?;
        Ok(Stmt::Foreach {
            subject,
            key,
            value,
            by_ref,
            body: block_of(body),
        })
    }

    fn parse_for(&mut self) -> Result<Stmt, ParseError> {
        self.expect_symbol("(")?;
        let init = self.parse_expression_list(";")?;
        self.expect_symbol(";")?;
        let cond = self.parse_expression_list(";")?;
        self.expect_symbol(";")?;
        let step = self.parse_expression_list(")")?;
        self.expect_symbol(")")?;
        let body = self.parse_statement()?;
        Ok(Stmt::For {
            init,
            cond,
            step,
            body: block_of(body),
        })
    }

    fn parse_while(&mut self) -> Result<Stmt, ParseError> {
        self.expect_symbol("(")?;
        let cond = self.parse_expression()?;
        self.expect_symbol(")")?;
        let body = self.parse_statement()?;
        Ok(Stmt::While {
            cond,
            body: block_of(body),
        })
    }

    fn parse_switch(&mut self) -> Result<Stmt, ParseError> {
        self.expect_symbol("(")?;
        let subject = self.parse_expression()?;
        self.expect_symbol(")")?;
        self.expect_symbol("{")?;
        let mut cases = Vec::new();
        while !self.check_symbol("}") {
            let case = if self.eat_keyword("case") {
                let value = self.parse_expression()?;
                self.expect_symbol(":")?;
                Some(value)
            } else if self.eat_keyword("default") {
                self.expect_symbol(":")?;
                None
            } else {
                return Err(self.error_here("expected case or default"));
            };
            let mut body = Vec::new();
            while !self.check_keyword("case")
                && !self.check_keyword("default")
                && !self.check_symbol("}")
            {
                if let Some(text) = self.take_text() {
                    body.push(Stmt::Text(text));
                } else {
                    body.push(self.parse_statement()?);
                }
            }
            cases.push((case, body));
        }
        self.expect_symbol("}")?;
        Ok(Stmt::Switch { subject, cases })
    }

    fn parse_function(&mut self) -> Result<Stmt, ParseError> {
        let name = self.expect_ident()?;
        self.expect_symbol("(")?;
        let mut params = Vec::new();
        while !self.check_symbol(")") {
            let by_ref = self.eat_symbol("&");
            let name = self.expect_variable()?;
            let default = if self.eat_symbol("=") {
                Some(self.parse_expression()?)
            } else {
                None
            };
            params.push(Param {
                name,
                by_ref,
                default,
            });
            if !self.eat_symbol(",") {
                break;
            }
        }
        self.expect_symbol(")")?;
        self.expect_symbol("{")?;
        let body = self.parse_statements_until("}")?;
        Ok(Stmt::Function { name, params, body })
    }

    fn parse_global(&mut self) -> Result<Stmt, ParseError> {
        let mut names = Vec::new();
        while !self.at_statement_end() {
            names.push(self.expect_variable()?);
            if !self.eat_symbol(",") {
                break;
            }
        }
        self.consume_statement_end();
        Ok(Stmt::Global(names))
    }

    fn parse_expression_list_until_statement_end(&mut self) -> Result<Vec<Expr>, ParseError> {
        let mut values = Vec::new();
        while !self.at_statement_end() {
            values.push(self.parse_expression()?);
            if !self.eat_symbol(",") {
                break;
            }
        }
        Ok(values)
    }

    fn parse_expression_list(&mut self, end: &str) -> Result<Vec<Expr>, ParseError> {
        let mut values = Vec::new();
        while !self.check_symbol(end) {
            values.push(self.parse_expression()?);
            if !self.eat_symbol(",") {
                break;
            }
        }
        Ok(values)
    }

    fn parse_expression(&mut self) -> Result<Expr, ParseError> {
        self.parse_binary(0)
    }

    fn parse_binary(&mut self, min_precedence: u8) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            if self.check_symbol("?") {
                if 5 < min_precedence {
                    break;
                }
                self.pos += 1;
                let then = if self.check_symbol(":") {
                    None
                } else {
                    Some(Box::new(self.parse_expression()?))
                };
                self.expect_symbol(":")?;
                let otherwise = Box::new(self.parse_expression()?);
                left = Expr::Ternary {
                    cond: Box::new(left),
                    then,
                    otherwise,
                };
                continue;
            }
            let Some((op, precedence, right_assoc, assign)) = self.peek_binary() else {
                break;
            };
            if precedence < min_precedence {
                break;
            }
            self.pos += 1;
            let right = if right_assoc {
                self.parse_binary(precedence)?
            } else {
                self.parse_binary(precedence + 1)?
            };
            if let Some(assign_op) = assign {
                if !is_assignable(&left) {
                    return Err(self.error_here("invalid assignment target"));
                }
                left = Expr::Assign {
                    target: Box::new(left),
                    op: assign_op,
                    value: Box::new(right),
                };
            } else {
                left = Expr::Binary(op, Box::new(left), Box::new(right));
            }
        }
        Ok(left)
    }

    fn peek_binary(&self) -> Option<(BinOp, u8, bool, Option<AssignOp>)> {
        let symbol = self.peek_symbol()?;
        let result = match symbol {
            "or" => (BinOp::Or, 1, false, None),
            "xor" => (BinOp::Xor, 2, false, None),
            "and" => (BinOp::And, 3, false, None),
            "=" => (BinOp::Equal, 4, true, Some(AssignOp::Assign)),
            "+=" => (BinOp::Add, 4, true, Some(AssignOp::Add)),
            "-=" => (BinOp::Sub, 4, true, Some(AssignOp::Sub)),
            "*=" => (BinOp::Mul, 4, true, Some(AssignOp::Mul)),
            "/=" => (BinOp::Div, 4, true, Some(AssignOp::Div)),
            "%=" => (BinOp::Mod, 4, true, Some(AssignOp::Mod)),
            ".=" => (BinOp::Concat, 4, true, Some(AssignOp::Concat)),
            "&=" => (BinOp::BitAnd, 4, true, Some(AssignOp::BitAnd)),
            "|=" => (BinOp::BitOr, 4, true, Some(AssignOp::BitOr)),
            "^=" => (BinOp::BitXor, 4, true, Some(AssignOp::BitXor)),
            "<<=" => (BinOp::ShiftLeft, 4, true, Some(AssignOp::ShiftLeft)),
            ">>=" => (BinOp::ShiftRight, 4, true, Some(AssignOp::ShiftRight)),
            "??=" => (BinOp::Coalesce, 4, true, Some(AssignOp::Coalesce)),
            "??" => (BinOp::Coalesce, 6, true, None),
            "||" => (BinOp::Or, 7, false, None),
            "&&" => (BinOp::And, 8, false, None),
            "|" => (BinOp::BitOr, 9, false, None),
            "^" => (BinOp::BitXor, 10, false, None),
            "&" => (BinOp::BitAnd, 11, false, None),
            "==" => (BinOp::Equal, 12, false, None),
            "!=" | "<>" => (BinOp::NotEqual, 12, false, None),
            "===" => (BinOp::Identical, 12, false, None),
            "!==" => (BinOp::NotIdentical, 12, false, None),
            "<" => (BinOp::Less, 13, false, None),
            "<=" => (BinOp::LessEqual, 13, false, None),
            ">" => (BinOp::Greater, 13, false, None),
            ">=" => (BinOp::GreaterEqual, 13, false, None),
            "<=>" => (BinOp::Spaceship, 13, false, None),
            "<<" => (BinOp::ShiftLeft, 14, false, None),
            ">>" => (BinOp::ShiftRight, 14, false, None),
            "+" => (BinOp::Add, 15, false, None),
            "-" => (BinOp::Sub, 15, false, None),
            "." => (BinOp::Concat, 15, false, None),
            "*" => (BinOp::Mul, 16, false, None),
            "/" => (BinOp::Div, 16, false, None),
            "%" => (BinOp::Mod, 16, false, None),
            _ => return None,
        };
        Some(result)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        self.enter_depth()?;
        let res = self.parse_unary_inner();
        self.leave_depth();
        res
    }

    fn parse_unary_inner(&mut self) -> Result<Expr, ParseError> {
        if self.eat_symbol("!") {
            return Ok(Expr::Unary(UnOp::Not, Box::new(self.parse_unary()?)));
        }
        if self.eat_symbol("-") {
            return Ok(Expr::Unary(UnOp::Neg, Box::new(self.parse_unary()?)));
        }
        if self.eat_symbol("+") {
            return Ok(Expr::Unary(UnOp::Pos, Box::new(self.parse_unary()?)));
        }
        if self.eat_symbol("~") {
            return Ok(Expr::Unary(UnOp::BitNot, Box::new(self.parse_unary()?)));
        }
        if self.eat_symbol("@") {
            return Ok(Expr::Suppressed(Box::new(self.parse_unary()?)));
        }
        if self.eat_symbol("&") {
            return Ok(Expr::Reference(Box::new(self.parse_unary()?)));
        }
        if self.eat_symbol("++") {
            return Ok(Expr::PreInc(Box::new(self.parse_unary()?)));
        }
        if self.eat_symbol("--") {
            return Ok(Expr::PreDec(Box::new(self.parse_unary()?)));
        }
        if let Some(cast) = self.peek_cast() {
            self.pos += 3;
            return Ok(Expr::Cast(cast, Box::new(self.parse_unary()?)));
        }
        let mut expr = self.parse_primary()?;
        loop {
            if self.eat_symbol("[") {
                if self.eat_symbol("]") {
                    expr = Expr::Append(Box::new(expr));
                } else {
                    let index = self.parse_expression()?;
                    self.expect_symbol("]")?;
                    expr = Expr::Index(Box::new(expr), Box::new(index));
                }
            } else if self.eat_symbol("++") {
                expr = Expr::PostInc(Box::new(expr));
            } else if self.eat_symbol("--") {
                expr = Expr::PostDec(Box::new(expr));
            } else if self.eat_symbol("(") {
                let args = self.parse_expression_list(")")?;
                self.expect_symbol(")")?;
                expr = Expr::DynamicCall(Box::new(expr), args);
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let token = self
            .tokens
            .get(self.pos)
            .cloned()
            .ok_or_else(|| self.error_here("unexpected end of expression"))?;
        self.pos += 1;
        match token.kind {
            TokenKind::Variable(name) => Ok(Expr::Variable(name)),
            TokenKind::Int(value) => Ok(Expr::Int(value)),
            TokenKind::Float(value) => Ok(Expr::Float(value)),
            TokenKind::Str { raw, single } => Ok(Expr::Str { raw, single }),
            TokenKind::InlineHtml(_) => Err(ParseError {
                message: "unexpected inline HTML in expression".into(),
                line: token.line,
                column: token.column,
            }),
            TokenKind::Symbol(symbol) if symbol == "(" => {
                let expr = self.parse_expression()?;
                self.expect_symbol(")")?;
                Ok(expr)
            }
            TokenKind::Symbol(symbol) if symbol == "[" => {
                let items = self.parse_array_items("]")?;
                Ok(Expr::Array(items))
            }
            TokenKind::Ident(name) => self.parse_ident_expression(name, token.line, token.column),
            TokenKind::Symbol(symbol) => Err(ParseError {
                message: format!("unexpected symbol {symbol:?}"),
                line: token.line,
                column: token.column,
            }),
        }
    }

    fn parse_ident_expression(
        &mut self,
        name: String,
        _line: usize,
        _column: usize,
    ) -> Result<Expr, ParseError> {
        match name.to_ascii_lowercase().as_str() {
            "true" => return Ok(Expr::Bool(true)),
            "false" => return Ok(Expr::Bool(false)),
            "null" => return Ok(Expr::Null),
            "array" => {
                self.expect_symbol("(")?;
                let items = self.parse_array_items(")")?;
                return Ok(Expr::Array(items));
            }
            "isset" => {
                self.expect_symbol("(")?;
                let values = self.parse_expression_list(")")?;
                self.expect_symbol(")")?;
                return Ok(Expr::Isset(values));
            }
            "empty" => {
                self.expect_symbol("(")?;
                let value = self.parse_expression()?;
                self.expect_symbol(")")?;
                return Ok(Expr::Empty(Box::new(value)));
            }
            _ => {}
        }
        if self.eat_symbol("(") {
            let args = self.parse_expression_list(")")?;
            self.expect_symbol(")")?;
            return Ok(Expr::Call(name, args));
        }
        Ok(Expr::Constant(name))
    }

    fn parse_array_items(&mut self, end: &str) -> Result<Vec<(Option<Expr>, Expr)>, ParseError> {
        let mut items = Vec::new();
        while !self.check_symbol(end) {
            let first = self.parse_expression()?;
            let item = if self.eat_symbol("=>") {
                let value = self.parse_expression()?;
                (Some(first), value)
            } else {
                (None, first)
            };
            items.push(item);
            if !self.eat_symbol(",") {
                break;
            }
        }
        self.expect_symbol(end)?;
        Ok(items)
    }

    fn peek_cast(&self) -> Option<CastType> {
        if !self.check_symbol("(") {
            return None;
        }
        let name = match self.tokens.get(self.pos + 1)?.kind.clone() {
            TokenKind::Ident(name) => name.to_ascii_lowercase(),
            _ => return None,
        };
        if !self.check_symbol_at(self.pos + 2, ")") {
            return None;
        }
        Some(match name.as_str() {
            "int" | "integer" => CastType::Int,
            "float" | "double" => CastType::Float,
            "string" => CastType::String,
            "bool" | "boolean" => CastType::Bool,
            "array" => CastType::Array,
            _ => return None,
        })
    }

    fn at_statement_end(&self) -> bool {
        self.check_symbol(";") || self.pos >= self.tokens.len()
    }

    fn consume_statement_end(&mut self) {
        self.eat_symbol(";");
    }

    fn at_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn expect_variable(&mut self) -> Result<String, ParseError> {
        match self.tokens.get(self.pos).map(|token| token.kind.clone()) {
            Some(TokenKind::Variable(name)) => {
                self.pos += 1;
                Ok(name)
            }
            _ => Err(self.error_here("expected variable")),
        }
    }

    fn expect_ident(&mut self) -> Result<String, ParseError> {
        match self.tokens.get(self.pos).map(|token| token.kind.clone()) {
            Some(TokenKind::Ident(name)) => {
                self.pos += 1;
                Ok(name)
            }
            _ => Err(self.error_here("expected identifier")),
        }
    }

    fn expect_symbol(&mut self, symbol: &str) -> Result<(), ParseError> {
        if self.eat_symbol(symbol) {
            Ok(())
        } else {
            Err(self.error_here(&format!("expected {symbol:?}")))
        }
    }

    fn expect_keyword(&mut self, keyword: &str) -> Result<(), ParseError> {
        if self.eat_keyword(keyword) {
            Ok(())
        } else {
            Err(self.error_here(&format!("expected keyword {keyword:?}")))
        }
    }

    fn eat_symbol(&mut self, symbol: &str) -> bool {
        if self.check_symbol(symbol) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_keyword(&mut self, keyword: &str) -> bool {
        if self.check_keyword(keyword) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn check_symbol(&self, symbol: &str) -> bool {
        self.check_symbol_at(self.pos, symbol)
    }

    fn check_symbol_at(&self, index: usize, symbol: &str) -> bool {
        matches!(
            self.tokens.get(index).map(|token| &token.kind),
            Some(TokenKind::Symbol(value)) if value == symbol
        )
    }

    fn check_keyword(&self, keyword: &str) -> bool {
        matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(TokenKind::Ident(value)) if value.eq_ignore_ascii_case(keyword)
        )
    }

    fn peek_symbol(&self) -> Option<&str> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(TokenKind::Symbol(value)) => Some(value.as_str()),
            Some(TokenKind::Ident(value))
                if matches!(value.to_ascii_lowercase().as_str(), "or" | "xor" | "and") =>
            {
                Some(value.as_str())
            }
            _ => None,
        }
    }

    fn error_here(&self, message: &str) -> ParseError {
        let (line, column) = self
            .tokens
            .get(self.pos)
            .map(|token| (token.line, token.column))
            .unwrap_or((0, 0));
        ParseError {
            message: message.to_string(),
            line,
            column,
        }
    }
}

fn block_of(statement: Stmt) -> Vec<Stmt> {
    match statement {
        Stmt::Block(body) => body,
        other => vec![other],
    }
}

fn is_assignable(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Variable(_) | Expr::Index(_, _) | Expr::Append(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fador_testutil::{iterations, Rng};

    #[test]
    fn parses_core_constructs() {
        let code = r#"<?php
function f(&$x, $y = 2) {
    global $context;
    if ($y > 1) { echo 'yes'; } elseif ($y == 1) { echo 'one'; } else { echo 'no'; }
    foreach ($context['items'] as $key => $item) { $x .= $item; }
    for ($i = 0; $i < 3; $i++) { if ($i == 1) continue; }
    while (false) { break; }
    switch ($y) { case 1: echo 'a'; break; default: echo 'b'; }
    return $x;
}
?>"#;
        let statements = parse(code).unwrap();
        assert!(!statements.is_empty());
        assert!(matches!(statements[0], Stmt::Function { .. }));
        let Stmt::Function { params, .. } = &statements[0] else {
            unreachable!()
        };
        assert!(params[0].by_ref);
        assert!(params[1].default.is_some());
    }

    #[test]
    fn parses_inline_html_between_php_blocks() {
        let statements = parse("a<?php echo $x; ?>b<?= $y ?>c").unwrap();
        assert!(matches!(&statements[0], Stmt::Text(text) if text == "a"));
        assert!(matches!(&statements[1], Stmt::Echo(_)));
        assert!(matches!(&statements[2], Stmt::Text(text) if text == "b"));
        assert!(matches!(&statements[3], Stmt::Echo(_)));
        assert!(matches!(&statements[4], Stmt::Text(text) if text == "c"));
    }

    #[test]
    fn operator_precedence_follows_php() {
        // `.` binds tighter than `+`? No: PHP 8 gives `.` and `+` the same
        // precedence, and both bind tighter than comparison.
        let statements = parse("<?php $x = 1 + 2 * 3; ?>").unwrap();
        let Stmt::Expr(Expr::Assign { value, .. }) = &statements[0] else {
            panic!("unexpected statement {:?}", statements[0]);
        };
        assert_eq!(
            **value,
            Expr::Binary(
                BinOp::Add,
                Box::new(Expr::Int(1)),
                Box::new(Expr::Binary(
                    BinOp::Mul,
                    Box::new(Expr::Int(2)),
                    Box::new(Expr::Int(3))
                ))
            )
        );
        let statements = parse("<?php $x = 1 == 2 && 3; ?>").unwrap();
        let Stmt::Expr(Expr::Assign { value, .. }) = &statements[0] else {
            panic!("unexpected statement");
        };
        assert!(matches!(**value, Expr::Binary(BinOp::And, _, _)));
    }

    #[test]
    fn assignment_targets_are_validated() {
        assert!(parse("<?php 1 = 2; ?>").is_err());
        assert!(parse("<?php $a = $b = 1; ?>").is_ok());
        assert!(parse("<?php $a[] = 1; ?>").is_ok());
        assert!(parse("<?php f() = 1; ?>").is_err());
    }

    #[test]
    fn rejects_broken_syntax() {
        for source in [
            "<?php if (1) {",
            "<?php function () {} ?>",
            "<?php echo ; ?>",
            "<?php echo , $x; ?>",
            "<?php switch ($x) { foo: } ?>",
            "<?php $a[1 = 2; ?>",
            "<?php foreach ($a as 1) {} ?>",
        ] {
            assert!(parse(source).is_err(), "accepted {source:?}");
        }
    }

    #[test]
    fn array_literals_keep_explicit_keys() {
        let statements = parse("<?php $a = array(1 => 'a', 'b' => 'c', 'd'); ?>").unwrap();
        let Stmt::Expr(Expr::Assign { value, .. }) = &statements[0] else {
            panic!("unexpected statement");
        };
        let Expr::Array(items) = value.as_ref() else {
            panic!("unexpected value {value:?}");
        };
        assert_eq!(items.len(), 3);
        assert!(items[0].0.is_some());
        assert!(items[1].0.is_some());
        assert!(items[2].0.is_none());
    }

    /// Mutated template snippets and random token soup must parse or fail,
    /// never panic or hang.
    #[test]
    fn fuzz_lexer_and_parser() {
        const SNIPPETS: &[&str] = &[
            "<?php echo 'x', $y; ?><b><?= $z ?></b>",
            "<?php function template_main() { global $context, $txt; echo $txt['title']; } ?>",
            "<?php foreach ($context['items'] as $key => $value) { if ($value) { echo $key; } } ?>",
            "<?php switch ($x) { case 1: echo 'a'; break; default: echo 'b'; } ?>",
            "<?php $a = array('b' => 1, 2, 3); $a[] = &$b; unset($a[0]); ?>",
            "<?php echo sprintf('%1$s %02d', $a, $b), htmlspecialchars($c); ?>",
            "<?php while ($row = next($x)) { $i += 1; } for (;;) { break 2; } ?>",
            "<?php echo $a ? 'yes' : 'no', $b ?: 'default', $c ?? 'fallback'; ?>",
        ];
        let mut rng = Rng::new(0x7068_0001);
        for _ in 0..iterations(600) {
            let snippet = SNIPPETS[rng.below(SNIPPETS.len())];
            let mut raw = snippet.as_bytes().to_vec();
            for _ in 0..1 + rng.below(8) {
                if raw.is_empty() {
                    break;
                }
                let position = rng.below(raw.len());
                raw[position] = rng.byte();
            }
            let text = String::from_utf8_lossy(&raw);
            let _ = tokenize(&text);
            let _ = parse(&text);
        }

        const TOKENS: &[&str] = &[
            "<?php",
            "?>",
            "<?=",
            "function",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            ";",
            ",",
            "$x",
            "$",
            "=",
            "==",
            "===",
            "!=",
            "<",
            ">",
            "+",
            "-",
            "*",
            "/",
            "%",
            ".",
            "=>",
            "if",
            "else",
            "elseif",
            "while",
            "for",
            "foreach",
            "as",
            "global",
            "return",
            "echo",
            "break",
            "continue",
            "switch",
            "case",
            "default",
            "isset",
            "empty",
            "unset",
            "array",
            "\"",
            "'",
            "\\",
            "0",
            "1",
            "999999999999999999999",
            "1.5e400",
            "#",
            "/*",
            "*/",
            "//",
            "\n",
            "\r\n",
            "\t",
            " ",
            "😀",
            "\u{0}",
            "\u{7f}",
            "&",
            "|",
            "&&",
            "||",
            "!",
            "++",
            "--",
            "?:",
            "??",
            "&$x",
            "->",
        ];
        for _ in 0..iterations(1_500) {
            let mut text = String::new();
            for _ in 0..rng.below(60) {
                text.push_str(TOKENS[rng.below(TOKENS.len())]);
            }
            let _ = tokenize(&text);
            let _ = parse(&text);
        }
    }

    /// Parse a real SMF theme tree when the caller points at one. The
    /// templates themselves are not vendored: they are content, not code.
    ///
    /// ```text
    /// FADOR_SMF_THEME_CORPUS=/path/to/original/Themes/default cargo test
    /// ```
    #[test]
    fn parses_an_optional_external_template_corpus() {
        let Ok(directory) = std::env::var("FADOR_SMF_THEME_CORPUS") else {
            return;
        };
        let directory = std::path::PathBuf::from(directory);
        if !directory.is_dir() {
            return;
        }
        let mut templates = Vec::new();
        collect_templates(&directory, &mut templates);
        templates.sort();
        for path in &templates {
            let bytes = std::fs::read(path).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            parse(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        }
        assert!(!templates.is_empty(), "corpus directory held no templates");
    }

    fn collect_templates(directory: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_templates(&path, out);
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".template.php"))
            {
                out.push(path);
            }
        }
    }
}
