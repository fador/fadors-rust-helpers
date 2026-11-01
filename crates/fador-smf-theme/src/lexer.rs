//! Lexer for the PHP subset the SMF theme templates are written in.
//!
//! The lexer switches between inline HTML and PHP at `<?php`, `<?=` and `?>`,
//! and emits the tokens the parser consumes. It never interprets anything: a
//! template is data, and the only outputs are tokens or a [`ParseError`].
//!
//! The work is linear in the input. Strings, comments and PHP blocks must be
//! terminated, and an unterminated construct is a parse error rather than a
//! scan to the end of a much larger buffer.

use crate::parser::ParseError;

/// One lexical token.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    /// Literal HTML between two PHP blocks.
    InlineHtml(String),
    /// A `$name` variable reference, without the leading `$`.
    Variable(String),
    /// A bare identifier: keyword, constant or function name.
    Ident(String),
    /// An integer literal.
    Int(i64),
    /// A floating-point literal.
    Float(f64),
    /// A quoted string. `raw` still holds the escapes; `single` records whether
    /// the source used single quotes, because only double-quoted strings
    /// interpolate variables.
    Str {
        /// The string body exactly as written, escapes included.
        raw: String,
        /// Whether the literal was written with single quotes.
        single: bool,
    },
    /// An operator or punctuation character.
    Symbol(String),
}

/// A token plus its position in the source.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    /// What the token is.
    pub kind: TokenKind,
    /// One-based line of the token's first character.
    pub line: usize,
    /// One-based column of the token's first character.
    pub column: usize,
}

/// Split a template into tokens.
///
/// # Errors
///
/// Returns a [`ParseError`] for an unterminated PHP block, string or block
/// comment, an invalid number, or a character that cannot start a token.
pub fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    Lexer::new(input).run()
}

struct Lexer {
    chars: Vec<char>,
    index: usize,
    line: usize,
    column: usize,
    out: Vec<Token>,
    in_php: bool,
    in_echo_tag: bool,
}

impl Lexer {
    fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            index: 0,
            line: 1,
            column: 1,
            out: Vec::new(),
            in_php: false,
            in_echo_tag: false,
        }
    }

    fn run(mut self) -> Result<Vec<Token>, ParseError> {
        while self.index < self.chars.len() {
            if self.in_php {
                self.lex_php()?;
            } else {
                self.lex_html()?;
            }
        }
        if self.in_php {
            return Err(self.error("unterminated PHP block"));
        }
        Ok(self.out)
    }

    fn lex_html(&mut self) -> Result<(), ParseError> {
        let start = self.index;
        while self.index < self.chars.len() {
            if self.starts_with("<?php") && self.php_tag_boundary(self.index + 5) {
                let html: String = self.chars[start..self.index].iter().collect();
                if !html.is_empty() {
                    self.push(TokenKind::InlineHtml(html), start);
                }
                for _ in 0..5 {
                    self.bump();
                }
                self.in_php = true;
                self.in_echo_tag = false;
                return Ok(());
            }
            if self.starts_with("<?=") {
                let html: String = self.chars[start..self.index].iter().collect();
                if !html.is_empty() {
                    self.push(TokenKind::InlineHtml(html), start);
                }
                for _ in 0..3 {
                    self.bump();
                }
                self.in_php = true;
                self.in_echo_tag = true;
                self.out.push(Token {
                    kind: TokenKind::Ident("echo".into()),
                    line: self.line,
                    column: self.column,
                });
                return Ok(());
            }
            self.bump();
        }
        let html: String = self.chars[start..].iter().collect();
        if !html.is_empty() {
            self.push(TokenKind::InlineHtml(html), start);
        }
        Ok(())
    }

    fn php_tag_boundary(&self, index: usize) -> bool {
        match self.chars.get(index) {
            None => true,
            Some(c) => c.is_whitespace() || *c == '?' || *c == ';',
        }
    }

    fn lex_php(&mut self) -> Result<(), ParseError> {
        self.skip_whitespace_and_comments()?;
        if self.index >= self.chars.len() {
            return Ok(());
        }
        if self.starts_with("?>") {
            if self.in_echo_tag {
                self.out.push(Token {
                    kind: TokenKind::Symbol(";".into()),
                    line: self.line,
                    column: self.column,
                });
                self.in_echo_tag = false;
            }
            self.bump();
            self.bump();
            self.in_php = false;
            return Ok(());
        }
        let start = self.index;
        let line = self.line;
        let column = self.column;
        if self.peek() == Some('$') {
            self.bump();
            let name = self.take_while(|c| c.is_alphanumeric() || c == '_');
            if name.is_empty() {
                return Err(self.error("expected variable name"));
            }
            self.out.push(Token {
                kind: TokenKind::Variable(name),
                line,
                column,
            });
            return Ok(());
        }
        if let Some(c) = self.peek() {
            if c.is_ascii_digit()
                || (c == '.'
                    && self
                        .chars
                        .get(self.index + 1)
                        .is_some_and(|next| next.is_ascii_digit()))
            {
                return self.lex_number(line, column);
            }
            if c == '\'' || c == '"' {
                return self.lex_string(c, line, column);
            }
            if c.is_alphabetic() || c == '_' {
                let ident = self.take_while(|c| c.is_alphanumeric() || c == '_');
                self.out.push(Token {
                    kind: TokenKind::Ident(ident),
                    line,
                    column,
                });
                return Ok(());
            }
        }
        self.lex_operator(line, column, start)
    }

    fn lex_number(&mut self, line: usize, column: usize) -> Result<(), ParseError> {
        let start = self.index;
        if self.starts_with("0x") || self.starts_with("0X") {
            self.bump();
            self.bump();
            let digits = self.take_while(|c| c.is_ascii_hexdigit());
            if digits.is_empty() {
                return Err(self.error("invalid hexadecimal number"));
            }
            let value = i64::from_str_radix(&digits, 16)
                .map_err(|_| self.error("hexadecimal number out of range"))?;
            self.out.push(Token {
                kind: TokenKind::Int(value),
                line,
                column,
            });
            return Ok(());
        }
        while self.peek().is_some_and(|c| c.is_ascii_digit() || c == '_') {
            self.bump();
        }
        let mut float = false;
        if self.peek() == Some('.') {
            float = true;
            self.bump();
            while self.peek().is_some_and(|c| c.is_ascii_digit() || c == '_') {
                self.bump();
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            float = true;
            self.bump();
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.bump();
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
            }
        }
        let raw: String = self.chars[start..self.index]
            .iter()
            .filter(|c| **c != '_')
            .collect();
        let kind = if float {
            TokenKind::Float(
                raw.parse()
                    .map_err(|_| self.error("invalid floating point number"))?,
            )
        } else {
            TokenKind::Int(
                raw.parse()
                    .map_err(|_| self.error("integer out of range"))?,
            )
        };
        self.out.push(Token { kind, line, column });
        Ok(())
    }

    fn lex_string(&mut self, quote: char, line: usize, column: usize) -> Result<(), ParseError> {
        self.bump();
        let mut raw = String::new();
        while let Some(c) = self.peek() {
            if c == quote {
                self.bump();
                self.out.push(Token {
                    kind: TokenKind::Str {
                        raw,
                        single: quote == '\'',
                    },
                    line,
                    column,
                });
                return Ok(());
            }
            if c == '\\' {
                raw.push(c);
                self.bump();
                if let Some(next) = self.peek() {
                    raw.push(next);
                    self.bump();
                }
                continue;
            }
            raw.push(c);
            self.bump();
        }
        Err(ParseError {
            message: "unterminated string".into(),
            line,
            column,
        })
    }

    fn lex_operator(&mut self, line: usize, column: usize, start: usize) -> Result<(), ParseError> {
        const OPERATORS: &[&str] = &[
            "<=>", "===", "!==", "**=", "??=", "<<=", ">>=", "...", "->", "::", "++", "--", "+=",
            "-=", "*=", "/=", "%=", ".=", "&=", "|=", "^=", "<<", ">>", "==", "!=", "<>", "<=",
            ">=", "&&", "||", "??", "=>", "**",
        ];
        for operator in OPERATORS {
            if self.starts_with(operator) {
                for _ in 0..operator.chars().count() {
                    self.bump();
                }
                self.out.push(Token {
                    kind: TokenKind::Symbol((*operator).into()),
                    line,
                    column,
                });
                return Ok(());
            }
        }
        let c = self
            .peek()
            .ok_or_else(|| self.error("unexpected end of input"))?;
        if "+-*/%=<>&|^~!?:;,.()[]{}@".contains(c) {
            self.bump();
            self.out.push(Token {
                kind: TokenKind::Symbol(c.to_string()),
                line,
                column,
            });
            return Ok(());
        }
        let _ = start;
        Err(self.error(&format!("unexpected character {c:?}")))
    }

    fn skip_whitespace_and_comments(&mut self) -> Result<(), ParseError> {
        loop {
            while self.peek().is_some_and(|c| c.is_whitespace()) {
                self.bump();
            }
            if self.starts_with("//") || self.peek() == Some('#') {
                while let Some(c) = self.peek() {
                    if c == '\n' || self.starts_with("?>") {
                        break;
                    }
                    self.bump();
                }
                continue;
            }
            if self.starts_with("/*") {
                self.bump();
                self.bump();
                while self.index < self.chars.len() && !self.starts_with("*/") {
                    self.bump();
                }
                if !self.starts_with("*/") {
                    return Err(self.error("unterminated block comment"));
                }
                self.bump();
                self.bump();
                continue;
            }
            break;
        }
        Ok(())
    }

    fn push(&mut self, kind: TokenKind, start: usize) {
        let _ = start;
        self.out.push(Token {
            kind,
            line: self.line,
            column: self.column,
        });
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    fn starts_with(&self, text: &str) -> bool {
        let expected: Vec<char> = text.chars().collect();
        let end = self.index + expected.len();
        self.chars.get(self.index..end) == Some(expected.as_slice())
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.index).copied()?;
        self.index += 1;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(c)
    }

    fn take_while(&mut self, predicate: impl Fn(char) -> bool) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if !predicate(c) {
                break;
            }
            out.push(c);
            self.bump();
        }
        out
    }

    fn error(&self, message: &str) -> ParseError {
        ParseError {
            message: message.to_string(),
            line: self.line,
            column: self.column,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(input: &str) -> Vec<TokenKind> {
        tokenize(input)
            .unwrap()
            .into_iter()
            .map(|token| token.kind)
            .collect()
    }

    #[test]
    fn tokenizes_tags_strings_and_variables() {
        let tokens = kinds("<?php echo 'x', $y; ?><b><?= $z ?></b>");
        assert_eq!(tokens[0], TokenKind::Ident("echo".into()));
        assert!(tokens
            .iter()
            .any(|token| matches!(token, TokenKind::Variable(name) if name == "y")));
        assert!(tokens
            .iter()
            .any(|token| matches!(token, TokenKind::InlineHtml(_))));
        assert!(tokens
            .iter()
            .any(|token| matches!(token, TokenKind::Variable(name) if name == "z")));
    }

    #[test]
    fn records_lines_and_columns() {
        let tokens = tokenize("a<?php\n  $x; ?>").unwrap();
        let variable = tokens
            .iter()
            .find(|token| matches!(token.kind, TokenKind::Variable(_)))
            .unwrap();
        assert_eq!((variable.line, variable.column), (2, 3));
    }

    #[test]
    fn reads_numbers_in_every_supported_form() {
        let tokens = kinds("<?php 0x1f 1_000 1.5 1e3 2E-2 ?>");
        assert_eq!(tokens[0], TokenKind::Int(31));
        assert_eq!(tokens[1], TokenKind::Int(1000));
        assert_eq!(tokens[2], TokenKind::Float(1.5));
        assert_eq!(tokens[3], TokenKind::Float(1000.0));
        assert_eq!(tokens[4], TokenKind::Float(0.02));
    }

    #[test]
    fn strings_keep_escapes_and_quote_style() {
        let tokens = kinds(r#"<?php 'a\'b' "c\"d" ?>"#);
        assert_eq!(
            tokens[0],
            TokenKind::Str {
                raw: r"a\'b".into(),
                single: true
            }
        );
        assert_eq!(
            tokens[1],
            TokenKind::Str {
                raw: r#"c\"d"#.into(),
                single: false
            }
        );
    }

    #[test]
    fn skips_every_comment_form() {
        let tokens = kinds("<?php // line\n# hash\n/* block */ $x ?>");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], TokenKind::Variable(ref name) if name == "x"));
    }

    #[test]
    fn unterminated_constructs_are_errors() {
        for source in [
            "<?php echo 'x",
            "<?php /* open",
            "<?php echo $x;",
            "<?php 0x",
            "<?php `",
        ] {
            assert!(tokenize(source).is_err(), "accepted {source:?}");
        }
    }

    #[test]
    fn php_open_tag_requires_a_boundary() {
        // `<?phpx` is text, not an opening tag.
        assert_eq!(
            kinds("<?phpx"),
            vec![TokenKind::InlineHtml("<?phpx".into())]
        );
        // `<?=` closes with a synthetic statement end so `<?= $x ?>` parses
        // like `echo $x;`.
        assert_eq!(
            kinds("<?= $x ?>"),
            vec![
                TokenKind::Ident("echo".into()),
                TokenKind::Variable("x".into()),
                TokenKind::Symbol(";".into()),
            ]
        );
        assert!(kinds("<?php ?>").is_empty());
    }
}
