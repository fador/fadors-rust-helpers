use crate::expr::{parse_expression, BinaryOp, Expr};
use crate::value::Value;
use std::fmt;

/// One node of a compiled template.
///
/// A template is a flat list of nodes; block nodes own their bodies. The
/// renderer walks the list once per page and never re-parses source.
#[derive(Debug, Clone)]
pub enum Node {
    /// Literal text copied to the output unchanged.
    Text(String),
    /// A `{NAME}`, `{{ expression }}` or `{L_KEY}` output expression.
    Output(Expr),
    /// An `<!-- IF -->` / `{% if %}` chain. Each entry is a condition and its
    /// body; the final entry has no condition and is the `else` branch.
    If(Vec<(Option<Expr>, Vec<Node>)>),
    /// A legacy `<!-- BEGIN name -->` loop over the block array `name`.
    BlockLoop {
        /// Block array name, as written after `BEGIN`.
        name: String,
        /// Body rendered once per row.
        body: Vec<Node>,
        /// `<!-- BEGINELSE -->` body rendered when the array is empty.
        else_body: Vec<Node>,
    },
    /// A Twig `{% for name in expression %}` loop.
    For {
        /// Loop variable name.
        name: String,
        /// Expression producing the array to iterate.
        expr: Expr,
        /// Body rendered once per row.
        body: Vec<Node>,
        /// `{% else %}` body rendered when the array is empty.
        else_body: Vec<Node>,
    },
    /// A `{% set name = expression %}` assignment into the local scope.
    Set {
        /// Local variable name.
        name: String,
        /// Value expression.
        expr: Expr,
    },
    /// A `{% DEFINE name = expression %}` definition, readable as
    /// `definition.name` (and, for an upper-case name, as `{NAME}`).
    Define {
        /// Definition name.
        name: String,
        /// Value expression.
        expr: Expr,
    },
    /// A `{% UNDEFINE name %}` that removes a definition.
    Undefine(String),
    /// An `<!-- INCLUDE name -->` or `{% include name %}` include.
    Include(Expr),
    /// A `{% apply spaceless %}` block: whitespace between tags is removed.
    Spaceless(Vec<Node>),
    /// An `<!-- INCLUDEJS -->` or `<!-- INCLUDECSS -->` asset request.
    Asset {
        /// JavaScript or stylesheet.
        kind: AssetKind,
        /// Path expression, usually a literal.
        value: Expr,
    },
    /// An `<!-- EVENT name -->` extension event.
    Event(String),
}

/// The two kinds of asset a template can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    /// A JavaScript file, from `INCLUDEJS`.
    JavaScript,
    /// A stylesheet, from `INCLUDECSS`.
    Stylesheet,
}

#[derive(Debug, Clone)]
enum Tag {
    If(Expr),
    ElseIf(Expr),
    Else,
    EndIf,
    Begin(String),
    EndBlock(String),
    BeginElse,
    For(String, Expr),
    EndFor,
    Set(String, Expr),
    Define(String, Expr),
    Undefine(String),
    Include(Expr),
    Asset(AssetKind, Expr),
    Event(String),
    ApplySpaceless,
    EndApply,
}

#[derive(Debug, Clone)]
enum Token {
    Text(String),
    Output(Expr),
    Tag(Tag),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TagKind {
    If,
    ElseIf,
    Else,
    EndIf,
    Begin,
    EndBlock,
    BeginElse,
    For,
    EndFor,
    Set,
    Define,
    Undefine,
    Include,
    Asset,
    Event,
    ApplySpaceless,
    EndApply,
}

impl Tag {
    fn kind(&self) -> TagKind {
        match self {
            Tag::If(_) => TagKind::If,
            Tag::ElseIf(_) => TagKind::ElseIf,
            Tag::Else => TagKind::Else,
            Tag::EndIf => TagKind::EndIf,
            Tag::Begin(_) => TagKind::Begin,
            Tag::EndBlock(_) => TagKind::EndBlock,
            Tag::BeginElse => TagKind::BeginElse,
            Tag::For(_, _) => TagKind::For,
            Tag::EndFor => TagKind::EndFor,
            Tag::Set(_, _) => TagKind::Set,
            Tag::Define(_, _) => TagKind::Define,
            Tag::Undefine(_) => TagKind::Undefine,
            Tag::Include(_) => TagKind::Include,
            Tag::Asset(_, _) => TagKind::Asset,
            Tag::Event(_) => TagKind::Event,
            Tag::ApplySpaceless => TagKind::ApplySpaceless,
            Tag::EndApply => TagKind::EndApply,
        }
    }
}

/// A syntax error with a human-readable message.
///
/// The message names the offending construct, not the file; callers add the
/// template name when they know it.
#[derive(Debug)]
pub struct ParseError {
    /// Human-readable diagnostic.
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Compile a template source into nodes.
///
/// The source is untrusted: unbalanced blocks, unsupported tags, `INCLUDEPHP`,
/// excessive block nesting, excessive expression depth and oversized
/// expressions all return [`ParseError`] instead of panicking. Includes are not
/// resolved here; the engine does that at render time, which is why a template
/// with a missing include still compiles.
pub fn parse(source: &str) -> Result<Vec<Node>, ParseError> {
    let tokens = tokenize(source)?;
    let mut pos = 0usize;
    let (nodes, stop) = parse_sequence(&tokens, &mut pos, &[], 0)?;
    if stop.is_some() {
        return Err(ParseError::new("unexpected closing tag"));
    }
    if pos != tokens.len() {
        return Err(ParseError::new("unexpected trailing template tokens"));
    }
    Ok(nodes)
}

/// Deepest block nesting accepted.  Both the parser and the renderer recurse
/// per block, so a hostile template must be rejected before it exhausts the
/// stack.
const MAX_TEMPLATE_DEPTH: usize = 64;

fn parse_sequence(
    tokens: &[Token],
    pos: &mut usize,
    stop: &[TagKind],
    depth: usize,
) -> Result<(Vec<Node>, Option<Tag>), ParseError> {
    if depth > MAX_TEMPLATE_DEPTH {
        return Err(ParseError::new("template nesting is too deep"));
    }
    let mut nodes = Vec::new();
    while *pos < tokens.len() {
        match &tokens[*pos] {
            Token::Text(text) => {
                if !text.is_empty() {
                    nodes.push(Node::Text(text.clone()));
                }
                *pos += 1;
            }
            Token::Output(expr) => {
                nodes.push(Node::Output(expr.clone()));
                *pos += 1;
            }
            Token::Tag(tag) => {
                if stop.contains(&tag.kind()) {
                    let tag = tag.clone();
                    *pos += 1;
                    return Ok((nodes, Some(tag)));
                }
                let tag = tag.clone();
                *pos += 1;
                match tag {
                    Tag::If(condition) => nodes.push(parse_if(tokens, pos, condition, depth + 1)?),
                    Tag::Begin(name) => nodes.push(parse_begin(tokens, pos, name, depth + 1)?),
                    Tag::For(name, expr) => {
                        nodes.push(parse_for(tokens, pos, name, expr, depth + 1)?)
                    }
                    Tag::ApplySpaceless => nodes.push(parse_apply(tokens, pos, depth + 1)?),
                    Tag::Set(name, expr) => nodes.push(Node::Set { name, expr }),
                    Tag::Define(name, expr) => nodes.push(Node::Define { name, expr }),
                    Tag::Undefine(name) => nodes.push(Node::Undefine(name)),
                    Tag::Include(expr) => nodes.push(Node::Include(expr)),
                    Tag::Asset(kind, value) => nodes.push(Node::Asset { kind, value }),
                    Tag::Event(name) => nodes.push(Node::Event(name)),
                    Tag::Else
                    | Tag::ElseIf(_)
                    | Tag::EndIf
                    | Tag::EndBlock(_)
                    | Tag::BeginElse
                    | Tag::EndFor
                    | Tag::EndApply => {
                        return Err(ParseError::new("unexpected closing tag in template"));
                    }
                }
            }
        }
    }
    Ok((nodes, None))
}

fn parse_if(
    tokens: &[Token],
    pos: &mut usize,
    first_condition: Expr,
    depth: usize,
) -> Result<Node, ParseError> {
    let mut branches = Vec::new();
    let mut condition = Some(first_condition);
    loop {
        let (body, stop) = parse_sequence(
            tokens,
            pos,
            &[TagKind::ElseIf, TagKind::Else, TagKind::EndIf],
            depth,
        )?;
        branches.push((condition, body));
        match stop {
            Some(Tag::ElseIf(next)) => condition = Some(next),
            Some(Tag::Else) => {
                let (else_body, end) = parse_sequence(tokens, pos, &[TagKind::EndIf], depth)?;
                if !matches!(end, Some(Tag::EndIf)) {
                    return Err(ParseError::new("unterminated IF block"));
                }
                branches.push((None, else_body));
                break;
            }
            Some(Tag::EndIf) => break,
            _ => return Err(ParseError::new("unterminated IF block")),
        }
    }
    Ok(Node::If(branches))
}

fn parse_begin(
    tokens: &[Token],
    pos: &mut usize,
    name: String,
    depth: usize,
) -> Result<Node, ParseError> {
    let (body, stop) =
        parse_sequence(tokens, pos, &[TagKind::BeginElse, TagKind::EndBlock], depth)?;
    let else_body = match stop {
        Some(Tag::BeginElse) => {
            let (else_body, end) = parse_sequence(tokens, pos, &[TagKind::EndBlock], depth)?;
            match end {
                Some(Tag::EndBlock(end_name)) if end_name == name => else_body,
                Some(Tag::EndBlock(end_name)) => {
                    return Err(ParseError::new(format!(
                        "block {name} closed by {end_name}"
                    )))
                }
                _ => return Err(ParseError::new(format!("unterminated block {name}"))),
            }
        }
        Some(Tag::EndBlock(end_name)) if end_name == name => Vec::new(),
        Some(Tag::EndBlock(end_name)) => {
            return Err(ParseError::new(format!(
                "block {name} closed by {end_name}"
            )))
        }
        _ => return Err(ParseError::new(format!("unterminated block {name}"))),
    };
    Ok(Node::BlockLoop {
        name,
        body,
        else_body,
    })
}

fn parse_for(
    tokens: &[Token],
    pos: &mut usize,
    name: String,
    expr: Expr,
    depth: usize,
) -> Result<Node, ParseError> {
    let (body, stop) = parse_sequence(tokens, pos, &[TagKind::Else, TagKind::EndFor], depth)?;
    let else_body = match stop {
        Some(Tag::Else) => {
            let (else_body, end) = parse_sequence(tokens, pos, &[TagKind::EndFor], depth)?;
            if !matches!(end, Some(Tag::EndFor)) {
                return Err(ParseError::new("unterminated for block"));
            }
            else_body
        }
        Some(Tag::EndFor) => Vec::new(),
        _ => return Err(ParseError::new("unterminated for block")),
    };
    Ok(Node::For {
        name,
        expr,
        body,
        else_body,
    })
}

fn parse_apply(tokens: &[Token], pos: &mut usize, depth: usize) -> Result<Node, ParseError> {
    let (body, end) = parse_sequence(tokens, pos, &[TagKind::EndApply], depth)?;
    if !matches!(end, Some(Tag::EndApply)) {
        return Err(ParseError::new("unterminated apply block"));
    }
    Ok(Node::Spaceless(body))
}

fn tokenize(source: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let mut text = String::new();
    let mut i = 0usize;
    let mut trim_next = false;

    while i < source.len() {
        if trim_next {
            let ch = source[i..]
                .chars()
                .next()
                .ok_or_else(|| ParseError::new("invalid template encoding"))?;
            if ch.is_whitespace() {
                i += ch.len_utf8();
                continue;
            }
            trim_next = false;
        }
        let rest = &source[i..];
        if let Some(after) = rest.strip_prefix("<!--") {
            if let Some(end) = after.find("-->") {
                let content = &after[..end];
                if let Some(tag) = parse_legacy_tag(content)? {
                    flush_text(&mut text, &mut tokens);
                    tokens.push(Token::Tag(tag));
                    i += 4 + end + 3;
                    skip_block_newline(source, &mut i);
                } else {
                    // Ordinary HTML comments still take part in the legacy
                    // `{VAR}` substitution. Browsers never see the variables,
                    // but conditional comments such as `<!--[if lte IE 9]>`
                    // do.
                    flush_text(&mut text, &mut tokens);
                    tokens.push(Token::Text("<!--".into()));
                    push_legacy_fragment(content, &mut text, &mut tokens)?;
                    text.push_str("-->");
                    i += 4 + end + 3;
                }
                continue;
            }
        }
        if let Some(after) = rest.strip_prefix("{#") {
            if let Some(end) = after.find("#}") {
                i += 2 + end + 2;
                skip_block_newline(source, &mut i);
                continue;
            }
        }
        if let Some(after) = rest.strip_prefix("{{") {
            if let Some(end) = after.find("}}") {
                let trim_left = rest.starts_with("{{-");
                let raw = &after[..end];
                let trim_right = raw.trim_end().ends_with('-');
                let content = raw
                    .trim()
                    .trim_start_matches('-')
                    .trim_end_matches('-')
                    .trim();
                let expr = parse_expression(content).map_err(|error| {
                    ParseError::new(format!("invalid output expression: {error}"))
                })?;
                if trim_left {
                    trim_text_end(&mut text);
                }
                flush_text(&mut text, &mut tokens);
                tokens.push(Token::Output(expr));
                trim_next = trim_right;
                i += 2 + end + 2;
                continue;
            }
        }
        if let Some(after) = rest.strip_prefix("{%") {
            if let Some(end) = after.find("%}") {
                let trim_left = rest.starts_with("{%-");
                let raw = &after[..end];
                let trim_right = raw.trim_end().ends_with('-');
                let content = raw
                    .trim()
                    .trim_start_matches('-')
                    .trim_end_matches('-')
                    .trim();
                let tag = parse_twig_tag(content)?;
                if trim_left {
                    trim_text_end(&mut text);
                }
                flush_text(&mut text, &mut tokens);
                tokens.push(Token::Tag(tag));
                trim_next = trim_right;
                i += 2 + end + 2;
                if !trim_right {
                    skip_block_newline(source, &mut i);
                }
                continue;
            }
        }
        if let Some(after) = rest.strip_prefix('{') {
            if let Some(end) = after.find('}') {
                let content = after[..end].trim();
                let candidate = is_legacy_candidate(content);
                if candidate {
                    if let Some(expr) = legacy_expression(content) {
                        flush_text(&mut text, &mut tokens);
                        tokens.push(Token::Output(expr));
                        i += 1 + end + 1;
                        continue;
                    }
                }
            }
        }
        let ch = rest
            .chars()
            .next()
            .ok_or_else(|| ParseError::new("invalid template encoding"))?;
        text.push(ch);
        i += ch.len_utf8();
    }
    flush_text(&mut text, &mut tokens);
    Ok(tokens)
}

fn flush_text(text: &mut String, tokens: &mut Vec<Token>) {
    if !text.is_empty() {
        tokens.push(Token::Text(std::mem::take(text)));
    }
}

/// Twig removes one newline immediately after every block tag (`%}`). phpBB
/// turns legacy control comments into block tags, so the same rule applies
/// after `<!-- IF ... -->`, `<!-- BEGIN ... -->`, `<!-- EVENT ... -->` and the
/// rest.
fn skip_block_newline(source: &str, index: &mut usize) {
    if source[*index..].starts_with('\n') {
        *index += 1;
    }
}

fn push_legacy_fragment(
    fragment: &str,
    text: &mut String,
    tokens: &mut Vec<Token>,
) -> Result<(), ParseError> {
    let mut offset = 0usize;
    while offset < fragment.len() {
        let rest = &fragment[offset..];
        if let Some(after) = rest.strip_prefix('{') {
            if let Some(end) = after.find('}') {
                let content = after[..end].trim();
                if is_legacy_candidate(content) {
                    if let Some(expr) = legacy_expression(content) {
                        flush_text(text, tokens);
                        tokens.push(Token::Output(expr));
                        offset += 1 + end + 1;
                        continue;
                    }
                }
            }
        }
        let ch = rest
            .chars()
            .next()
            .ok_or_else(|| ParseError::new("invalid template encoding"))?;
        text.push(ch);
        offset += ch.len_utf8();
    }
    Ok(())
}

fn trim_text_end(text: &mut String) {
    let len = text.trim_end().len();
    text.truncate(len);
}

fn is_legacy_candidate(content: &str) -> bool {
    if content.is_empty()
        || content
            .chars()
            .any(|ch| ch.is_whitespace() || ch == ':' || ch == ';')
    {
        return false;
    }
    content.starts_with('$')
        || content.starts_with("L_")
        || content.starts_with("LA_")
        || content.chars().any(|ch| ch.is_ascii_uppercase())
        || content.contains('|')
        || content.contains('.')
}

fn legacy_expression(content: &str) -> Option<Expr> {
    let (head, filters) = match content.split_once('|') {
        Some((head, filters)) => (head, Some(filters)),
        None => (content, None),
    };
    if let Some(key) = head.strip_prefix("LA_") {
        if !valid_lang_key(key) {
            return None;
        }
        let mut source = format!("lang('{key}')|e('js')");
        if let Some(filters) = filters {
            source.push('|');
            source.push_str(filters);
        }
        return parse_expression(&source).ok();
    }
    if let Some(key) = head.strip_prefix("L_") {
        if !valid_lang_key(key) {
            return None;
        }
        let mut source = format!("lang('{key}')");
        if let Some(filters) = filters {
            source.push('|');
            source.push_str(filters);
        }
        return parse_expression(&source).ok();
    }
    parse_expression(content).ok()
}

/// Language keys are upper-case identifiers.  The key is interpolated into a
/// synthetic expression, so a quote or operator in a hostile template must not
/// be able to turn `{L_X}` into a different expression.
fn valid_lang_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn parse_legacy_tag(content: &str) -> Result<Option<Tag>, ParseError> {
    let content = content.trim();
    if let Some(rest) = content.strip_prefix("IF ") {
        return Ok(Some(Tag::If(parse_expression(rest.trim()).map_err(
            |error| ParseError::new(format!("invalid IF expression: {error}")),
        )?)));
    }
    if let Some(rest) = content.strip_prefix("ELSEIF ") {
        return Ok(Some(Tag::ElseIf(parse_expression(rest.trim()).map_err(
            |error| ParseError::new(format!("invalid ELSEIF expression: {error}")),
        )?)));
    }
    if let Some(rest) = content.strip_prefix("ELSE IF ") {
        return Ok(Some(Tag::ElseIf(parse_expression(rest.trim()).map_err(
            |error| ParseError::new(format!("invalid ELSE IF expression: {error}")),
        )?)));
    }
    if content == "ELSE" {
        return Ok(Some(Tag::Else));
    }
    if content == "ENDIF" {
        return Ok(Some(Tag::EndIf));
    }
    if let Some(rest) = content.strip_prefix("BEGIN ") {
        let name = rest.trim();
        if name.is_empty() {
            return Err(ParseError::new("empty BEGIN block name"));
        }
        return Ok(Some(Tag::Begin(name.to_string())));
    }
    if content == "BEGINELSE" {
        return Ok(Some(Tag::BeginElse));
    }
    if let Some(rest) = content.strip_prefix("END ") {
        let name = rest.trim();
        if name.is_empty() {
            return Err(ParseError::new("empty END block name"));
        }
        return Ok(Some(Tag::EndBlock(name.to_string())));
    }
    if let Some(rest) = content.strip_prefix("INCLUDE ") {
        return Ok(Some(Tag::Include(parse_include_arg(rest.trim())?)));
    }
    if let Some(rest) = content.strip_prefix("INCLUDEJS ") {
        return Ok(Some(Tag::Asset(
            AssetKind::JavaScript,
            parse_embedded_expr(rest.trim())?,
        )));
    }
    if let Some(rest) = content.strip_prefix("INCLUDECSS ") {
        return Ok(Some(Tag::Asset(
            AssetKind::Stylesheet,
            parse_embedded_expr(rest.trim())?,
        )));
    }
    if let Some(rest) = content.strip_prefix("DEFINE ") {
        return Ok(Some(parse_define(rest)?));
    }
    if let Some(rest) = content.strip_prefix("UNDEFINE ") {
        return Ok(Some(Tag::Undefine(rest.trim().to_string())));
    }
    if let Some(rest) = content.strip_prefix("EVENT ") {
        return Ok(Some(Tag::Event(rest.trim().to_string())));
    }
    if content.starts_with("INCLUDEPHP ") {
        return Err(ParseError::new(
            "INCLUDEPHP is not supported by this server",
        ));
    }
    Ok(None)
}

fn parse_twig_tag(content: &str) -> Result<Tag, ParseError> {
    let content = content.trim();
    if let Some(rest) = content.strip_prefix("if ") {
        return Ok(Tag::If(parse_expression(rest.trim()).map_err(|error| {
            ParseError::new(format!("invalid if expression: {error}"))
        })?));
    }
    if let Some(rest) = content.strip_prefix("elseif ") {
        return Ok(Tag::ElseIf(parse_expression(rest.trim()).map_err(
            |error| ParseError::new(format!("invalid elseif expression: {error}")),
        )?));
    }
    if content == "else" {
        return Ok(Tag::Else);
    }
    if content == "endif" {
        return Ok(Tag::EndIf);
    }
    if let Some(rest) = content.strip_prefix("for ") {
        let (name, expr) = rest.split_once(" in ").ok_or_else(|| {
            ParseError::new("for tag must be of the form 'for name in expression'")
        })?;
        let name = name.trim();
        if name.is_empty() {
            return Err(ParseError::new("empty for variable name"));
        }
        let expr = parse_expression(expr.trim())
            .map_err(|error| ParseError::new(format!("invalid for expression: {error}")))?;
        return Ok(Tag::For(name.to_string(), expr));
    }
    if content == "endfor" {
        return Ok(Tag::EndFor);
    }
    if let Some(rest) = content.strip_prefix("set ") {
        let (name, expr) = rest
            .split_once('=')
            .ok_or_else(|| ParseError::new("set tag must contain '='"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(ParseError::new("empty set variable name"));
        }
        let expr = parse_expression(expr.trim())
            .map_err(|error| ParseError::new(format!("invalid set expression: {error}")))?;
        return Ok(Tag::Set(name.to_string(), expr));
    }
    if let Some(rest) = content.strip_prefix("include ") {
        return Ok(Tag::Include(parse_include_arg(rest.trim())?));
    }
    if let Some(rest) = content.strip_prefix("INCLUDE ") {
        return Ok(Tag::Include(parse_include_arg(rest.trim())?));
    }
    if let Some(rest) = content.strip_prefix("INCLUDEJS ") {
        return Ok(Tag::Asset(
            AssetKind::JavaScript,
            parse_embedded_expr(rest.trim())?,
        ));
    }
    if let Some(rest) = content.strip_prefix("INCLUDECSS ") {
        return Ok(Tag::Asset(
            AssetKind::Stylesheet,
            parse_embedded_expr(rest.trim())?,
        ));
    }
    if let Some(rest) = content.strip_prefix("DEFINE ") {
        return parse_define(rest);
    }
    if let Some(rest) = content.strip_prefix("UNDEFINE ") {
        return Ok(Tag::Undefine(rest.trim().to_string()));
    }
    if let Some(rest) = content.strip_prefix("EVENT ") {
        return Ok(Tag::Event(rest.trim().to_string()));
    }
    if content == "apply spaceless" {
        return Ok(Tag::ApplySpaceless);
    }
    if content == "endapply" {
        return Ok(Tag::EndApply);
    }
    Err(ParseError::new(format!(
        "unsupported template tag: {content}"
    )))
}

fn parse_define(rest: &str) -> Result<Tag, ParseError> {
    let (name, expr) = rest
        .split_once('=')
        .ok_or_else(|| ParseError::new("DEFINE must contain '='"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(ParseError::new("empty DEFINE variable"));
    }
    let expr = parse_expression(expr.trim())
        .map_err(|error| ParseError::new(format!("invalid DEFINE expression: {error}")))?;
    Ok(Tag::Define(name.to_string(), expr))
}

fn parse_include_arg(value: &str) -> Result<Expr, ParseError> {
    let value = value.trim();
    if value.starts_with('{') && value.ends_with('}') && value.len() >= 2 {
        return parse_expression(value[1..value.len() - 1].trim())
            .map_err(|error| ParseError::new(format!("invalid INCLUDE expression: {error}")));
    }
    if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        return parse_expression(value)
            .map_err(|error| ParseError::new(format!("invalid INCLUDE name: {error}")));
    }
    Ok(Expr::Literal(Value::Str(value.to_string())))
}

fn parse_embedded_expr(value: &str) -> Result<Expr, ParseError> {
    let value = value.trim();
    let mut parts: Vec<Expr> = Vec::new();
    let mut literal = String::new();
    let mut i = 0usize;
    while i < value.len() {
        let rest = &value[i..];
        if let Some(after) = rest.strip_prefix('{') {
            if let Some(end) = after.find('}') {
                let inner = after[..end].trim();
                if !inner.chars().any(char::is_whitespace) {
                    if let Ok(expr) = parse_expression(inner) {
                        if !literal.is_empty() {
                            parts.push(Expr::Literal(Value::Str(std::mem::take(&mut literal))));
                        }
                        parts.push(expr);
                        i += 1 + end + 1;
                        continue;
                    }
                }
            }
        }
        let ch = rest
            .chars()
            .next()
            .ok_or_else(|| ParseError::new("invalid asset path"))?;
        literal.push(ch);
        i += ch.len_utf8();
    }
    if !literal.is_empty() {
        parts.push(Expr::Literal(Value::Str(literal)));
    }
    if parts.is_empty() {
        return Ok(Expr::Literal(Value::Str(String::new())));
    }
    let mut iter = parts.into_iter();
    let mut result = iter.next().unwrap();
    for part in iter {
        result = Expr::Binary(BinaryOp::Concat, Box::new(result), Box::new(part));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_and_twig_blocks() {
        let nodes = parse(
            r#"Hello {NAME}
<!-- IF S_IS_BOT -->bot<!-- ELSEIF COUNT > 1 -->many<!-- ELSE -->one<!-- ENDIF -->
<!-- BEGIN row -->[{row.NAME} {row.S_ROW_COUNT}<!-- BEGIN sub -->/{row.sub.NAME}<!-- END sub -->]<!-- END row -->
{% for field in fields %}{{ field.NAME }}{% endfor %}
<!-- INCLUDE footer.html -->"#,
        )
        .unwrap();
        assert_eq!(nodes.len(), 7);
    }

    #[test]
    fn rejects_unbalanced_blocks() {
        assert!(parse("<!-- IF X -->").is_err());
        assert!(parse("<!-- BEGIN x --><!-- END y -->").is_err());
        assert!(parse("{% for x in y %}").is_err());
    }
}
