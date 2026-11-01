use crate::context::Context;
use crate::parser::{AssetKind, Node};
use crate::value::Value;
use crate::{Engine, RenderOutput, Runtime, TemplateError};

/// Deepest block nesting the renderer will enter.  It mirrors the parser limit
/// so a template accepted by `parse` can never overflow the stack on render.
const MAX_RENDER_DEPTH: usize = 64;

pub(crate) fn render_nodes(
    nodes: &[Node],
    context: &mut Context,
    runtime: &dyn Runtime,
    out: &mut String,
    assets: &mut crate::AssetBag,
    depth: usize,
    engine: &Engine,
) -> Result<(), TemplateError> {
    if depth > MAX_RENDER_DEPTH {
        return Err(TemplateError::new("template render depth exceeded"));
    }
    for node in nodes {
        match node {
            Node::Text(text) => out.push_str(text),
            Node::Output(expr) => {
                let mut value = expr.eval(context, runtime);
                if matches!(value, Value::Null) {
                    if let crate::expr::Expr::Path(path) = expr {
                        if let Some(key) = path.strip_prefix("L_") {
                            value = Value::Str(runtime.lang(key, &[]));
                        } else if let Some(key) = path.strip_prefix("LA_") {
                            value = Value::Str(addslashes(&runtime.lang(key, &[])));
                        }
                    }
                }
                out.push_str(&value.to_output());
            }
            Node::If(branches) => {
                for (condition, body) in branches {
                    let matched = condition
                        .as_ref()
                        .map(|condition| condition.eval(context, runtime).truthy())
                        .unwrap_or(true);
                    if matched {
                        render_nodes(body, context, runtime, out, assets, depth + 1, engine)?;
                        break;
                    }
                }
            }
            Node::BlockLoop {
                name,
                body,
                else_body,
            } => {
                let (rows, path) = context.resolve_block(name);
                if rows.is_empty() {
                    render_nodes(else_body, context, runtime, out, assets, depth + 1, engine)?;
                    continue;
                }
                for index in 0..rows.len() {
                    if !context.push_loop(name, &path, &rows, index) {
                        continue;
                    }
                    let result =
                        render_nodes(body, context, runtime, out, assets, depth + 1, engine);
                    context.pop_loop();
                    result?;
                }
            }
            Node::For {
                name,
                expr,
                body,
                else_body,
            } => {
                let value = expr.eval(context, runtime);
                let rows = match value {
                    Value::Array(rows) => rows,
                    _ => Vec::new(),
                };
                if rows.is_empty() {
                    render_nodes(else_body, context, runtime, out, assets, depth + 1, engine)?;
                    continue;
                }
                for index in 0..rows.len() {
                    if !context.push_loop(name, name, &rows, index) {
                        continue;
                    }
                    let result =
                        render_nodes(body, context, runtime, out, assets, depth + 1, engine);
                    context.pop_loop();
                    result?;
                }
            }
            Node::Set { name, expr } => {
                let value = expr.eval(context, runtime);
                context.set_local(name, value);
            }
            Node::Define { name, expr } => {
                let value = expr.eval(context, runtime);
                context.set_local(name, value);
            }
            Node::Undefine(name) => context.remove_local(name),
            Node::Include(expr) => {
                let name = expr.eval(context, runtime);
                let name = name.as_str().unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                let mut included = RenderOutput {
                    html: String::new(),
                    assets: crate::AssetBag::default(),
                };
                engine.render_include(name, context, runtime, &mut included, depth + 1)?;
                out.push_str(&included.html);
                for value in included.assets.javascript {
                    assets.add_javascript(value);
                }
                for value in included.assets.stylesheets {
                    assets.add_stylesheet(value);
                }
            }
            Node::Spaceless(body) => {
                let mut inner = String::new();
                render_nodes(
                    body,
                    context,
                    runtime,
                    &mut inner,
                    assets,
                    depth + 1,
                    engine,
                )?;
                out.push_str(&strip_spaceless(&inner));
            }
            Node::Asset { kind, value } => {
                let path = value.eval(context, runtime).to_output();
                match kind {
                    AssetKind::JavaScript => assets.add_javascript(path),
                    AssetKind::Stylesheet => assets.add_stylesheet(path),
                }
            }
            Node::Event(name) => {
                let mut event_output = RenderOutput {
                    html: String::new(),
                    assets: crate::AssetBag::default(),
                };
                engine.render_event(name, context, runtime, &mut event_output, depth + 1)?;
                out.push_str(&event_output.html);
                for value in event_output.assets.javascript {
                    assets.add_javascript(value);
                }
                for value in event_output.assets.stylesheets {
                    assets.add_stylesheet(value);
                }
            }
        }
    }
    Ok(())
}

fn strip_spaceless(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = input[i..].chars().next().expect("valid template output");
        out.push(ch);
        i += ch.len_utf8();
        if ch == '>' {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'<' {
                i = j;
            }
        }
    }
    out.trim().to_string()
}

fn addslashes(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('"', "\\\"")
        .replace('\0', "\\0")
}
