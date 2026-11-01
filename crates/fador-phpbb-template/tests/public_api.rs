//! Integration tests that exercise only the crate's public API.
//!
//! The unit tests inside `src/` may use crate-private helpers; these tests prove
//! that a dependent crate can build a context, render a template, resolve
//! includes and event templates, and inspect the compiled nodes.

use fador_phpbb_template::{
    parse, AssetKind, Context, Engine, Node, RenderOutput, Runtime, TemplateError, Value,
};
use std::fs;
use std::path::PathBuf;

struct TestRuntime;

impl Runtime for TestRuntime {
    fn lang(&self, key: &str, _args: &[Value]) -> String {
        match key {
            "HELLO" => "Hello".into(),
            "COLON" => ":".into(),
            other => other.into(),
        }
    }

    fn lang_defined(&self, key: &str) -> bool {
        matches!(key, "HELLO" | "COLON")
    }

    fn path(&self, route: &str, params: &Value) -> String {
        let id = params.get("forum_id").and_then(Value::as_i64).unwrap_or(0);
        format!("/app.php/{route}/{id}")
    }

    fn url(&self, route: &str, _params: &Value) -> String {
        format!("https://example.test/{route}")
    }
}

/// A template tree under the system temporary directory.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fador-phpbb-template-public-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("template")).unwrap();
        fs::create_dir_all(root.join("event")).unwrap();
        Self { root }
    }

    fn dir(&self) -> PathBuf {
        self.root.join("template")
    }

    fn event_dir(&self) -> PathBuf {
        self.root.join("event")
    }

    fn write(&self, name: &str, contents: &str) {
        let path = self.root.join("template").join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn engine(&self) -> Engine {
        Engine::new(vec![self.dir()]).with_event_dirs(vec![self.event_dir()])
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn render(engine: &Engine, name: &str, context: &mut Context) -> RenderOutput {
    engine
        .render(name, context, &TestRuntime)
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

#[test]
fn compiled_nodes_are_inspectable() {
    let nodes = parse("text<!-- IF X -->yes<!-- ENDIF -->{NAME}").unwrap();
    assert_eq!(nodes.len(), 3);
    assert!(matches!(&nodes[0], Node::Text(text) if text == "text"));
    assert!(matches!(&nodes[1], Node::If(branches) if branches.len() == 1));
    assert!(matches!(&nodes[2], Node::Output(_)));
}

#[test]
fn includes_contribute_html_and_assets_in_order() {
    let tree = Tree::new("include-assets");
    tree.write("inc.html", "inc<!-- INCLUDEJS inc.js -->");
    tree.write(
        "main.html",
        "<!-- INCLUDE inc.html --><!-- INCLUDECSS main.css -->",
    );
    let mut context = Context::new();
    let output = render(&tree.engine(), "main.html", &mut context);
    assert_eq!(output.html, "inc");
    assert_eq!(output.assets.javascript, vec!["inc.js"]);
    assert_eq!(output.assets.stylesheets, vec!["main.css"]);
}

#[test]
fn every_event_directory_contributes_once() {
    let tree = Tree::new("events");
    tree.write("main.html", "<!-- EVENT footer -->");
    fs::write(tree.event_dir().join("footer.html"), "first").unwrap();
    fs::create_dir_all(tree.root.join("event2")).unwrap();
    fs::write(tree.root.join("event2/footer.html"), "second").unwrap();
    let engine = Engine::new(vec![tree.dir()])
        .with_event_dirs(vec![tree.event_dir(), tree.root.join("event2")]);
    let mut context = Context::new();
    let output = render(&engine, "main.html", &mut context);
    assert_eq!(output.html, "firstsecond");
}

#[test]
fn event_names_cannot_traverse_the_event_dirs() {
    let tree = Tree::new("event-escape");
    tree.write("main.html", "<!-- EVENT ../template/main -->");
    let mut context = Context::new();
    let error = tree
        .engine()
        .render("main.html", &mut context, &TestRuntime)
        .unwrap_err();
    assert!(error.message.contains("invalid event template name"));
}

#[test]
fn asset_kinds_are_reported_for_the_compiled_tree() {
    let tree = Tree::new("asset-kind");
    tree.write("main.html", "<!-- INCLUDEJS a.js -->{% INCLUDECSS b.css %}");
    let mut context = Context::new();
    let output = render(&tree.engine(), "main.html", &mut context);
    assert_eq!(output.assets.javascript, vec!["a.js"]);
    assert_eq!(output.assets.stylesheets, vec!["b.css"]);

    let nodes = parse("<!-- INCLUDEJS a.js -->").unwrap();
    assert!(matches!(
        &nodes[0],
        Node::Asset {
            kind: AssetKind::JavaScript,
            ..
        }
    ));
}

#[test]
fn template_names_are_sandboxed_to_their_root() {
    let tree = Tree::new("sandbox");
    tree.write("ok.html", "ok");
    fs::write(tree.root.join("outside.html"), "outside").unwrap();
    let engine = tree.engine();

    for name in [
        "../outside.html",
        "../../outside.html",
        "/etc/passwd",
        "..\\outside.html",
        "C:\\Windows\\win.ini",
        "\\\\server\\share\\outside.html",
        "template/../../outside.html",
        "ok.html\0",
        "",
        ".",
    ] {
        let mut context = Context::new();
        assert!(
            engine.render(name, &mut context, &TestRuntime).is_err(),
            "rendered {name:?}"
        );
    }

    let mut context = Context::new();
    assert_eq!(render(&engine, "ok.html", &mut context).html, "ok");
}

#[test]
fn errors_name_the_template_and_never_leak_contents() {
    let tree = Tree::new("errors");
    tree.write("bad.html", "<!-- IF X -->");
    let mut context = Context::new();
    let error: TemplateError = tree
        .engine()
        .render("bad.html", &mut context, &TestRuntime)
        .unwrap_err();
    assert!(error.message.contains("bad.html"));
    assert!(!error.message.contains("IF X"));
}

#[test]
fn raw_output_matches_phpbb_and_escaping_is_explicit() {
    let mut context = Context::new();
    context.set(
        "POST_SUBJECT",
        Value::Str("<script>alert(1)</script>".into()),
    );
    let output = Engine::new(Vec::new())
        .render_source(
            "escape.html",
            "{POST_SUBJECT}|{{ POST_SUBJECT|e }}",
            &mut context,
            &TestRuntime,
        )
        .unwrap();
    assert_eq!(
        output.html,
        "<script>alert(1)</script>|&lt;script&gt;alert(1)&lt;/script&gt;"
    );
}

#[test]
fn context_loop_metadata_and_language_helpers_are_public() {
    let mut context = Context::new();
    context.set("L_HELLO", Value::Str("Hei".into()));
    context.set(
        "row",
        Value::Array(vec![Value::object([
            ("NAME".into(), Value::Str("one".into())),
            ("NAME2".into(), Value::Str("two".into())),
        ])]),
    );
    assert!(context.is_defined("row"));
    assert!(context.block_exists(".row"));
    assert_eq!(context.get("row.0.NAME2"), Some(Value::Str("two".into())));

    let output = Engine::new(Vec::new())
        .render_source(
            "loops.html",
            "{L_HELLO}{L_COLON}<!-- BEGIN row -->{row.NAME}{row.S_ROW_COUNT}<!-- END row -->",
            &mut context,
            &TestRuntime,
        )
        .unwrap();
    assert_eq!(output.html, "Hei:one0");
}

#[test]
fn nested_include_recursion_is_bounded() {
    let tree = Tree::new("recursion");
    tree.write("self.html", "x<!-- INCLUDE self.html -->");
    let mut context = Context::new();
    let error = tree
        .engine()
        .render("self.html", &mut context, &TestRuntime)
        .unwrap_err();
    assert!(error.message.contains("depth"), "{}", error.message);
}

#[test]
fn template_dirs_are_reported_in_priority_order() {
    let first = PathBuf::from("first");
    let second = PathBuf::from("second");
    let engine = Engine::new(vec![first.clone(), second.clone()]);
    assert_eq!(engine.template_dirs(), &[first, second]);
}
