//! Seeded fuzz tests for the template compiler and renderer.
//!
//! Templates are normally read from the asset tree, but the ACP also compiles
//! administrator-supplied tag templates, so the compiler must treat its input
//! as untrusted: unbalanced blocks, deep nesting, huge expressions, include
//! escapes and self-inclusion all have to end in a defined error instead of a
//! panic or a stack overflow.

use crate::testutil::iterations;
use crate::{Context, Engine, Runtime, TemplateError, Value};
use std::fs;
use std::path::PathBuf;

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fador-phpbb-template-fuzz-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("styles/prosilver/template")).unwrap();
        fs::create_dir_all(root.join("event")).unwrap();
        Self { root }
    }

    fn template_dir(&self) -> PathBuf {
        self.root.join("styles/prosilver/template")
    }

    fn write(&self, name: &str, contents: &str) {
        fs::write(self.template_dir().join(name), contents).unwrap();
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct TestRuntime;

impl Runtime for TestRuntime {
    fn lang(&self, key: &str, _args: &[Value]) -> String {
        key.to_string()
    }

    fn lang_defined(&self, key: &str) -> bool {
        !key.is_empty()
    }

    fn path(&self, route: &str, _params: &Value) -> String {
        format!("/app.php/{route}")
    }

    fn url(&self, route: &str, _params: &Value) -> String {
        format!("/{route}")
    }
}

fn context() -> Context {
    let mut context = Context::new();
    context.set("X", Value::Bool(true));
    context.set("rows", Value::Array(Vec::new()));
    context.set("FILE", Value::Str("missing.html".into()));
    context
}

fn render(engine: &Engine, name: &str, source: &str) -> Result<String, TemplateError> {
    engine
        .render_source(name, source, &mut context(), &TestRuntime)
        .map(|output| output.html)
}

#[test]
fn rejects_unbalanced_blocks_and_bad_includes() {
    let engine = Engine::new(Vec::new());
    for source in [
        "<!-- IF X -->",
        "<!-- ENDIF -->",
        "<!-- BEGIN a --><!-- END b -->",
        "<!-- BEGIN a -->",
        "<!-- BEGINELSE -->",
        "{% for x in rows %}",
        "{% endfor %}",
        "{% if X %}",
        "{% apply spaceless %}",
        "{% endapply %}",
        "<!-- IF X --><!-- ELSE --><!-- ELSE --><!-- ENDIF -->",
    ] {
        assert!(
            engine.validate_source("bad.html", source).is_err(),
            "accepted {source:?}"
        );
    }

    // Unknown includes are a defined error, not a panic.
    assert!(render(&engine, "main.html", "<!-- INCLUDE missing.html -->").is_err());
    assert!(render(&engine, "main.html", "{% include 'missing.html' %}").is_err());
}

#[test]
fn include_names_cannot_escape_the_template_dirs() {
    let tree = TempTree::new("includes");
    tree.write("secret.html", "SECRET");
    tree.write("ok.html", "ok");
    std::fs::write(tree.root.join("outside.html"), "outside").unwrap();
    let engine = Engine::new(vec![tree.template_dir()]);
    let mut context = context();

    for name in [
        "../secret.html",
        "../../outside.html",
        "/etc/passwd",
        "..\\secret.html",
        "C:\\Windows\\win.ini",
        "\\\\server\\share\\secret.html",
        "%2e%2e/secret.html",
        "%2e%2e%2fsecret.html",
        "./../secret.html",
        "styles/../../secret.html",
        "secret.html\0",
    ] {
        context.set("FILE", Value::Str(name.into()));
        let result = engine.render_source(
            "main.html",
            "<!-- INCLUDE {FILE} -->",
            &mut context,
            &TestRuntime,
        );
        assert!(result.is_err(), "include escaped its directory: {name:?}");
    }

    // An empty dynamic include is a no-op, not an escape.
    context.set("FILE", Value::Str(String::new()));
    let output = engine
        .render_source(
            "main.html",
            "<!-- INCLUDE {FILE} -->",
            &mut context,
            &TestRuntime,
        )
        .unwrap();
    assert_eq!(output.html, "");

    context.set("FILE", Value::Str("ok.html".into()));
    let output = engine
        .render_source(
            "main.html",
            "<!-- INCLUDE {FILE} -->",
            &mut context,
            &TestRuntime,
        )
        .unwrap();
    assert_eq!(output.html, "ok");
}

#[test]
fn self_inclusion_stops_at_the_depth_limit() {
    let tree = TempTree::new("self");
    tree.write("self.html", "x<!-- INCLUDE self.html -->");
    tree.write("a.html", "a<!-- INCLUDE b.html -->");
    tree.write("b.html", "b<!-- INCLUDE a.html -->");
    let engine = Engine::new(vec![tree.template_dir()]);
    for name in ["self.html", "a.html"] {
        let error = engine
            .render(name, &mut context(), &TestRuntime)
            .expect_err("recursive include must fail");
        assert!(
            error.message.contains("depth"),
            "unexpected error: {}",
            error.message
        );
    }
}

#[test]
fn deep_nesting_and_huge_expressions_are_rejected() {
    let engine = Engine::new(Vec::new());

    let mut nested = String::new();
    for _ in 0..200 {
        nested.push_str("<!-- IF X -->");
    }
    nested.push_str("deep");
    for _ in 0..200 {
        nested.push_str("<!-- ENDIF -->");
    }
    assert!(engine.validate_source("deep.html", &nested).is_err());

    let mut blocks = String::new();
    for index in 0..200 {
        blocks.push_str(&format!("<!-- BEGIN b{index} -->"));
    }
    blocks.push_str("deep");
    for index in (0..200).rev() {
        blocks.push_str(&format!("<!-- END b{index} -->"));
    }
    assert!(engine.validate_source("blocks.html", &blocks).is_err());

    let parentheses = format!("{{{{ {}1{} }}}}", "(".repeat(10_000), ")".repeat(10_000));
    assert!(engine.validate_source("parens.html", &parentheses).is_err());

    let mut expression = String::from("{{ 1");
    for _ in 0..5_000 {
        expression.push_str(" + 1");
    }
    expression.push_str(" }}");
    assert!(engine.validate_source("long.html", &expression).is_err());

    let mut huge = String::from("{{ ");
    for _ in 0..5_000 {
        huge.push_str("1 + ");
    }
    huge.push('1');
    huge.push_str(" }}");
    assert!(engine.validate_source("huge.html", &huge).is_err());

    // A language-key bomb renders linearly, not quadratically.
    let bomb = "{L_A}".repeat(20_000);
    let output = render(&engine, "bomb.html", &bomb).unwrap();
    assert_eq!(output.len(), 20_000);
}

#[test]
fn language_variables_cannot_become_arbitrary_expressions() {
    let engine = Engine::new(Vec::new());
    // A quote in a legacy key must not splice a filter call into the
    // synthetic `lang(...)` expression.
    for source in [
        "{L_A')|upper|lang('B}",
        "{LA_A')|upper|lang('B}",
        "{L_A\")|upper|lang(\"B}",
        "{L_}",
        "{L_ä}",
    ] {
        let output = render(&engine, "lang.html", source).unwrap();
        assert_eq!(output, source, "legacy key was rewritten: {source:?}");
    }

    // Valid keys still resolve.
    assert_eq!(render(&engine, "lang.html", "{L_HELLO}").unwrap(), "HELLO");
    assert_eq!(render(&engine, "lang.html", "{LA_HELLO}").unwrap(), "HELLO");
}

#[test]
fn multibyte_expression_text_never_panics() {
    // Regression: operator scanning used byte slices and panicked when the
    // next character was multi-byte (`ää`, `ä==ä`).
    for input in [
        "ää",
        "ä",
        "aä",
        "ääää",
        "ä==ä",
        "1ä+2",
        "\u{1f4a3}\u{1f4a3}==\u{1f4a3}",
        "ä!=ä",
        "ä<=ä",
    ] {
        let _ = crate::expr::parse_expression(input);
    }
    let engine = Engine::new(Vec::new());
    let _ = engine.validate_source("mb.html", "{{ ää }}");
    let _ = engine.validate_source("mb.html", "{{ 1ä+2 }}");
}

#[test]
fn fuzz_template_compiler_and_renderer() {
    let engine = Engine::new(Vec::new());
    let tokens = [
        "<!-- IF X -->",
        "<!-- ELSE -->",
        "<!-- ELSEIF X -->",
        "<!-- ENDIF -->",
        "<!-- BEGIN rows -->",
        "<!-- BEGINELSE -->",
        "<!-- END rows -->",
        "<!-- INCLUDE missing.html -->",
        "<!-- EVENT footer -->",
        "{% if X %}",
        "{% else %}",
        "{% endif %}",
        "{% for row in rows %}",
        "{% endfor %}",
        "{% set a = 1 %}",
        "{% apply spaceless %}",
        "{% endapply %}",
        "{{ X }}",
        "{{ 1 + 2 }}",
        "{{ ((( }}",
        "{L_A}",
        "{X}",
        "<!--",
        "-->",
        "{%",
        "%}",
        "{",
        "}",
        "text",
        "ä",
        "💣",
        "\0",
    ];
    let mut seed = crate::testutil::Rng::new(0x5445_4d50_4c41_5445);
    for _ in 0..iterations(3_000) {
        let mut source = String::new();
        for _ in 0..seed.below(40) {
            source.push_str(seed.pick(&tokens));
        }
        match engine.validate_source("fuzz.html", &source) {
            Ok(()) => {
                let output = render(&engine, "fuzz.html", &source);
                match output {
                    Ok(html) => assert!(html.len() <= source.len() + 4_096, "{}", html.len()),
                    Err(error) => assert!(!error.message.is_empty()),
                }
            }
            Err(error) => assert!(!error.message.is_empty()),
        }
    }

    let len = 400;
    let input = seed.text(len);
    let _ = render(&engine, "text.html", &input);
    let _ = render(&engine, "raw.html", &format!("<b>{input}</b>"));
}

#[cfg(unix)]
#[test]
fn include_symlinks_cannot_escape_the_template_dir() {
    use std::os::unix::fs::symlink;
    let tree = TempTree::new("symlink");
    let outside = tree.root.join("outside.html");
    std::fs::write(&outside, "outside").unwrap();
    symlink(&outside, tree.template_dir().join("link.html")).unwrap();
    let engine = Engine::new(vec![tree.template_dir()]);
    assert!(render(&engine, "main.html", "<!-- INCLUDE link.html -->").is_err());
}
