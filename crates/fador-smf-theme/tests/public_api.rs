//! Integration tests that exercise only the crate's public API.
//!
//! The unit tests inside `src/` may use crate-private helpers; these tests
//! prove that a dependent crate can parse a template, run it with or without a
//! host, register a theme and render a page from it.

use fador_smf_theme::{
    array, int_key, parse, str_key, EvalLimits, Evaluator, HostContext, HostFunctions, Key,
    PhpArray, SmfFunctions, TemplateEngine, TemplateError, Theme, Value,
};
use std::fs;
use std::path::PathBuf;

/// A theme tree under the system temporary directory.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fador-smf-theme-public-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("Themes/default")).unwrap();
        Self { root }
    }

    fn write(&self, theme: &str, template: &str, source: &str) {
        let directory = self.root.join("Themes").join(theme);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(format!("{template}.template.php")), source).unwrap();
    }

    fn engine(&self) -> TemplateEngine {
        TemplateEngine::new(&self.root, "default", EvalLimits::default()).unwrap()
    }

    fn default_theme(&self) -> Theme {
        Theme {
            name: "default".into(),
            directory: PathBuf::from("Themes/default"),
            url: "/Themes/default".into(),
            images_url: "/Themes/default/images".into(),
            layers: vec!["html".into(), "body".into()],
            templates: vec!["index".into()],
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn globals() -> Vec<(String, Value)> {
    vec![
        (
            "txt".to_string(),
            array(vec![
                (str_key("title"), Value::Str("Hello".into())),
                (str_key("save"), Value::Str("Save".into())),
            ]),
        ),
        (
            "settings".to_string(),
            array(vec![
                (
                    str_key("images_url"),
                    Value::Str("/Themes/default/images".into()),
                ),
                (str_key("use_image_buttons"), Value::Bool(true)),
            ]),
        ),
    ]
}

#[test]
fn parses_and_evaluates_a_template_without_a_host() {
    let mut evaluator = Evaluator::new(EvalLimits::default());
    for (name, value) in globals() {
        evaluator.set_global(&name, value);
    }
    let statements = parse(
        "<?php
function template_main() {
    global $txt;
    foreach (array('a', 'b') as $key => $item) {
        echo $key, '=', $item, ';';
    }
    echo $txt['title'];
}
?>",
    )
    .unwrap();
    evaluator.execute(&statements).unwrap();
    let _ = evaluator.take_output();
    evaluator.call("template_main", Vec::new()).unwrap();
    assert_eq!(evaluator.take_output(), "0=a;1=b;Hello");
    // `create_button()` is an SMF function, so it is not available here.
    let statements =
        parse("<?php function template_main() { echo create_button('x'); } ?>").unwrap();
    evaluator.execute(&statements).unwrap();
    let error = evaluator.call("template_main", Vec::new()).unwrap_err();
    assert!(error.message.contains("allow-list"), "{}", error.message);
}

#[test]
fn the_smf_host_functions_are_opt_in() {
    let mut evaluator = Evaluator::new(EvalLimits::default());
    evaluator.set_host(Box::new(SmfFunctions));
    for (name, value) in globals() {
        evaluator.set_global(&name, value);
    }
    let statements =
        parse("<?php function template_main() { echo create_button('save.gif', 'save'); } ?>")
            .unwrap();
    evaluator.execute(&statements).unwrap();
    let _ = evaluator.take_output();
    evaluator.call("template_main", Vec::new()).unwrap();
    assert_eq!(
        evaluator.take_output(),
        "<img src=\"/Themes/default/images/save.gif\" alt=\"Save\"  />"
    );
}

struct UpperCase;

impl HostFunctions for UpperCase {
    fn has(&self, name: &str) -> bool {
        name == "shout"
    }

    fn call(
        &mut self,
        name: &str,
        args: Vec<Value>,
        context: &mut dyn HostContext,
    ) -> Option<Result<Value, String>> {
        if name != "shout" {
            return None;
        }
        let text = args.first().map(Value::to_php_string).unwrap_or_default();
        let suffix = context
            .global_field("txt", "title")
            .map(|value| value.to_php_string())
            .unwrap_or_default();
        Some(Ok(Value::Str(format!("{} {suffix}", text.to_uppercase()))))
    }
}

#[test]
fn a_custom_host_sees_the_template_globals() {
    let mut evaluator = Evaluator::new(EvalLimits::default());
    evaluator.set_host(Box::new(UpperCase));
    for (name, value) in globals() {
        evaluator.set_global(&name, value);
    }
    let statements = parse("<?php function template_main() { echo shout('hey'); } ?>").unwrap();
    evaluator.execute(&statements).unwrap();
    let _ = evaluator.take_output();
    evaluator.call("template_main", Vec::new()).unwrap();
    assert_eq!(evaluator.take_output(), "HEY Hello");
}

#[test]
fn the_evaluator_stops_at_its_limits() {
    let limits = EvalLimits {
        max_steps: 500,
        max_call_depth: 8,
        max_output_bytes: 1_024,
        max_string_bytes: 1_024,
        max_array_entries: 32,
    };
    for source in [
        "<?php while (true) {} ?>",
        "<?php function f() { return f(); } f(); ?>",
        "<?php for ($i = 0; $i < 100; $i++) { echo 'xxxxxxxxxx'; } ?>",
        "<?php $a = array(); for ($i = 0; $i < 100; $i++) { $a[] = $i; } ?>",
    ] {
        let statements = parse(source).unwrap();
        let mut evaluator = Evaluator::new(limits.clone());
        assert!(
            evaluator.execute(&statements).is_err(),
            "finished: {source}"
        );
    }
}

#[test]
fn renders_a_page_from_a_registered_theme() {
    let tree = Tree::new("page");
    tree.write(
        "default",
        "index",
        "<?php
function template_html_above() { echo '<html>'; }
function template_body_above() { echo '<body>'; }
function template_body_below() { echo '</body>'; }
function template_html_below() { echo '</html>'; }
?>",
    );
    tree.write(
        "default",
        "BoardIndex",
        "<?php function template_main() { global $txt; echo $txt['title']; } ?>",
    );
    let engine = tree.engine();
    engine.add_theme(tree.default_theme()).unwrap();
    let output = engine
        .render_page(
            "default",
            &["index", "BoardIndex"],
            &["html".into(), "body".into()],
            "template_main",
            globals(),
        )
        .unwrap();
    assert_eq!(output, "<html><body>Hello</body></html>");
}

#[test]
fn the_parse_cache_reloads_an_edited_template() {
    let tree = Tree::new("cache");
    tree.write(
        "default",
        "index",
        "<?php function template_main() { echo 'one'; } ?>",
    );
    let engine = tree.engine();
    engine.add_theme(tree.default_theme()).unwrap();
    let render = || {
        engine
            .render_function("default", "index", "template_main", Vec::new())
            .unwrap()
    };
    assert_eq!(render(), "one");
    assert_eq!(render(), "one");
    let stats = engine.stats();
    assert_eq!(stats.misses, 1);
    assert!(stats.hits >= 1);
    assert_eq!(stats.entries, 1);

    tree.write(
        "default",
        "index",
        "<?php function template_main() { echo 'rewritten'; } ?>",
    );
    assert_eq!(render(), "rewritten");
    assert_eq!(engine.stats().misses, 2);
    engine.reset_stats();
    assert_eq!(engine.stats().hits, 0);
    assert_eq!(engine.stats().misses, 0);
    assert_eq!(engine.cache_len(), 1);
}

#[test]
fn a_child_theme_falls_back_per_file() {
    let tree = Tree::new("fallback");
    tree.write(
        "default",
        "index",
        "<?php function template_main() { echo 'default-index'; } ?>",
    );
    tree.write(
        "default",
        "BoardIndex",
        "<?php function template_main() { echo 'default-board'; } ?>",
    );
    tree.write(
        "child",
        "BoardIndex",
        "<?php function template_main() { echo 'child-board'; } ?>",
    );
    let engine = tree.engine();
    engine.add_theme(tree.default_theme()).unwrap();
    engine
        .add_theme(Theme {
            name: "child".into(),
            directory: PathBuf::from("Themes/child"),
            url: String::new(),
            images_url: String::new(),
            layers: vec!["html".into()],
            templates: vec!["BoardIndex".into()],
        })
        .unwrap();
    assert_eq!(
        engine
            .render_function("child", "BoardIndex", "template_main", Vec::new())
            .unwrap(),
        "child-board"
    );
    assert_eq!(
        engine
            .render_function("child", "index", "template_main", Vec::new())
            .unwrap(),
        "default-index"
    );
}

#[test]
fn template_names_are_sandboxed() {
    let tree = Tree::new("sandbox");
    tree.write(
        "default",
        "index",
        "<?php function template_main() { echo 'ok'; } ?>",
    );
    let engine = tree.engine();
    engine.add_theme(tree.default_theme()).unwrap();
    for name in [
        "../index",
        "..\\index",
        "Themes/default/index",
        "index\0",
        "",
        ".",
    ] {
        assert!(
            engine
                .render_function("default", name, "template_main", Vec::new())
                .is_err(),
            "rendered {name:?}"
        );
    }
    assert_eq!(
        engine
            .render_function("default", "index", "template_main", Vec::new())
            .unwrap(),
        "ok"
    );
}

#[test]
fn errors_name_the_file_and_never_leak_contents() {
    let tree = Tree::new("errors");
    tree.write(
        "default",
        "index",
        "<?php function template_main() { echo 'secret';",
    );
    let engine = tree.engine();
    engine.add_theme(tree.default_theme()).unwrap();
    let error = engine
        .render_function("default", "index", "template_main", Vec::new())
        .unwrap_err();
    assert!(matches!(error, TemplateError::Parse(_)));
    let message = error.to_string();
    assert!(message.contains("index.template.php"), "{message}");
    assert!(!message.contains("secret"), "{message}");
}

#[test]
fn the_engine_accepts_a_host_factory() {
    let tree = Tree::new("factory");
    tree.write(
        "default",
        "index",
        "<?php function template_main() { echo shout('hi'); } ?>",
    );
    let engine = tree
        .engine()
        .with_host_factory(std::sync::Arc::new(|| Box::new(UpperCase)));
    engine.add_theme(tree.default_theme()).unwrap();
    assert_eq!(
        engine
            .render_function("default", "index", "template_main", globals())
            .unwrap(),
        "HI Hello"
    );
}

#[test]
fn array_helpers_build_controller_globals() {
    let mut entries = PhpArray::new();
    entries.insert(int_key(0), Value::Int(1));
    entries.insert(str_key("name"), Value::Str("x".into()));
    let value = array(vec![
        (Key::Int(0), Value::from_array(entries)),
        (Key::Str("count".into()), Value::Int(1)),
    ]);
    let outer = value.as_array().unwrap();
    assert_eq!(outer.borrow().len(), 2);
    assert_eq!(
        outer
            .borrow()
            .get(&Key::Int(0))
            .unwrap()
            .borrow()
            .as_array()
            .unwrap()
            .borrow()
            .len(),
        2
    );
}
