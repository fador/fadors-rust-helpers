//! Compiler and renderer for the phpBB template dialect.
//!
//! The dialect combines phpBB's legacy control comments (`<!-- IF -->`,
//! `<!-- BEGIN -->`, `<!-- INCLUDE -->`), legacy variables (`{NAME}`,
//! `{L_KEY}`, `{LA_KEY}`, `{$DEFINED}`) and a small Twig subset
//! (`{% if %}`, `{% for %}`, `{% set %}`, `{% DEFINE %}`, `{{ ... }}`).
//! Compilation is separate from rendering, so an application can compile once,
//! cache the resulting AST and render many pages from one process.
//!
//! # Escaping
//!
//! **Values are inserted raw by default, exactly like phpBB.** A template that
//! emits user-controlled text must opt into escaping with the `e` filter
//! (`{{ subject|e }}`, or `{% set safe = subject|e %}`) or one of its
//! strategies:
//!
//! - `|e` and `|e('html')` escape `& < > " '` as named HTML entities;
//! - `|e('html_attr')` escapes everything outside `[A-Za-z0-9,.-_]`;
//! - `|e('js')` escapes quotes, control characters and `<`, `>`, `&` for a
//!   JavaScript string literal.
//!
//! The legacy `{LA_KEY}` form applies the JavaScript strategy automatically.
//! The renderer never guesses: a plain `{NAME}` or `{{ name }}` is the same
//! byte sequence the context holds.
//!
//! # Security contract
//!
//! - Template names are sandboxed: no absolute paths, drive letters, `..`
//!   components, backslashes, NUL bytes or symlinks that leave a template
//!   directory.
//! - Block nesting, expression depth, expression token count and include depth
//!   are bounded, so a hostile template ends in a [`TemplateError`] instead of
//!   a panic or a stack overflow.
//! - `INCLUDEPHP` is rejected at compile time; there is no interpreter.
//! - Every parser error is returned, never printed, and rendering never writes
//!   to stdout.
//!
//! ```
//! use fador_phpbb_template::{Context, Engine, Runtime, Value};
//!
//! struct Strings;
//!
//! impl Runtime for Strings {
//!     fn lang(&self, key: &str, _args: &[Value]) -> String {
//!         if key == "HELLO" { "Hello".into() } else { key.into() }
//!     }
//!     fn lang_defined(&self, key: &str) -> bool { key == "HELLO" }
//!     fn path(&self, route: &str, _params: &Value) -> String { format!("/app.php/{route}") }
//!     fn url(&self, route: &str, _params: &Value) -> String { format!("/{route}") }
//! }
//!
//! let mut context = Context::new();
//! context.set("NAME", Value::Str("<b>Naruto</b>".into()));
//!
//! let output = Engine::new(Vec::new())
//!     .render_source("example.html", "{L_HELLO} {NAME} {{ NAME|e }}", &mut context, &Strings)
//!     .unwrap();
//!
//! assert_eq!(output.html, "Hello <b>Naruto</b> &lt;b&gt;Naruto&lt;/b&gt;");
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod context;
mod expr;
mod parser;
mod render;
mod value;

#[cfg(test)]
pub(crate) use fador_testutil as testutil;

#[cfg(test)]
mod security_tests;

pub use context::Context;
pub use expr::Expr;
pub use parser::{parse, AssetKind, Node, ParseError};
pub use value::Value;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The application services a template can call while it renders.
///
/// The compiler does not know about languages, routes or board URLs; the host
/// supplies them. Implementations must be cheap enough to call per output
/// expression and must not panic.
pub trait Runtime {
    /// Resolve a language key such as `HELLO` to text. `args` are the
    /// additional arguments of a `lang('KEY', ...)` call.
    fn lang(&self, key: &str, args: &[Value]) -> String;

    /// Report whether a language key exists, for `lang_defined('KEY')`.
    fn lang_defined(&self, key: &str) -> bool;

    /// Build a board-relative route for `path('route', params)`.
    fn path(&self, route: &str, params: &Value) -> String;

    /// Build an absolute URL for `url('route', params)`.
    fn url(&self, route: &str, params: &Value) -> String;
}

/// The JavaScript files and stylesheets a template asked for.
///
/// `<!-- INCLUDEJS -->`, `<!-- INCLUDECSS -->`, `{% INCLUDEJS %}`, `{%
/// INCLUDECSS %}` and included or event templates append to the bag. Duplicate
/// and empty entries are dropped, so a page can merge the bags of several
/// renders without a second pass.
#[derive(Debug, Default, Clone)]
pub struct AssetBag {
    /// JavaScript paths in first-use order.
    pub javascript: Vec<String>,
    /// Stylesheet paths in first-use order.
    pub stylesheets: Vec<String>,
}

impl AssetBag {
    /// Add a JavaScript path unless it is empty or already present.
    pub fn add_javascript(&mut self, value: String) {
        if !value.is_empty() && !self.javascript.contains(&value) {
            self.javascript.push(value);
        }
    }

    /// Add a stylesheet path unless it is empty or already present.
    pub fn add_stylesheet(&mut self, value: String) {
        if !value.is_empty() && !self.stylesheets.contains(&value) {
            self.stylesheets.push(value);
        }
    }
}

/// One finished render: the HTML body and the assets it referenced.
#[derive(Debug, Clone)]
pub struct RenderOutput {
    /// The rendered body. Values are not escaped unless the template asked for
    /// it; see the crate documentation.
    pub html: String,
    /// Assets requested by the rendered template, its includes and its event
    /// templates.
    pub assets: AssetBag,
}

/// A compile or render failure.
///
/// The message already names the template when the engine knows it, so callers
/// can log it as-is. Errors never carry a rendered body or a partial asset bag.
#[derive(Debug)]
pub struct TemplateError {
    /// Human-readable diagnostic. It never contains file contents.
    pub message: String,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TemplateError {}

impl From<ParseError> for TemplateError {
    fn from(value: ParseError) -> Self {
        Self {
            message: value.message,
        }
    }
}

impl TemplateError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct Template {
    nodes: Vec<Node>,
}

/// A compiled-template cache bound to an ordered list of template roots.
///
/// The engine compiles a template on first use and keeps the AST in an internal
/// map keyed by the name it was requested under. The map is behind a mutex, so
/// one engine can serve several worker threads; [`Engine::clear_cache`] drops
/// every entry after a template file or style change.
///
/// Lookup order is the order of the directory list passed to [`Engine::new`]:
/// the first directory that contains a readable file wins. Names are sandboxed
/// per directory, and event templates come from a separate list so a board
/// template can never shadow an extension event file.
pub struct Engine {
    dirs: Vec<PathBuf>,
    event_dirs: Vec<PathBuf>,
    cache: Mutex<HashMap<String, Arc<Template>>>,
    max_include_depth: usize,
}

impl Engine {
    /// Create an engine that loads templates from `dirs`, in priority order.
    ///
    /// The include depth limit is 64; deeper recursion is a
    /// [`TemplateError`].
    pub fn new(dirs: Vec<PathBuf>) -> Self {
        Self {
            dirs,
            event_dirs: Vec::new(),
            cache: Mutex::new(HashMap::new()),
            max_include_depth: 64,
        }
    }

    /// Set the directories searched by `<!-- EVENT name -->`.
    ///
    /// An event template is `<dir>/<name>.html`. Every directory that contains
    /// the file contributes output, in list order, which is how phpBB merges
    /// several extensions listening to the same event.
    pub fn with_event_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.event_dirs = dirs;
        self
    }

    /// The template roots this engine searches, in priority order.
    pub fn template_dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// Drop every cached AST, including cached event templates.
    ///
    /// Call this after a template file changes; the engine does not stat files
    /// on a cache hit.
    pub fn clear_cache(&self) {
        self.cache
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    /// Load, compile (once) and render the named template.
    ///
    /// The name is resolved against the configured roots and sandboxed; see the
    /// crate documentation for the rules.
    pub fn render(
        &self,
        name: &str,
        context: &mut Context,
        runtime: &dyn Runtime,
    ) -> Result<RenderOutput, TemplateError> {
        let template = self.load(name)?;
        let mut output = RenderOutput {
            html: String::new(),
            assets: AssetBag::default(),
        };
        self.render_template(&template, context, runtime, &mut output, 0)?;
        Ok(output)
    }

    /// Compile and render an inline source, without touching the cache or disk.
    ///
    /// `name` only labels errors and the recursion it triggers still resolves
    /// includes through this engine's directories. This is the entry point for
    /// administrator-supplied tag templates and for tests.
    pub fn render_source(
        &self,
        name: &str,
        source: &str,
        context: &mut Context,
        runtime: &dyn Runtime,
    ) -> Result<RenderOutput, TemplateError> {
        let nodes =
            parse(source).map_err(|error| TemplateError::new(format!("{name}: {error}")))?;
        let template = Template { nodes };
        let mut output = RenderOutput {
            html: String::new(),
            assets: AssetBag::default(),
        };
        self.render_template(&template, context, runtime, &mut output, 0)?;
        Ok(output)
    }

    /// Compile `source` and discard the AST, reporting only syntax errors.
    ///
    /// This is the validation hook for the ACP: it applies the same nesting,
    /// expression and tag rules as [`Engine::render_source`] but evaluates
    /// nothing and never reads a file.
    pub fn validate_source(&self, name: &str, source: &str) -> Result<(), TemplateError> {
        parse(source)
            .map(|_| ())
            .map_err(|error| TemplateError::new(format!("{name}: {error}")))
    }

    fn load(&self, name: &str) -> Result<Arc<Template>, TemplateError> {
        if let Some(template) = self
            .cache
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(name)
            .cloned()
        {
            return Ok(template);
        }
        let relative = sanitize_template_name(name)?;
        let mut last_error = None;
        for dir in &self.dirs {
            let Some(path) = resolve_inside_dir(dir, &relative) else {
                continue;
            };
            match fs::read_to_string(&path) {
                Ok(source) => {
                    return self.compile_from_source(&path, name, &source);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    last_error = Some(error);
                }
                Err(error) => {
                    return Err(TemplateError::new(format!("{}: {error}", path.display())));
                }
            }
        }
        Err(TemplateError::new(format!(
            "template {name:?} not found{}",
            last_error
                .map(|error| format!(" ({error})"))
                .unwrap_or_default()
        )))
    }

    fn render_template(
        &self,
        template: &Template,
        context: &mut Context,
        runtime: &dyn Runtime,
        output: &mut RenderOutput,
        depth: usize,
    ) -> Result<(), TemplateError> {
        if depth > self.max_include_depth {
            return Err(TemplateError::new("template include depth exceeded"));
        }
        render::render_nodes(
            &template.nodes,
            context,
            runtime,
            &mut output.html,
            &mut output.assets,
            depth,
            self,
        )
    }

    pub(crate) fn render_include(
        &self,
        name: &str,
        context: &mut Context,
        runtime: &dyn Runtime,
        output: &mut RenderOutput,
        depth: usize,
    ) -> Result<(), TemplateError> {
        let template = self.load(name)?;
        self.render_template(&template, context, runtime, output, depth)
    }

    pub(crate) fn render_event(
        &self,
        name: &str,
        context: &mut Context,
        runtime: &dyn Runtime,
        output: &mut RenderOutput,
        depth: usize,
    ) -> Result<(), TemplateError> {
        if name.is_empty()
            || name.contains("..")
            || name.contains('/')
            || name.contains('\\')
            || name.contains('\0')
        {
            return Err(TemplateError::new(format!(
                "invalid event template name {name:?}"
            )));
        }
        for dir in &self.event_dirs {
            let path = dir.join(format!("{name}.html"));
            if !path.is_file() {
                continue;
            }
            let Some(path) = resolve_inside_dir(dir, Path::new(&format!("{name}.html"))) else {
                return Err(TemplateError::new(format!(
                    "event template {name:?} escapes its directory"
                )));
            };
            let key = format!("@event:{}", path.display());
            if let Some(template) = self
                .cache
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(&key)
                .cloned()
            {
                self.render_template(&template, context, runtime, output, depth)?;
                continue;
            }
            let source = fs::read_to_string(&path)
                .map_err(|error| TemplateError::new(format!("{}: {error}", path.display())))?;
            let template = self.compile_from_source(&path, &key, &source)?;
            self.render_template(&template, context, runtime, output, depth)?;
        }
        Ok(())
    }

    fn compile_from_source(
        &self,
        path: &Path,
        cache_key: &str,
        source: &str,
    ) -> Result<Arc<Template>, TemplateError> {
        let nodes = parse(source)
            .map_err(|error| TemplateError::new(format!("{}: {error}", path.display())))?;
        let template = Arc::new(Template { nodes });
        self.cache
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(cache_key.to_string(), Arc::clone(&template));
        Ok(template)
    }
}

/// Resolve `relative` under `dir`, following symlinks, and require the result
/// to stay inside the canonical directory.  A style tree may contain a symlink
/// that points at `/etc`, and `read_to_string` would happily follow it.
fn resolve_inside_dir(dir: &Path, relative: &Path) -> Option<PathBuf> {
    let root = dir.canonicalize().ok()?;
    let candidate = dir.join(relative);
    let path = candidate.canonicalize().ok()?;
    if path.starts_with(&root) && path.is_file() {
        Some(path)
    } else {
        None
    }
}

fn sanitize_template_name(name: &str) -> Result<PathBuf, TemplateError> {
    if name.is_empty()
        || name.contains('\0')
        || name.contains('\\')
        || name.starts_with('/')
        || name.starts_with('\\')
    {
        return Err(TemplateError::new(format!(
            "invalid template name {name:?}"
        )));
    }
    let path = Path::new(name);
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            _ => {
                return Err(TemplateError::new(format!(
                    "invalid template name {name:?}"
                )))
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(TemplateError::new(format!(
            "invalid template name {name:?}"
        )));
    }
    Ok(clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRuntime;

    impl Runtime for TestRuntime {
        fn lang(&self, key: &str, _args: &[Value]) -> String {
            match key {
                "COLON" => ":".into(),
                "HELLO" => "Hei".into(),
                other => other.into(),
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

    fn engine() -> Engine {
        Engine::new(Vec::new())
    }

    #[test]
    fn renders_legacy_and_twig_constructs() {
        let mut context = Context::new();
        context.set("NAME", Value::Str("Naruto".into()));
        context.set("S_IS_BOT", Value::Bool(false));
        context.set(
            "rows",
            Value::Array(vec![
                Value::object([("NAME".into(), Value::Str("one".into()))]),
                Value::object([("NAME".into(), Value::Str("two".into()))]),
            ]),
        );
        context.set(
            "fields",
            Value::Array(vec![Value::object([(
                "NAME".into(),
                Value::Str("field".into()),
            )])]),
        );
        let source = "\
{NAME}\
<!-- IF S_IS_BOT -->bot<!-- ELSE -->human<!-- ENDIF -->\
<!-- BEGIN rows -->[{rows.NAME}:{rows.S_ROW_COUNT}<!-- IF rows.S_LAST_ROW -->!<!-- ENDIF -->]<!-- END rows -->\
{% for field in fields %}{{ field.NAME }}{% endfor %}\
{% apply spaceless %}<b> a </b> <i> b </i>{% endapply %}\
{L_HELLO}{L_COLON}";
        let output = engine()
            .render_source("test.html", source, &mut context, &TestRuntime)
            .unwrap();
        assert_eq!(
            output.html,
            "Narutohuman[one:0][two:1!]field<b> a </b><i> b </i>Hei:"
        );
    }

    #[test]
    fn renders_nested_legacy_blocks_and_else() {
        let mut context = Context::new();
        context.set(
            "forumrow",
            Value::Array(vec![Value::object([
                ("NAME".into(), Value::Str("F".into())),
                (
                    "subforum".into(),
                    Value::Array(vec![Value::object([(
                        "NAME".into(),
                        Value::Str("S".into()),
                    )])]),
                ),
            ])]),
        );
        let source = "<!-- BEGIN forumrow -->{forumrow.NAME}:<!-- BEGIN subforum -->{forumrow.subforum.NAME}<!-- END subforum --><!-- END forumrow -->";
        let output = engine()
            .render_source("nested.html", source, &mut context, &TestRuntime)
            .unwrap();
        assert_eq!(output.html, "F:S");
    }

    #[test]
    fn renders_block_else_and_dynamic_include() {
        let dir = std::env::temp_dir().join(format!(
            "fador-phpbb-template-include-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("inc.html"), "included").unwrap();
        let engine = Engine::new(vec![dir.clone()]);
        let mut context = Context::new();
        context.set("ROWS", Value::Array(Vec::new()));
        context.set("FILE", Value::Str("inc.html".into()));
        let source =
            "<!-- BEGIN rows -->x<!-- BEGINELSE -->empty<!-- END rows -->|<!-- INCLUDE {FILE} -->";
        let output = engine
            .render_source("main.html", source, &mut context, &TestRuntime)
            .unwrap();
        assert_eq!(output.html, "empty|included");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn renders_event_templates_and_collects_assets() {
        let dir = std::env::temp_dir().join(format!(
            "fador-phpbb-template-events-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("event")).unwrap();
        fs::write(dir.join("event/footer.html"), "event-{NAME}").unwrap();
        let engine = Engine::new(Vec::new()).with_event_dirs(vec![dir.join("event")]);
        let mut context = Context::new();
        context.set("NAME", Value::Str("x".into()));
        let source =
            "<!-- EVENT footer --><!-- INCLUDEJS forum_fn.js --><!-- INCLUDECSS theme.css -->";
        let output = engine
            .render_source("main.html", source, &mut context, &TestRuntime)
            .unwrap();
        assert_eq!(output.html, "event-x");
        assert_eq!(output.assets.javascript, vec!["forum_fn.js"]);
        assert_eq!(output.assets.stylesheets, vec!["theme.css"]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Validate a whole style tree when the caller points at one.
    ///
    /// The phpBB templates themselves are GPL content and live with the
    /// application, not in this crate, so the test is opt-in:
    ///
    /// ```text
    /// FADOR_PHPBB_TEMPLATE_CORPUS=/path/to/styles/prosilver/template cargo test
    /// ```
    #[test]
    fn compiles_an_optional_external_template_corpus() {
        let Ok(dir) = std::env::var("FADOR_PHPBB_TEMPLATE_CORPUS") else {
            return;
        };
        let dir = PathBuf::from(dir);
        if !dir.is_dir() {
            return;
        }
        let engine = engine();
        let mut count = 0usize;
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("html") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let source = fs::read_to_string(&path).unwrap();
            engine
                .validate_source(&name, &source)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            count += 1;
        }
        assert!(count > 0, "corpus directory held no templates");
    }

    #[test]
    fn block_tags_consume_one_following_newline() {
        let output = render_source("A\n<!-- IF X -->yes<!-- ENDIF -->\nB");
        assert_eq!(output, "A\nyesB");
        let output = render_source("A\n{% if X %}\nyes\n{% endif %}\nB");
        assert_eq!(output, "A\nyes\nB");
        let output = render_source("A\n{{ X }}\nB");
        assert_eq!(output, "A\n1\nB");
    }

    fn render_source(source: &str) -> String {
        let mut context = Context::new();
        context.set("X", Value::Bool(true));
        engine()
            .render_source("test.html", source, &mut context, &TestRuntime)
            .unwrap()
            .html
    }

    #[test]
    fn spaceless_trims_and_collapses_whitespace_between_tags() {
        let output =
            render_source("{% apply spaceless %}\n  <b> a </b>\n  <i> b </i>\n{% endapply %}X");
        assert_eq!(output, "<b> a </b><i> b </i>X");
    }

    #[test]
    fn legacy_variables_fall_back_from_defines_to_globals() {
        let mut context = Context::new();
        context.set("SCRIPTS", Value::Str("global".into()));
        context.set_local("$LOCAL", Value::Str("local".into()));
        let output = engine()
            .render_source(
                "test.html",
                "{$SCRIPTS}|{$LOCAL}",
                &mut context,
                &TestRuntime,
            )
            .unwrap();
        assert_eq!(output.html, "global|local");
    }

    #[test]
    fn legacy_language_variables_fall_back_to_the_runtime() {
        let mut context = Context::new();
        let output = engine()
            .render_source(
                "test.html",
                "{L_HELLO}|{LA_HELLO}|{L_UNKNOWN_KEY}",
                &mut context,
                &TestRuntime,
            )
            .unwrap();
        assert_eq!(output.html, "Hei|Hei|UNKNOWN_KEY");
    }

    fn render_escaped(template: &str) -> String {
        let mut context = Context::new();
        context.set("VALUE", Value::Str("<b>\"x\" & 'y'</b>".into()));
        engine()
            .render_source("escape.html", template, &mut context, &TestRuntime)
            .unwrap()
            .html
    }

    #[test]
    fn values_are_inserted_raw_by_default_like_phpbb() {
        assert_eq!(
            render_escaped("{VALUE}"),
            "<b>\"x\" & 'y'</b>",
            "legacy output must not escape"
        );
        assert_eq!(
            render_escaped("{{ VALUE }}"),
            "<b>\"x\" & 'y'</b>",
            "twig output must not escape"
        );
        assert_eq!(
            render_escaped("{% set raw = VALUE %}{{ raw }}"),
            "<b>\"x\" & 'y'</b>"
        );
    }

    #[test]
    fn html_escaping_is_opt_in_through_the_e_filter() {
        assert_eq!(
            render_escaped("{{ VALUE|e }}"),
            "&lt;b&gt;&quot;x&quot; &amp; &#039;y&#039;&lt;/b&gt;"
        );
        assert_eq!(
            render_escaped("{{ VALUE|e('html') }}"),
            "&lt;b&gt;&quot;x&quot; &amp; &#039;y&#039;&lt;/b&gt;"
        );
        assert_eq!(
            render_escaped("{{ VALUE|escape }}").matches("&lt;").count(),
            2
        );
    }

    #[test]
    fn html_attr_escaping_uses_named_and_hexadecimal_entities() {
        assert_eq!(
            render_escaped("{{ VALUE|e('html_attr') }}"),
            "&lt;b&gt;&quot;x&quot;&#x20;&amp;&#x20;&#x27;y&#x27;&lt;&#x2F;b&gt;"
        );
    }

    #[test]
    fn js_escaping_produces_a_safe_string_literal() {
        assert_eq!(
            render_escaped("{{ VALUE|e('js') }}"),
            "\\u003Cb\\u003E\\\"x\\\" \\u0026 \\'y\\'\\u003C/b\\u003E"
        );
        // The legacy `LA_` form always applies the JavaScript strategy.
        assert_eq!(render_escaped("{LA_HELLO}"), "Hei");
    }

    #[test]
    fn exposes_defined_variables_through_definition_path() {
        let mut context = Context::new();
        let output = engine()
            .render_source(
                "test.html",
                "{% DEFINE COLSPAN = 4 %}{{ definition.COLSPAN }}",
                &mut context,
                &TestRuntime,
            )
            .unwrap();
        assert_eq!(output.html, "4");
    }

    #[test]
    fn rejects_path_traversal_in_include_names() {
        let engine = engine();
        let mut context = Context::new();
        context.set("FILE", Value::Str("../secret.html".into()));
        let source = "<!-- INCLUDE {FILE} -->";
        assert!(engine
            .render_source("main.html", source, &mut context, &TestRuntime)
            .is_err());
    }
}
