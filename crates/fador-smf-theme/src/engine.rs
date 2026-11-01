//! SMF theme resolution, template loading and the sandboxed render bridge.
//!
//! A theme directory is resolved from the protected content tree. Only
//! `*.template.php` files under that tree are parsed, and every path is
//! canonicalised before it is read, so a symlink cannot escape the tree.
//!
//! Parsed templates are cached by canonical path, modification time and size,
//! so an edited template is reloaded on the next render while an unchanged one
//! is parsed once. The cache is bounded and shared by every thread that holds
//! the engine.
//!
//! A page is rendered the way SMF renders it: `template_init()` when the theme
//! defines one, then every `template_<layer>_above` in layer order, the page's
//! main function, then the `template_<layer>_below` functions in reverse
//! order. A template file the theme does not ship falls back to the default
//! theme, which is how a child theme overrides only the files it changes.

use crate::eval::{EvalError, EvalLimits, Evaluator};
use crate::host::HostFunctions;
use crate::smf::SmfFunctions;
use crate::value::{Key, PhpArray, Value};
use crate::Stmt;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::UNIX_EPOCH;

/// A registered theme.
///
/// `directory` is the canonical theme directory inside the engine's content
/// root; the URL fields are informational and are only passed on to the
/// controller that builds the template globals.
#[derive(Debug, Clone)]
pub struct Theme {
    /// Theme name as the board stores it, for example `default`.
    pub name: String,
    /// Canonical directory holding the `*.template.php` files.
    pub directory: PathBuf,
    /// Public URL of the theme directory.
    pub url: String,
    /// Public URL of the theme's images.
    pub images_url: String,
    /// Layer names in render order, for example `["html", "body"]`.
    pub layers: Vec<String>,
    /// Template files the theme ships, without the `.template.php` suffix.
    pub templates: Vec<String>,
}

/// A theme that could not be resolved, parsed or rendered.
#[derive(Debug)]
pub enum TemplateError {
    /// Reading a template file failed.
    Io(String),
    /// The template is not valid in the supported PHP subset.
    Parse(String),
    /// The template parsed but failed to evaluate, or exceeded a limit.
    Eval(String),
    /// A theme, template file or template function does not exist.
    NotFound(String),
    /// A name or directory was rejected by the sandbox.
    Invalid(String),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateError::Io(message) => write!(f, "template I/O: {message}"),
            TemplateError::Parse(message) => write!(f, "template parse: {message}"),
            TemplateError::Eval(message) => write!(f, "template evaluation: {message}"),
            TemplateError::NotFound(message) => write!(f, "template not found: {message}"),
            TemplateError::Invalid(message) => write!(f, "template error: {message}"),
        }
    }
}

impl std::error::Error for TemplateError {}

impl From<EvalError> for TemplateError {
    fn from(error: EvalError) -> Self {
        TemplateError::Eval(error.to_string())
    }
}

/// A [`HostFunctions`] implementation that provides nothing.
///
/// Installed by [`TemplateEngine::without_host`] when a caller wants the
/// language core only.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHostFunctions;

impl HostFunctions for NoHostFunctions {
    fn has(&self, _name: &str) -> bool {
        false
    }

    fn call(
        &mut self,
        _name: &str,
        _args: Vec<Value>,
        _context: &mut dyn crate::host::HostContext,
    ) -> Option<Result<Value, String>> {
        None
    }
}

struct CachedTemplate {
    modified: u128,
    size: u64,
    statements: Arc<Vec<Stmt>>,
}

/// Builds the host functions for one render.
///
/// A fresh instance per render keeps [`TemplateEngine`] free of interior
/// mutability and lets several threads render at once.
pub type HostFactory = Arc<dyn Fn() -> Box<dyn HostFunctions> + Send + Sync>;

/// Upper bound on the parse cache. The stock theme has ~60 templates; the
/// bound only matters if an administrator installs many themes at runtime.
const MAX_CACHED_TEMPLATES: usize = 512;
const MAX_RESOLVED_PATHS: usize = 512;

/// Parse-cache counters for the benchmark and the cache unit tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TemplateCacheStats {
    /// Renders that reused a parsed template.
    pub hits: u64,
    /// Renders that had to read and parse a template.
    pub misses: u64,
    /// Templates currently cached.
    pub entries: usize,
}

/// Resolves SMF themes and renders their templates.
///
/// One engine is shared by every request: the theme map, the parse cache and
/// the resolved-path cache are behind locks, and each render creates its own
/// [`Evaluator`] and host functions.
pub struct TemplateEngine {
    root: PathBuf,
    themes: RwLock<HashMap<String, Theme>>,
    default_theme: String,
    cache: RwLock<HashMap<PathBuf, CachedTemplate>>,
    /// Constructed theme path -> canonical path. The containment check runs
    /// once per file; later requests only stat the canonical path.
    resolved: RwLock<HashMap<PathBuf, PathBuf>>,
    limits: EvalLimits,
    host: HostFactory,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

impl TemplateEngine {
    /// Create an engine for `root`, with `default_theme` as the fallback.
    ///
    /// `root` must exist and is canonicalised; every theme directory is
    /// required to resolve inside it. The engine starts with the SMF theme
    /// functions installed; use [`TemplateEngine::without_host`] or
    /// [`TemplateEngine::with_host_factory`] to change that.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::Io`] when `root` cannot be canonicalised and
    /// [`TemplateError::Invalid`] when it is not a directory.
    pub fn new(
        root: impl AsRef<Path>,
        default_theme: &str,
        limits: EvalLimits,
    ) -> Result<Self, TemplateError> {
        let root = fs::canonicalize(root.as_ref())
            .map_err(|error| TemplateError::Io(format!("{}: {error}", root.as_ref().display())))?;
        if !root.is_dir() {
            return Err(TemplateError::Invalid(format!(
                "content root {} is not a directory",
                root.display()
            )));
        }
        Ok(Self {
            root,
            themes: RwLock::new(HashMap::new()),
            default_theme: default_theme.to_string(),
            cache: RwLock::new(HashMap::new()),
            resolved: RwLock::new(HashMap::new()),
            limits,
            host: Arc::new(|| Box::new(SmfFunctions)),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        })
    }

    /// Replace the factory that builds the host functions of every render.
    pub fn with_host_factory(mut self, factory: HostFactory) -> Self {
        self.host = factory;
        self
    }

    /// Render with the language core only: no host functions are installed.
    pub fn without_host(mut self) -> Self {
        self.host = Arc::new(|| Box::new(NoHostFunctions));
        self
    }

    /// Parse-cache counters.
    pub fn stats(&self) -> TemplateCacheStats {
        TemplateCacheStats {
            hits: self.cache_hits.load(Ordering::Relaxed),
            misses: self.cache_misses.load(Ordering::Relaxed),
            entries: self.cache.read().map(|cache| cache.len()).unwrap_or(0),
        }
    }

    /// Reset the hit and miss counters. The cached templates stay.
    pub fn reset_stats(&self) {
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
    }

    /// Drop every parsed template.
    ///
    /// Not needed after a file edit (the cache checks the modification time
    /// and size), but useful after a bulk theme update.
    pub fn clear_cache(&self) {
        self.cache
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
        self.resolved
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }

    /// Register a theme directory.
    ///
    /// A relative directory is resolved against the content root. The
    /// canonical result must stay inside the root, so a theme entry cannot
    /// point at `/etc`. Registering the same name and directory twice is a
    /// no-op.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::Invalid`] for an invalid name or a directory
    /// outside the root, and [`TemplateError::Io`] when it cannot be
    /// canonicalised.
    pub fn add_theme(&self, theme: Theme) -> Result<(), TemplateError> {
        if !valid_name(&theme.name) {
            return Err(TemplateError::Invalid(format!(
                "invalid theme name {:?}",
                theme.name
            )));
        }
        if let Ok(themes) = self.themes.read() {
            if let Some(existing) = themes.get(&theme.name) {
                if existing.directory == theme.directory {
                    return Ok(());
                }
            }
        }
        let directory = if theme.directory.is_absolute() {
            theme.directory.clone()
        } else {
            self.root.join(&theme.directory)
        };
        let canonical = fs::canonicalize(&directory)
            .map_err(|error| TemplateError::Io(format!("{}: {error}", directory.display())))?;
        if !canonical.starts_with(&self.root) {
            return Err(TemplateError::Invalid(format!(
                "theme directory {} escapes the content tree",
                directory.display()
            )));
        }
        let mut themes = self
            .themes
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(existing) = themes.get(&theme.name) {
            if existing.directory == canonical {
                return Ok(());
            }
        }
        let mut theme = theme;
        theme.directory = canonical;
        themes.insert(theme.name.clone(), theme);
        Ok(())
    }

    /// A registered theme by name.
    pub fn theme(&self, name: &str) -> Option<Theme> {
        self.themes
            .read()
            .ok()
            .and_then(|themes| themes.get(name).cloned())
    }

    /// The theme used when a requested theme is not registered.
    pub fn default_theme(&self) -> Option<Theme> {
        self.theme(&self.default_theme)
    }

    /// Number of parsed templates currently cached.
    pub fn cache_len(&self) -> usize {
        self.cache.read().map(|cache| cache.len()).unwrap_or(0)
    }

    /// Render a single named function from one template file.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::NotFound`] when the theme, the template file
    /// or the function is missing, and a parse or evaluation error otherwise.
    pub fn render_function(
        &self,
        theme: &str,
        template: &str,
        function: &str,
        globals: Vec<(String, Value)>,
    ) -> Result<String, TemplateError> {
        let path = self.resolve(theme, template)?;
        let statements = self.load(&path)?;
        let mut evaluator = self.evaluator(globals);
        let _ = evaluator.execute(&statements)?;
        let _ = evaluator.take_output();
        if !evaluator.has_function(function) {
            return Err(TemplateError::NotFound(format!(
                "{} in {}",
                function,
                path.display()
            )));
        }
        evaluator.call(function, Vec::new())?;
        Ok(evaluator.take_output())
    }

    /// Render a page using SMF's layer order: every `template_<layer>_above`
    /// in order, the main function, then the layers' `_below` in reverse.
    ///
    /// `templates` lists every template file the controller loaded (the page
    /// template plus any layer templates such as `GenericMenu`). Missing layer
    /// functions are skipped, matching themes that do not define every layer.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::NotFound`] when the theme, a template file or
    /// `main_function` is missing, and a parse or evaluation error otherwise.
    pub fn render_page(
        &self,
        theme: &str,
        templates: &[&str],
        layers: &[String],
        main_function: &str,
        globals: Vec<(String, Value)>,
    ) -> Result<String, TemplateError> {
        let index_path = self.resolve(theme, "index")?;
        let index = self.load(&index_path)?;
        let mut loaded = Vec::new();
        for template in templates {
            let path = self.resolve(theme, template)?;
            loaded.push(self.load(&path)?);
        }
        let mut evaluator = self.evaluator(globals);
        let _ = evaluator.execute(&index)?;
        for parsed in &loaded {
            let _ = evaluator.execute(parsed)?;
        }
        let _ = evaluator.take_output();

        let mut output = String::new();
        if evaluator.has_function("template_init") {
            evaluator.call("template_init", Vec::new())?;
            output.push_str(&evaluator.take_output());
        }
        for layer in layers {
            let function = format!("template_{layer}_above");
            if !evaluator.has_function(&function) {
                continue;
            }
            evaluator.call(&function, Vec::new())?;
            output.push_str(&evaluator.take_output());
        }
        if !evaluator.has_function(main_function) {
            let file = templates.first().copied().unwrap_or("index").to_string();
            return Err(TemplateError::NotFound(format!(
                "{main_function} in {file}"
            )));
        }
        evaluator.call(main_function, Vec::new())?;
        output.push_str(&evaluator.take_output());
        for layer in layers.iter().rev() {
            let function = format!("template_{layer}_below");
            if !evaluator.has_function(&function) {
                continue;
            }
            evaluator.call(&function, Vec::new())?;
            output.push_str(&evaluator.take_output());
        }
        Ok(output)
    }

    /// Render one function from one template file without the page shell.
    ///
    /// Used by popups, which print their own document instead of using the
    /// html/body layers.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::NotFound`] when the theme, the template file
    /// or the function is missing, and a parse or evaluation error otherwise.
    pub fn render_function_page(
        &self,
        theme: &str,
        template: &str,
        function: &str,
        globals: Vec<(String, Value)>,
    ) -> Result<String, TemplateError> {
        self.render_function(theme, template, function, globals)
    }

    fn evaluator(&self, globals: Vec<(String, Value)>) -> Evaluator {
        let mut evaluator = Evaluator::new(self.limits.clone());
        evaluator.set_host((self.host)());
        for (name, value) in globals {
            evaluator.set_global(&name, value);
        }
        evaluator
    }

    fn resolve(&self, theme: &str, template: &str) -> Result<PathBuf, TemplateError> {
        if !valid_name(template) {
            return Err(TemplateError::Invalid(format!(
                "invalid template name {template:?}"
            )));
        }
        let themes = self
            .themes
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        let theme = themes
            .get(theme)
            .or_else(|| themes.get(&self.default_theme))
            .ok_or_else(|| TemplateError::NotFound(format!("theme {theme:?}")))?;
        let file = format!("{template}.template.php");
        let primary = theme.directory.join(&file);
        if primary.is_file() {
            return Ok(primary);
        }
        let default = themes
            .get(&self.default_theme)
            .ok_or_else(|| TemplateError::NotFound("default theme".into()))?;
        let fallback = default.directory.join(&file);
        if fallback.is_file() {
            return Ok(fallback);
        }
        Err(TemplateError::NotFound(file))
    }

    fn load(&self, path: &Path) -> Result<Arc<Vec<Stmt>>, TemplateError> {
        let canonical = {
            let resolved = self
                .resolved
                .read()
                .unwrap_or_else(|poison| poison.into_inner());
            resolved.get(path).cloned()
        };
        let canonical = match canonical {
            Some(canonical) => canonical,
            None => {
                let canonical = fs::canonicalize(path)
                    .map_err(|error| TemplateError::Io(format!("{}: {error}", path.display())))?;
                if !canonical.starts_with(&self.root) {
                    return Err(TemplateError::Invalid(format!(
                        "template {} escapes the content tree",
                        path.display()
                    )));
                }
                let mut resolved = self
                    .resolved
                    .write()
                    .unwrap_or_else(|poison| poison.into_inner());
                if resolved.len() >= MAX_RESOLVED_PATHS {
                    resolved.clear();
                }
                resolved.insert(path.to_path_buf(), canonical.clone());
                canonical
            }
        };
        let metadata = fs::metadata(&canonical)
            .map_err(|error| TemplateError::Io(format!("{}: {error}", canonical.display())))?;
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let size = metadata.len();
        if let Ok(cache) = self.cache.read() {
            if let Some(cached) = cache.get(&canonical) {
                if cached.modified == modified && cached.size == size {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(Arc::clone(&cached.statements));
                }
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let bytes = fs::read(&canonical)
            .map_err(|error| TemplateError::Io(format!("{}: {error}", canonical.display())))?;
        let text = decode_template(&bytes);
        let statements = crate::parse(&text)
            .map_err(|error| TemplateError::Parse(format!("{}: {error}", canonical.display())))?;
        let statements = Arc::new(statements);
        let mut cache = self
            .cache
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        if cache.len() >= MAX_CACHED_TEMPLATES {
            cache.clear();
        }
        cache.insert(
            canonical,
            CachedTemplate {
                modified,
                size,
                statements: Arc::clone(&statements),
            },
        );
        Ok(statements)
    }
}

/// Whether a theme or template name is a plain file name.
///
/// The name may not be empty, may only use `[A-Za-z0-9_.-]`, may not contain
/// `..`, and must be a single normal path component.
fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !value.contains("..")
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Decode a template as UTF-8, falling back to a byte-per-character mapping
/// so a Latin-1 theme still renders instead of failing.
fn decode_template(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|byte| char::from(*byte)).collect(),
    }
}

/// Build an array value from `(key, value)` pairs.
pub fn array(entries: Vec<(Key, Value)>) -> Value {
    let mut array = PhpArray::new();
    for (key, value) in entries {
        array.insert(key, value);
    }
    Value::from_array(array)
}

/// A string array key.
pub fn str_key(value: &str) -> Key {
    Key::Str(value.to_string())
}

/// An integer array key.
pub fn int_key(value: i64) -> Key {
    Key::Int(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "fador-smf-theme-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(path.join("Themes/default")).unwrap();
            Self(path)
        }

        fn write(&self, theme: &str, template: &str, source: &str) {
            let directory = self.0.join("Themes").join(theme);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join(format!("{template}.template.php")), source).unwrap();
        }

        fn engine(&self) -> TemplateEngine {
            let engine = TemplateEngine::new(&self.0, "default", EvalLimits::default()).unwrap();
            engine
                .add_theme(Theme {
                    name: "default".into(),
                    directory: PathBuf::from("Themes/default"),
                    url: String::new(),
                    images_url: String::new(),
                    layers: vec!["html".into(), "body".into()],
                    templates: vec!["index".into()],
                })
                .unwrap();
            engine
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn globals() -> Vec<(String, Value)> {
        vec![(
            "txt".to_string(),
            array(vec![
                (str_key("title"), Value::Str("Hello".into())),
                (str_key("greeting"), Value::Str("Hei".into())),
            ]),
        )]
    }

    #[test]
    fn renders_a_page_in_layer_order() {
        let scratch = Scratch::new("layers");
        scratch.write(
            "default",
            "index",
            "<?php
function template_init() { echo '[init]'; }
function template_html_above() { echo '[html]'; }
function template_body_above() { echo '[body]'; }
function template_main() { echo '[main]'; }
function template_body_below() { echo '[body-]'; }
function template_html_below() { echo '[html-]'; }
?>",
        );
        let engine = scratch.engine();
        let output = engine
            .render_page(
                "default",
                &["index"],
                &["html".into(), "body".into()],
                "template_main",
                globals(),
            )
            .unwrap();
        assert_eq!(output, "[init][html][body][main][body-][html-]");
    }

    #[test]
    fn renders_one_function_from_a_file() {
        let scratch = Scratch::new("function");
        scratch.write(
            "default",
            "index",
            "<?php function template_main() { global $txt; echo $txt['title']; } ?>",
        );
        let engine = scratch.engine();
        assert_eq!(
            engine
                .render_function("default", "index", "template_main", globals())
                .unwrap(),
            "Hello"
        );
        assert_eq!(
            engine
                .render_function_page("default", "index", "template_main", globals())
                .unwrap(),
            "Hello"
        );
        assert!(engine
            .render_function("default", "index", "template_missing", globals())
            .is_err());
    }

    #[test]
    fn a_theme_falls_back_to_the_default_theme_per_file() {
        let scratch = Scratch::new("fallback");
        scratch.write(
            "default",
            "index",
            "<?php function template_main() { echo 'default'; } ?>",
        );
        scratch.write(
            "default",
            "BoardIndex",
            "<?php function template_main() { echo 'default-board'; } ?>",
        );
        scratch.write(
            "child",
            "BoardIndex",
            "<?php function template_main() { echo 'child-board'; } ?>",
        );
        let engine = scratch.engine();
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
        // The child overrides BoardIndex but not index.
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
            "default"
        );
        // An unregistered theme name uses the default theme.
        assert_eq!(
            engine
                .render_function("missing", "index", "template_main", Vec::new())
                .unwrap(),
            "default"
        );
    }

    #[test]
    fn the_parse_cache_is_keyed_by_path_time_and_size() {
        let scratch = Scratch::new("cache");
        scratch.write(
            "default",
            "index",
            "<?php function template_probe() { echo 'one'; } ?>",
        );
        let engine = scratch.engine();
        assert_eq!(
            engine
                .render_function_page("default", "index", "template_probe", Vec::new())
                .unwrap(),
            "one"
        );
        assert_eq!(engine.stats().misses, 1);
        assert_eq!(
            engine
                .render_function_page("default", "index", "template_probe", Vec::new())
                .unwrap(),
            "one"
        );
        assert_eq!(engine.stats().misses, 1);
        assert!(engine.stats().hits >= 1);

        // The size differs, so the cache must notice even within the same
        // modification-time tick.
        scratch.write(
            "default",
            "index",
            "<?php function template_probe() { echo 'rewritten'; } ?>",
        );
        assert_eq!(
            engine
                .render_function_page("default", "index", "template_probe", Vec::new())
                .unwrap(),
            "rewritten"
        );
        assert_eq!(engine.stats().misses, 2);

        engine.reset_stats();
        assert_eq!(engine.stats().hits, 0);
        assert_eq!(engine.stats().misses, 0);
        assert_eq!(engine.stats().entries, 1);
        engine.clear_cache();
        assert_eq!(engine.cache_len(), 0);
    }

    #[test]
    fn adding_the_same_theme_is_idempotent() {
        let scratch = Scratch::new("idempotent");
        let engine = scratch.engine();
        for _ in 0..3 {
            engine
                .add_theme(Theme {
                    name: "default".into(),
                    directory: scratch.0.join("Themes/default"),
                    url: String::new(),
                    images_url: String::new(),
                    layers: vec!["html".into()],
                    templates: vec!["index".into()],
                })
                .unwrap();
        }
        assert_eq!(
            engine.theme("default").unwrap().directory,
            fs::canonicalize(scratch.0.join("Themes/default")).unwrap()
        );
        assert!(engine.default_theme().is_some());
    }

    #[test]
    fn rejects_traversal_and_directories_outside_the_root() {
        let scratch = Scratch::new("sandbox");
        scratch.write(
            "default",
            "index",
            "<?php function template_main() { echo 'x'; } ?>",
        );
        let engine = scratch.engine();
        assert!(engine
            .render_function("default", "../Settings", "template_main", Vec::new())
            .is_err());
        assert!(engine
            .render_function("default", "index", "template_main\0", Vec::new())
            .is_err());
        assert!(engine
            .add_theme(Theme {
                name: "escape".into(),
                directory: PathBuf::from(".."),
                url: String::new(),
                images_url: String::new(),
                layers: Vec::new(),
                templates: Vec::new(),
            })
            .is_err());
        assert!(engine
            .add_theme(Theme {
                name: "../bad".into(),
                directory: PathBuf::from("Themes/default"),
                url: String::new(),
                images_url: String::new(),
                layers: Vec::new(),
                templates: Vec::new(),
            })
            .is_err());
    }

    #[test]
    fn the_default_host_is_smf_and_can_be_replaced() {
        let scratch = Scratch::new("host");
        scratch.write(
            "default",
            "index",
            "<?php function template_main() { echo create_button('x.gif', 'title'); } ?>",
        );
        let engine = scratch.engine();
        // The default engine installs the SMF theme functions.
        assert!(engine
            .render_function("default", "index", "template_main", globals())
            .is_ok());
        // Without a host the same template is outside the allow-list.
        let bare = scratch.engine().without_host();
        let error = bare
            .render_function("default", "index", "template_main", globals())
            .unwrap_err();
        assert!(error.to_string().contains("allow-list"), "{error}");
    }

    #[test]
    fn a_parse_error_names_the_file() {
        let scratch = Scratch::new("parse");
        scratch.write("default", "index", "<?php function template_main() {");
        let engine = scratch.engine();
        let error = engine
            .render_function("default", "index", "template_main", Vec::new())
            .unwrap_err();
        assert!(matches!(error, TemplateError::Parse(_)));
        assert!(error.to_string().contains("index.template.php"), "{error}");
    }

    #[test]
    fn the_engine_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TemplateEngine>();
        assert_send_sync::<Theme>();
        assert_send_sync::<TemplateCacheStats>();
        assert_send_sync::<TemplateError>();
    }

    #[test]
    fn helpers_build_values_and_keys() {
        let value = array(vec![
            (int_key(0), Value::Int(1)),
            (str_key("a"), Value::Int(2)),
        ]);
        let array = value.as_array().unwrap();
        assert_eq!(array.borrow().len(), 2);
        assert_eq!(
            array.borrow().get(&Key::Int(0)).unwrap().borrow().to_int(),
            1
        );
        assert_eq!(
            array
                .borrow()
                .get(&Key::Str("a".into()))
                .unwrap()
                .borrow()
                .to_int(),
            2
        );
    }
}
