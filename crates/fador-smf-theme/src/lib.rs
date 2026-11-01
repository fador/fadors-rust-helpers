//! A sandboxed PHP-subset evaluator and the SMF theme resolver.
//!
//! SMF 2.x themes are PHP files: `*.template.php` mixes inline HTML with
//! `echo`, `if`, `foreach`, functions and array lookups. Rendering a board
//! page means running a small, well-understood part of PHP, so this crate
//! implements that part directly instead of embedding an interpreter.
//!
//! # Layers
//!
//! - [`parse`] turns a template into a [`Stmt`] tree. The lexer and parser are
//!   separate from evaluation, so a template can be compiled once and rendered
//!   many times.
//! - [`Evaluator`] executes the tree. It implements PHP's standard functions
//!   itself and exposes everything else through [`HostFunctions`], so the
//!   language core works without SMF and [`SmfFunctions`] adds the theme
//!   functions (`create_button()`, `allowedTo()`, `theme_copyright()`,
//!   `timeformat()`, ...).
//! - [`TemplateEngine`] resolves a theme directory, falls back to the default
//!   theme per file, caches parsed templates by canonical path, modification
//!   time and size, and renders pages in SMF's layer order.
//!
//! # Security
//!
//! A template is untrusted input. There is no filesystem, network, process,
//! object system or database access, and the callable set is a fixed
//! allow-list:
//!
//! - [`EvalLimits`] caps the steps, call depth, output bytes, string bytes and
//!   array entries of one execution;
//! - a function call only reaches a function the template declared, one of the
//!   PHP standard functions the evaluator implements, or a host function whose
//!   [`HostFunctions::has`] returns true;
//! - `preg_replace()` accepts three hard-coded patterns instead of a general
//!   regular-expression engine, so a template cannot make the server
//!   backtrack;
//! - theme and template names are validated and every path is canonicalised
//!   inside the content root, so a symlink cannot escape it;
//! - errors carry a message, never rendered output or file contents.
//!
//! # Example
//!
//! ```
//! use fador_smf_theme::{parse, EvalLimits, Evaluator, Value};
//!
//! let mut evaluator = Evaluator::new(EvalLimits::default());
//! evaluator.set_global("txt", Value::Str("Hello".into()));
//! let statements =
//!     parse("<?php function template_main() { global $txt; echo $txt, '!'; } ?>").unwrap();
//! evaluator.execute(&statements).unwrap();
//! evaluator.call("template_main", Vec::new()).unwrap();
//! assert_eq!(evaluator.take_output(), "Hello!");
//! ```
//!
//! Rendering an installed theme is the engine's job:
//!
//! ```no_run
//! use fador_smf_theme::{EvalLimits, TemplateEngine, Theme};
//! use std::path::PathBuf;
//!
//! let engine = TemplateEngine::new("/srv/board/original", "default", EvalLimits::default())?;
//! engine.add_theme(Theme {
//!     name: "default".into(),
//!     directory: PathBuf::from("Themes/default"),
//!     url: "/Themes/default".into(),
//!     images_url: "/Themes/default/images".into(),
//!     layers: vec!["html".into(), "body".into()],
//!     templates: vec!["index".into()],
//! })?;
//! let html = engine.render_page(
//!     "default",
//!     &["index", "BoardIndex"],
//!     &["html".into(), "body".into()],
//!     "template_main",
//!     Vec::new(),
//! )?;
//! # Ok::<(), fador_smf_theme::TemplateError>(())
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod builtins;
mod engine;
mod eval;
mod host;
mod lexer;
mod parser;
mod smf;
mod time;
mod value;

pub use engine::{
    array, int_key, str_key, HostFactory, NoHostFunctions, TemplateCacheStats, TemplateEngine,
    TemplateError, Theme,
};
pub use eval::{
    profile_results, profiling, reset_profile, set_profiling, EvalError, EvalLimits, Evaluator,
};
pub use host::{HostContext, HostFunctions};
pub use lexer::{tokenize, Token, TokenKind};
pub use parser::{parse, AssignOp, BinOp, CastType, Expr, Param, ParseError, Stmt, UnOp};
pub use smf::SmfFunctions;
pub use time::{format_time, timezone_offset_seconds, OffsetType, TimeSettings, TodayKind};
pub use value::{
    key_from_value, php_float_string, FunctionValue, Key, NativeFunction, PhpArray, Value,
};

/// `strftime` formatting with localized names, re-exported from `fador-i18n`.
pub use fador_i18n::format_strftime;
/// The day and month names `format_time` renders, re-exported from
/// `fador-i18n`.
pub use fador_i18n::TimeStrings;
