//! Facade and prelude for the fador Rust helpers.
//!
//! Each sub-crate is re-exported as a module, so a consumer can depend on one
//! crate and enable only the pieces it needs:
//!
//! ```toml
//! [dependencies]
//! fador = { version = "0.1", default-features = false, features = ["http", "mysql"] }
//! ```
//!
//! ```
//! use fador::prelude::*;
//!
//! let response = Response::text(200, "OK", "hello".to_string());
//! assert_eq!(response.status, 200);
//! ```
//!
//! The facade adds no code of its own. Every module is the independently
//! versioned crate of the same name.

#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "auth")]
pub use fador_auth as auth;
#[cfg(feature = "compress")]
pub use fador_compress as compress;
#[cfg(feature = "core")]
pub use fador_core as core;
#[cfg(feature = "http")]
pub use fador_http as http;
#[cfg(feature = "i18n")]
pub use fador_i18n as i18n;
#[cfg(feature = "markup")]
pub use fador_markup as markup;
#[cfg(feature = "mysql")]
pub use fador_mysql as mysql;
#[cfg(feature = "phpbb-template")]
pub use fador_phpbb_template as phpbb_template;
#[cfg(feature = "services")]
pub use fador_services as services;
#[cfg(feature = "smf-theme")]
pub use fador_smf_theme as smf_theme;
#[cfg(feature = "thumbnails")]
pub use fador_thumb as thumb;
#[cfg(feature = "wikitext")]
pub use fador_wikitext as wikitext;

/// The types most applications start with.
///
/// Every item is feature gated; the prelude only exposes what the selected
/// facade features compiled.
pub mod prelude {
    #[cfg(feature = "auth")]
    pub use crate::auth::{
        BanRule, CookieCodec, CsrfTokens, PasswordVerifier, SessionId, SessionPolicy,
    };
    #[cfg(feature = "compress")]
    pub use crate::compress::{gzip_compress, inflate, zlib_compress};
    #[cfg(feature = "core")]
    pub use crate::core::{json::Json, multipart::Part, random::RandomError, TimedCache};
    #[cfg(feature = "http")]
    pub use crate::http::{accepts_gzip, Body, Handler, HttpConfig, Request, Response, Server};
    #[cfg(feature = "i18n")]
    pub use crate::i18n::{
        format_date_php, format_placeholders, plural_form, LanguagePack, LanguageSet, Tzdb,
    };
    #[cfg(feature = "markup")]
    pub use crate::markup::{
        escape, highlight_html, is_safe_url, Censor, EscapePolicy, SchemePolicy,
    };
    #[cfg(feature = "mysql")]
    pub use crate::mysql::{MysqlParams, Pool, QueryResult, Row, SqlValue};
    #[cfg(feature = "phpbb-template")]
    pub use crate::phpbb_template::{Context, Engine, Runtime, Value};
    #[cfg(feature = "smf-theme")]
    pub use crate::smf_theme::{EvalLimits, Evaluator, TemplateEngine};
    #[cfg(feature = "thumbnails")]
    pub use crate::thumb::{plan, render, scaled_size, ThumbnailSettings};
    #[cfg(feature = "wikitext")]
    pub use crate::wikitext::{Parser, ParserConfig, Title, WikiResolver};
}
