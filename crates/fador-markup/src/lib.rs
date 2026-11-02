//! Dependency-free markup leaf helpers.
//!
//! `fador-markup` collects the small decisions every markup pipeline makes at
//! its edges: escaping text for HTML or XML, refusing unsafe URL schemes,
//! censoring words, matching smiley codes, stripping tags down to plain text
//! and highlighting search keywords without breaking tags or UTF-8.
//!
//! It is deliberately **not** a renderer. BBCode, wikitext and stored-XML
//! parsers stay in the servers that own them; this crate holds the pieces they
//! all share, with no database, template or HTTP knowledge.
//!
//! ```
//! use fador_markup::{
//!     escape, highlight_html, is_safe_url, strip_markup, EscapePolicy, SchemePolicy,
//! };
//!
//! assert_eq!(
//!     escape(EscapePolicy::Text, "<b>hi</b>"),
//!     "&lt;b&gt;hi&lt;/b&gt;"
//! );
//! assert!(!is_safe_url("javascript:alert(1)", &SchemePolicy::STRICT));
//! assert_eq!(strip_markup("<p>one</p><p>two</p>"), "one\ntwo\n");
//! assert_eq!(
//!     highlight_html("<b>fox</b>", &["fox"]),
//!     "<b><strong class=\"highlight\">fox</strong></b>"
//! );
//! ```
//!
//! # Design rules
//!
//! - Standard library only.
//! - No parser state, no I/O, no allocation hidden behind a `&str` return type
//!   that the caller did not ask for.
//! - Every scanner is bounded: a tag, a character reference and a reference
//!   name all have a maximum length, and highlighting has a range cap.
//! - Case-insensitive matching keeps byte offsets in the original string, so a
//!   lowercasing that changes byte length can never split a `&str` slice.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod censor;
mod code;
mod escape;
mod fold;
mod highlight;
mod html;
mod strip;
mod url;

pub use censor::{Censor, CensorBoundary};
pub use code::{
    match_longest_code, replace_codes, smiley_boundary_after, smiley_boundary_before, strtr,
};
pub use escape::{
    decode_entities, decode_entities_bounded, escape, escape_into, unescape_compat, EscapePolicy,
};
pub use highlight::{excerpt, highlight_html, highlight_segment, HIGHLIGHT_CLOSE, HIGHLIGHT_OPEN};
pub use html::{
    is_allowed_attr, is_url_attribute, is_void_element, sanitize_style, MAX_STYLE_LENGTH,
};
pub use strip::strip_markup;
pub use url::{is_safe_url, neutralise_url, sanitize_url, SchemePolicy};
