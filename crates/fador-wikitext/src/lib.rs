//! MediaWiki-compatible wikitext renderer.
//!
//! The renderer is a single-pass, bounded parser rather than a complete
//! reimplementation of Parsoid. It covers the constructs a typical wiki uses:
//! headings and a table of contents, paragraphs, nested lists, tables, links,
//! images, templates, magic words, categories, Cite references, `nowiki`/`pre`
//! and a sanitised subset of raw HTML.
//!
//! The parser owns no database, filesystem or configuration model. The caller
//! supplies three things:
//!
//! - a [`WikiResolver`] for page text, page existence, file metadata,
//!   category and namespace counts and site statistics;
//! - a [`ParserConfig`] for the script/article/upload paths, the interface
//!   language, the namespace table and the resource limits;
//! - a [`MessageSource`] for `{{int:...}}` and the interface strings the
//!   renderer itself emits.
//!
//! ```
//! use fador_wikitext::{MapMessages, MemoryResolver, Parser, ParserConfig, Title};
//!
//! let resolver = MemoryResolver::new().with_page(10, "Hello", "Hello, {{{1|world}}}!");
//! let config = ParserConfig::default()
//!     .with_script_path("/w")
//!     .with_article_path("/wiki/$1");
//! let messages = MapMessages::new();
//! let title = Title::new(0, "Sandbox");
//!
//! let result = Parser::render(&resolver, &config, &messages, &title, "{{Hello}}");
//! assert!(result.html.contains("Hello, world!"));
//! ```
//!
//! # Limits
//!
//! Every recursive construct is bounded: template depth and expansion bytes,
//! template page size, link/table/list nesting, raw-HTML and stored-template
//! brace nesting, block recursion and reference count. A hostile page ends in
//! literal text or an error span, never in a panic or an unbounded allocation.
//!
//! # Escaping
//!
//! Escaped text positions and attribute values use [`fador_markup`]'s HTML
//! escaping; URLs go through its scheme policy and inline styles through its
//! declaration allow-list. The MediaWiki-specific entity normalisation and
//! `$1` message placeholders stay local because they are not the generic HTML
//! or `sprintf` behaviour those helpers implement; see the crate README for the
//! reasoning.
//!
//! # Deliberate scope
//!
//! The crate contains code only. It does not ship MediaWiki skins, CSS, images
//! or language packs. Built-in messages are the renderer's own short English
//! fallbacks; a deployment supplies its interface language through
//! [`MessageSource`] and its namespace names through the `namespaces` field of
//! [`ParserConfig`].

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod cache;
mod config;
mod messages;
mod namespaces;
mod parser;
mod resolver;
mod sanitize;
mod title;

#[cfg(test)]
pub(crate) use fador_testutil as testutil;

pub use cache::ParserCache;
pub use config::ParserConfig;
pub use messages::{MapMessages, MessageContext, MessageSource};
pub use namespaces::{Namespace, Namespaces};
pub use parser::{Category, ParseResult, Parser};
pub use resolver::{
    FileInfo, MemoryResolver, PageFlags, RevisionInfo, SiteStats, TitleKey, WikiResolver,
};
pub use title::Title;
