//! Dependency-free service primitives: mail transport, captcha rendering, a
//! cron scheduler and feed rendering.
//!
//! The crate collects the pieces of a web application that talk to the outside
//! world but do not belong to a database schema, an HTTP framework or a
//! template dialect:
//!
//! | module | contents |
//! | --- | --- |
//! | [`mail`] | RFC 5322 message rendering, strict address parsing, SMTP/sendmail/log transport |
//! | [`captcha`] | PNG and WAV challenges, friendly codes, third-party challenge verification |
//! | [`cron`] | heartbeat leader lock, execution lock, atomic status file, scheduler thread |
//! | [`feed`] | RSS 0.92/2.0, Atom 1.0 and RDF feed documents |
//!
//! Every module is behind a feature and enabled by default. The crate has no
//! dependencies outside the workspace: [`fador_core`] supplies the date,
//! random, base64, CRC-32 and JSON helpers, and [`fador_compress`] supplies the
//! zlib stream inside a captcha PNG.
//!
//! # Invariants
//!
//! - **No `unsafe`.** The crate is `#![deny(unsafe_code)]`.
//! - **Bounded work.** Addresses, header lines, message bodies, SMTP replies,
//!   captcha sizes, status files, feed entries and provider responses all have
//!   explicit limits. A hostile input returns an error or a smaller document
//!   instead of occupying a worker.
//! - **No injection.** A line break in an address, header value, SMTP command
//!   or status source is rejected before it reaches a wire format.
//! - **No database, routes, templates or board settings.** A caller supplies
//!   the configuration, the clock and the task closure.
//!
//! # Feature matrix
//!
//! | feature | module | default |
//! | --- | --- | --- |
//! | `mail` | [`mail`] | yes |
//! | `captcha` | [`captcha`] | yes |
//! | `cron` | [`cron`] | yes |
//! | `feed` | [`feed`] | yes |
//!
//! `cargo test -p fador-services --no-default-features` compiles the empty
//! library; each module's own tests are skipped with its feature.

#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "captcha")]
pub mod captcha;
#[cfg(feature = "cron")]
pub mod cron;
#[cfg(feature = "feed")]
pub mod feed;
#[cfg(feature = "mail")]
pub mod mail;

#[cfg(feature = "captcha")]
pub use captcha::{
    accepts, friendly_code, render_png, render_wav, verify_provider, CaptchaOptions, Difficulty,
    Provider, ProviderConfig, ProviderError,
};
#[cfg(feature = "cron")]
pub use cron::{
    clamp_interval, run_once, spawn, unix_now, CronRun, CronStatus, LeaderLock, RunLock,
    RunOutcome, RunSource, SchedulerConfig, SchedulerHandle, StatusResult,
};
#[cfg(feature = "feed")]
pub use feed::{cdata, render, xml_escape, xml_escape_attr, Category, Entry, Feed, Format};
#[cfg(feature = "mail")]
pub use mail::{
    dot_stuff, mail_date, render_rfc5322, send, Address, MailError, Message, SmtpConfig, Transport,
};
