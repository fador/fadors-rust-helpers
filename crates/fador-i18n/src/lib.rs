//! Language packs, plural rules, date formatting and time-zone data.
//!
//! The crate has no external dependencies and no `unsafe` code. It provides
//! the pieces a forum or wiki needs to render a page in the visitor's
//! language:
//!
//! - [`LanguagePack`] parses a JSON pack; [`LanguageSet`] pairs it with an
//!   English fallback and resolves keys per pack, per file and per page.
//!   No pack data is compiled into the crate: the application embeds its own
//!   JSON with `include_str!` or loads it from a directory.
//! - [`plural_form`] implements all sixteen phpBB plural rules and
//!   [`select_plural`] the nullar/singular/plural choice phpBB's `lang()`
//!   performs.
//! - [`format_placeholders`] is the bounded `sprintf` subset language strings
//!   use: `%s`, `%d`, `%u`, `%f`, `%x`, `%X`, positional `%1$s`, precision,
//!   width and `%%`.
//! - [`format_date_php`] renders PHP `date()` tokens with localized names and
//!   [`format_strftime`] the `strftime` subset SMF uses.
//! - [`Tzdb`] reads the embedded IANA archive, parses TZif files and applies
//!   the POSIX footer, so a date after the last stored transition still
//!   follows the zone's summer-time rule.
//!
//! ```
//! use fador_i18n::{format_date_php, DateTimeNames, LanguagePack, LanguageSet, Tzdb};
//!
//! let en = LanguagePack::from_json(
//!     r#"{"code":"en","messages":{"PLURAL_RULE":1,"POSTS":["no posts","1 post","%d posts"]}}"#,
//!     "en",
//! )
//! .unwrap();
//! let fi = LanguagePack::from_json(r#"{"code":"fi"}"#, "fi").unwrap();
//! let set = LanguageSet::new(fi, en);
//!
//! assert_eq!(set.lang("POSTS", &["4".to_string()]), "4 posts");
//! assert_eq!(
//!     format_date_php(
//!         Tzdb::embedded(),
//!         &DateTimeNames::english(),
//!         true,
//!         0,
//!         "Europe/Helsinki",
//!         "D d.m.Y H:i",
//!     ),
//!     "Thu 01.01.1970 02:00"
//! );
//! ```
//!
//! # Time-zone data
//!
//! `data/tzdata.bin` is a `KTZ1` archive of 497 zones copied verbatim from the
//! IANA time-zone database, which is **public domain**. The archive is not a
//! derived work of any application; see the crate README for the format and
//! the update procedure.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod calendar;
mod date;
mod format;
mod pack;
mod plural;
mod tz;

pub use date::{
    format_date_php, format_offset, format_strftime, format_strftime_in_zone, DateTimeNames,
    TimeStrings,
};
pub use format::{format_placeholders, MAX_PADDING};
pub use pack::{normalize_language_code, EmbeddedPacks, LanguagePack, LanguageSet, PackError};
pub use plural::{plural_form, select_plural, select_plural_entries, PLURAL_RULES};
pub use tz::{
    is_known, is_valid_zone_name, local_parts, offset_for, zone_names, LocalTime, PosixTz, TzError,
    Tzdb, Zone, MAX_ZONES,
};

/// A parsed JSON value, re-exported so [`LanguagePack::message`] is usable
/// without adding `fador-core` to the dependency list.
pub use fador_core::json::Json;
