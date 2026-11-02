//! IANA time-zone data: an embedded archive, TZif parsing and POSIX footer
//! extrapolation.
//!
//! The crate embeds `data/tzdata.bin`, a `KTZ1` archive of 497 zones taken
//! verbatim from the IANA time-zone database (public domain). Every blob is a
//! complete TZif v2 file, including its trailing POSIX rule, so a date after
//! the last stored transition (2037 in this build) still follows the zone's
//! summer-time rule.
//!
//! ```
//! use fador_i18n::Tzdb;
//!
//! let tz = Tzdb::embedded();
//! assert_eq!(tz.offset_for("Europe/Helsinki", 1_782_907_200), Some(10_800));
//! // 2040 is past the last transition; the footer supplies the EU rule.
//! assert_eq!(tz.offset_for("Europe/Helsinki", 2_225_966_400), Some(10_800));
//! ```

use crate::calendar::{civil_from_days, days_from_civil, month_day_from_ordinal, month_week_day};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

const TZDATA: &[u8] = include_bytes!("../data/tzdata.bin");

/// Largest number of zones a [`Tzdb`] accepts from one archive or directory.
pub const MAX_ZONES: usize = 4096;

const MAX_TRANSITIONS: usize = 100_000;
const MAX_TYPES: usize = 256;
const MAX_CHARS: usize = 1_000_000;
const MAX_LEAPS: usize = 1_000;
const MAX_INDICATORS: usize = 256;
const MAX_NAME_LENGTH: usize = 100;
const MAX_DIR_DEPTH: usize = 8;

/// A civil date and time in a particular zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    /// Proleptic Gregorian year.
    pub year: i32,
    /// Month, 1-12.
    pub month: u32,
    /// Day of the month, 1-31.
    pub day: u32,
    /// Hour, 0-23.
    pub hour: u32,
    /// Minute, 0-59.
    pub minute: u32,
    /// Second, 0-59.
    pub second: u32,
}

impl LocalTime {
    /// Day of the week, 0 = Sunday through 6 = Saturday.
    #[must_use]
    pub fn weekday(&self) -> usize {
        crate::calendar::weekday_from_days(days_from_civil(self.year, self.month, self.day))
    }

    /// Day of the year, 1-366.
    #[must_use]
    pub fn day_of_year(&self) -> u32 {
        crate::calendar::day_of_year(self.year, self.month, self.day)
    }

    /// The same parts as `(year, month, day, hour, minute, second)`.
    #[must_use]
    pub fn parts(&self) -> (i32, u32, u32, u32, u32, u32) {
        (
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
    }
}

/// Why a time-zone database, zone or POSIX rule could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TzError {
    /// The input does not start with the `KTZ1` or `TZif` magic.
    BadMagic,
    /// A length or count field points past the end of the input.
    Truncated,
    /// A count field exceeds the parser's limit.
    TooManyEntries,
    /// A field is inconsistent, for example a transition index outside the
    /// local-time-type table.
    InvalidData,
    /// A zone name contains a path separator, `..`, an illegal byte or is too
    /// long.
    InvalidName(String),
    /// The archive or directory did not contain a single usable zone.
    NoZones,
    /// Reading a zone file failed.
    Io(String),
}

impl fmt::Display for TzError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => formatter.write_str("time-zone data has an unknown magic"),
            Self::Truncated => formatter.write_str("time-zone data is truncated"),
            Self::TooManyEntries => formatter.write_str("time-zone data has too many entries"),
            Self::InvalidData => formatter.write_str("time-zone data is inconsistent"),
            Self::InvalidName(name) => write!(formatter, "invalid time-zone name {name:?}"),
            Self::NoZones => formatter.write_str("time-zone data contains no zones"),
            Self::Io(message) => write!(formatter, "cannot read time-zone data: {message}"),
        }
    }
}

impl std::error::Error for TzError {}

/// One local-time type inside a TZif file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZoneType {
    offset: i32,
    is_dst: bool,
    abbreviation: String,
}

/// A parsed TZif zone: its transition table plus the POSIX rule that applies
/// after the last transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    transitions: Vec<i64>,
    indices: Vec<usize>,
    types: Vec<ZoneType>,
    initial: usize,
    posix: Option<PosixTz>,
}

impl Zone {
    /// Parse one TZif file (version 1, 2, 3 or 4).
    ///
    /// The version 1 block of a version 2+ file is skipped: its 32-bit
    /// transitions are a strict subset of the 64-bit block that follows.
    pub fn parse_tzif(data: &[u8]) -> Result<Self, TzError> {
        let first = Header::parse(data, 0)?;
        let (header, start) = if first.version >= b'2' {
            let second = 44usize
                .checked_add(first.block_size(4)?)
                .ok_or(TzError::Truncated)?;
            (
                Header::parse(data, second)?,
                second.checked_add(44).ok_or(TzError::Truncated)?,
            )
        } else {
            (first, 44)
        };
        if header.typecnt == 0 {
            return Err(TzError::InvalidData);
        }
        let time_size = if header.version >= b'2' { 8 } else { 4 };
        let times_end = start
            .checked_add(
                header
                    .timecnt
                    .checked_mul(time_size)
                    .ok_or(TzError::Truncated)?,
            )
            .ok_or(TzError::Truncated)?;
        let indices_end = times_end
            .checked_add(header.timecnt)
            .ok_or(TzError::Truncated)?;
        let types_end = indices_end
            .checked_add(header.typecnt.checked_mul(6).ok_or(TzError::Truncated)?)
            .ok_or(TzError::Truncated)?;
        let chars_end = types_end
            .checked_add(header.charcnt)
            .ok_or(TzError::Truncated)?;
        let end = chars_end
            .checked_add(
                header
                    .leapcnt
                    .checked_mul(time_size + 4)
                    .ok_or(TzError::Truncated)?,
            )
            .and_then(|value| value.checked_add(header.isstdcnt))
            .and_then(|value| value.checked_add(header.isutcnt))
            .ok_or(TzError::Truncated)?;
        if end > data.len() {
            return Err(TzError::Truncated);
        }

        let mut transitions = Vec::with_capacity(header.timecnt);
        for index in 0..header.timecnt {
            let position = start + index * time_size;
            transitions.push(read_signed(data, position, time_size)?);
        }

        let characters = &data[types_end..chars_end];
        let mut types = Vec::with_capacity(header.typecnt);
        for index in 0..header.typecnt {
            let position = indices_end + index * 6;
            let offset = i32::from_be_bytes(
                data[position..position + 4]
                    .try_into()
                    .map_err(|_| TzError::Truncated)?,
            );
            let is_dst = data[position + 4] != 0;
            let abbreviation =
                abbreviation_text(characters, data[position + 5] as usize).to_string();
            types.push(ZoneType {
                offset,
                is_dst,
                abbreviation,
            });
        }

        let mut indices = Vec::with_capacity(header.timecnt);
        for index in 0..header.timecnt {
            let value = data[times_end + index] as usize;
            if value >= types.len() {
                return Err(TzError::InvalidData);
            }
            indices.push(value);
        }

        // RFC 8536: before the first transition the first standard-time type
        // applies, or type 0 when the zone is daylight time throughout.
        let initial = types.iter().position(|kind| !kind.is_dst).unwrap_or(0);
        let posix = if header.version >= b'2' {
            parse_footer(data, end)
        } else {
            None
        };
        Ok(Self {
            transitions,
            indices,
            types,
            initial,
            posix,
        })
    }

    /// Seconds east of UTC at `unix_time`.
    #[must_use]
    pub fn offset_at(&self, unix_time: i64) -> i32 {
        if self.uses_footer(unix_time) {
            if let Some(posix) = &self.posix {
                return posix.offset_at(unix_time);
            }
        }
        self.types[self.type_index_at(unix_time)].offset
    }

    /// Whether daylight saving time is in effect at `unix_time`.
    #[must_use]
    pub fn is_dst_at(&self, unix_time: i64) -> bool {
        if self.uses_footer(unix_time) {
            if let Some(posix) = &self.posix {
                return posix.is_dst_at(unix_time);
            }
        }
        self.types[self.type_index_at(unix_time)].is_dst
    }

    /// The zone abbreviation in effect at `unix_time`, for example `EEST`.
    #[must_use]
    pub fn abbreviation_at(&self, unix_time: i64) -> &str {
        if self.uses_footer(unix_time) {
            if let Some(posix) = &self.posix {
                return posix.name_at(unix_time);
            }
        }
        &self.types[self.type_index_at(unix_time)].abbreviation
    }

    /// The stored transition times, oldest first.
    #[must_use]
    pub fn transition_times(&self) -> &[i64] {
        &self.transitions
    }

    /// The POSIX rule that applies after the last stored transition.
    #[must_use]
    pub fn posix_rule(&self) -> Option<&PosixTz> {
        self.posix.as_ref()
    }

    /// Whether `unix_time` is at or after the last stored transition, where
    /// the POSIX footer takes over. A zone without transitions is defined by
    /// its footer alone.
    fn uses_footer(&self, unix_time: i64) -> bool {
        match self.transitions.last() {
            Some(last) => unix_time >= *last,
            None => self.posix.is_some(),
        }
    }

    /// Index into `types` for `unix_time`, using the initial type before the
    /// first transition.
    fn type_index_at(&self, unix_time: i64) -> usize {
        let Some(first) = self.transitions.first() else {
            return self.initial;
        };
        if unix_time < *first {
            return self.initial;
        }
        let position = match self.transitions.binary_search(&unix_time) {
            Ok(mut found) => {
                // A repeated transition time keeps the last entry, which is
                // what a sequential scan would do.
                while found + 1 < self.transitions.len() && self.transitions[found + 1] == unix_time
                {
                    found += 1;
                }
                found
            }
            Err(found) => found.saturating_sub(1),
        };
        self.indices.get(position).copied().unwrap_or(self.initial)
    }
}

/// A parsed POSIX TZ rule such as `EET-2EEST,M3.5.0/3,M10.5.0/4`.
///
/// POSIX offsets count positive hours *west* of UTC, so the rule stores the
/// negated value as seconds east of UTC. A rule without a daylight part is a
/// fixed offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixTz {
    std_offset: i32,
    std_name: String,
    dst: Option<PosixDst>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PosixDst {
    offset: i32,
    name: String,
    start: Rule,
    end: Rule,
}

impl PosixTz {
    /// Parse a POSIX TZ string, or return `None` when it is malformed.
    ///
    /// Both the standard and daylight names may be quoted with `<...>`, and a
    /// missing daylight offset means one hour more than standard time. A
    /// daylight part without rules uses the current United States rule, as
    /// POSIX specifies.
    #[must_use]
    pub fn parse(spec: &str) -> Option<Self> {
        let mut cursor = PosixCursor::new(spec);
        let std_name = cursor.name()?.to_string();
        let std_offset = -cursor.offset()?;
        let mut dst = None;
        if !cursor.done() {
            let name = cursor.name()?.to_string();
            let offset = if cursor
                .peek()
                .is_some_and(|byte| byte == b'+' || byte == b'-' || byte.is_ascii_digit())
            {
                -cursor.offset()?
            } else {
                std_offset + 3_600
            };
            let (start, end) = if cursor.take(b',') {
                let start = cursor.rule()?;
                if !cursor.take(b',') {
                    return None;
                }
                (start, cursor.rule()?)
            } else {
                (
                    Rule::month_week_day(3, 2, 0, 7_200)?,
                    Rule::month_week_day(11, 1, 0, 7_200)?,
                )
            };
            dst = Some(PosixDst {
                offset,
                name,
                start,
                end,
            });
        }
        if !cursor.done() {
            return None;
        }
        Some(Self {
            std_offset,
            std_name,
            dst,
        })
    }

    /// The standard-time name, for example `EET`.
    #[must_use]
    pub fn std_name(&self) -> &str {
        &self.std_name
    }

    /// Seconds east of UTC in standard time.
    #[must_use]
    pub fn std_offset(&self) -> i32 {
        self.std_offset
    }

    /// The daylight-saving name, or `None` for a fixed-offset rule.
    #[must_use]
    pub fn dst_name(&self) -> Option<&str> {
        self.dst.as_ref().map(|dst| dst.name.as_str())
    }

    /// Seconds east of UTC in daylight time, or `None` for a fixed rule.
    #[must_use]
    pub fn dst_offset(&self) -> Option<i32> {
        self.dst.as_ref().map(|dst| dst.offset)
    }

    /// Whether the rule has a daylight-saving part.
    #[must_use]
    pub fn has_dst(&self) -> bool {
        self.dst.is_some()
    }

    /// Seconds east of UTC at `unix_time`.
    #[must_use]
    pub fn offset_at(&self, unix_time: i64) -> i32 {
        match self.daylight_at(unix_time) {
            Some(dst) => dst.offset,
            None => self.std_offset,
        }
    }

    /// Whether daylight saving time is in effect at `unix_time`.
    #[must_use]
    pub fn is_dst_at(&self, unix_time: i64) -> bool {
        self.daylight_at(unix_time).is_some()
    }

    /// The name in effect at `unix_time`.
    #[must_use]
    pub fn name_at(&self, unix_time: i64) -> &str {
        match self.daylight_at(unix_time) {
            Some(dst) => &dst.name,
            None => &self.std_name,
        }
    }

    /// The daylight rule when `unix_time` falls inside its window.
    fn daylight_at(&self, unix_time: i64) -> Option<&PosixDst> {
        let dst = self.dst.as_ref()?;
        // The rule is evaluated for the local calendar year, which the
        // standard offset decides well enough except in the first hours of a
        // year; the window test below uses absolute instants, so a mismatch
        // only affects a transition that falls on January 1.
        let year = civil_from_days(
            unix_time
                .saturating_add(i64::from(self.std_offset))
                .div_euclid(86_400),
        )
        .0;
        let start = dst.start.utc_seconds(year, self.std_offset)?;
        let end = dst.end.utc_seconds(year, dst.offset)?;
        let inside = if start <= end {
            unix_time >= start && unix_time < end
        } else {
            // Southern hemisphere: the window wraps around the new year.
            unix_time >= start || unix_time < end
        };
        inside.then_some(dst)
    }
}

/// The embedded database, or any archive or zone directory in the same format.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tzdb {
    zones: BTreeMap<String, Zone>,
}

impl Tzdb {
    /// An empty database.
    ///
    /// Every named zone resolves to UTC until one is added with
    /// [`Tzdb::insert`] or loaded with [`Tzdb::load_dir`].
    #[must_use]
    pub fn empty() -> Self {
        Self {
            zones: BTreeMap::new(),
        }
    }

    /// The database compiled into the crate.
    ///
    /// The archive is parsed once and cached for the life of the process. A
    /// corrupt archive yields an empty database, in which every named zone
    /// resolves to UTC; `--check`-style validation should use
    /// [`Tzdb::from_archive`] instead.
    #[must_use]
    pub fn embedded() -> &'static Self {
        static DATABASE: OnceLock<Tzdb> = OnceLock::new();
        DATABASE.get_or_init(|| Self::from_archive(TZDATA).unwrap_or_default())
    }

    /// Parse a `KTZ1` archive: a little-endian zone count followed by
    /// `(u16 name length, name, u32 blob length, TZif blob)` records.
    ///
    /// A blob that is not a valid TZif file is skipped, so one unknown zone
    /// version cannot hide the rest; an archive with no usable zone at all is
    /// an error.
    pub fn from_archive(data: &[u8]) -> Result<Self, TzError> {
        if data.len() < 8 || &data[..4] != b"KTZ1" {
            return Err(TzError::BadMagic);
        }
        let count = read_u32(data, 4)? as usize;
        if count > MAX_ZONES {
            return Err(TzError::TooManyEntries);
        }
        let mut position = 8usize;
        let mut zones = BTreeMap::new();
        for _ in 0..count {
            let name_length = read_u16(data, position)? as usize;
            position += 2;
            let name_end = position
                .checked_add(name_length)
                .ok_or(TzError::Truncated)?;
            let name = std::str::from_utf8(data.get(position..name_end).ok_or(TzError::Truncated)?)
                .map_err(|_| TzError::InvalidName("<invalid UTF-8>".to_string()))?;
            position = name_end;
            if !is_valid_zone_name(name) {
                return Err(TzError::InvalidName(name.to_string()));
            }
            let blob_length = read_u32(data, position)? as usize;
            position += 4;
            let blob_end = position
                .checked_add(blob_length)
                .ok_or(TzError::Truncated)?;
            let blob = data.get(position..blob_end).ok_or(TzError::Truncated)?;
            position = blob_end;
            if let Ok(zone) = Zone::parse_tzif(blob) {
                zones.insert(name.to_string(), zone);
            }
        }
        if zones.is_empty() {
            return Err(TzError::NoZones);
        }
        Ok(Self { zones })
    }

    /// Read a system zone directory such as `/usr/share/zoneinfo`.
    ///
    /// Files are named by their path relative to `dir` (`Europe/Helsinki`),
    /// which becomes the zone name. Non-TZif files, names that fail
    /// [`is_valid_zone_name`] and unreadable files are skipped; a directory
    /// that cannot be listed is an error, and a tree that contains no zone at
    /// all is [`TzError::NoZones`].
    pub fn load_dir(dir: &Path) -> Result<Self, TzError> {
        let mut zones = BTreeMap::new();
        read_zone_dir(dir, "", 0, &mut zones)?;
        if zones.is_empty() {
            return Err(TzError::NoZones);
        }
        Ok(Self { zones })
    }

    /// Add or replace one zone.
    ///
    /// The name is not validated: call [`is_valid_zone_name`] first when it
    /// comes from a request.
    pub fn insert(&mut self, name: &str, zone: Zone) -> Option<Zone> {
        self.zones.insert(name.to_string(), zone)
    }

    /// The parsed zone, or `None` when the name is unknown.
    #[must_use]
    pub fn zone(&self, name: &str) -> Option<&Zone> {
        self.zones.get(name.trim())
    }

    /// Whether the database knows this zone or POSIX fixed-offset name.
    #[must_use]
    pub fn is_known(&self, name: &str) -> bool {
        let name = name.trim();
        fixed_offset(name).is_some() || self.zones.contains_key(name)
    }

    /// Every stored zone name, sorted.
    #[must_use]
    pub fn zone_names(&self) -> Vec<String> {
        self.zones.keys().cloned().collect()
    }

    /// Every stored zone with its name, sorted.
    pub fn zones(&self) -> impl Iterator<Item = (&str, &Zone)> {
        self.zones.iter().map(|(name, zone)| (name.as_str(), zone))
    }

    /// Number of stored zones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Whether the database holds no zone.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// Seconds east of UTC for `name` at `unix_time`, or `None` when the name
    /// is unknown.
    #[must_use]
    pub fn offset_for(&self, name: &str, unix_time: i64) -> Option<i32> {
        let name = name.trim();
        if let Some(offset) = fixed_offset(name) {
            return Some(offset);
        }
        self.zones.get(name).map(|zone| zone.offset_at(unix_time))
    }

    /// Whether daylight saving time is in effect, or `None` when the name is
    /// unknown.
    #[must_use]
    pub fn is_dst(&self, name: &str, unix_time: i64) -> Option<bool> {
        let name = name.trim();
        if fixed_offset(name).is_some() {
            return Some(false);
        }
        self.zones.get(name).map(|zone| zone.is_dst_at(unix_time))
    }

    /// The abbreviation in effect, or `None` when the name is unknown.
    ///
    /// A fixed-offset name reports itself, so `UTC` stays `UTC`.
    #[must_use]
    pub fn abbreviation(&self, name: &str, unix_time: i64) -> Option<String> {
        let name = name.trim();
        if fixed_offset(name).is_some() {
            return Some(name.to_string());
        }
        self.zones
            .get(name)
            .map(|zone| zone.abbreviation_at(unix_time).to_string())
    }

    /// The civil date and time in `name` at `unix_time`.
    #[must_use]
    pub fn local_parts(&self, name: &str, unix_time: i64) -> Option<LocalTime> {
        let offset = self.offset_for(name, unix_time)?;
        Some(local_time(unix_time, offset))
    }
}

/// Convert a UTC timestamp and an offset into civil parts.
fn local_time(unix_time: i64, offset: i32) -> LocalTime {
    let local = unix_time.saturating_add(i64::from(offset));
    let days = local.div_euclid(86_400);
    let seconds = local.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    LocalTime {
        year,
        month,
        day,
        hour: (seconds / 3_600) as u32,
        minute: ((seconds % 3_600) / 60) as u32,
        second: (seconds % 60) as u32,
    }
}

/// Every zone name in the embedded archive, sorted.
#[must_use]
pub fn zone_names() -> Vec<String> {
    Tzdb::embedded().zone_names()
}

/// Whether the embedded archive knows this zone or fixed-offset name.
///
/// `Z` is accepted as UTC, as POSIX and PHP treat it.
#[must_use]
pub fn is_known(zone: &str) -> bool {
    Tzdb::embedded().is_known(zone)
}

/// Seconds east of UTC for `zone` at `unix_time`.
///
/// An unknown zone resolves to UTC, which matches the behaviour of the ported
/// server code. Use [`Tzdb::offset_for`] when the difference matters.
#[must_use]
pub fn offset_for(zone: &str, unix_time: i64) -> i32 {
    Tzdb::embedded().offset_for(zone, unix_time).unwrap_or(0)
}

/// The civil date and time in `zone` at `unix_time`, or `None` for an unknown
/// zone.
#[must_use]
pub fn local_parts(zone: &str, unix_time: i64) -> Option<LocalTime> {
    Tzdb::embedded().local_parts(zone, unix_time)
}

/// Whether `name` is a safe IANA zone name.
///
/// The name must be non-empty, at most 100 bytes, and made of ASCII letters,
/// digits, `/`, `_`, `-`, `+` and `.`. It must not start or end with `/` and
/// must not contain an empty, `.` or `..` path component, so it can be joined
/// to a zone directory without escaping it.
#[must_use]
pub fn is_valid_zone_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > MAX_NAME_LENGTH
        || name.starts_with('/')
        || name.ends_with('/')
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return false;
    }
    name.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'+' | b'.')
    })
}

/// A fixed offset written the POSIX way: `Etc/GMT-3` is UTC+3.
fn fixed_offset(zone: &str) -> Option<i32> {
    if matches!(zone, "UTC" | "Etc/UTC" | "GMT" | "Etc/GMT" | "Zulu" | "Z") {
        return Some(0);
    }
    let rest = zone
        .strip_prefix("Etc/GMT")
        .or_else(|| zone.strip_prefix("GMT"))?;
    if rest.is_empty() {
        return Some(0);
    }
    let (sign, digits) = match rest.as_bytes().first().copied() {
        Some(b'+') => (-1, &rest[1..]),
        Some(b'-') => (1, &rest[1..]),
        _ => return None,
    };
    let hours: i32 = digits.parse().ok()?;
    if hours > 14 {
        return None;
    }
    Some(sign * hours * 3_600)
}

/// TZif header counts.
struct Header {
    version: u8,
    isutcnt: usize,
    isstdcnt: usize,
    leapcnt: usize,
    timecnt: usize,
    typecnt: usize,
    charcnt: usize,
}

impl Header {
    fn parse(data: &[u8], position: usize) -> Result<Self, TzError> {
        let header = data
            .get(position..position.checked_add(44).ok_or(TzError::Truncated)?)
            .ok_or(TzError::Truncated)?;
        if &header[..4] != b"TZif" {
            return Err(TzError::BadMagic);
        }
        let count = |offset: usize| -> Result<usize, TzError> {
            let bytes: [u8; 4] = header[offset..offset + 4]
                .try_into()
                .map_err(|_| TzError::Truncated)?;
            Ok(u32::from_be_bytes(bytes) as usize)
        };
        let header = Self {
            version: header[4],
            isutcnt: count(20)?,
            isstdcnt: count(24)?,
            leapcnt: count(28)?,
            timecnt: count(32)?,
            typecnt: count(36)?,
            charcnt: count(40)?,
        };
        if header.timecnt > MAX_TRANSITIONS
            || header.typecnt > MAX_TYPES
            || header.charcnt > MAX_CHARS
            || header.leapcnt > MAX_LEAPS
            || header.isstdcnt > MAX_INDICATORS
            || header.isutcnt > MAX_INDICATORS
        {
            return Err(TzError::TooManyEntries);
        }
        Ok(header)
    }

    /// Size of the data block that follows this header.
    fn block_size(&self, time_size: usize) -> Result<usize, TzError> {
        self.timecnt
            .checked_mul(time_size)
            .and_then(|value| value.checked_add(self.timecnt))
            .and_then(|value| value.checked_add(self.typecnt.checked_mul(6)?))
            .and_then(|value| value.checked_add(self.charcnt))
            .and_then(|value| value.checked_add(self.leapcnt.checked_mul(time_size + 4)?))
            .and_then(|value| value.checked_add(self.isstdcnt))
            .and_then(|value| value.checked_add(self.isutcnt))
            .ok_or(TzError::Truncated)
    }
}

/// A NUL-terminated abbreviation at `index` inside the character block.
fn abbreviation_text(characters: &[u8], index: usize) -> &str {
    let rest = characters.get(index..).unwrap_or(&[]);
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).unwrap_or("")
}

/// The POSIX rule in the footer of a version 2+ TZif file.
fn parse_footer(data: &[u8], position: usize) -> Option<PosixTz> {
    if data.get(position) != Some(&b'\n') {
        return None;
    }
    let rest = data.get(position + 1..)?;
    let end = rest.iter().position(|byte| *byte == b'\n')?;
    PosixTz::parse(std::str::from_utf8(&rest[..end]).ok()?)
}

fn read_signed(data: &[u8], position: usize, size: usize) -> Result<i64, TzError> {
    let bytes = data
        .get(position..position.checked_add(size).ok_or(TzError::Truncated)?)
        .ok_or(TzError::Truncated)?;
    match size {
        4 => Ok(i64::from(i32::from_be_bytes(
            bytes.try_into().map_err(|_| TzError::Truncated)?,
        ))),
        8 => Ok(i64::from_be_bytes(
            bytes.try_into().map_err(|_| TzError::Truncated)?,
        )),
        _ => Err(TzError::Truncated),
    }
}

fn read_u16(data: &[u8], position: usize) -> Result<u16, TzError> {
    let bytes = data.get(position..position + 2).ok_or(TzError::Truncated)?;
    Ok(u16::from_le_bytes(
        bytes.try_into().map_err(|_| TzError::Truncated)?,
    ))
}

fn read_u32(data: &[u8], position: usize) -> Result<u32, TzError> {
    let bytes = data.get(position..position + 4).ok_or(TzError::Truncated)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| TzError::Truncated)?,
    ))
}

/// Walk a zone directory, skipping anything that is not a usable TZif file.
fn read_zone_dir(
    dir: &Path,
    prefix: &str,
    depth: usize,
    zones: &mut BTreeMap<String, Zone>,
) -> Result<(), TzError> {
    if depth > MAX_DIR_DEPTH || zones.len() >= MAX_ZONES {
        return Ok(());
    }
    let entries =
        fs::read_dir(dir).map_err(|error| TzError::Io(format!("{}: {error}", dir.display())))?;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let name = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if file_type.is_dir() {
            read_zone_dir(&entry.path(), &name, depth + 1, zones)?;
        } else if file_type.is_file() && is_valid_zone_name(&name) {
            let Ok(data) = fs::read(entry.path()) else {
                continue;
            };
            if let Ok(zone) = Zone::parse_tzif(&data) {
                zones.insert(name, zone);
            }
        }
    }
    Ok(())
}

/// A POSIX rule cursor over the bytes of the footer.
struct PosixCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> PosixCursor<'a> {
    fn new(spec: &'a str) -> Self {
        Self {
            bytes: spec.as_bytes(),
            position: 0,
        }
    }

    fn done(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    /// A zone abbreviation, either alphabetic or quoted with `<...>`.
    fn name(&mut self) -> Option<&'a str> {
        let (start, end) = if self.take(b'<') {
            let start = self.position;
            while self.peek()? != b'>' {
                self.position += 1;
            }
            let end = self.position;
            if end == start {
                return None;
            }
            self.position += 1;
            (start, end)
        } else {
            let start = self.position;
            while self.peek().is_some_and(|byte| byte.is_ascii_alphabetic()) {
                self.position += 1;
            }
            if self.position == start {
                return None;
            }
            (start, self.position)
        };
        std::str::from_utf8(&self.bytes[start..end]).ok()
    }

    fn digits(&mut self) -> Option<u32> {
        let start = self.position;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
        if self.position == start || self.position - start > 6 {
            return None;
        }
        std::str::from_utf8(&self.bytes[start..self.position])
            .ok()?
            .parse()
            .ok()
    }

    /// A signed hours, hours:minutes or hours:minutes:seconds value, positive
    /// west of UTC.
    fn offset(&mut self) -> Option<i32> {
        let (sign, value) = self.signed_time(167)?;
        Some(sign * value)
    }

    /// A signed time in seconds, bounded by `max_hours`.
    fn signed_time(&mut self, max_hours: u32) -> Option<(i32, i32)> {
        let sign = match self.peek() {
            Some(b'-') => {
                self.position += 1;
                -1
            }
            Some(b'+') => {
                self.position += 1;
                1
            }
            _ => 1,
        };
        let hours = self.digits()?;
        if hours > max_hours {
            return None;
        }
        let mut seconds = hours as i32 * 3_600;
        if self.take(b':') {
            let minutes = self.digits()?;
            if minutes > 59 {
                return None;
            }
            seconds += minutes as i32 * 60;
            if self.take(b':') {
                let seconds_part = self.digits()?;
                if seconds_part > 59 {
                    return None;
                }
                seconds += seconds_part as i32;
            }
        }
        Some((sign, seconds))
    }

    fn rule(&mut self) -> Option<Rule> {
        let kind = match self.peek()? {
            b'M' => {
                self.position += 1;
                let month = self.digits()?;
                if !self.take(b'.') {
                    return None;
                }
                let week = self.digits()?;
                if !self.take(b'.') {
                    return None;
                }
                let weekday = self.digits()?;
                if month == 0 || month > 12 || week == 0 || week > 5 || weekday > 6 {
                    return None;
                }
                RuleKind::MonthWeekDay {
                    month,
                    week,
                    weekday,
                }
            }
            b'J' => {
                self.position += 1;
                let day = self.digits()?;
                if day == 0 || day > 365 {
                    return None;
                }
                RuleKind::Julian1(day)
            }
            _ => {
                let day = self.digits()?;
                if day > 365 {
                    return None;
                }
                RuleKind::Julian0(day)
            }
        };
        let time = if self.take(b'/') {
            let (sign, seconds) = self.signed_time(167)?;
            sign * seconds
        } else {
            7_200
        };
        Some(Rule { kind, time })
    }
}

/// One transition rule of a POSIX footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rule {
    kind: RuleKind,
    /// Seconds after local midnight at which the rule fires.
    time: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    /// `Jn`: day 1-365, February 29 never counted.
    Julian1(u32),
    /// `n`: day 0-365, February 29 counted in leap years.
    Julian0(u32),
    /// `Mmonth.week.weekday`.
    MonthWeekDay { month: u32, week: u32, weekday: u32 },
}

impl Rule {
    fn month_week_day(month: u32, week: u32, weekday: u32, time: i32) -> Option<Self> {
        if month == 0 || month > 12 || week == 0 || week > 5 || weekday > 6 {
            return None;
        }
        Some(Self {
            kind: RuleKind::MonthWeekDay {
                month,
                week,
                weekday,
            },
            time,
        })
    }

    /// The instant this rule fires, in UTC, for the given local year.
    fn utc_seconds(&self, year: i32, offset_before: i32) -> Option<i64> {
        Some(self.local_seconds(year)? - i64::from(offset_before))
    }

    fn local_seconds(&self, year: i32) -> Option<i64> {
        let (month, day) = match self.kind {
            RuleKind::MonthWeekDay {
                month,
                week,
                weekday,
            } => (month, month_week_day(year, month, week, weekday)?),
            RuleKind::Julian1(day) => month_day_from_ordinal(year, day - 1, false)?,
            RuleKind::Julian0(day) => month_day_from_ordinal(year, day, true)?,
        };
        days_from_civil(year, month, day)
            .checked_mul(86_400)?
            .checked_add(i64::from(self.time))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fador_testutil::{iterations, Rng};

    fn embedded() -> &'static Tzdb {
        Tzdb::embedded()
    }

    #[test]
    fn fixed_offsets_follow_posix_signs() {
        assert_eq!(offset_for("UTC", 0), 0);
        assert_eq!(offset_for("Etc/GMT-3", 0), 3 * 3_600);
        assert_eq!(offset_for("Etc/GMT+4", 0), -4 * 3_600);
        assert_eq!(offset_for("GMT", 0), 0);
        assert_eq!(offset_for("Z", 0), 0);
        assert_eq!(offset_for("Etc/GMT+15", 0), 0, "out of range falls back");
        assert!(is_known("Etc/GMT-2"));
        assert!(is_known("Z"));
        assert!(!is_known("Not/AZone"));
    }

    #[test]
    fn embedded_zoneinfo_resolves_helsinki_summer_and_winter() {
        assert_eq!(offset_for("Europe/Helsinki", 1_782_907_200), 3 * 3_600);
        assert_eq!(offset_for("Europe/Helsinki", 1_767_268_800), 2 * 3_600);
        assert!(!zone_names().is_empty());
        assert!(zone_names().iter().any(|zone| zone == "Europe/Helsinki"));
    }

    #[test]
    fn helsinki_switches_to_winter_time_on_the_last_october_sunday() {
        // 2026-10-25T00:59:59Z is 03:59:59 EEST; 01:00:00Z is 03:00:00 EET.
        assert_eq!(offset_for("Europe/Helsinki", 1_792_889_999), 3 * 3_600);
        assert_eq!(offset_for("Europe/Helsinki", 1_792_890_000), 2 * 3_600);
        // ... and back on the last Sunday of March 2027.
        assert_eq!(offset_for("Europe/Helsinki", 1_806_195_600), 3 * 3_600);
    }

    #[test]
    fn posix_footer_covers_2040_for_helsinki_and_new_york() {
        let tz = embedded();
        // 2040-01-15T12:00:00Z and 2040-07-15T12:00:00Z.
        assert_eq!(tz.offset_for("Europe/Helsinki", 2_210_241_600), Some(7_200));
        assert_eq!(
            tz.offset_for("Europe/Helsinki", 2_225_966_400),
            Some(10_800)
        );
        assert_eq!(
            tz.offset_for("America/New_York", 2_210_241_600),
            Some(-18_000)
        );
        assert_eq!(
            tz.offset_for("America/New_York", 2_225_966_400),
            Some(-14_400)
        );
        // The EU rule starts 2040-03-25T01:00:00Z and ends 2040-10-28T01:00:00Z.
        assert_eq!(tz.offset_for("Europe/Helsinki", 2_216_249_999), Some(7_200));
        assert_eq!(
            tz.offset_for("Europe/Helsinki", 2_216_250_000),
            Some(10_800)
        );
        assert_eq!(
            tz.offset_for("Europe/Helsinki", 2_234_998_799),
            Some(10_800)
        );
        assert_eq!(tz.offset_for("Europe/Helsinki", 2_234_998_800), Some(7_200));
        // The US rule starts 2040-03-11T07:00:00Z and ends 2040-11-04T06:00:00Z.
        assert_eq!(
            tz.offset_for("America/New_York", 2_215_061_999),
            Some(-18_000)
        );
        assert_eq!(
            tz.offset_for("America/New_York", 2_215_062_000),
            Some(-14_400)
        );
        assert_eq!(
            tz.offset_for("America/New_York", 2_235_621_599),
            Some(-14_400)
        );
        assert_eq!(
            tz.offset_for("America/New_York", 2_235_621_600),
            Some(-18_000)
        );
        // Abbreviations come from the footer after the last transition.
        assert_eq!(
            tz.abbreviation("Europe/Helsinki", 2_225_966_400).as_deref(),
            Some("EEST")
        );
        assert_eq!(
            tz.abbreviation("Europe/Helsinki", 2_210_241_600).as_deref(),
            Some("EET")
        );
        assert_eq!(tz.is_dst("Europe/Helsinki", 2_225_966_400), Some(true));
        assert_eq!(tz.is_dst("Europe/Helsinki", 2_210_241_600), Some(false));
    }

    #[test]
    fn local_parts_follow_the_zone() {
        let tz = embedded();
        assert_eq!(
            tz.local_parts("UTC", 0).map(|time| time.parts()),
            Some((1970, 1, 1, 0, 0, 0))
        );
        // 2026-07-15T21:30:00Z is 2026-07-16 00:30 EEST.
        assert_eq!(
            tz.local_parts("Europe/Helsinki", 1_784_151_000)
                .map(|time| time.parts()),
            Some((2026, 7, 16, 0, 30, 0))
        );
        let local = tz.local_parts("Europe/Helsinki", 1_784_151_000).unwrap();
        assert_eq!(local.weekday(), 4);
        assert_eq!(local.day_of_year(), 197);
        assert_eq!(tz.local_parts("Not/AZone", 0), None);
        assert_eq!(
            super::local_parts("Europe/Helsinki", 1_784_151_000).map(|time| time.parts()),
            Some((2026, 7, 16, 0, 30, 0))
        );
    }

    #[test]
    fn parses_posix_footer_rules() {
        let helsinki = PosixTz::parse("EET-2EEST,M3.5.0/3,M10.5.0/4").unwrap();
        assert_eq!(helsinki.std_name(), "EET");
        assert_eq!(helsinki.std_offset(), 7_200);
        assert_eq!(helsinki.dst_name(), Some("EEST"));
        assert_eq!(helsinki.dst_offset(), Some(10_800));
        assert!(helsinki.has_dst());
        // 2040: summer time from 2040-03-25T01:00:00Z to 2040-10-28T01:00:00Z.
        assert_eq!(helsinki.offset_at(2_216_249_999), 7_200);
        assert_eq!(helsinki.offset_at(2_216_250_000), 10_800);
        assert_eq!(helsinki.offset_at(2_234_998_799), 10_800);
        assert_eq!(helsinki.offset_at(2_234_998_800), 7_200);
        assert_eq!(helsinki.name_at(2_225_966_400), "EEST");

        let utc = PosixTz::parse("UTC0").unwrap();
        assert_eq!(utc.std_offset(), 0);
        assert!(!utc.has_dst());
        assert_eq!(utc.offset_at(0), 0);
        assert_eq!(utc.name_at(0), "UTC");

        let india = PosixTz::parse("IST-5:30").unwrap();
        assert_eq!(india.std_offset(), 19_800);
        assert_eq!(india.offset_at(0), 19_800);

        let quoted = PosixTz::parse("<+03>-3").unwrap();
        assert_eq!(quoted.std_name(), "+03");
        assert_eq!(quoted.std_offset(), 10_800);

        // No daylight offset given: one hour more than standard time.
        let default_offset = PosixTz::parse("EST5EDT,M3.2.0,M11.1.0").unwrap();
        assert_eq!(default_offset.dst_offset(), Some(-14_400));
        // No rules given: POSIX's default United States rule.
        let default_rules = PosixTz::parse("EST5EDT").unwrap();
        assert_eq!(default_rules.offset_at(2_215_062_000), -14_400);
        assert_eq!(default_rules.offset_at(2_210_241_600), -18_000);

        // Southern hemisphere: the window wraps around the new year.
        let sydney = PosixTz::parse("AEST-10AEDT,M10.1.0,M4.1.0/3").unwrap();
        assert_eq!(sydney.offset_at(2_210_241_600), 39_600);
        assert_eq!(sydney.offset_at(2_225_966_400), 36_000);
    }

    #[test]
    fn parses_julian_posix_rules() {
        // J60 is March 1 in every year; 60 counts February 29, so in a leap
        // year both are March 1 but in 2023 the plain form is March 2.
        let julian = PosixTz::parse("XXX0YYY,J60/0,J300/0").unwrap();
        assert_eq!(julian.offset_at(1_709_251_200), 3_600, "2024-03-01T00:00Z");
        let plain = PosixTz::parse("XXX0YYY,60/0,300/0").unwrap();
        assert_eq!(plain.offset_at(1_709_251_200), 3_600, "2024-03-01T00:00Z");
        assert_eq!(julian.offset_at(1_677_628_800), 3_600, "2023-03-01T00:00Z");
        assert_eq!(plain.offset_at(1_677_628_800), 0, "2023-03-01T00:00Z");
    }

    #[test]
    fn rejects_malformed_posix_rules() {
        for spec in [
            "",
            "UTC",
            "UTC0,",
            "EET-2EEST,M13.5.0/3,M10.5.0/4",
            "EET-2EEST,M3.6.0/3,M10.5.0/4",
            "EET-2EEST,M3.5.7/3,M10.5.0/4",
            "EET-2EEST,M3.5.0/3,M10.5.0/4extra",
            "EET-2EEST,M3.5.0/999999999",
            "UTC999999",
            "<>0",
            "UTC0 ",
        ] {
            assert!(PosixTz::parse(spec).is_none(), "accepted {spec:?}");
        }
    }

    #[test]
    fn validates_zone_names() {
        for name in [
            "UTC",
            "Europe/Helsinki",
            "America/Argentina/Buenos_Aires",
            "Etc/GMT-3",
            "Etc/GMT+3",
            "right/UTC",
            "Z",
            "CET",
            "+03",
        ] {
            assert!(is_valid_zone_name(name), "rejected {name:?}");
        }
        for name in [
            "",
            "../UTC",
            "/UTC",
            "Europe/../UTC",
            "Europe//UTC",
            "Europe/",
            "A\\B",
            "Europe/UTC\0",
            "Europe/Ü",
            "Europe/ UTC",
            &"a".repeat(101),
        ] {
            assert!(!is_valid_zone_name(name), "accepted {name:?}");
        }
    }

    #[test]
    fn parses_the_embedded_archive_and_rejects_damage() {
        let tz = embedded();
        assert!(tz.len() > 400);
        assert!(!tz.is_empty());
        assert!(tz.zone("Europe/Helsinki").is_some());
        assert_eq!(tz.zones().count(), tz.len());
        assert!(tz.zone("Europe/Helsinki").unwrap().posix_rule().is_some());
        assert!(!tz
            .zone("Europe/Helsinki")
            .unwrap()
            .transition_times()
            .is_empty());

        assert_eq!(Tzdb::from_archive(b"nope").unwrap_err(), TzError::BadMagic);
        assert_eq!(
            Tzdb::from_archive(b"KTZ1\x01\x00\x00\x00").unwrap_err(),
            TzError::Truncated
        );
        let mut truncated = TZDATA.to_vec();
        truncated.truncate(64);
        assert!(Tzdb::from_archive(&truncated).is_err());
        let mut huge = b"KTZ1".to_vec();
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Tzdb::from_archive(&huge).unwrap_err(),
            TzError::TooManyEntries
        );
    }

    /// The raw TZif blob of one zone in the embedded archive.
    fn archive_blob(name: &str) -> &'static [u8] {
        let count = u32::from_le_bytes(TZDATA[4..8].try_into().expect("zone count")) as usize;
        let mut position = 8usize;
        for _ in 0..count {
            let name_length = u16::from_le_bytes([TZDATA[position], TZDATA[position + 1]]) as usize;
            position += 2;
            let entry =
                std::str::from_utf8(&TZDATA[position..position + name_length]).expect("zone name");
            position += name_length;
            let length = u32::from_le_bytes(
                TZDATA[position..position + 4]
                    .try_into()
                    .expect("length field"),
            ) as usize;
            position += 4;
            let blob = &TZDATA[position..position + length];
            position += length;
            if entry == name {
                return blob;
            }
        }
        panic!("{name} is not in the archive");
    }

    #[test]
    fn parses_one_tzif_blob_from_the_archive() {
        let blob = archive_blob("Africa/Abidjan");
        let zone = Zone::parse_tzif(blob).expect("parse one zone");
        assert_eq!(zone.offset_at(0), 0);
        assert!(Zone::parse_tzif(b"TZif").is_err());
        assert!(Zone::parse_tzif(&blob[..40]).is_err());
    }

    #[test]
    fn insert_adds_and_replaces_a_zone() {
        let mut tz = Tzdb::default();
        assert!(tz.is_empty());
        assert_eq!(tz.len(), 0);
        let zone = Zone::parse_tzif(archive_blob("Europe/Helsinki")).expect("Helsinki");
        assert!(tz.insert("Europe/Helsinki", zone).is_none());
        assert_eq!(tz.len(), 1);
        assert!(tz.is_known("Europe/Helsinki"));
        assert_eq!(
            tz.offset_for("Europe/Helsinki", 1_782_907_200),
            Some(10_800)
        );
        let replacement = Zone::parse_tzif(archive_blob("Europe/Helsinki")).expect("Helsinki");
        assert!(tz.insert("Europe/Helsinki", replacement).is_some());
        assert_eq!(tz.len(), 1);
    }

    #[test]
    fn empty_database_is_usable() {
        let tz = Tzdb::empty();
        assert!(tz.is_empty());
        assert!(!tz.is_known("Europe/Helsinki"));
        assert!(tz.zone("Europe/Helsinki").is_none());
    }

    #[test]
    fn loads_a_zone_directory() {
        let directory = std::env::temp_dir().join(format!(
            "fador-i18n-zones-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let europe = directory.join("Europe");
        std::fs::create_dir_all(&europe).expect("create zone directory");
        // Reuse the embedded Helsinki blob so the test needs no system tzdata.
        std::fs::write(europe.join("Helsinki"), archive_blob("Europe/Helsinki"))
            .expect("write zone file");
        std::fs::write(directory.join("README"), b"not a zone").expect("write non-zone file");

        let tz = Tzdb::load_dir(&directory).expect("load zone directory");
        assert_eq!(tz.zone_names(), vec!["Europe/Helsinki".to_string()]);
        assert_eq!(
            tz.offset_for("Europe/Helsinki", 1_782_907_200),
            Some(10_800)
        );
        assert!(matches!(
            Tzdb::load_dir(&directory.join("missing")),
            Err(TzError::Io(_))
        ));
        std::fs::remove_dir_all(&directory).expect("remove zone directory");
    }

    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let tz = embedded();
        for stamp in [i64::MIN, i64::MIN + 1, -1, i64::MAX - 1, i64::MAX] {
            let _ = tz.offset_for("Europe/Helsinki", stamp);
            let _ = tz.offset_for("America/New_York", stamp);
            let _ = tz.local_parts("Australia/Sydney", stamp);
            let _ = super::offset_for("UTC", stamp);
            let rule = PosixTz::parse("EET-2EEST,M3.5.0/3,M10.5.0/4").unwrap();
            let _ = rule.offset_at(stamp);
            let _ = rule.name_at(stamp);
        }
    }

    #[test]
    fn fuzz_timezone_parsers_do_not_panic() {
        let mut rng = Rng::new(0x7a11_0001);
        let cases = iterations(400);
        for _ in 0..cases {
            let spec_length = rng.below(80);
            let spec = rng.text(spec_length);
            let _ = PosixTz::parse(&spec);
            let _ = is_valid_zone_name(&spec);
            let byte_length = rng.below(120);
            let bytes = rng.bytes(byte_length);
            let _ = Zone::parse_tzif(&bytes);
            let _ = Tzdb::from_archive(&bytes);
            let zone = rng.pick(&["UTC", "Europe/Helsinki", "Not/AZone", "", "Z"]);
            let stamp = (rng.next_u64() % 8_000_000_000) as i64 - 2_000_000_000;
            let _ = offset_for(zone, stamp);
            let _ = embedded().local_parts(zone, stamp);
        }
        for hostile in fador_testutil::MALICIOUS_STRINGS {
            let _ = PosixTz::parse(hostile);
            let _ = is_valid_zone_name(hostile);
            let _ = Tzdb::from_archive(hostile.as_bytes());
        }
    }
}
