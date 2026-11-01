//! Date formatting: PHP `date()` tokens and SMF's `strftime` subset.

use crate::calendar::{
    civil_from_days, day_of_year, days_in_month, is_leap, iso_week, weekday_from_days,
};
use crate::tz::Tzdb;

/// Localized day and month names, the "today/yesterday" labels and the
/// relative-time templates a language pack provides.
///
/// The default value holds the English names, so a caller without a pack can
/// still render a date. A pack fills the same structure from its `datetime`
/// object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateTimeNames {
    /// Seven full day names, Sunday first.
    pub days_full: [String; 7],
    /// Seven abbreviated day names, Sunday first.
    pub days_short: [String; 7],
    /// Twelve full month names, January first.
    pub months_full: [String; 12],
    /// Twelve abbreviated month names, January first.
    pub months_short: [String; 12],
    /// Label for the current day, for example `Today`.
    pub today: String,
    /// Label for the next day.
    pub tomorrow: String,
    /// Label for the previous day.
    pub yesterday: String,
    /// Relative-time templates such as `%d minutes ago`, shortest first.
    pub ago: Vec<String>,
}

impl Default for DateTimeNames {
    fn default() -> Self {
        Self::english()
    }
}

impl DateTimeNames {
    /// English day and month names with empty relative-time templates.
    #[must_use]
    pub fn english() -> Self {
        Self {
            days_full: [
                "Sunday",
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
            ]
            .map(str::to_string),
            days_short: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map(str::to_string),
            months_full: [
                "January",
                "February",
                "March",
                "April",
                "May",
                "June",
                "July",
                "August",
                "September",
                "October",
                "November",
                "December",
            ]
            .map(str::to_string),
            months_short: [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ]
            .map(str::to_string),
            today: "Today".to_string(),
            tomorrow: "Tomorrow".to_string(),
            yesterday: "Yesterday".to_string(),
            ago: Vec::new(),
        }
    }

    /// Full day name for `index` (0 = Sunday), or an empty string.
    #[must_use]
    pub fn day_full(&self, index: usize) -> &str {
        self.days_full.get(index).map_or("", String::as_str)
    }

    /// Abbreviated day name for `index` (0 = Sunday), or an empty string.
    #[must_use]
    pub fn day_short(&self, index: usize) -> &str {
        self.days_short.get(index).map_or("", String::as_str)
    }

    /// Full month name for `index` (0 = January), or an empty string.
    #[must_use]
    pub fn month_full(&self, index: usize) -> &str {
        self.months_full.get(index).map_or("", String::as_str)
    }

    /// Abbreviated month name for `index` (0 = January), or an empty string.
    #[must_use]
    pub fn month_short(&self, index: usize) -> &str {
        self.months_short.get(index).map_or("", String::as_str)
    }

    /// The "today" label.
    #[must_use]
    pub fn today(&self) -> &str {
        &self.today
    }

    /// The "tomorrow" label.
    #[must_use]
    pub fn tomorrow(&self) -> &str {
        &self.tomorrow
    }

    /// The "yesterday" label.
    #[must_use]
    pub fn yesterday(&self) -> &str {
        &self.yesterday
    }

    /// The relative-time template for `count`, with `%d` replaced.
    ///
    /// The templates are ordered from the smallest unit up, so a count larger
    /// than the number of templates uses the last one.
    #[must_use]
    pub fn ago(&self, count: i64) -> String {
        if self.ago.is_empty() {
            return String::new();
        }
        let index = if count <= 0 {
            0
        } else {
            (count as usize).min(self.ago.len() - 1)
        };
        self.ago[index].replace("%d", &count.to_string())
    }
}

/// Day and month names for SMF's `strftime` subset.
///
/// SMF reads these from its language files, and `capitalize` mirrors the
/// pack's `ucwords` setting: Finnish month names stay lower case while English
/// ones are capitalized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimeStrings {
    /// Seven day names, Sunday first.
    pub days: Vec<String>,
    /// Seven abbreviated day names, Sunday first.
    pub days_short: Vec<String>,
    /// Twelve month names, January first.
    pub months: Vec<String>,
    /// Twelve abbreviated month names, January first.
    pub months_short: Vec<String>,
    /// The AM marker, for example `am`.
    pub time_am: String,
    /// The PM marker, for example `pm`.
    pub time_pm: String,
    /// SMF's "today" prefix, provided for callers that implement
    /// `timeformat()`'s relative dates.
    pub today: String,
    /// SMF's "yesterday" prefix.
    pub yesterday: String,
    /// Whether names are passed through `ucwords()` before they are printed.
    pub capitalize: bool,
}

impl TimeStrings {
    /// English names with `capitalize` enabled and SMF's default labels.
    #[must_use]
    pub fn english() -> Self {
        Self {
            days: [
                "Sunday",
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
            ]
            .map(str::to_string)
            .to_vec(),
            days_short: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
                .map(str::to_string)
                .to_vec(),
            months: [
                "January",
                "February",
                "March",
                "April",
                "May",
                "June",
                "July",
                "August",
                "September",
                "October",
                "November",
                "December",
            ]
            .map(str::to_string)
            .to_vec(),
            months_short: [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ]
            .map(str::to_string)
            .to_vec(),
            time_am: "am".to_string(),
            time_pm: "pm".to_string(),
            today: "Today at ".to_string(),
            yesterday: "Yesterday at ".to_string(),
            capitalize: true,
        }
    }
}

/// Format `unix_time` with PHP `date()` tokens in `zone`.
///
/// The tokens are the ones PHP's `date()` supports: `d j D l N S w z W F m M n
/// t L o Y y a A B g G h H i s u v e I O P p T Z c r U`. A backslash escapes
/// the next character, and an unknown token is copied through unchanged.
///
/// Day and month names come from `names`, so the result is localized even
/// though the token letters are PHP's. `english_ordinals` controls `S`: PHP
/// always prints `st`/`nd`/`rd`/`th`, but a non-English pack usually wants no
/// suffix at all (Finnish writes `1.`), so the ported behaviour keeps the
/// suffix for English packs only.
///
/// ```
/// use fador_i18n::{format_date_php, DateTimeNames, Tzdb};
///
/// let names = DateTimeNames::english();
/// let tz = Tzdb::embedded();
/// assert_eq!(
///     format_date_php(&tz, &names, true, 0, "UTC", "D, d M Y H:i:s O"),
///     "Thu, 01 Jan 1970 00:00:00 +0000"
/// );
/// ```
#[must_use]
pub fn format_date_php(
    tz: &Tzdb,
    names: &DateTimeNames,
    english_ordinals: bool,
    unix_time: i64,
    zone: &str,
    format: &str,
) -> String {
    let offset = tz.offset_for(zone, unix_time).unwrap_or(0);
    let abbreviation = tz
        .abbreviation(zone, unix_time)
        .unwrap_or_else(|| zone.to_string());
    let is_dst = tz.is_dst(zone, unix_time).unwrap_or(false);

    let local = unix_time.saturating_add(i64::from(offset));
    let days = local.div_euclid(86_400);
    let seconds = local.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = weekday_from_days(days);
    let weekday_iso = ((weekday + 6) % 7) + 1;
    let hour = (seconds / 3_600) as u32;
    let minute = ((seconds % 3_600) / 60) as u32;
    let second = (seconds % 60) as u32;
    let hour12 = if hour.is_multiple_of(12) {
        12
    } else {
        hour % 12
    };
    let ordinal = day_of_year(year, month, day);
    let leap = is_leap(year);
    let month_days = days_in_month(year, month);
    let iso = iso_week(year, month, day);
    // Swatch Internet Time counts 1/1000 of a day in UTC+1.
    let beats = ((unix_time.saturating_add(3_600).rem_euclid(86_400)) as f64 / 86.4) as u32;

    let mut out = String::with_capacity(format.len() + 16);
    let mut chars = format.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
            continue;
        }
        match ch {
            'd' => out.push_str(&format!("{day:02}")),
            'j' => out.push_str(&day.to_string()),
            'D' => out.push_str(names.day_short(weekday)),
            'l' => out.push_str(names.day_full(weekday)),
            'N' => out.push_str(&weekday_iso.to_string()),
            'S' => {
                if english_ordinals {
                    out.push_str(ordinal_suffix(day));
                }
            }
            'w' => out.push_str(&weekday.to_string()),
            'z' => out.push_str(&(ordinal - 1).to_string()),
            'W' => out.push_str(&format!("{:02}", iso.1)),
            'F' => out.push_str(names.month_full((month - 1) as usize)),
            'm' => out.push_str(&format!("{month:02}")),
            'M' => out.push_str(names.month_short((month - 1) as usize)),
            'n' => out.push_str(&month.to_string()),
            't' => out.push_str(&month_days.to_string()),
            'L' => out.push(if leap { '1' } else { '0' }),
            'o' => out.push_str(&iso.0.to_string()),
            'Y' => out.push_str(&year.to_string()),
            'y' => out.push_str(&format!("{:02}", year.rem_euclid(100))),
            'a' => out.push_str(if hour < 12 { "am" } else { "pm" }),
            'A' => out.push_str(if hour < 12 { "AM" } else { "PM" }),
            'B' => out.push_str(&format!("{beats:03}")),
            'g' => out.push_str(&hour12.to_string()),
            'G' => out.push_str(&hour.to_string()),
            'h' => out.push_str(&format!("{hour12:02}")),
            'H' => out.push_str(&format!("{hour:02}")),
            'i' => out.push_str(&format!("{minute:02}")),
            's' => out.push_str(&format!("{second:02}")),
            'u' => out.push_str("000000"),
            'v' => out.push_str("000"),
            'e' => out.push_str(zone),
            'I' => out.push(if is_dst { '1' } else { '0' }),
            'O' => out.push_str(&format_offset(offset, false)),
            'P' => out.push_str(&format_offset(offset, true)),
            'p' => {
                if offset == 0 {
                    out.push('Z');
                } else {
                    out.push_str(&format_offset(offset, true));
                }
            }
            'T' => out.push_str(&abbreviation),
            'Z' => out.push_str(&offset.to_string()),
            'c' => out.push_str(&format!(
                "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{}",
                format_offset(offset, true)
            )),
            'r' => out.push_str(&format!(
                "{}, {day:02} {} {year} {hour:02}:{minute:02}:{second:02} {}",
                names.day_short(weekday),
                names.month_short((month - 1) as usize),
                format_offset(offset, false)
            )),
            'U' => out.push_str(&unix_time.to_string()),
            other => out.push(other),
        }
    }
    out
}

/// Format a UTC offset as `+03:00` (with a colon) or `+0300`.
#[must_use]
pub fn format_offset(offset_seconds: i32, colon: bool) -> String {
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let absolute = offset_seconds.unsigned_abs();
    let hours = absolute / 3_600;
    let minutes = (absolute % 3_600) / 60;
    if colon {
        format!("{sign}{hours:02}:{minutes:02}")
    } else {
        format!("{sign}{hours:02}{minutes:02}")
    }
}

/// English ordinal suffix for a day of the month.
fn ordinal_suffix(day: u32) -> &'static str {
    match day {
        11..=13 => "th",
        _ => match day % 10 {
            1 => "st",
            2 => "nd",
            3 => "rd",
            _ => "th",
        },
    }
}

/// Format a local wall-clock timestamp with SMF's `strftime` subset.
///
/// `local_seconds` is a timestamp that already includes the zone offset, the
/// same value SMF's `timeformat()` passes to `strftime()`. Use
/// [`format_strftime_in_zone`] to convert a UTC timestamp first.
///
/// Supported tokens are `a A b h B d e H I l M m p S T w j y Y %%`. An unknown
/// token is copied through as `%` plus the letter, and a trailing `%` is kept.
///
/// ```
/// use fador_i18n::{format_strftime, TimeStrings};
///
/// assert_eq!(
///     format_strftime("%B %d, %Y, %I:%M:%S %p", 0, &TimeStrings::english()),
///     "January 01, 1970, 12:00:00 am"
/// );
/// ```
#[must_use]
pub fn format_strftime(format: &str, local_seconds: i64, strings: &TimeStrings) -> String {
    let days = local_seconds.div_euclid(86_400);
    let seconds = local_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = weekday_from_days(days);
    let hour = (seconds / 3_600) as u32;
    let minute = ((seconds % 3_600) / 60) as u32;
    let second = (seconds % 60) as u32;
    let hour12 = if hour.is_multiple_of(12) {
        12
    } else {
        hour % 12
    };
    let ordinal = day_of_year(year, month, day);

    let mut out = String::with_capacity(format.len() + 16);
    let mut chars = format.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        let Some(token) = chars.next() else {
            out.push('%');
            break;
        };
        match token {
            'a' => out.push_str(&name(&strings.days_short, weekday, strings.capitalize)),
            'A' => out.push_str(&name(&strings.days, weekday, strings.capitalize)),
            'b' | 'h' => out.push_str(&name(
                &strings.months_short,
                (month as usize).saturating_sub(1),
                strings.capitalize,
            )),
            'B' => out.push_str(&name(
                &strings.months,
                (month as usize).saturating_sub(1),
                strings.capitalize,
            )),
            'd' => out.push_str(&format!("{day:02}")),
            'e' => out.push_str(&format!("{day:2}")),
            'H' => out.push_str(&format!("{hour:02}")),
            'I' => out.push_str(&format!("{hour12:02}")),
            'l' => out.push_str(&format!("{hour12:2}")),
            'M' => out.push_str(&format!("{minute:02}")),
            'm' => out.push_str(&format!("{month:02}")),
            'p' => out.push_str(if hour < 12 {
                &strings.time_am
            } else {
                &strings.time_pm
            }),
            'S' => out.push_str(&format!("{second:02}")),
            'T' => out.push_str(&format!("{hour:02}:{minute:02}:{second:02}")),
            'w' => out.push_str(&weekday.to_string()),
            'j' => out.push_str(&format!("{:03}", ordinal)),
            'y' => out.push_str(&format!("{:02}", year.rem_euclid(100))),
            'Y' => out.push_str(&format!("{year:04}")),
            '%' => out.push('%'),
            other => {
                out.push('%');
                out.push(other);
            }
        }
    }
    out
}

/// Format a UTC timestamp in `zone` with SMF's `strftime` subset.
///
/// ```
/// use fador_i18n::{format_strftime_in_zone, TimeStrings};
///
/// assert_eq!(
///     format_strftime_in_zone("%H:%M %d.%m.%Y", 0, "Etc/GMT-2", &TimeStrings::english()),
///     "02:00 01.01.1970"
/// );
/// ```
#[must_use]
pub fn format_strftime_in_zone(
    format: &str,
    unix_time: i64,
    zone: &str,
    strings: &TimeStrings,
) -> String {
    let offset = Tzdb::embedded().offset_for(zone, unix_time).unwrap_or(0);
    format_strftime(format, unix_time.saturating_add(i64::from(offset)), strings)
}

/// Look up a name, applying SMF's `ucwords()` when the pack asks for it.
fn name(list: &[String], index: usize, capitalize: bool) -> String {
    let value = list.get(index).cloned().unwrap_or_default();
    if capitalize {
        ucwords(&value)
    } else {
        value
    }
}

/// Capitalize the first letter of every whitespace-separated word.
fn ucwords(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut start = true;
    for ch in value.chars() {
        if ch.is_whitespace() {
            out.push(ch);
            start = true;
        } else if start {
            out.extend(ch.to_uppercase());
            start = false;
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fador_testutil::{iterations, Rng};

    fn tz() -> &'static Tzdb {
        Tzdb::embedded()
    }

    fn names() -> DateTimeNames {
        DateTimeNames::english()
    }

    fn finnish() -> DateTimeNames {
        let mut names = DateTimeNames::english();
        names.days_full = [
            "Sunnuntai",
            "Maanantai",
            "Tiistai",
            "Keskiviikko",
            "Torstai",
            "Perjantai",
            "Lauantai",
        ]
        .map(str::to_string);
        names.days_short = ["Su", "Ma", "Ti", "Ke", "To", "Pe", "La"].map(str::to_string);
        names.months_full = [
            "Tammikuu",
            "Helmikuu",
            "Maaliskuu",
            "Huhtikuu",
            "Toukokuu",
            "Kesäkuu",
            "Heinäkuu",
            "Elokuu",
            "Syyskuu",
            "Lokakuu",
            "Marraskuu",
            "Joulukuu",
        ]
        .map(str::to_string);
        names.months_short = [
            "Tammi", "Helmi", "Maalis", "Huhti", "Touko", "Kesä", "Heinä", "Elo", "Syys", "Loka",
            "Marras", "Joulu",
        ]
        .map(str::to_string);
        names
    }

    #[test]
    fn formats_php_tokens_in_utc() {
        let format = |format: &str| format_date_php(tz(), &names(), true, 0, "UTC", format);
        assert_eq!(format("Y-m-d H:i:s"), "1970-01-01 00:00:00");
        assert_eq!(
            format("D, d M Y H:i:s O"),
            "Thu, 01 Jan 1970 00:00:00 +0000"
        );
        assert_eq!(format("l jS F Y"), "Thursday 1st January 1970");
        assert_eq!(format("y n j"), "70 1 1");
        assert_eq!(format("N w z W o"), "4 4 0 01 1970");
        assert_eq!(format("L t"), "0 31");
        assert_eq!(format("a A g G h H"), "am AM 12 0 12 00");
        assert_eq!(format("U"), "0");
        assert_eq!(format("u v"), "000000 000");
        assert_eq!(format("e T I Z"), "UTC UTC 0 0");
        assert_eq!(format("c"), "1970-01-01T00:00:00+00:00");
        assert_eq!(format("r"), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(format("p"), "Z");
        assert_eq!(format("B"), "041");
    }

    #[test]
    fn formats_afternoon_tokens_and_leap_years() {
        // 2024-02-29T13:05:09Z
        let stamp = 1_709_211_909;
        let format = |format: &str| format_date_php(tz(), &names(), true, stamp, "UTC", format);
        assert_eq!(format("Y-m-d H:i:s"), "2024-02-29 13:05:09");
        assert_eq!(format("L t z"), "1 29 59");
        assert_eq!(format("a A g G h H"), "pm PM 1 13 01 13");
        assert_eq!(format("D jS F"), "Thu 29th February");
        assert_eq!(format("N w"), "4 4");
    }

    #[test]
    fn localizes_names_and_omits_english_ordinals() {
        let stamp = 0;
        assert_eq!(
            format_date_php(tz(), &finnish(), false, stamp, "Etc/GMT-3", "D M d, Y H:i"),
            "To Tammi 01, 1970 03:00"
        );
        assert_eq!(
            format_date_php(tz(), &finnish(), false, stamp, "UTC", "F jS, Y"),
            "Tammikuu 1, 1970"
        );
        assert_eq!(
            format_date_php(tz(), &names(), true, stamp, "UTC", "F jS, Y"),
            "January 1st, 1970"
        );
        // 11th, 12th and 13th take "th"; 21st and 22nd do not.
        let suffix = |day: i64| format_date_php(tz(), &names(), true, day * 86_400, "UTC", "jS");
        assert_eq!(suffix(10), "11th");
        assert_eq!(suffix(11), "12th");
        assert_eq!(suffix(12), "13th");
        assert_eq!(suffix(20), "21st");
        assert_eq!(suffix(21), "22nd");
        assert_eq!(suffix(22), "23rd");
    }

    #[test]
    fn follows_helsinki_summer_time_and_abbreviations() {
        // 2026-07-01T12:00:00Z is 15:00 EEST.
        assert_eq!(
            format_date_php(
                tz(),
                &names(),
                true,
                1_782_907_200,
                "Europe/Helsinki",
                "d.m.Y H:i T I O P Z p"
            ),
            "01.07.2026 15:00 EEST 1 +0300 +03:00 10800 +03:00"
        );
        // 2026-01-01T12:00:00Z is 14:00 EET.
        assert_eq!(
            format_date_php(
                tz(),
                &names(),
                true,
                1_767_268_800,
                "Europe/Helsinki",
                "d.m.Y H:i T I O P Z"
            ),
            "01.01.2026 14:00 EET 0 +0200 +02:00 7200"
        );
        // Past the last stored transition the POSIX footer keeps the rule.
        assert_eq!(
            format_date_php(
                tz(),
                &names(),
                true,
                2_225_966_400,
                "Europe/Helsinki",
                "Y-m-d H:i T"
            ),
            "2040-07-15 15:00 EEST"
        );
    }

    #[test]
    fn unknown_zones_fall_back_to_utc() {
        assert_eq!(
            format_date_php(tz(), &names(), true, 0, "Not/AZone", "Y-m-d H:i e T"),
            "1970-01-01 00:00 Not/AZone Not/AZone"
        );
    }

    #[test]
    fn escapes_literals_and_keeps_unknown_tokens() {
        let format = |format: &str| format_date_php(tz(), &names(), true, 0, "UTC", format);
        assert_eq!(format(r"\Y\m\d"), "Ymd");
        assert_eq!(format(r"\\"), "\\");
        assert_eq!(format("Q"), "Q");
        assert_eq!(format("Y\\"), "1970");
        assert_eq!(format(""), "");
    }

    #[test]
    fn formats_smf_strftime_subset() {
        let strings = TimeStrings::english();
        assert_eq!(
            format_strftime("%B %d, %Y, %I:%M:%S %p", 0, &strings),
            "January 01, 1970, 12:00:00 am"
        );
        assert_eq!(
            format_strftime("%A %e. %B %Y", 0, &strings),
            "Thursday  1. January 1970"
        );
        assert_eq!(format_strftime("%T %% %j", 0, &strings), "00:00:00 % 001");
        assert_eq!(
            format_strftime("%a %b %h %w %y %m %d %l", 259_200, &strings),
            "Sun Jan Jan 0 70 01 04 12"
        );
        // 2024-02-29T13:05:09Z, already local.
        assert_eq!(
            format_strftime("%Y-%m-%d %H:%M:%S", 1_709_211_909, &strings),
            "2024-02-29 13:05:09"
        );
        assert_eq!(format_strftime("%q", 0, &strings), "%q");
        assert_eq!(format_strftime("100%", 0, &strings), "100%");
        assert_eq!(format_strftime("", 0, &strings), "");
    }

    #[test]
    fn smf_names_follow_the_capitalize_flag() {
        let strings = TimeStrings {
            days: vec!["sunnuntai".into(), "maanantai".into()],
            months: vec!["tammikuu".into()],
            capitalize: false,
            time_am: "ap".into(),
            time_pm: "ip".into(),
            ..TimeStrings::default()
        };
        assert_eq!(
            format_strftime("%A %e %B", 259_200, &strings),
            "sunnuntai  4 tammikuu"
        );
        let mut strings = strings;
        strings.capitalize = true;
        assert_eq!(
            format_strftime("%A %e %B", 259_200, &strings),
            "Sunnuntai  4 Tammikuu"
        );
    }

    #[test]
    fn formats_strftime_in_a_zone() {
        assert_eq!(
            format_strftime_in_zone("%H:%M %d.%m.%Y", 0, "Etc/GMT-2", &TimeStrings::english()),
            "02:00 01.01.1970"
        );
        assert_eq!(
            format_strftime_in_zone("%H:%M %Z", 0, "UTC", &TimeStrings::english()),
            "00:00 %Z"
        );
    }

    #[test]
    fn relative_templates_replace_the_count() {
        let mut names = DateTimeNames::english();
        // The ported semantics index the template list with the count, the
        // way phpBB's packs store "less than a minute" at index 0.
        names.ago = vec![
            "less than a minute ago".to_string(),
            "%d minute ago".to_string(),
            "%d minutes ago".to_string(),
        ];
        assert_eq!(names.ago(0), "less than a minute ago");
        assert_eq!(names.ago(1), "1 minute ago");
        assert_eq!(names.ago(5), "5 minutes ago");
        assert_eq!(names.ago(-5), "less than a minute ago");
        assert_eq!(DateTimeNames::default().ago(3), "");
        assert_eq!(names.today(), "Today");
        assert_eq!(names.tomorrow(), "Tomorrow");
        assert_eq!(names.yesterday(), "Yesterday");
        assert_eq!(names.day_full(9), "");
        assert_eq!(names.month_short(0), "Jan");
    }

    #[test]
    fn extreme_timestamps_do_not_panic() {
        for stamp in [i64::MIN, i64::MIN + 1, -1, i64::MAX - 1, i64::MAX] {
            let _ = format_date_php(
                tz(),
                &names(),
                true,
                stamp,
                "Europe/Helsinki",
                "c r U B z W o Y y L t N w",
            );
            let _ = format_date_php(tz(), &names(), false, stamp, "UTC", "e T I O P Z p");
            let _ = format_strftime("%Y-%m-%d %H:%M:%S %j %w", stamp, &TimeStrings::english());
        }
    }

    #[test]
    fn fuzz_date_formats_do_not_panic() {
        let mut rng = Rng::new(0xda7e_0001);
        let cases = iterations(300);
        let zones = [
            "UTC",
            "Europe/Helsinki",
            "America/New_York",
            "Australia/Sydney",
            "Not/AZone",
            "",
        ];
        for _ in 0..cases {
            let length = rng.below(60);
            let format = rng.text(length);
            let stamp = (rng.next_u64() % 4_000_000_000) as i64 - 1_000_000_000;
            let zone = zones[rng.below(zones.len())];
            let _ = format_date_php(tz(), &names(), rng.below(2) == 0, stamp, zone, &format);
            let _ = format_strftime(&format, stamp, &TimeStrings::english());
        }
    }
}
