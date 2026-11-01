//! SMF's `timeformat()` on top of [`fador_i18n`].
//!
//! The original templates call `timeformat()` for every displayed date. SMF
//! computes the local instant in three steps: add the user's and the board's
//! hour offset, apply the board's PHP `default_timezone` (including its
//! daylight-saving transitions), and format the result with an `strftime`
//! subset read from the language pack. A `todayMod` setting replaces the date
//! part with "Today" or "Yesterday" for the current and previous day.
//!
//! The token formatting and the time-zone database come from
//! [`fador_i18n::format_strftime`] and [`fador_i18n::offset_for`]; this module
//! keeps only the SMF-specific wrapper, because the offsets are applied to the
//! timestamp *before* the zone lookup (so a DST transition is resolved at the
//! shifted instant) and the today/yesterday labels are SMF's, not phpBB's.

pub use fador_i18n::{format_strftime, TimeStrings};

/// SMF's date settings, as `$user_info` and `$modSettings` hold them.
#[derive(Debug, Clone)]
pub struct TimeSettings {
    /// `strftime` format string, for example `%B %d, %Y, %I:%M:%S %p`.
    pub format: String,
    /// `0` for a plain date, `1` for "Today", `2` for "Today" and "Yesterday".
    pub today_mod: i64,
    /// The visitor's time offset in hours.
    pub user_offset: f64,
    /// The board's time offset in hours.
    pub forum_offset: f64,
    /// PHP `default_timezone` identifier, for example `Europe/Helsinki`.
    pub zone: String,
}

impl Default for TimeSettings {
    fn default() -> Self {
        Self {
            format: "%B %d, %Y, %I:%M:%S %p".into(),
            today_mod: 0,
            user_offset: 0.0,
            forum_offset: 0.0,
            zone: String::new(),
        }
    }
}

/// Which format string `format_time()` uses for the date part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TodayKind<'a> {
    /// `timeformat($stamp)` — use the configured format, with "Today" when
    /// `today_mod` is enabled.
    Today,
    /// `timeformat($stamp, 'format')` — use this format instead.
    Custom(&'a str),
    /// `timeformat($stamp, false)` — use the configured format, but never the
    /// "Today"/"Yesterday" labels.
    User,
}

/// Which hour offsets apply to the timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetType {
    /// The visitor's offset plus the board's (`timeformat()`'s default).
    UserAndForum,
    /// Only the board's offset (`timeformat($stamp, true, 'forum')`).
    ForumOnly,
    /// No offset (`timeformat($stamp, true, false)`).
    None,
}

/// Format one timestamp the way SMF's `timeformat()` does.
///
/// `now` is the current time, used only for the "Today"/"Yesterday" labels.
pub fn format_time(
    timestamp: i64,
    now: i64,
    kind: TodayKind<'_>,
    offset_type: OffsetType,
    settings: &TimeSettings,
    strings: &TimeStrings,
) -> String {
    let offset = match offset_type {
        OffsetType::UserAndForum => settings.user_offset + settings.forum_offset,
        OffsetType::ForumOnly => settings.forum_offset,
        OffsetType::None => 0.0,
    };
    let shifted = timestamp.saturating_add((offset * 3600.0) as i64);
    let time = shifted.saturating_add(timezone_offset_seconds(&settings.zone, shifted));

    if settings.today_mod >= 1 && kind == TodayKind::Today {
        let now_shifted =
            now.saturating_add(((settings.user_offset + settings.forum_offset) * 3600.0) as i64);
        let now_time =
            now_shifted.saturating_add(timezone_offset_seconds(&settings.zone, now_shifted));
        let then = DateParts::new(time);
        let current = DateParts::new(now_time);
        if then.yday == current.yday && then.year == current.year {
            let today_format = today_format(&settings.format);
            return format!(
                "{}{}",
                strings.today,
                format_time(
                    timestamp,
                    now,
                    TodayKind::Custom(&today_format),
                    offset_type,
                    settings,
                    strings,
                )
            );
        }
        if settings.today_mod == 2
            && ((then.yday == current.yday - 1 && then.year == current.year)
                || (current.yday == 0
                    && then.year == current.year - 1
                    && then.month == 12
                    && then.day == 31))
        {
            let today_format = today_format(&settings.format);
            return format!(
                "{}{}",
                strings.yesterday,
                format_time(
                    timestamp,
                    now,
                    TodayKind::Custom(&today_format),
                    offset_type,
                    settings,
                    strings,
                )
            );
        }
    }

    let format = match kind {
        TodayKind::Custom(format) => format,
        TodayKind::Today | TodayKind::User => &settings.format,
    };
    format_strftime(format, time, strings)
}

/// Seconds east of UTC for a PHP `default_timezone` identifier at the given
/// instant.
///
/// Fixed zones such as `Etc/GMT-2` never change; named zones follow their
/// daylight-saving transitions from the embedded IANA archive.
pub fn timezone_offset_seconds(zone: &str, timestamp: i64) -> i64 {
    i64::from(fador_i18n::offset_for(zone, timestamp))
}

/// The shorter format SMF shows after the "Today" label.
fn today_format(format: &str) -> String {
    let seconds = if format.contains("%S") { ":%S" } else { "" };
    if !format.contains("%H") && !format.contains("%T") {
        let hour = if format.contains("%l") { "%l" } else { "%I" };
        format!("{hour}:%M{seconds} %p")
    } else {
        format!("%H:%M{seconds}")
    }
}

/// The calendar fields the today/yesterday comparison needs.
struct DateParts {
    year: i32,
    month: u32,
    day: u32,
    yday: i64,
}

impl DateParts {
    fn new(timestamp: i64) -> Self {
        let days = timestamp.div_euclid(86_400);
        let (year, month, day) = fador_core::util::civil_from_days(days);
        Self {
            year,
            month,
            day,
            yday: days - fador_core::util::days_from_civil(year, 1, 1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn english() -> TimeStrings {
        TimeStrings {
            days: [
                "Sunday",
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            days_short: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
                .into_iter()
                .map(str::to_string)
                .collect(),
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
            .into_iter()
            .map(str::to_string)
            .collect(),
            months_short: [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            time_am: "am".into(),
            time_pm: "pm".into(),
            today: "<strong>Today</strong> at ".into(),
            yesterday: "<strong>Yesterday</strong> at ".into(),
            capitalize: true,
        }
    }

    fn settings() -> TimeSettings {
        TimeSettings::default()
    }

    #[test]
    fn formats_the_default_smf_date() {
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::User,
                OffsetType::UserAndForum,
                &settings(),
                &english()
            ),
            "January 01, 1970, 12:00:00 am"
        );
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::Custom("%A %e. %B %Y"),
                OffsetType::UserAndForum,
                &settings(),
                &english()
            ),
            "Thursday  1. January 1970"
        );
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::Custom("%T %% %j"),
                OffsetType::UserAndForum,
                &settings(),
                &english()
            ),
            "00:00:00 % 001"
        );
    }

    #[test]
    fn applies_the_board_timezone() {
        let mut settings = settings();
        settings.zone = "Etc/GMT-2".into();
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::User,
                OffsetType::UserAndForum,
                &settings,
                &english()
            ),
            "January 01, 1970, 02:00:00 am"
        );
        assert_eq!(timezone_offset_seconds("Etc/GMT+5", 0), -5 * 3600);
        assert_eq!(timezone_offset_seconds("UTC", 0), 0);
    }

    #[test]
    fn named_zones_switch_between_summer_and_winter_time() {
        let mut settings = settings();
        settings.zone = "Europe/Helsinki".into();
        let rendered = |timestamp: i64| {
            format_time(
                timestamp,
                0,
                TodayKind::User,
                OffsetType::UserAndForum,
                &settings,
                &english(),
            )
        };
        // 2026-01-01T00:00:00Z is 02:00 EET.
        assert_eq!(rendered(1_767_225_600), "January 01, 2026, 02:00:00 am");
        // 2026-07-01T00:00:00Z is 03:00 EEST.
        assert_eq!(rendered(1_782_864_000), "July 01, 2026, 03:00:00 am");
        // Winter time begins at 2026-10-25T01:00:00Z (03:00 EET).
        assert_eq!(rendered(1_792_890_000), "October 25, 2026, 03:00:00 am");
        // A moment earlier still uses summer time.
        assert_eq!(rendered(1_792_889_999), "October 25, 2026, 03:59:59 am");
    }

    #[test]
    fn today_detection_uses_the_board_timezone() {
        let mut settings = settings();
        settings.zone = "Europe/Helsinki".into();
        settings.today_mod = 2;
        // 2026-10-26T22:30:00Z is already 2026-10-27 00:30 in Helsinki.
        let timestamp = 1_793_053_800;
        assert_eq!(
            format_time(
                timestamp,
                timestamp,
                TodayKind::Today,
                OffsetType::UserAndForum,
                &settings,
                &english()
            ),
            "<strong>Today</strong> at 12:30:00 am"
        );
    }

    #[test]
    fn applies_user_and_forum_offsets() {
        let mut settings = settings();
        settings.user_offset = 2.0;
        settings.forum_offset = -1.0;
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::User,
                OffsetType::UserAndForum,
                &settings,
                &english()
            ),
            "January 01, 1970, 01:00:00 am"
        );
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::User,
                OffsetType::ForumOnly,
                &settings,
                &english()
            ),
            "December 31, 1969, 11:00:00 pm"
        );
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::User,
                OffsetType::None,
                &settings,
                &english()
            ),
            "January 01, 1970, 12:00:00 am"
        );
    }

    #[test]
    fn replaces_today_and_yesterday() {
        let mut settings = settings();
        settings.today_mod = 2;
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::Today,
                OffsetType::UserAndForum,
                &settings,
                &english()
            ),
            "<strong>Today</strong> at 12:00:00 am"
        );
        assert_eq!(
            format_time(
                0,
                86_400,
                TodayKind::Today,
                OffsetType::UserAndForum,
                &settings,
                &english()
            ),
            "<strong>Yesterday</strong> at 12:00:00 am"
        );
        // Across a year boundary the previous day is still recognised:
        // 2025-12-31T00:00:00Z seen from 2026-01-01T00:00:00Z.
        assert_eq!(
            format_time(
                1_767_139_200,
                1_767_225_600,
                TodayKind::Today,
                OffsetType::UserAndForum,
                &settings,
                &english()
            ),
            "<strong>Yesterday</strong> at 12:00:00 am"
        );
    }

    #[test]
    fn today_label_is_skipped_when_disabled() {
        let mut settings = settings();
        settings.today_mod = 0;
        assert_eq!(
            format_time(
                0,
                0,
                TodayKind::Today,
                OffsetType::UserAndForum,
                &settings,
                &english()
            ),
            "January 01, 1970, 12:00:00 am"
        );
    }

    #[test]
    fn uses_language_names_without_capitalisation_when_disabled() {
        let strings = TimeStrings {
            days: vec!["sunnuntai".into(), "maanantai".into()],
            months: vec!["tammikuu".into()],
            capitalize: false,
            time_am: "ap".into(),
            time_pm: "ip".into(),
            ..TimeStrings::default()
        };
        assert_eq!(
            format_time(
                259_200,
                0,
                TodayKind::Custom("%A %e %B"),
                OffsetType::UserAndForum,
                &settings(),
                &strings
            ),
            "sunnuntai  4 tammikuu"
        );
    }

    #[test]
    fn extreme_timestamps_do_not_panic() {
        let mut settings = settings();
        settings.zone = "Europe/Helsinki".into();
        for stamp in [i64::MIN, i64::MIN + 1, -1, i64::MAX - 1, i64::MAX] {
            let _ = format_time(
                stamp,
                stamp,
                TodayKind::Today,
                OffsetType::UserAndForum,
                &settings,
                &english(),
            );
        }
    }
}
