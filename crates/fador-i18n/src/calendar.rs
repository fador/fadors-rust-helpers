//! Proleptic-Gregorian calendar helpers shared by the date and zone code.

pub(crate) use fador_core::util::{civil_from_days, days_from_civil, weekday_from_days};

/// Whether `year` is a leap year in the proleptic Gregorian calendar.
pub(crate) fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Number of days in `month` (1-12) of `year`; zero for an invalid month.
pub(crate) fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Day of the year, 1-366.
pub(crate) fn day_of_year(year: i32, month: u32, day: u32) -> u32 {
    let mut total = day;
    for current in 1..month.min(13) {
        total += days_in_month(year, current);
    }
    total
}

/// ISO-8601 week-numbering year and week for a civil date.
pub(crate) fn iso_week(year: i32, month: u32, day: u32) -> (i32, u32) {
    let ordinal = day_of_year(year, month, day) as i32;
    let weekday = ((days_from_civil(year, month, day) + 3).rem_euclid(7)) as i32 + 1;
    let mut week = (ordinal - weekday + 10) / 7;
    let mut week_year = year;
    if week < 1 {
        week_year = week_year.saturating_sub(1);
        week = iso_weeks_in_year(week_year);
    } else if week > iso_weeks_in_year(week_year) {
        week_year = week_year.saturating_add(1);
        week = 1;
    }
    (week_year, week as u32)
}

/// Number of ISO weeks in `year` (52 or 53).
fn iso_weeks_in_year(year: i32) -> i32 {
    let jan1 = (days_from_civil(year, 1, 1) + 3).rem_euclid(7) + 1;
    if jan1 == 4 || (jan1 == 3 && is_leap(year)) {
        53
    } else {
        52
    }
}

/// Day of the month for POSIX `Mmonth.week.weekday` rules.
///
/// `weekday` counts Sunday as 0. Week 5 means "the last such weekday in the
/// month", which may fall in week 4.
pub(crate) fn month_week_day(year: i32, month: u32, week: u32, weekday: u32) -> Option<u32> {
    if month == 0 || month > 12 || week == 0 || week > 5 || weekday > 6 {
        return None;
    }
    let first = days_from_civil(year, month, 1);
    // 1970-01-01 was a Thursday (4) and POSIX weekdays count Sunday as 0.
    let first_weekday = (first + 4).rem_euclid(7) as u32;
    let mut result = 1 + (weekday + 7 - first_weekday) % 7 + (week - 1) * 7;
    while result > days_in_month(year, month) {
        result -= 7;
    }
    Some(result)
}

/// Month and day for a zero-based day of the year.
///
/// POSIX `J` rules do not count February 29 (`leap_counted == false`); the
/// plain `n` form does.
pub(crate) fn month_day_from_ordinal(
    year: i32,
    day: u32,
    leap_counted: bool,
) -> Option<(u32, u32)> {
    let mut remaining = day;
    for month in 1..=12 {
        let mut days = days_in_month(year, month);
        if !leap_counted && month == 2 && is_leap(year) {
            days -= 1;
        }
        if remaining < days {
            return Some((month, remaining + 1));
        }
        remaining -= days;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_helpers_agree_with_known_dates() {
        assert!(is_leap(2000));
        assert!(!is_leap(1900));
        assert!(is_leap(2024));
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2023, 2), 28);
        assert_eq!(days_in_month(2023, 13), 0);
        assert_eq!(day_of_year(2024, 3, 1), 61);
        assert_eq!(day_of_year(2023, 3, 1), 60);
        assert_eq!(iso_week(2026, 1, 1), (2026, 1));
        assert_eq!(iso_week(2021, 1, 1), (2020, 53));
        assert_eq!(iso_week(2024, 12, 30), (2025, 1));
        assert_eq!(month_week_day(2040, 3, 5, 0), Some(25));
        assert_eq!(month_week_day(2040, 10, 5, 0), Some(28));
        assert_eq!(month_week_day(2040, 11, 1, 0), Some(4));
        assert_eq!(month_week_day(2040, 13, 1, 0), None);
        assert_eq!(month_day_from_ordinal(2024, 59, false), Some((3, 1)));
        assert_eq!(month_day_from_ordinal(2024, 59, true), Some((2, 29)));
        assert_eq!(month_day_from_ordinal(2023, 365, true), None);
        assert_eq!(month_day_from_ordinal(2023, 364, true), Some((12, 31)));
        assert_eq!(day_of_year(2024, u32::MAX, 1), 367);
        let _ = iso_week(i32::MIN, 1, 1);
        let _ = iso_week(i32::MAX, 12, 31);
    }
}
