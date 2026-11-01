//! phpBB's plural rules and the form selection its `lang()` performs.
//!
//! phpBB ships a single `PLURAL_RULE` number in each language pack and a table
//! of sixteen rules based on the Mozilla plural-forms list. [`plural_form`]
//! reproduces `phpbb\language\language::get_plural_form()` exactly, and
//! [`select_plural`] reproduces the nullar/singular/plural choice, including
//! the fallback to the greatest defined form below the requested one.

/// The number of plural rules phpBB defines (rules `0` to `15`).
pub const PLURAL_RULES: u8 = 16;

/// The plural form (1-based) for `number` under phpBB `rule`.
///
/// Rules outside `0..=15` fall back to rule 1 (the Germanic/Finno-Ugric rule),
/// which is also phpBB's default when a pack does not name one. Counts are
/// expected to be non-negative; the modulo arithmetic follows PHP's `%`, so a
/// negative count simply selects a later form.
#[must_use]
pub fn plural_form(number: i64, rule: u8) -> u8 {
    match rule {
        // Asian, Persian, Turkic/Altaic, Thai, Lao: one form for everything.
        0 => 1,
        // Germanic, Finno-Ugric, Basque, Greek, Hebrew, most Romanic.
        2 => {
            if number == 0 || number == 1 {
                1
            } else {
                2
            }
        }
        // Latvian: 0; ends in 1 but not 11; everything else.
        3 => {
            if number == 0 {
                1
            } else if number % 10 == 1 && number % 100 != 11 {
                2
            } else {
                3
            }
        }
        // Scottish Gaelic: 1/11, 2/12, 3-19, everything else.
        4 => {
            if number == 1 || number == 11 {
                1
            } else if number == 2 || number == 12 {
                2
            } else if (3..=19).contains(&number) {
                3
            } else {
                4
            }
        }
        // Romanian: 1; 0 or ends in 01-19; everything else.
        5 => {
            if number == 1 {
                1
            } else if number == 0 || (number % 100 > 0 && number % 100 < 20) {
                2
            } else {
                3
            }
        }
        // Lithuanian: ends in 1 but not 11; ends in 0 or 10-20; everything else.
        6 => {
            if number % 10 == 1 && number % 100 != 11 {
                1
            } else if number % 10 < 2 || (10..20).contains(&(number % 100)) {
                2
            } else {
                3
            }
        }
        // Slavic: ends in 1 but not 11; ends in 2-4 but not 12-14; everything else.
        7 => {
            if number % 10 == 1 && number % 100 != 11 {
                1
            } else if (2..=4).contains(&(number % 10)) && (number % 100 < 10 || number % 100 >= 20)
            {
                2
            } else {
                3
            }
        }
        // Slovak and Czech: 1; 2-4; everything else.
        8 => {
            if number == 1 {
                1
            } else if (2..=4).contains(&number) {
                2
            } else {
                3
            }
        }
        // Polish: 1; ends in 2-4 but not 12-14; everything else.
        9 => {
            if number == 1 {
                1
            } else if (2..=4).contains(&(number % 10)) && !(12..=14).contains(&(number % 100)) {
                2
            } else {
                3
            }
        }
        // Slovenian and Sorbian: ends in 01, 02, 03-04, everything else.
        10 => match number % 100 {
            1 => 1,
            2 => 2,
            3 | 4 => 3,
            _ => 4,
        },
        // Irish: 1, 2, 3-6, 7-10, everything else.
        11 => {
            if number == 1 {
                1
            } else if number == 2 {
                2
            } else if (3..=6).contains(&number) {
                3
            } else if (7..=10).contains(&number) {
                4
            } else {
                5
            }
        }
        // Arabic: 1, 2, ends in 03-10, ends in 11-99, 100-102, 0.
        12 => {
            if number == 1 {
                1
            } else if number == 2 {
                2
            } else if (3..=10).contains(&(number % 100)) {
                3
            } else if (11..=99).contains(&(number % 100)) {
                4
            } else if number != 0 {
                5
            } else {
                6
            }
        }
        // Maltese: 1; 0 or ends in 01-10; ends in 11-19; everything else.
        13 => {
            if number == 1 {
                1
            } else if number == 0 || (number % 100 > 1 && number % 100 < 11) {
                2
            } else if number % 100 > 10 && number % 100 < 20 {
                3
            } else {
                4
            }
        }
        // Macedonian: ends in 1; ends in 2; everything else.
        14 => {
            if number % 10 == 1 {
                1
            } else if number % 10 == 2 {
                2
            } else {
                3
            }
        }
        // Icelandic: ends in 1 but not 11; everything else.
        15 => {
            if number % 10 == 1 && number % 100 != 11 {
                1
            } else {
                2
            }
        }
        // Rule 1 and every unknown rule.
        _ => {
            if number == 1 {
                1
            } else {
                2
            }
        }
    }
}

/// Select a plural form from an indexed list such as a JSON array.
///
/// Index `0` is the nullar entry, index `1` form 1 and so on. A `count` of zero
/// uses index `0` when it exists; otherwise the form returned by
/// [`plural_form`] is used, falling back to the last entry when the list is
/// shorter. A missing count (`None`) selects the last entry, which is normally
/// the plural form.
#[must_use]
pub fn select_plural<T>(forms: &[T], count: Option<i64>, rule: u8) -> Option<&T> {
    let last = forms.last()?;
    let Some(count) = count else {
        return Some(last);
    };
    if count == 0 {
        return forms.first();
    }
    forms.get(plural_form(count, rule) as usize).or(Some(last))
}

/// Select a plural form from entries keyed by their phpBB form number.
///
/// The entries must be sorted by key in ascending order, which is how a pack
/// stores an object such as `{"0": "no posts", "1": "1 post", "2": "%d posts"}`.
/// Selection matches phpBB: a zero count uses key `0` when present, then the
/// exact form, then the greatest key below it, then the last entry.
#[must_use]
pub fn select_plural_entries<T>(entries: &[(i64, T)], count: Option<i64>, rule: u8) -> Option<&T> {
    let last = &entries.last()?.1;
    let Some(count) = count else {
        return Some(last);
    };
    if count == 0 {
        if let Some((_, value)) = entries.iter().find(|(key, _)| *key == 0) {
            return Some(value);
        }
    }
    let form = i64::from(plural_form(count, rule));
    if let Some((_, value)) = entries.iter().find(|(key, _)| *key == form) {
        return Some(value);
    }
    let mut fallback = None;
    for (key, value) in entries {
        if *key > form {
            break;
        }
        fallback = Some(value);
    }
    Some(fallback.unwrap_or(last))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (rule, number, expected form) vectors taken from phpBB's rule comments.
    const VECTORS: &[(u8, i64, u8)] = &[
        (0, 0, 1),
        (0, 1, 1),
        (0, 5, 1),
        (1, 0, 2),
        (1, 1, 1),
        (1, 2, 2),
        (1, 11, 2),
        (2, 0, 1),
        (2, 1, 1),
        (2, 2, 2),
        (2, 100, 2),
        (3, 0, 1),
        (3, 1, 2),
        (3, 11, 3),
        (3, 21, 2),
        (3, 101, 2),
        (3, 111, 3),
        (4, 0, 4),
        (4, 1, 1),
        (4, 2, 2),
        (4, 3, 3),
        (4, 11, 1),
        (4, 12, 2),
        (4, 19, 3),
        (4, 20, 4),
        (5, 0, 2),
        (5, 1, 1),
        (5, 19, 2),
        (5, 20, 3),
        (5, 100, 3),
        (5, 101, 2),
        (6, 0, 2),
        (6, 1, 1),
        (6, 2, 3),
        (6, 10, 2),
        (6, 11, 2),
        (6, 19, 2),
        (6, 20, 2),
        (6, 21, 1),
        (6, 22, 3),
        (7, 0, 3),
        (7, 1, 1),
        (7, 2, 2),
        (7, 4, 2),
        (7, 5, 3),
        (7, 11, 3),
        (7, 12, 3),
        (7, 21, 1),
        (7, 22, 2),
        (8, 0, 3),
        (8, 1, 1),
        (8, 2, 2),
        (8, 4, 2),
        (8, 5, 3),
        (9, 0, 3),
        (9, 1, 1),
        (9, 2, 2),
        (9, 12, 3),
        (9, 22, 2),
        (9, 112, 3),
        (10, 0, 4),
        (10, 1, 1),
        (10, 2, 2),
        (10, 3, 3),
        (10, 4, 3),
        (10, 5, 4),
        (10, 101, 1),
        (10, 102, 2),
        (10, 103, 3),
        (11, 0, 5),
        (11, 1, 1),
        (11, 2, 2),
        (11, 3, 3),
        (11, 6, 3),
        (11, 7, 4),
        (11, 10, 4),
        (11, 11, 5),
        (12, 0, 6),
        (12, 1, 1),
        (12, 2, 2),
        (12, 3, 3),
        (12, 10, 3),
        (12, 11, 4),
        (12, 99, 4),
        (12, 100, 5),
        (12, 103, 3),
        (12, 111, 4),
        (13, 0, 2),
        (13, 1, 1),
        (13, 2, 2),
        (13, 10, 2),
        (13, 11, 3),
        (13, 19, 3),
        (13, 20, 4),
        (13, 101, 4),
        (13, 110, 2),
        (14, 0, 3),
        (14, 1, 1),
        (14, 2, 2),
        (14, 11, 1),
        (14, 12, 2),
        (14, 21, 1),
        (15, 0, 2),
        (15, 1, 1),
        (15, 2, 2),
        (15, 11, 2),
        (15, 21, 1),
        (15, 101, 1),
    ];

    #[test]
    fn every_rule_matches_phpbb() {
        for (rule, number, expected) in VECTORS {
            assert_eq!(
                plural_form(*number, *rule),
                *expected,
                "rule {rule}, number {number}"
            );
        }
    }

    #[test]
    fn rules_are_one_based_and_unknown_rules_fall_back() {
        for rule in 0..PLURAL_RULES {
            for number in 0..200 {
                let form = plural_form(number, rule);
                assert!((1..=6).contains(&form), "rule {rule} number {number}");
            }
        }
        assert_eq!(plural_form(1, 200), 1);
        assert_eq!(plural_form(2, 200), 2);
    }

    #[test]
    fn selects_the_nullar_entry_only_for_zero() {
        let forms = ["no posts", "one post", "many posts"];
        assert_eq!(select_plural(&forms, Some(0), 1), Some(&"no posts"));
        assert_eq!(select_plural(&forms, Some(1), 1), Some(&"one post"));
        assert_eq!(select_plural(&forms, Some(2), 1), Some(&"many posts"));
        assert_eq!(select_plural(&forms, Some(99), 1), Some(&"many posts"));
    }

    #[test]
    fn falls_back_to_the_greatest_defined_form_below() {
        let forms = ["zero", "one", "few", "many"];
        // Rule 7 asks for form 2 for 2; a two-entry list uses the last entry.
        assert_eq!(select_plural(&forms[..2], Some(2), 7), Some(&"one"));
        // A missing form uses the greatest key below it.
        let short = ["zero", "one", "many"];
        assert_eq!(select_plural(&short, Some(5), 7), Some(&"many"));
        assert_eq!(select_plural::<&str>(&[], Some(1), 1), None);
        assert_eq!(select_plural(&forms, None, 1), Some(&"many"));
    }

    #[test]
    fn keyed_entries_follow_the_same_rules() {
        let entries = [(0_i64, "no posts"), (1, "one post"), (2, "many posts")];
        assert_eq!(
            select_plural_entries(&entries, Some(0), 1),
            Some(&"no posts")
        );
        assert_eq!(
            select_plural_entries(&entries, Some(1), 1),
            Some(&"one post")
        );
        assert_eq!(
            select_plural_entries(&entries, Some(9), 1),
            Some(&"many posts")
        );
        assert_eq!(
            select_plural_entries(&entries, None, 1),
            Some(&"many posts")
        );
        assert_eq!(
            select_plural_entries::<&str>(&[], Some(1), 1),
            None,
            "an empty list has no form"
        );
        // A pack without a nullar entry keeps phpBB's fallback: a zero count
        // asks for form 2, which is the plural entry.
        let without_nullar = [(1_i64, "one post"), (2, "many posts")];
        assert_eq!(
            select_plural_entries(&without_nullar, Some(0), 1),
            Some(&"many posts")
        );
    }
}
