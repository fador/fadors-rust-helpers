//! Case-insensitive matching that keeps byte offsets in the original text.
//!
//! Lowercasing a string can change its byte length (`İ` becomes two code
//! points, `ẞ` becomes one), so a match is never found by lowercasing the
//! haystack and reusing those offsets. Every helper here compares the lowercase
//! expansion of one code point at a time and reports offsets into the original
//! `&str`, which keeps slicing sound and Unicode-correct.

/// Byte length of `word` matched case-insensitively at the start of `text`.
///
/// Returns `None` when `word` is empty or does not match. The returned length
/// is a char boundary of `text`.
pub(crate) fn match_prefix_ci(text: &str, word: &str) -> Option<usize> {
    if word.is_empty() {
        return None;
    }
    if word.is_ascii() {
        let bytes = text.as_bytes();
        if bytes.len() >= word.len()
            && text.is_char_boundary(word.len())
            && bytes[..word.len()].eq_ignore_ascii_case(word.as_bytes())
        {
            return Some(word.len());
        }
        // A non-ASCII code point in the haystack can lowercase to an ASCII
        // character (`K` U+212A lowercases to `k`), so fall through instead of
        // reporting a miss here.
    }
    let mut offset = 0usize;
    let mut text_chars = text.char_indices();
    for word_char in word.chars() {
        let (index, text_char) = text_chars.next()?;
        offset = index + text_char.len_utf8();
        if !word_char.to_lowercase().eq(text_char.to_lowercase()) {
            return None;
        }
    }
    Some(offset)
}

/// Push every case-insensitive occurrence of `needle` in `text` into `out`.
///
/// Matches may overlap; callers merge the ranges they keep. At most `limit`
/// ranges are appended in total.
pub(crate) fn find_ranges_ci(
    text: &str,
    needle: &str,
    limit: usize,
    out: &mut Vec<(usize, usize)>,
) {
    if needle.is_empty() || out.len() >= limit {
        return;
    }
    for (start, _) in text.char_indices() {
        if out.len() >= limit {
            return;
        }
        if let Some(len) = match_prefix_ci(&text[start..], needle) {
            out.push((start, start + len));
        }
    }
}

/// Byte offset of the first case-insensitive occurrence of `needle` in `text`.
pub(crate) fn find_ci(text: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    for (start, _) in text.char_indices() {
        if match_prefix_ci(&text[start..], needle).is_some() {
            return Some(start);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ascii_case_insensitively() {
        assert_eq!(match_prefix_ci("Hello", "hello"), Some(5));
        assert_eq!(match_prefix_ci("Hello", "hell"), Some(4));
        assert_eq!(match_prefix_ci("Hello", "hellx"), None);
        assert_eq!(match_prefix_ci("Hi", "hello"), None);
    }

    #[test]
    fn matches_unicode_case_insensitively() {
        assert_eq!(match_prefix_ci("Ääkkösiä", "äÄKKÖSIÄ"), Some(12));
        assert_eq!(match_prefix_ci("Ää", "a"), None);
        assert_eq!(match_prefix_ci("Kelvin K", "k"), Some(1));
        assert_eq!(match_prefix_ci("\u{212a}", "k"), Some(3));
    }

    #[test]
    fn never_splits_a_code_point() {
        // The ASCII fast path must not report a match that ends inside a
        // multi-byte character.
        assert_eq!(match_prefix_ci("ä", "a"), None);
        assert_eq!(match_prefix_ci("aä", "a"), Some(1));
    }

    #[test]
    fn finds_every_range() {
        let mut ranges = Vec::new();
        find_ranges_ci("aa aa", "aa", 8, &mut ranges);
        assert_eq!(ranges, vec![(0, 2), (3, 5)]);
    }

    #[test]
    fn respects_the_range_limit() {
        let mut ranges = Vec::new();
        find_ranges_ci("aaaa", "a", 2, &mut ranges);
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn find_ci_reports_original_offsets() {
        assert_eq!(find_ci("Ääb", "B"), Some(4));
        assert_eq!(find_ci("abc", "z"), None);
        assert_eq!(find_ci("abc", ""), Some(0));
    }
}
