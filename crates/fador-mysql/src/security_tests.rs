//! Seeded fuzz tests for the textual SQL placeholder builder.
//!
//! `format_sql` is the only path that turns a value into SQL text, so the
//! invariant is strict: a string parameter can only ever appear as a hex
//! literal, and a question mark inside a quoted string or a comment is never
//! treated as a placeholder.

use super::*;
use crate::testutil::{iterations, Rng, MALICIOUS_STRINGS};

fn replaces(sql: &str, value: &str) -> String {
    format_sql(sql, &[SqlValue::Str(value)])
}

#[test]
fn preserves_non_ascii_sql_text() {
    let sql = format_sql("SELECT 'ä' AS x, ?", &[SqlValue::Str("ö")]);
    assert_eq!(sql, "SELECT 'ä' AS x, CONVERT(X'c3b6' USING utf8mb4)");
}

#[test]
fn string_values_only_appear_as_hex_literals() {
    for value in MALICIOUS_STRINGS {
        let sql = replaces("SELECT ?", value);
        assert!(sql.starts_with("SELECT CONVERT(X'"));
        assert!(sql.ends_with("' USING utf8mb4)"), "{sql}");
        assert!(
            !sql.contains('\\') && sql.matches('\'').count() == 2,
            "value escaped the literal: {sql}"
        );
        let hex: String = value.bytes().map(|byte| format!("{byte:02x}")).collect();
        assert!(sql.contains(&hex), "hex payload missing for {value:?}");
        assert!(!sql.contains('\0'));
    }

    // A NUL byte is encoded like any other byte, not truncated.
    assert_eq!(
        format_sql("X ?", &[SqlValue::Bytes(b"a\0b")]),
        "X X'610062'"
    );
    assert_eq!(
        format_sql("i ? d ?", &[SqlValue::Int(-1), SqlValue::UInt(u64::MAX)]),
        "i -1 d 18446744073709551615"
    );
    assert_eq!(
        format_sql("f ?", &[SqlValue::Float(f64::INFINITY)]),
        "f NULL"
    );
    assert_eq!(format_sql("f ?", &[SqlValue::Float(f64::NAN)]), "f NULL");
    assert_eq!(format_sql("n ?", &[SqlValue::Null]), "n NULL");
}

#[test]
fn placeholders_inside_quotes_and_comments_are_literal() {
    assert_eq!(
        format_sql("SELECT '?' AS q, \"?\" AS d, `?` AS b", &[]),
        "SELECT '?' AS q, \"?\" AS d, `?` AS b"
    );
    assert_eq!(
        format_sql(
            "SELECT 'a\\'?', ? -- ?\n/* ? */ ?",
            &[SqlValue::Int(1), SqlValue::Int(2)]
        ),
        "SELECT 'a\\'?', 1 -- ?\n/* ? */ 2"
    );
    // Fewer parameters than placeholders leaves the remainder visible; more
    // parameters are ignored.  Neither can turn a value into SQL.
    assert_eq!(format_sql("? ?", &[SqlValue::Int(7)]), "7 ?");
    assert_eq!(
        format_sql("?", &[SqlValue::Str("a"), SqlValue::Str("b")]),
        "CONVERT(X'61' USING utf8mb4)"
    );
}

#[test]
fn fuzz_placeholder_builder() {
    let mut rng = Rng::new(0x5351_4c5f_504c_4143);
    let alphabet = b"?'\"`\\/*-#;\n\0 abcXYZ019_";
    for _ in 0..iterations(5_000) {
        let sql_len = rng.below(300);
        let sql = rng.ascii(sql_len, alphabet);
        let count = rng.below(8);
        let mut owned: Vec<String> = Vec::new();
        for _ in 0..count {
            let len = rng.below(64);
            let value = if rng.below(3) == 0 {
                (*rng.pick(MALICIOUS_STRINGS)).to_string()
            } else {
                rng.text(len)
            };
            owned.push(value);
        }
        let params: Vec<SqlValue<'_>> = owned.iter().map(|value| SqlValue::Str(value)).collect();
        let output = format_sql(&sql, &params);
        // Hex encoding doubles a byte and adds `CONVERT(X'...')` framing, so
        // the result is bounded by the SQL plus the escaped parameters.
        let bound = sql.len()
            + params
                .iter()
                .map(|value| match value {
                    SqlValue::Str(text) => text.len() * 2 + 26,
                    SqlValue::Bytes(bytes) => bytes.len() * 2 + 3,
                    _ => 24,
                })
                .sum::<usize>();
        assert!(output.len() <= bound, "{} > {bound}", output.len());
        // Every string parameter must appear as a complete, even-length hex
        // literal.  A raw quote or backslash inside a value can never close the
        // literal early.
        let mut rest = output.as_str();
        while let Some(start) = rest.find("CONVERT(X'") {
            let after = &rest[start + "CONVERT(X'".len()..];
            let Some(end) = after.find('\'') else {
                panic!("unterminated hex literal in {output:?}");
            };
            let hex = &after[..end];
            assert!(
                hex.len().is_multiple_of(2) && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid hex literal {hex:?}"
            );
            assert!(
                after[end..].starts_with("' USING utf8mb4)"),
                "unexpected hex literal suffix in {output:?}"
            );
            rest = &after[end + 1..];
        }
    }
}

#[test]
fn sql_comment_edge_cases_and_executable_comments() {
    // MySQL requires whitespace or control characters after `--` for it to start a comment.
    // Expressions like `a--1` (decrement or double negation) are not comments.
    let sql = format_sql("SELECT a--1, ?", &[SqlValue::Int(42)]);
    assert_eq!(sql, "SELECT a--1, 42");

    // `#` is always a line comment in MySQL.
    let sql = format_sql("SELECT # comment with ?\n?", &[SqlValue::Int(42)]);
    assert_eq!(sql, "SELECT # comment with ?\n42");

    // `/*! ... */` is an executable comment in MySQL; placeholders inside it must be replaced.
    let sql = format_sql("SELECT /*!50000 ? */", &[SqlValue::Int(99)]);
    assert_eq!(sql, "SELECT /*!50000 99 */");

    // Optimizer hints `/*+ ... */` also retain placeholders.
    let sql = format_sql("SELECT /*+ BKA(t1) */ ?", &[SqlValue::Int(7)]);
    assert_eq!(sql, "SELECT /*+ BKA(t1) */ 7");

    // Standard block comments `/* ... */` do NOT replace placeholders.
    let sql = format_sql("SELECT /* standard comment ? */ ?", &[SqlValue::Int(5)]);
    assert_eq!(sql, "SELECT /* standard comment ? */ 5");
}

#[test]
fn parse_ok_and_eof_status_flags_track_transactions() {
    // OK packet: header 0x00, affected rows 0, insert id 0, status_flags (SERVER_STATUS_IN_TRANS = 0x0001)
    let ok_packet = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let (affected, insert_id, status) = parse_ok(&ok_packet);
    assert_eq!(affected, 0);
    assert_eq!(insert_id, 0);
    assert_eq!(status & SERVER_STATUS_IN_TRANS, SERVER_STATUS_IN_TRANS);

    // EOF packet: header 0xfe, warnings 0, status_flags 0x0001
    let eof_packet = [0xfe, 0x00, 0x00, 0x01, 0x00];
    assert!(is_eof(&eof_packet));
    let status = eof_status_flags(&eof_packet);
    assert_eq!(status & SERVER_STATUS_IN_TRANS, SERVER_STATUS_IN_TRANS);
}
