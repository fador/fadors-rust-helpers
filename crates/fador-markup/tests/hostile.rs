//! Hostile-input and seeded fuzz tests.
//!
//! Every helper is fed the shared malicious corpus and a deterministic random
//! stream, then checked against the property it promises. The default case
//! count keeps `cargo test` fast; `FADOR_FUZZ_ITERATIONS=200000` runs the same
//! assertions over a much larger sample.

use fador_markup::{
    decode_entities, decode_entities_bounded, escape, excerpt, highlight_html, highlight_segment,
    is_safe_url, match_longest_code, neutralise_url, replace_codes, sanitize_style, sanitize_url,
    strip_markup, unescape_compat, Censor, EscapePolicy, SchemePolicy, HIGHLIGHT_CLOSE,
    HIGHLIGHT_OPEN,
};
use fador_testutil::{iterations, Rng, MALICIOUS_STRINGS};

const POLICIES: [EscapePolicy; 4] = [
    EscapePolicy::Text,
    EscapePolicy::Attribute,
    EscapePolicy::CompatAttr,
    EscapePolicy::XsltText,
];

/// Remove the highlight markers from `html`.
fn without_highlights(html: &str) -> String {
    html.replace(HIGHLIGHT_OPEN, "")
        .replace(HIGHLIGHT_CLOSE, "")
}

/// Random text of a random length up to `max`.
fn random_text(rng: &mut Rng, max: usize) -> String {
    let len = rng.below(max);
    rng.text(len)
}

/// An independent, deliberately naive check for a whole-word occurrence.
fn has_whole_word(text: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let lowered = word.to_lowercase();
    for (start, _) in text.char_indices() {
        let Some(end) = start.checked_add(lowered.len()) else {
            continue;
        };
        if end > text.len() || !text.is_char_boundary(end) {
            continue;
        }
        if text[start..end].to_lowercase() != lowered {
            continue;
        }
        let before = text[..start]
            .chars()
            .next_back()
            .is_none_or(|ch| !(ch.is_alphanumeric() || ch == '_'));
        let after = text[end..]
            .chars()
            .next()
            .is_none_or(|ch| !(ch.is_alphanumeric() || ch == '_'));
        if before && after {
            return true;
        }
    }
    false
}

/// The leading scheme region of a URL after one entity decode and normalising.
fn leading_scheme(url: &str) -> String {
    let decoded = decode_entities(url).to_ascii_lowercase();
    let mut out = String::new();
    for ch in decoded.chars() {
        match ch {
            ':' => {
                out.push(':');
                break;
            }
            '/' | '?' | '#' => break,
            c if c.is_whitespace() || c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[test]
fn hostile_strings_are_escaped() {
    for input in MALICIOUS_STRINGS {
        for policy in POLICIES {
            let escaped = escape(policy, input);
            assert!(!escaped.contains('<'), "{policy:?} {input:?}");
            assert!(!escaped.contains('>'), "{policy:?} {input:?}");
            assert!(!escaped.contains('\0'), "{policy:?} {input:?}");
            if matches!(policy, EscapePolicy::Attribute | EscapePolicy::CompatAttr) {
                assert!(!escaped.contains('"'), "{policy:?} {input:?}");
            }
            if policy == EscapePolicy::Attribute {
                assert!(!escaped.contains('\''), "{input:?}");
            }
        }
    }
}

#[test]
fn hostile_strings_are_not_links() {
    for input in MALICIOUS_STRINGS {
        for policy in [SchemePolicy::STRICT, SchemePolicy::WEB, SchemePolicy::IMAGE] {
            if is_safe_url(input, &policy) {
                let scheme = leading_scheme(input);
                assert!(
                    !matches!(scheme.as_str(), "javascript:" | "vbscript:" | "data:"),
                    "{input:?} was accepted by {policy:?}"
                );
            }
            let neutralised = neutralise_url(input, &policy);
            assert!(neutralised == "#" || neutralised == *input);
            if neutralised != "#" {
                assert!(is_safe_url(input, &policy));
            }
            if let Some(sanitized) = sanitize_url(input, &policy) {
                assert!(is_safe_url(&sanitized, &policy));
            }
        }
    }
}

#[test]
fn hostile_strings_strip_without_growth() {
    for input in MALICIOUS_STRINGS {
        let stripped = strip_markup(input);
        assert!(stripped.len() <= input.len(), "{input:?} grew");
    }
}

#[test]
fn hostile_strings_highlight_without_corruption() {
    for input in MALICIOUS_STRINGS {
        for keywords in [&["a"][..], &["amp"][..], &["script"][..], &["ä"][..]] {
            let highlighted = highlight_html(input, keywords);
            assert!(highlighted.len() >= input.len());
            if !input.contains(HIGHLIGHT_OPEN) && !input.contains(HIGHLIGHT_CLOSE) {
                assert_eq!(without_highlights(&highlighted), *input);
            }
        }
    }
}

#[test]
fn hostile_strings_survive_the_censor() {
    let censor = Censor::new()
        .with_word("damn")
        .with_word("perkele")
        .with_word("sää");
    for input in MALICIOUS_STRINGS {
        let censored = censor.apply(input);
        assert!(!has_whole_word(&censored, "damn"), "{input:?}");
        assert!(!has_whole_word(&censored, "perkele"), "{input:?}");
        assert!(!has_whole_word(&censored, "sää"), "{input:?}");
    }
}

#[test]
fn fuzz_escape_roundtrips() {
    let mut rng = Rng::new(0xfad0_0001);
    for _ in 0..iterations(4_000) {
        let input = random_text(&mut rng, 80);
        for policy in [
            EscapePolicy::Text,
            EscapePolicy::Attribute,
            EscapePolicy::CompatAttr,
        ] {
            let escaped = escape(policy, &input);
            assert_eq!(
                unescape_compat(&escaped),
                input.replace('\0', "\u{fffd}"),
                "{policy:?} {input:?}"
            );
            assert!(!escaped.contains('<') && !escaped.contains('>'));
        }
    }
}

#[test]
fn fuzz_decoding_is_bounded() {
    let mut rng = Rng::new(0xfad0_0002);
    for _ in 0..iterations(3_000) {
        let input = random_text(&mut rng, 64);
        let decoded = decode_entities(&input);
        assert!(decoded.len() <= input.len());
        for limit in [0, 1, 2, 3, 5, 8, 13, input.len()] {
            let bounded = decode_entities_bounded(&input, limit);
            assert!(bounded.len() <= limit);
            assert!(bounded.len() <= input.len());
        }
    }
}

#[test]
fn fuzz_url_check_never_accepts_an_active_scheme() {
    let mut rng = Rng::new(0xfad0_0003);
    let mut cases = MALICIOUS_STRINGS
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    for _ in 0..iterations(3_000) {
        let mut value = random_text(&mut rng, 48);
        if rng.below(2) == 0 {
            value.push_str("javascript:alert(1)");
        }
        if rng.below(3) == 0 {
            value.push_str("&colon;alert(1)");
        }
        cases.push(value);
    }
    for input in cases {
        for policy in [SchemePolicy::STRICT, SchemePolicy::WEB, SchemePolicy::IMAGE] {
            if is_safe_url(&input, &policy) {
                let scheme = leading_scheme(&input);
                assert!(
                    !matches!(scheme.as_str(), "javascript:" | "vbscript:" | "data:"),
                    "{input:?} accepted by {policy:?}"
                );
            }
        }
    }
}

#[test]
fn fuzz_censor_removes_every_boundary_match() {
    let mut rng = Rng::new(0xfad0_0004);
    let words = ["damn", "heck", "sää", "ab"];
    let mut censor = Censor::new();
    for word in words {
        censor = censor.with_word(word);
    }
    for _ in 0..iterations(3_000) {
        let input = random_text(&mut rng, 64);
        let censored = censor.apply(&input);
        for word in words {
            assert!(
                !has_whole_word(&censored, word),
                "{input:?} -> {censored:?}"
            );
        }
        assert_eq!(censor.apply(&censored), censored, "{input:?}");
    }
}

#[test]
fn fuzz_longest_code_is_a_prefix() {
    let mut rng = Rng::new(0xfad0_0005);
    let alphabet = ["a", "b", ":", ")", "ä", "💣"];
    for _ in 0..iterations(3_000) {
        let codes = (0..rng.below(6))
            .map(|_| {
                (0..1 + rng.below(4))
                    .map(|_| *rng.pick(&alphabet))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        let text = random_text(&mut rng, 32);
        let borrowed = codes.iter().map(String::as_str).collect::<Vec<_>>();
        if let Some(found) = match_longest_code(&text, &borrowed) {
            assert!(text.starts_with(found), "{text:?} {found:?}");
            for code in &codes {
                if text.starts_with(code.as_str()) {
                    assert!(code.len() <= found.len(), "{text:?} {code:?}");
                }
            }
        }
        let pairs = codes
            .iter()
            .map(|code| (code.as_str(), ""))
            .collect::<Vec<_>>();
        let replaced = replace_codes(&text, &pairs);
        assert!(replaced.len() <= text.len());
    }
}

#[test]
fn fuzz_strip_never_grows() {
    let mut rng = Rng::new(0xfad0_0006);
    for _ in 0..iterations(3_000) {
        let input = random_text(&mut rng, 96);
        let stripped = strip_markup(&input);
        assert!(stripped.len() <= input.len(), "{input:?}");
    }
}

#[test]
fn fuzz_highlight_roundtrips() {
    let mut rng = Rng::new(0xfad0_0007);
    for _ in 0..iterations(3_000) {
        let input = random_text(&mut rng, 64);
        let keywords = ["a", "ä", "amp", "💣", "zz"];
        let highlighted = highlight_html(&input, &keywords);
        if !input.contains(HIGHLIGHT_OPEN) && !input.contains(HIGHLIGHT_CLOSE) {
            assert_eq!(without_highlights(&highlighted), input, "{input:?}");
        }
        let segment = highlight_segment(&input, &keywords);
        assert_eq!(without_highlights(&segment), input, "{input:?}");
    }
}

#[test]
fn fuzz_excerpt_is_safe_html() {
    let mut rng = Rng::new(0xfad0_0008);
    for _ in 0..iterations(2_000) {
        let input = random_text(&mut rng, 96);
        let snippet = excerpt(&input, &["a", "ä", "b"], rng.below(12));
        let rest = snippet
            .replace(HIGHLIGHT_OPEN, "")
            .replace(HIGHLIGHT_CLOSE, "")
            .replace("&hellip;", "");
        assert!(!rest.contains('<'), "{input:?} -> {snippet:?}");
        assert!(!rest.contains('>'), "{input:?} -> {snippet:?}");
        let mut offset = 0usize;
        while let Some(position) = rest[offset..].find('&') {
            let absolute = offset + position;
            let tail = &rest[absolute..];
            assert!(
                tail.starts_with("&amp;") || tail.starts_with("&lt;") || tail.starts_with("&gt;"),
                "{input:?} -> {snippet:?}"
            );
            offset = absolute + 1;
        }
    }
}

#[test]
fn fuzz_style_sanitizer_is_all_or_nothing() {
    let mut rng = Rng::new(0xfad0_0009);
    for _ in 0..iterations(2_000) {
        let input = random_text(&mut rng, 64);
        let style = sanitize_style(&input);
        if !style.is_empty() {
            assert_eq!(style, input);
            assert!(!style.contains('<') && !style.contains('>'));
            let lower = style.to_ascii_lowercase();
            assert!(!lower.contains("url"));
            assert!(!lower.contains("expression"));
            assert!(!lower.contains("javascript:"));
        }
    }
}
