//! Golden outputs for the helpers.
//!
//! These are the exact strings the fador servers expect to see; a change here
//! is a compatibility change, not a refactor.

use fador_markup::{
    decode_entities, decode_entities_bounded, escape, escape_into, excerpt, highlight_html,
    highlight_segment, is_safe_url, match_longest_code, neutralise_url, replace_codes,
    sanitize_style, sanitize_url, smiley_boundary_before, strip_markup, strtr, unescape_compat,
    Censor, EscapePolicy, SchemePolicy, HIGHLIGHT_CLOSE, HIGHLIGHT_OPEN,
};

#[test]
fn escape_policies() {
    let input = "<a href=\"x\">&'";
    assert_eq!(
        escape(EscapePolicy::Text, input),
        "&lt;a href=\"x\"&gt;&amp;'"
    );
    assert_eq!(
        escape(EscapePolicy::Attribute, input),
        "&lt;a href=&quot;x&quot;&gt;&amp;&#039;"
    );
    assert_eq!(
        escape(EscapePolicy::CompatAttr, input),
        "&lt;a href=&quot;x&quot;&gt;&amp;'"
    );
    assert_eq!(
        escape(EscapePolicy::XsltText, input),
        "&lt;a href=\"x\"&gt;&amp;'"
    );
    assert_eq!(escape(EscapePolicy::XsltText, "line\r\n"), "line&#13;\n");
    assert_eq!(escape(EscapePolicy::Text, "a\0b"), "a\u{fffd}b");
}

#[test]
fn escape_into_appends_to_a_buffer() {
    let mut out = String::from("<li>");
    escape_into(EscapePolicy::Text, "a & b", &mut out);
    escape_into(EscapePolicy::Text, "</li>", &mut out);
    assert_eq!(out, "<li>a &amp; b&lt;/li&gt;");
}

#[test]
fn unescape_compat_golden() {
    assert_eq!(
        unescape_compat("&lt;b&gt;phpBB&#039;s &amp; SMF&apos;s&nbsp;"),
        "<b>phpBB's & SMF's\u{a0}"
    );
    assert_eq!(unescape_compat("&amp;lt;"), "&lt;");
    assert_eq!(unescape_compat("&copy;"), "&copy;");
    assert_eq!(unescape_compat("a & b"), "a & b");
}

#[test]
fn decode_entities_golden() {
    assert_eq!(
        decode_entities("&lt;p&gt; &amp; &quot;x&quot; &apos;y&apos;"),
        "<p> & \"x\" 'y'"
    );
    assert_eq!(decode_entities("&#65;&#x42;&#X43;"), "ABC");
    assert_eq!(decode_entities("&euro;&ndash;&mdash;&hellip;"), "€–—…");
    assert_eq!(
        decode_entities("&#0;&#xD800;&#x110000;"),
        "\u{fffd}\u{fffd}\u{fffd}"
    );
    assert_eq!(decode_entities("&unknown; &amp"), "&unknown; &amp");
    assert_eq!(decode_entities_bounded("&amp;tail", 1), "&");
}

#[test]
fn url_policies() {
    let strict = &SchemePolicy::STRICT;
    let web = &SchemePolicy::WEB;
    let image = &SchemePolicy::IMAGE;
    let cases: &[(&str, bool, bool, bool)] = &[
        ("https://example.com/", true, true, true),
        ("HTTP://EXAMPLE.COM/", true, true, true),
        ("ftp://example.com/", true, false, false),
        ("mailto:a@example.com", true, true, false),
        ("irc://example.com/", true, false, false),
        ("/index.php", true, true, true),
        ("images/x.png", true, true, true),
        ("#section", true, true, false),
        ("//example.com/x", true, true, false),
        ("javascript:alert(1)", false, false, false),
        ("JAVASCRIPT:alert(1)", false, false, false),
        ("vbscript:msgbox(1)", false, false, false),
        ("data:text/html,x", false, false, false),
        ("java script:alert(1)", false, false, false),
        ("java\tscript:alert(1)", false, false, false),
        ("javascript&colon;alert(1)", false, false, false),
        ("&#106;avascript:alert(1)", false, false, false),
        ("Luokka:Testi", false, false, false),
        ("", true, true, true),
    ];
    for (url, in_strict, in_web, in_image) in cases {
        assert_eq!(is_safe_url(url, strict), *in_strict, "strict {url:?}");
        assert_eq!(is_safe_url(url, web), *in_web, "web {url:?}");
        assert_eq!(is_safe_url(url, image), *in_image, "image {url:?}");
    }
}

#[test]
fn url_sanitising_golden() {
    assert_eq!(
        sanitize_url("  https://example.com/x  ", &SchemePolicy::WEB).as_deref(),
        Some("https://example.com/x")
    );
    assert_eq!(
        sanitize_url("javascript:alert(1)", &SchemePolicy::WEB),
        None
    );
    assert_eq!(
        neutralise_url("javascript:alert(1)", &SchemePolicy::WEB),
        "#"
    );
    assert_eq!(
        neutralise_url("https://example.com/", &SchemePolicy::WEB),
        "https://example.com/"
    );
}

#[test]
fn censor_golden() {
    let censor = Censor::new().with_word("damn").with_word("perkele");
    assert_eq!(
        censor.apply("Damn it, damnation! Perkele."),
        "**** it, damnation! *******."
    );
    let censor = Censor::new()
        .with_word("damn")
        .with_replacement("damnation", "[removed]");
    assert_eq!(censor.apply("damnation"), "[removed]");
    assert_eq!(censor.apply("damn"), "****");
    assert_eq!(censor.apply("DAMN!"), "****!");
    assert_eq!(censor.apply("damn_2"), "damn_2");
}

#[test]
fn code_matching_golden() {
    let codes = [":)", ":))", ":lol:"];
    assert_eq!(match_longest_code(":)) hi", &codes), Some(":))"));
    assert_eq!(match_longest_code("nope", &codes), None);
    assert!(smiley_boundary_before(' '));
    assert!(!smiley_boundary_before('a'));

    let pairs = [(":)", "[smile]"), (":lol:", "[lol]")];
    assert_eq!(replace_codes("hi :)", &pairs), "hi [smile]");
    assert_eq!(replace_codes("hi :lol:", &pairs), "hi [lol]");
    assert_eq!(replace_codes("a:)b", &pairs), "a:)b");

    assert_eq!(strtr("ab", &[("a", "1"), ("ab", "2")]), "2");
    assert_eq!(strtr("&amp;", &[("&", "&amp;")]), "&amp;amp;");
}

#[test]
fn strip_markup_golden() {
    assert_eq!(
        strip_markup("<p>Hello <b>world</b></p><script>alert(1)</script>"),
        "Hello world\n"
    );
    assert_eq!(strip_markup("a<br>b<br>c"), "a\nb\nc");
    assert_eq!(strip_markup("a &amp; b &lt;c&gt;"), "a & b <c>");
    assert_eq!(strip_markup("1 < 2"), "1 < 2");
    assert_eq!(strip_markup("<!-- x -->text"), "text");
}

#[test]
fn highlight_golden() {
    assert_eq!(
        highlight_html("<p>Hello <b>world</b></p>", &["world"]),
        "<p>Hello <b><strong class=\"highlight\">world</strong></b></p>"
    );
    assert_eq!(
        highlight_segment("Ääkkösiä", &["äkkö"]),
        "Ä<strong class=\"highlight\">äkkö</strong>siä"
    );
    assert_eq!(
        highlight_segment("one two three", &["two", "three"]),
        "one <strong class=\"highlight\">two</strong> <strong class=\"highlight\">three</strong>"
    );
    assert_eq!(highlight_html("a &amp; b", &["amp"]), "a &amp; b");
    assert_eq!(
        format!("{HIGHLIGHT_OPEN}x{HIGHLIGHT_CLOSE}"),
        "<strong class=\"highlight\">x</strong>"
    );
}

#[test]
fn excerpt_golden() {
    assert_eq!(
        excerpt("The quick brown fox jumps over the lazy dog", &["fox"], 10),
        "&hellip;ick brown <strong class=\"highlight\">fox</strong> jumps ove&hellip;"
    );
    assert_eq!(
        excerpt("fox", &["fox"], 10),
        "<strong class=\"highlight\">fox</strong>"
    );
    assert_eq!(excerpt("the fox", &["cat"], 10), "");
}

#[test]
fn style_golden() {
    assert_eq!(sanitize_style("color: red"), "color: red");
    assert_eq!(sanitize_style("background: url(x)"), "");
    assert_eq!(sanitize_style("width: expression(alert(1))"), "");
}
