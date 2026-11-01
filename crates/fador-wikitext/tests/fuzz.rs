//! Seeded fuzz tests for the renderer.
//!
//! The corpus is deterministic: a fixed seed and a fixed alphabet, so a
//! failure reproduces in a normal `cargo test`. `FADOR_FUZZ_ITERATIONS` raises
//! the case count for a deeper local pass.

use fador_testutil::{iterations, Rng, MALICIOUS_STRINGS};
use fador_wikitext::{
    FileInfo, MapMessages, MemoryResolver, Parser, ParserConfig, SiteStats, Title,
};

fn resolver() -> MemoryResolver {
    MemoryResolver::new()
        .with_page(10, "A", "a{{{1|}}}")
        .with_page(10, "B", "{{A|b}}")
        .with_page(10, "Loop", "{{Loop}}")
        .with_page(0, "Page", "A page.")
        .with_redirect(0, "Old", "Page")
        .with_file(FileInfo::new("Pic.png", 640, 480))
        .with_category_count("People", 7)
        .with_namespace_count(0, 42)
        .with_site_stats(SiteStats {
            pages: 1234,
            articles: 1000,
            edits: 5000,
            users: 20,
            active_users: 3,
            images: 50,
        })
}

fn config() -> ParserConfig {
    ParserConfig::default()
        .with_template_depth(8)
        .with_expansion_bytes(64 * 1024)
        .with_page_bytes(64 * 1024)
}

fn assert_safe(html: &str) {
    assert!(
        html.len() < 4 * 1024 * 1024,
        "output grew to {} bytes",
        html.len()
    );
    assert!(!html.contains("<script"), "raw script survived: {html}");
    let lower = html.to_ascii_lowercase();
    for forbidden in [
        "href=\"javascript:",
        "src=\"javascript:",
        "href=\"vbscript:",
        "src=\"vbscript:",
        "href=\"data:",
        "src=\"data:",
        "style=\"background:url",
        "style=\"width:expression",
    ] {
        assert!(!lower.contains(forbidden), "{forbidden} survived: {html}");
    }
}

#[test]
fn fuzz_wikitext_render_is_bounded_and_safe() {
    let resolver = resolver();
    let config = config();
    let messages = MapMessages::with_defaults();
    let title = Title::new(0, "Fuzz");
    let mut rng = Rng::new(0x9a11_1000);
    // Braces and brackets are included: they exercise templates, links,
    // tables and the brace-aware scanners. The resolver keeps every lookup
    // in memory, so the run needs no database or network.
    let alphabet = b"abc XYZ0123 \n=*#:;|!-_<>&\"'/\\\t{}[]~.,";
    for _ in 0..iterations(500) {
        let length = rng.below(800);
        let source = rng.ascii(length, alphabet);
        let result = Parser::render(&resolver, &config, &messages, &title, &source);
        assert_safe(&result.html);
        assert!(result.categories.len() <= 5_000);
        assert!(result
            .display_title
            .as_ref()
            .is_none_or(|title| title.len() < 10_000));
    }
}

#[test]
fn fuzz_hostile_corpus_never_emits_an_active_url() {
    let resolver = resolver();
    let config = config();
    let messages = MapMessages::with_defaults();
    let title = Title::new(0, "Fuzz");
    for source in MALICIOUS_STRINGS {
        let result = Parser::render(&resolver, &config, &messages, &title, source);
        assert_safe(&result.html);
    }
    // The same strings in the middle of a page exercise the inline scanner
    // rather than only the block scanner.
    for source in MALICIOUS_STRINGS {
        let wrapped = format!("before {source} after");
        let result = Parser::render(&resolver, &config, &messages, &title, &wrapped);
        assert_safe(&result.html);
    }
}

#[test]
fn fuzz_template_nesting_stays_within_the_configured_depth() {
    let resolver = resolver();
    let config = config().with_template_depth(4);
    let messages = MapMessages::with_defaults();
    let title = Title::new(0, "Fuzz");
    let mut rng = Rng::new(0x9a11_1001);
    for _ in 0..iterations(200) {
        let depth = rng.below(64) + 1;
        let source = format!("{}x{}", "{{A|".repeat(depth), "}}".repeat(depth));
        let result = Parser::render(&resolver, &config, &messages, &title, &source);
        assert_safe(&result.html);
        assert!(result.html.len() < 1024 * 1024);
    }
}

#[test]
fn pathological_delimiters_are_bounded() {
    let resolver = resolver();
    let config = config();
    let messages = MapMessages::with_defaults();
    let title = Title::new(0, "Fuzz");
    for source in [
        "{{".repeat(20_000),
        "[[".repeat(20_000),
        "{|".repeat(5_000),
        "{|\n".repeat(2_000),
        "*".repeat(20_000),
        "''".repeat(20_000),
        "<ref>".repeat(2_000),
    ] {
        let result = Parser::render(&resolver, &config, &messages, &title, &source);
        assert_safe(&result.html);
        assert!(result.html.len() < 4 * 1024 * 1024);
    }
}

#[test]
fn a_single_template_body_cannot_grow_without_limit() {
    let resolver = resolver().with_page(10, "Repeat", "{{{1}}}".repeat(1_000));
    let config = config().with_expansion_bytes(10_000);
    let messages = MapMessages::with_defaults();
    let title = Title::new(0, "Fuzz");
    let source = format!("{{{{Repeat|{}}}}}", "x".repeat(10_000));
    let result = Parser::render(&resolver, &config, &messages, &title, &source);
    assert_safe(&result.html);
    assert!(result.html.len() < 100_000, "{}", result.html.len());
    assert!(result.html.contains("Template recursion depth exceeded"));
}

#[test]
fn fuzz_titles_and_urls_stay_safe() {
    let namespaces = fador_wikitext::Namespaces::standard();
    let config = config();
    let mut rng = Rng::new(0x9a11_1002);
    for _ in 0..iterations(300) {
        let length = rng.below(300);
        let input = rng.text(length);
        if let Some(title) = Title::parse(&input, &namespaces) {
            let url = title.local_url(&config, &namespaces);
            assert!(!url.contains('\r') && !url.contains('\n') && !url.contains('\0'));
            assert!(!url.to_ascii_lowercase().contains("javascript:"));
        }
    }
}
