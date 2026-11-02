//! End-to-end renderer tests: headings, blocks, links, images, templates,
//! parser functions, references, sanitising and the resource limits.

use fador_wikitext::{
    FileInfo, MapMessages, MemoryResolver, Namespaces, Parser, ParserConfig, RevisionInfo,
    SiteStats, Title,
};

fn config() -> ParserConfig {
    ParserConfig::default()
        .with_script_path("/w")
        .with_article_path("/wiki/$1")
        .with_server_url("https://wiki.example")
        .with_site_name("Test Wiki")
}

fn render(source: &str) -> String {
    render_with(&MemoryResolver::new(), &config(), source)
}

fn render_with(resolver: &MemoryResolver, config: &ParserConfig, source: &str) -> String {
    Parser::render(
        resolver,
        config,
        &MapMessages::new(),
        &Title::new(0, "Test"),
        source,
    )
    .html
}

fn render_result(
    resolver: &MemoryResolver,
    config: &ParserConfig,
    title: &Title,
    source: &str,
) -> fador_wikitext::ParseResult {
    Parser::render(resolver, config, &MapMessages::new(), title, source)
}

fn file_resolver() -> MemoryResolver {
    MemoryResolver::new()
        .with_page(10, "Hello", "Hello, {{{1|world}}}!")
        .with_page(0, "Page", "A page.")
        .with_page(0, "Test", "The test page.")
        .with_page(0, "Existing", "Exists.")
        .with_page(10, "Loop", "{{Loop}}")
        .with_page(10, "Outer", "O({{{1}}})")
        .with_file(FileInfo::new("Pic.png", 640, 480).with_size(4096))
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

// --------------------------------------------------------------- headings

#[test]
fn headings_build_a_numbered_table_of_contents() {
    let html =
        render("== One ==\nA\n\n== Two ==\nB\n\n=== Two point one ===\nC\n\n== Three ==\nD\n");
    assert!(html.contains("id=\"toc\""), "{html}");
    assert!(html.contains("mw-toc-heading"), "{html}");
    assert!(
        html.contains("<span class=\"tocnumber\">1</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"tocnumber\">2.1</span>"),
        "{html}"
    );
    assert!(html.contains("toctext\">Three</span>"), "{html}");
    assert!(html.contains("<h2>"), "{html}");
    assert!(html.contains("<h3>"), "{html}");
    assert!(html.contains("mw-headline"), "{html}");
    assert!(html.contains("action=edit&amp;section=1"), "{html}");
    assert!(html.contains("action=edit&amp;section=4"), "{html}");
    assert!(html.contains("id=\"One\""), "{html}");
    assert!(
        html.contains("<span id=\"Two\"></span>") || html.contains("id=\"Two\""),
        "{html}"
    );
}

#[test]
fn toc_switches_are_honoured() {
    let html = render("__NOTOC__\n== One ==\nA\n");
    assert!(!html.contains("id=\"toc\""), "{html}");
    assert!(html.contains("<h2>"), "{html}");

    let html = render("__TOC__\n== One ==\nA\n");
    assert!(html.contains("id=\"toc\""), "{html}");

    let html = render("__FORCETOC__\n== One ==\nA\n");
    assert!(html.contains("id=\"toc\""), "{html}");

    let html = render("__NOEDITSECTION__\n== One ==\nA\n");
    assert!(!html.contains("mw-editsection"), "{html}");
}

#[test]
fn duplicate_heading_ids_are_disambiguated() {
    let html = render("== Same ==\nA\n\n== Same ==\nB\n\n== Same ==\nC\n\n== Same ==\nD\n");
    assert!(html.contains("id=\"Same\""), "{html}");
    assert!(html.contains("id=\"Same_2\""), "{html}");
    assert!(html.contains("id=\"Same_3\""), "{html}");
    assert!(html.contains("id=\"Same_4\""), "{html}");
}

// ------------------------------------------------------------- paragraphs

#[test]
fn paragraphs_split_on_blank_lines_and_join_soft_breaks() {
    let html = render("one\n\ntwo");
    assert!(html.contains("<p>one</p>"), "{html}");
    assert!(html.contains("<p>two</p>"), "{html}");

    let html = render("one\ntwo");
    assert!(html.contains("<p>one\ntwo</p>"), "{html}");

    let html = render("a<br>b");
    assert!(html.contains("<p>a<br />b</p>"), "{html}");

    let html = render("<br />");
    assert_eq!(html.trim(), "<br />");
}

#[test]
fn block_html_stays_outside_paragraphs() {
    let html = render("<div class=\"box\">block</div>\n\npara");
    assert!(html.contains("<div class=\"box\">block</div>"), "{html}");
    assert!(html.contains("<p>para</p>"), "{html}");
    assert!(!html.contains("<p><div"), "{html}");
}

#[test]
fn block_html_headings_and_rules_stay_outside_paragraphs() {
    let html = render("text\n<hr>\nmore");
    assert!(html.contains("<p>text</p>"), "{html}");
    assert!(html.contains("<hr />"), "{html}");
    assert!(!html.contains("<p><hr"), "{html}");

    let html = render("text\n<h2>Heading</h2>");
    assert!(html.contains("<p>text</p>"), "{html}");
    assert!(html.contains("<h2>Heading</h2>"), "{html}");
    assert!(!html.contains("<p><h2"), "{html}");

    let html = render("<div>\nblock\n</div>\n\nafter");
    assert!(html.contains("<div>"), "{html}");
    assert!(html.contains("<p>block</p>"), "{html}");
    assert!(html.contains("</div>"), "{html}");
    assert!(!html.contains("<p>block\n</div>"), "{html}");
}

// ------------------------------------------------------------------ lists

#[test]
fn lists_nest_bullets_numbers_and_definitions() {
    let html = render("* a\n** b\n* c");
    assert!(
        html.contains("<ul><li>a<ul><li>b</li></ul></li><li>c</li></ul>"),
        "{html}"
    );

    let html = render("# one\n## two\n# three");
    assert!(
        html.contains("<ol><li>one<ol><li>two</li></ol></li><li>three</li></ol>"),
        "{html}"
    );

    let html = render("; term : definition");
    assert!(
        html.contains("<dl><dt>term</dt><dd>definition</dd></dl>"),
        "{html}"
    );

    let html = render(": indented");
    assert!(html.contains("<dl><dd>indented</dd></dl>"), "{html}");
}

#[test]
fn list_nesting_is_capped() {
    let source = format!("{} deep\n", "*".repeat(300));
    let html = render(&source);
    assert!(html.contains("deep"), "{html}");
    assert!(
        html.matches("<ul>").count() <= 100,
        "{}",
        html.matches("<ul>").count()
    );
}

// ----------------------------------------------------------------- tables

#[test]
fn tables_render_headers_cells_captions_and_attributes() {
    let source = "{| class=\"wikitable\"\n|+ Caption\n|-\n! Head\n|-\n| A || B\n|}";
    let html = render(source);
    assert!(
        html.contains("<table class=\"wikitable\"><tbody>"),
        "{html}"
    );
    assert!(html.contains("<caption>Caption</caption>"), "{html}");
    assert!(html.contains("<th>"), "{html}");
    assert!(html.contains("Head"), "{html}");
    assert!(html.contains("<td>"), "{html}");
    assert!(html.contains("A"), "{html}");
    assert!(html.contains("B"), "{html}");
    assert_eq!(html.matches("<td>").count(), 2, "{html}");
}

#[test]
fn table_cell_attributes_and_links_stay_in_one_cell() {
    let source = "{| class=\"wikitable\"\n|colspan=2|Liittyvä tarina: [[#Sarjan esittely|Sarjan esittely]]\n|}";
    let html = render(source);
    assert_eq!(html.matches("<td").count(), 1, "{html}");
    assert!(
        html.contains("<a href=\"#Sarjan_esittely\">Sarjan esittely</a>"),
        "{html}"
    );
}

#[test]
fn nested_tables_are_rendered_inside_the_cell() {
    let source = "{| class=\"outer\"\n| cell\n{|\n| inner\n|}\n|}";
    let html = render(source);
    assert!(html.contains("class=\"outer\""), "{html}");
    assert!(html.contains("inner"), "{html}");
    assert!(html.matches("<table").count() >= 2, "{html}");
}

// ---------------------------------------------------------- bold / italic

#[test]
fn bold_and_italic_runs_are_well_nested() {
    let html = render("''italic'' '''bold''' '''''both'''''");
    assert!(html.contains("<i>italic</i>"), "{html}");
    assert!(html.contains("<b>bold</b>"), "{html}");
    assert!(html.contains("<b><i>both</i></b>"), "{html}");

    let html = render("''''four''''");
    assert!(html.contains("<b>"), "{html}");
    assert!(html.contains("four"), "{html}");
    assert!(html.contains("'"), "{html}");

    let html = render("''unclosed");
    assert!(html.contains("<i>unclosed</i>"), "{html}");
}

// ---------------------------------------------------------------- links

#[test]
fn internal_links_show_existence_redirect_and_self() {
    let resolver = file_resolver();
    let config = config();

    let html = render_with(&resolver, &config, "[[Page]]");
    assert!(
        html.contains("<a href=\"/wiki/Page\" title=\"Page\">Page</a>"),
        "{html}"
    );

    let html = render_with(&resolver, &config, "[[Missing]]");
    assert!(html.contains("class=\"new\""), "{html}");
    assert!(html.contains("redlink=1"), "{html}");
    assert!(
        html.contains("title=\"Missing (page does not exist)\""),
        "{html}"
    );

    let resolver = resolver.with_redirect(0, "Old", "Page");
    let html = render_with(&resolver, &config, "[[Old]]");
    assert!(html.contains("class=\"mw-redirect\""), "{html}");

    let html = render_with(&resolver, &config, "[[Test]]");
    assert!(html.contains("mw-selflink"), "{html}");
}

#[test]
fn internal_links_honour_labels_fragments_and_trails() {
    let resolver = file_resolver();
    let config = config();

    let html = render_with(&resolver, &config, "[[Page|Label]]");
    assert!(html.contains(">Label</a>"), "{html}");

    let html = render_with(&resolver, &config, "[[Page#Section]]");
    assert!(html.contains("href=\"/wiki/Page#Section\""), "{html}");
    assert!(html.contains(">Page#Section</a>"), "{html}");

    let html = render_with(&resolver, &config, "[[Page]]n");
    assert!(html.contains(">Pagen</a>"), "{html}");

    let html = render_with(&resolver, &config, "[[Page|Label]]n");
    assert!(html.contains(">Labeln</a>"), "{html}");

    let html = render_with(&resolver, &config, "[[Page]]N");
    assert!(html.contains(">Page</a>N"), "{html}");

    let html = render_with(&resolver, &config, "[[#Section|here]]");
    assert!(html.contains("<a href=\"#Section\">here</a>"), "{html}");
}

#[test]
fn pipe_trick_shortens_labels() {
    let resolver = file_resolver();
    let config = config();
    let html = render_with(&resolver, &config, "[[Naruto (manga)|]]");
    assert!(html.contains(">Naruto</a>"), "{html}");
    let html = render_with(&resolver, &config, "[[Naruto,|]]");
    assert!(html.contains(">Naruto</a>"), "{html}");
}

#[test]
fn categories_are_collected_and_links_to_them_can_be_forced() {
    let resolver = file_resolver();
    let config = config();
    let result = render_result(
        &resolver,
        &config,
        &Title::new(0, "Test"),
        "Text\n[[Category:People|Sort key]]\n[[:Category:People|shown]]",
    );
    assert_eq!(result.categories.len(), 1, "{:?}", result.categories);
    assert_eq!(result.categories[0].name, "People");
    assert_eq!(result.categories[0].sortkey, "Sort key");
    assert!(result.html.contains(">shown</a>"), "{}", result.html);
    assert!(!result.html.contains("Sort key"), "{}", result.html);
}

#[test]
fn special_pages_are_always_blue() {
    let html = render("[[Special:Search]]");
    assert!(html.contains("href=\"/wiki/Special:Search\""), "{html}");
    assert!(!html.contains("class=\"new\""), "{html}");
}

// ------------------------------------------------------------ external links

#[test]
fn external_links_are_sanitised_and_attributed() {
    let html = render("[https://example.test/ Example]");
    assert!(html.contains("rel=\"nofollow\""), "{html}");
    assert!(
        html.contains("href=\"https://example.test/\">Example</a>"),
        "{html}"
    );

    let html = render("See https://example.test/x.");
    assert!(html.contains("external free"), "{html}");
    assert!(html.contains("href=\"https://example.test/x\""), "{html}");
    assert!(html.contains("x</a>."), "{html}");

    let html =
        render("[ftp://example.test/x ftp] [//example.test/y proto] [mailto:a@example.test mail]");
    assert!(html.contains("href=\"ftp://example.test/x\""), "{html}");
    assert!(html.contains("href=\"//example.test/y\""), "{html}");
    assert!(html.contains("href=\"mailto:a@example.test\""), "{html}");
}

#[test]
fn active_url_schemes_never_become_links() {
    let html = render("[javascript:alert(1) click] [[javascript:alert(1)]]");
    assert!(!html.contains("href=\"javascript:"), "{html}");
    assert!(!html.contains("javascript:alert(1)</a>"), "{html}");
    assert!(html.contains("javascript:alert(1)"), "{html}");
}

// ---------------------------------------------------------------- images

#[test]
fn images_render_thumbs_captions_and_scaled_sizes() {
    let resolver = file_resolver();
    let config = config();

    let html = render_with(&resolver, &config, "[[File:Pic.png|thumb|Caption]]");
    assert!(html.contains("<div class=\"thumb tright\">"), "{html}");
    assert!(html.contains("thumbinner"), "{html}");
    assert!(html.contains("width:222px"), "{html}");
    assert!(html.contains("thumbimage"), "{html}");
    assert!(html.contains("srcset="), "{html}");
    assert!(html.contains("thumbcaption"), "{html}");
    assert!(html.contains("Caption"), "{html}");
    assert!(html.contains("magnify"), "{html}");
    assert!(html.contains("width=\"220\""), "{html}");
    assert!(html.contains("height=\"165\""), "{html}");

    let html = render_with(&resolver, &config, "[[File:Pic.png|100px]]");
    assert!(html.contains("width=\"100\""), "{html}");
    assert!(html.contains("height=\"75\""), "{html}");
    assert!(!html.contains("thumbinner"), "{html}");

    let html = render_with(&resolver, &config, "[[File:Pic.png|link=]]");
    assert!(!html.contains("<a "), "{html}");

    let html = render_with(&resolver, &config, "[[File:Pic.png|alt=Text]]");
    assert!(html.contains("alt=\"Text\""), "{html}");

    let html = render_with(&resolver, &config, "[[File:Missing.png]]");
    assert!(html.contains("class=\"new\""), "{html}");

    let html = render_with(&resolver, &config, "[[File:Pic.png|left|thumb|Caption]]");
    assert!(html.contains("thumb tleft"), "{html}");
}

#[test]
fn media_links_point_at_the_original_file() {
    let resolver = file_resolver();
    let config = config();
    let html = render_with(&resolver, &config, "[[Media:Pic.png|download]]");
    assert!(html.contains("class=\"internal\""), "{html}");
    assert!(html.contains("/images/"), "{html}");
    assert!(html.contains(">download</a>"), "{html}");
}

#[test]
fn galleries_render_known_files() {
    let resolver = file_resolver();
    let config = config();
    let html = render_with(
        &resolver,
        &config,
        "<gallery widths=\"100\">\nFile:Pic.png|One\nMissing.png\n</gallery>",
    );
    assert!(html.contains("mw-gallery-traditional"), "{html}");
    assert!(html.contains("gallerybox"), "{html}");
    assert!(html.contains(">One<"), "{html}");
    assert_eq!(html.matches("gallerybox").count(), 1, "{html}");
}

#[test]
fn external_images_require_an_allow_list() {
    let resolver = file_resolver();
    let html = render_with(&resolver, &config(), "[[https://cdn.test/x.png]]");
    assert!(!html.contains("<img"), "{html}");

    let allowed = config().with_external_image_prefix("https://cdn.test/");
    let html = render_with(&resolver, &allowed, "[[https://cdn.test/x.png]]");
    assert!(
        html.contains("<img src=\"https://cdn.test/x.png\""),
        "{html}"
    );
}

// ------------------------------------------------------------- templates

#[test]
fn templates_transclude_parameters_and_defaults() {
    let resolver = file_resolver();
    let config = config();
    assert_eq!(
        render_with(&resolver, &config, "{{Hello}}"),
        "<p>Hello, world!</p>\n"
    );
    assert_eq!(
        render_with(&resolver, &config, "{{Hello|Naruto}}"),
        "<p>Hello, Naruto!</p>\n"
    );
    assert_eq!(
        render_with(&resolver, &config, "{{Template:Hello}}"),
        "<p>Hello, world!</p>\n"
    );
    assert_eq!(
        render_with(&resolver, &config, "{{Outer|{{Hello|X}}}}"),
        "<p>O(Hello, X!)</p>\n"
    );
}

#[test]
fn missing_templates_render_as_red_links() {
    let html = render("{{Missing}}");
    assert!(html.contains("class=\"new\""), "{html}");
    assert!(html.contains("Template:Missing"), "{html}");
}

#[test]
fn template_redirects_are_followed() {
    let resolver = file_resolver().with_redirect(10, "Old", "Template:Hello");
    let html = render_with(&resolver, &config(), "{{Old}}");
    assert!(html.contains("Hello, world!"), "{html}");
}

#[test]
fn include_tags_are_applied_per_context() {
    let resolver = file_resolver().with_page(
        10,
        "Doc",
        "visible<noinclude>doc</noinclude><includeonly>inc</includeonly>",
    );
    let config = config();
    let html = render_with(&resolver, &config, "{{Doc}}");
    assert!(html.contains("visibleinc"), "{html}");
    assert!(!html.contains("doc"), "{html}");

    let result = render_result(
        &resolver,
        &config,
        &Title::new(10, "Doc"),
        "visible<noinclude>doc</noinclude><includeonly>inc</includeonly>",
    );
    assert!(result.html.contains("visibledoc"), "{}", result.html);
    assert!(!result.html.contains("inc"), "{}", result.html);
}

#[test]
fn template_depth_and_expansion_are_bounded() {
    let resolver = file_resolver();
    let shallow = config().with_template_depth(4);
    let html = render_with(&resolver, &shallow, "{{Loop}}");
    assert!(html.contains("Template recursion depth exceeded"), "{html}");
    assert!(html.len() < 10_000, "{html}");

    let resolver = resolver.with_page(10, "Big", "x".repeat(1000));
    let tiny = config().with_expansion_bytes(10);
    let html = render_with(&resolver, &tiny, "{{Big}}");
    assert!(html.contains("Template recursion depth exceeded"), "{html}");
    assert!(!html.contains(&"x".repeat(100)), "{html}");

    let tiny_page = config().with_page_bytes(10);
    let html = render_with(&resolver, &tiny_page, "{{Big}}");
    assert!(html.contains("Template:Big"), "{html}");
    assert!(!html.contains(&"x".repeat(100)), "{html}");
}

// ------------------------------------------------------- parser functions

#[test]
fn parser_functions_select_and_compute() {
    let resolver = file_resolver();
    let config = config();
    for (source, expected) in [
        ("{{#if:1|yes|no}}", "yes"),
        ("{{#if:|yes|no}}", "no"),
        ("{{#if:  |yes|no}}", "no"),
        ("{{#ifeq:a|a|same|diff}}", "same"),
        ("{{#ifeq:a|b|same|diff}}", "diff"),
        ("{{#switch:b|a=1|b=2|#default=3}}", "2"),
        ("{{#switch:z|a=1|#default=3}}", "3"),
        ("{{#switch:z|a=1}}", ""),
        ("{{#expr:2+3*4}}", "14"),
        ("{{#expr:(2+3)*4}}", "20"),
        ("{{#expr:1/0}}", ""),
        ("{{#len:abc}}", "3"),
        ("{{#sub:abcdef|1|3}}", "bcd"),
        ("{{#ifexist:Existing|yes|no}}", "yes"),
        ("{{#ifexist:Missing|yes|no}}", "no"),
    ] {
        let html = render_with(&resolver, &config, source);
        assert!(html.contains(expected), "{source} -> {html}");
    }
}

#[test]
fn parser_functions_can_be_disabled() {
    let resolver = file_resolver();
    let config = config().with_parser_functions(false);
    let html = render_with(&resolver, &config, "{{#if:1|yes|no}}");
    assert!(html.contains("{{#if:1|yes|no}}"), "{html}");
}

// ----------------------------------------------------------- nowiki / pre

#[test]
fn nowiki_protects_markup_from_parsing() {
    let html = render("<nowiki>[[Not a link]] & {{Hello}}</nowiki>");
    assert!(!html.contains("<a "), "{html}");
    assert!(html.contains("[[Not a link]]"), "{html}");
    assert!(html.contains("&amp;"), "{html}");
    assert!(html.contains("{{Hello}}"), "{html}");
}

#[test]
fn pre_blocks_are_escaped_and_indented_lines_become_pre() {
    let html = render("<pre>a & b</pre>");
    assert!(html.contains("<pre>a &amp; b</pre>"), "{html}");

    let html = render(" a & b\n");
    assert!(html.contains("<pre>a &amp; b\n</pre>"), "{html}");
}

#[test]
fn comments_are_removed() {
    let html = render("a<!-- hidden -->b");
    assert!(html.contains("<p>ab</p>"), "{html}");
    assert!(!html.contains("hidden"), "{html}");
}

// ------------------------------------------------------------ references

#[test]
fn references_render_a_numbered_list() {
    let html = render("Text<ref>First note</ref> and<ref name=\"n\">Second</ref>.<references/>");
    assert!(html.contains("cite_ref-1"), "{html}");
    assert!(html.contains("cite_ref-n"), "{html}");
    assert!(html.contains("cite_note-1"), "{html}");
    assert!(html.contains("reference-text"), "{html}");
    assert!(html.contains("First note"), "{html}");
    assert!(html.contains("Second"), "{html}");
}

#[test]
fn named_references_are_reused_and_groups_are_separate() {
    let html = render(
        "<ref name=\"a\">One</ref><ref name=\"a\"/><ref group=\"g\">Group</ref><references/>",
    );
    assert_eq!(html.matches("id=\"cite_ref-a\"").count(), 2, "{html}");
    assert!(html.contains("cite_ref-g-1"), "{html}");
    assert!(html.contains("&#91;1&#93;"), "{html}");
}

#[test]
fn empty_references_report_an_error() {
    let html = render("<ref name=\"missing\"/><references/>");
    assert!(html.contains("class=\"error\""), "{html}");
    assert!(html.contains("Cite error"), "{html}");
}

#[test]
fn references_without_a_references_tag_are_appended() {
    let html = render("Text<ref>Note</ref>");
    assert!(html.contains("cite_note-1"), "{html}");
    assert!(html.contains("Note"), "{html}");
}

// ----------------------------------------------------------- sanitising

#[test]
fn entities_are_normalised_not_decoded() {
    let html = render("&copy; &amp; &unknown; &#65; &");
    assert!(html.contains("&#169;"), "{html}");
    assert!(html.contains("&amp;"), "{html}");
    assert!(html.contains("&unknown;"), "{html}");
    assert!(html.contains("&#65;"), "{html}");
}

#[test]
fn raw_html_is_filtered() {
    let html =
        render("<div onclick=\"x\" style=\"background:url(javascript:x)\" class=\"ok\">text</div>");
    assert!(html.contains("class=\"ok\""), "{html}");
    assert!(!html.contains("onclick"), "{html}");
    assert!(!html.contains("javascript:"), "{html}");

    let html = render("<script>alert(1)</script>");
    assert!(!html.contains("<script"), "{html}");
    assert!(html.contains("&lt;script&gt;"), "{html}");

    let html = render("<a href=\"javascript:alert(1)\">x</a>");
    assert!(!html.contains("href=\"javascript:"), "{html}");
    assert!(html.contains("<a>x</a>"), "{html}");

    let html = render("<div data-x\"onclick=\"alert(1)\">x</div>");
    // The malformed tag must never be emitted as a live element.
    assert!(!html.contains("<div data-x"), "{html}");
    assert!(!html.contains("<div onclick"), "{html}");

    let html =
        render("<div style=\"background:<nowiki>url(javascript:alert(1))</nowiki>\">x</div>");
    assert!(!html.to_ascii_lowercase().contains("url("), "{html}");
    assert!(!html.to_ascii_lowercase().contains("javascript:"), "{html}");

    let html = render("<a href=\"<nowiki>javascript:alert(1)</nowiki>\">x</a>");
    assert!(
        !html.to_ascii_lowercase().contains("href=\"javascript:"),
        "{html}"
    );

    let html = render("<div title=\"__TOC__\">x</div>\n== One ==\nA\n== Two ==\nB\n== Three ==\nC\n== Four ==\nD\n");
    assert!(!html.contains("title=\"<div"), "{html}");
}

#[test]
fn padleft_and_sub_and_template_comments_are_hardened() {
    let html = render("{{PADLEFT:x|999999999|0}}");
    assert!(html.len() < 1000, "{html}");

    let html = render("{{#sub:abcdef|5|18446744073709551615}}");
    assert!(html.contains("f"), "{html}");

    // Internal marker bytes in a stored template are neutralised like the
    // page source is.
    let resolver =
        MemoryResolver::new().with_page(10, "Commented", "A<!-- secret -->B\r\nC\u{2}0\u{2}");
    let html = render_with(&resolver, &config(), "{{Commented}}");
    assert!(!html.contains("secret"), "{html}");
    assert!(!html.contains('\u{2}'), "{html}");
    assert!(!html.contains('\r'), "{html}");
    assert!(html.contains("AB"), "{html}");
}

#[test]
fn link_labels_are_escaped() {
    let html = render("[[Page|<script>alert(1)</script>]]");
    assert!(!html.contains("<script"), "{html}");
    assert!(html.contains("&lt;script&gt;"), "{html}");
}

// -------------------------------------------------------- magic words

#[test]
fn page_and_site_magic_words_expand() {
    let resolver = file_resolver();
    let config = config();
    let cases = [
        ("{{PAGENAME}}", "Test"),
        ("{{FULLPAGENAME}}", "Test"),
        ("{{NAMESPACE}}", ""),
        ("{{SITENAME}}", "Test Wiki"),
        ("{{SERVER}}", "https://wiki.example"),
        ("{{SERVERNAME}}", "wiki.example"),
        ("{{SCRIPTPATH}}", "/w"),
        ("{{STYLEPATH}}", "/skins"),
        ("{{UPLOADPATH}}", "/images"),
        ("{{ARTICLEPATH}}", "/wiki/$1"),
        ("{{CONTENTLANGUAGE}}", "en"),
        ("{{NUMBEROFPAGES}}", "1&#160;234"),
        ("{{PAGESINCATEGORY:People}}", "7"),
        ("{{PAGESINNAMESPACE:0}}", "42"),
        ("{{LOCALURL:Page}}", "/wiki/Page"),
        (
            "{{FULLURL:Page|action=edit}}",
            "https://wiki.example/w/index.php?title=Page&amp;action=edit",
        ),
        ("{{NS:Template}}", "Template"),
        ("{{NSE:Template}}", "Template"),
        ("{{PLURAL:1|one|many}}", "one"),
        ("{{PLURAL:2|one|many}}", "many"),
        ("{{FORMATNUM:1234}}", "1&#160;234"),
        ("{{LC:ABC}}", "abc"),
        ("{{UC:abc}}", "ABC"),
        ("{{LCFIRST:ABC}}", "aBC"),
        ("{{UCFIRST:abc}}", "Abc"),
        ("{{PADLEFT:7|3|0}}", "007"),
        ("{{PADRIGHT:7|3|0}}", "700"),
        ("{{GRAMMAR:elative|Talo}}", "Talosta"),
        ("{{GENDER:user|a|b}}", "a"),
        ("{{URLENCODE:Page One}}", "Page_One"),
        ("{{ANCHORENCODE:A b}}", "A_b"),
    ];
    for (source, expected) in cases {
        let html = render_with(&resolver, &config, source);
        assert!(html.contains(expected), "{source} -> {html}");
    }
}

#[test]
fn file_path_and_revision_magic_words() {
    let resolver = file_resolver();
    let config = config();
    let html = render_with(&resolver, &config, "{{FILEPATH:Pic.png}}");
    assert!(html.contains("/images/"), "{html}");

    let revision = RevisionInfo {
        id: 42,
        timestamp: "20260101120000".into(),
        user: "Ada".into(),
    };
    let result = Parser::render_with_revision(
        &fador_wikitext::ParserCache::disabled(),
        &resolver,
        &config,
        &MapMessages::new(),
        &Title::new(0, "Test"),
        Some(&revision),
        "{{REVISIONID}} {{REVISIONTIMESTAMP}} {{REVISIONUSER}}",
    );
    assert!(result.html.contains("42"), "{}", result.html);
    assert!(result.html.contains("20260101120000"), "{}", result.html);
    assert!(result.html.contains("Ada"), "{}", result.html);
}

#[test]
fn current_date_words_are_present() {
    let html = render(
        "{{CURRENTYEAR}} {{CURRENTMONTH}} {{CURRENTDAY}} {{CURRENTTIME}} {{CURRENTTIMESTAMP}}",
    );
    let text = html.trim();
    assert!(text.contains('<'), "{text}");
    assert!(
        text.chars().any(|character| character.is_ascii_digit()),
        "{text}"
    );
}

// ------------------------------------------------------ display title etc.

#[test]
fn display_title_defaultsort_and_noindex_are_collected() {
    let result = render_result(
        &MemoryResolver::new(),
        &config(),
        &Title::new(0, "Test"),
        "{{DISPLAYTITLE:Custom title}}{{DEFAULTSORT:Key}}__NOINDEX__\nBody",
    );
    assert_eq!(result.display_title.as_deref(), Some("Custom title"));
    assert!(result.noindex);
    assert!(result.html.contains("Body"), "{}", result.html);
    assert!(!result.html.contains("DEFAULTSORT"), "{}", result.html);
}

#[test]
fn interface_messages_come_from_the_source() {
    let messages = MapMessages::new()
        .with("toc", "Sisällys")
        .with("editsection", "muokkaa")
        .with("custom", "Oma viesti");
    let result = Parser::render(
        &MemoryResolver::new(),
        &config(),
        &messages,
        &Title::new(0, "Test"),
        "__TOC__\n== One ==\n{{int:custom}}\n",
    );
    assert!(result.html.contains("Sisällys"), "{}", result.html);
    assert!(result.html.contains("muokkaa"), "{}", result.html);
    assert!(result.html.contains("Oma viesti"), "{}", result.html);
}

// -------------------------------------------------- localised namespaces

#[test]
fn localised_namespaces_parse_links_templates_and_categories() {
    let mut namespaces = Namespaces::standard();
    for (id, name, canonical) in [
        (6, "Tiedosto", "File"),
        (10, "Malline", "Template"),
        (14, "Luokka", "Category"),
    ] {
        namespaces.insert(fador_wikitext::Namespace {
            id,
            name: name.into(),
            canonical: canonical.into(),
            aliases: Vec::new(),
        });
    }
    let config = config().with_namespaces(namespaces);
    let resolver = file_resolver();

    let result = render_result(
        &resolver,
        &config,
        &Title::new(0, "Test"),
        "[[Luokka:People]]\n[[Tiedosto:Pic.png|thumb|Kuva]]\n{{Malline:Hello}}",
    );
    assert_eq!(result.categories.len(), 1, "{:?}", result.categories);
    assert_eq!(result.categories[0].name, "People");
    assert!(result.html.contains("thumb"), "{}", result.html);
    assert!(result.html.contains("Hello, world!"), "{}", result.html);

    let html = render_with(&resolver, &config, "{{Missing}}");
    assert!(html.contains("Malline:Missing"), "{html}");
}
