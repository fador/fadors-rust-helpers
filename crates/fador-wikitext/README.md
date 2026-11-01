# fador-wikitext

A bounded, MediaWiki-compatible wikitext renderer extracted from the
Naruto.fi wiki rewrite. It turns stored wikitext into HTML for a page without
owning a database, a configuration file or a language pack.

- Headings and a numbered table of contents, `__TOC__`, `__NOTOC__`,
  `__FORCETOC__`, `__NOEDITSECTION__`
- Paragraphs, `<br>`, indented `<pre>`, `<nowiki>`, `<pre>` blocks and comments
- Nested `*`/`#`/`;`/`:` lists and `{| ... |}` tables with captions, headers,
  cell attributes and nested tables
- `''italic''`, `'''bold'''`, `'''''both'''''` with well-nested output
- Internal links with red/redirect/self classes, link trails, the pipe trick,
  fragments, `Media:` links and category collection
- External links, free links and an external-image allow-list
- `[[File:...]]` images with thumbs, frames, scaling, captions, `alt=`,
  `link=` and `srcset`
- Template transclusion with parameters, defaults, redirects, `subst:`,
  `safesubst:`, `msgnw:`, `<noinclude>`, `<includeonly>` and `<onlyinclude>`
- Parser functions (`#if`, `#ifeq`, `#switch`, `#ifexist`, `#expr`, `#len`,
  `#sub`) behind a configuration flag
- Magic words (page, site, date, URL, namespace, statistics, plural, grammar)
- Cite references with names, groups and a rendered list
- A sanitised subset of raw HTML, with entity, attribute, style and URL checks

There are no third-party crates, no `unsafe` code and no shipped skins, CSS,
images or language packs. The crate is code only.

## Usage

```rust
use fador_wikitext::{MapMessages, MemoryResolver, Parser, ParserConfig, Title};

let resolver = MemoryResolver::new()
    .with_page(10, "Hello", "Hello, {{{1|world}}}!")
    .with_file(fador_wikitext::FileInfo::new("Pic.png", 640, 480));

let config = ParserConfig::default()
    .with_script_path("/w")
    .with_article_path("/wiki/$1")
    .with_site_name("Test Wiki");

let messages = MapMessages::new().with("toc", "Contents");
let title = Title::new(0, "Sandbox");

let result = Parser::render(
    &resolver,
    &config,
    &messages,
    &title,
    "== Greeting ==\n{{Hello|Naruto}}\n\n[[File:Pic.png|thumb|A picture]]",
);

assert!(result.html.contains("Hello, Naruto!"));
assert!(result.html.contains("class=\"thumb tright\""));
```

The application implements three small interfaces:

| Trait | What the renderer asks for |
|---|---|
| `WikiResolver` | page text, page existence/redirect, file metadata, category and namespace counts, site statistics, optional batch existence |
| `MessageSource` | the raw text of an interface message key |
| `ParserConfig` | script/article/upload/style paths, server URL, language, site name, namespace table, limits and the parser-function flag |

`MemoryResolver` and `MapMessages` are the in-memory implementations used by
the tests and the example; a server implements the traits over its own storage.
`Parser::render` is a pure function with no cache. `Parser::render_cached`
takes a caller-owned `ParserCache` (a bounded TTL cache) and
`Parser::render_with_revision` also supplies the values behind `REVISIONID`,
`REVISIONTIMESTAMP` and `REVISIONUSER`.

## Limits

Every recursive or repetitive construct is bounded, and a hostile page ends in
literal text or an error span rather than a panic or an unbounded allocation:

| Limit | Default | Where |
|---|---:|---|
| Template transclusion depth | 40 | `ParserConfig::max_template_depth` |
| Template expansion bytes | 2 MiB | `ParserConfig::max_expansion_bytes` |
| One transcluded page | 2 MiB | `ParserConfig::max_page_bytes` |
| Template redirect chain | 8 | fixed |
| Brace/bracket nesting in one scan | 128 | fixed |
| List nesting | 100 | fixed |
| Table nesting in one table | 100 | fixed |
| Recursive block parse | 16 | fixed |
| Categories per page | 5,000 | fixed |
| References per page | 1,000 | fixed |
| Thumbnail width | 10,000 px | fixed |
| Brace/bracket scan work | 64 × source + 1 MiB | fixed |

The scan budget is the one addition the source parser did not have: a page made
only of `{{` or `[[` used to make every opener rescan the rest of the page.
The renderer now stops expanding and treats the remaining text literally once
the budget is spent. A single template body that repeats a parameter also stops
at the expansion budget instead of building the whole string first.

## Escaping and sanitising

- Escaped text positions and attribute values use `fador_markup`'s HTML
  escaping; ordinary text is written as-is, with `<`, `>` and `&` handled by the
  inline scanner.
- URLs go through `fador_markup::sanitize_url` with the strict web policy for
  links and the image policy for `src`/`poster`.
- Inline styles go through `fador_markup::sanitize_style`, and the attribute
  allow-list is `fador_markup::is_allowed_attr`.
- Attribute values are entity-decoded before the URL/style check and re-escaped
  afterwards, so `java&#115;cript:` cannot slip past the scheme check.
- Stored text keeps MediaWiki's entity normalisation: `&copy;` becomes
  `&#169;`, `&amp;` stays `&amp;`, and an unknown but well-formed name is
  passed through. The entity parser stays local because `fador-markup` decodes
  references instead of normalising them, which would change the stored page's
  bytes before they are escaped.
- `{{PLURAL:...}}` uses `fador_i18n::plural_form` with the configured
  phpBB/Mozilla rule (rule 1 is the two-form English/Finnish rule). The `$1`
  message placeholders stay local because MediaWiki messages use `$1`, not
  `sprintf`'s `%s`.
- `{{GRAMMAR:...}}` is a conservative Finnish elative helper. `fador-i18n`
  supplies plural rules but no case inflection, so the one rule the source wiki
  used stays here and no site name is hard-coded.

## Deviations from the source parser

The crate is a direct port of the parser in the Naruto.fi wiki server, with
these deliberate differences:

- The database, configuration and message types are replaced by
  `WikiResolver`, `ParserConfig` and `MessageSource`. `ParserConfig` carries the
  namespace table so `Parser::render` keeps its five arguments.
- No language packs are copied. Built-in messages are the renderer's own short
  English fallbacks (`Contents`, `edit`, `Cite error: $1`, month and day names);
  a deployment supplies its language through `MessageSource`. The namespace
  table defaults to the canonical English names, and the caller inserts the
  localized names and the site's project namespace.
- `CURRENTVERSION` returns `ParserConfig::version` instead of a hard-coded
  MediaWiki version.
- Parser functions are enabled by default. The source default was off because
  the target wiki did not load the ParserFunctions extension; a deployment with
  the same setup sets `enable_parser_functions = false`.
- `{{#if:...}}`, `{{#ifeq:...}}` and the other parser functions split the
  colon in the function name. The source matched the whole `#if:cond` string
  against `#if`, so the functions never fired; `#switch` also handles
  `#default=` now.
- `[[Page#Section]]` displays `Page#Section`; the source appended the fragment
  twice (`Page#Section#Section`).
- Bold and italic close in reverse order, so `'''''both'''''` renders
  `<b><i>both</i></b>` instead of the invalid `<b><i>both</b></i>`.
- A list item whose marker run jumps several levels is rendered instead of
  dropped, and a 20,000-apostrophe run is consumed five at a time instead of
  being recounted from every offset.
- A missing category count or namespace count renders `0` instead of being
  treated as a template name; a missing `FILEPATH` renders empty.
- Gallery file prefixes are resolved through the namespace table instead of the
  hard-coded `File:`, `Image:` and `Tiedosto:` list.
- Thumbnail widths are clamped and the attribute sanitizer is
  `fador-markup`'s allow-list, which is a superset of the source list.
- The `MediaWiki:` namespace override loader, the skin and the language-file
  reader are not part of this crate; they belong to the application.

## What is not here

The MonoBook skin, the HTTP server, the database, the search index, the
language packs and the page store. Those are applications of the renderer, not
the renderer itself.

## Tests

```sh
cargo test -p fador-wikitext
```

Unit tests cover the title, namespace, message, resolver, cache and sanitizer
modules. The integration suite covers headings/TOC, paragraphs, nested lists,
tables, bold/italic, internal and external links, the pipe trick and trails,
images and thumbs, templates with a stub resolver, parser functions,
nowiki/pre, references, entity and URL sanitising, display title/noindex,
magic words and the depth/expansion limits. The seeded fuzz suite uses
`fador-testutil`'s fixed PRNG and hostile corpus; `FADOR_FUZZ_ITERATIONS`
raises the case count for a deeper local pass.

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
The original templates, styles, images and language packs of the source wiki
are not included.
