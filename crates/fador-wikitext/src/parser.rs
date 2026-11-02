//! Wikitext to HTML renderer.
//!
//! The renderer is intentionally a single-pass, bounded parser rather than a
//! complete reimplementation of Parsoid. It covers the constructs used by the
//! source wiki: headings and TOC, paragraphs, lists, tables, links, images,
//! templates, magic words, categories, Cite references, nowiki/pre and a
//! sanitised subset of raw HTML.

use std::collections::{HashMap, HashSet};

use fador_core::crypto::mw_file_hash;
use fador_core::util::{anchor_html5, encode_title, normalize_title_text, now_parts};

use crate::cache::ParserCache;
use crate::config::ParserConfig;
use crate::messages::{grammar_fi, MessageContext, MessageFormatter, MessageSource};
use crate::namespaces::Namespaces;
use crate::resolver::{FileInfo, PageFlags, RevisionInfo, SiteStats, TitleKey, WikiResolver};
use crate::sanitize::{
    escape_html, is_allowed_tag, parse_entity, parse_tag_attr, sanitize_anchor, sanitize_attrs,
    sanitize_ref_part, strip_tags,
};
use crate::title::Title;

const TOC_MARKER: &str = "\u{1}TOC\u{1}";
const REFS_PREFIX: &str = "\u{4}REFS:";
const REFS_SUFFIX: &str = "\u{4}";
const NOWIKI_MARKER: char = '\u{2}';

/// The deepest `*`/`#`/`;`/`:` list nesting the renderer builds.
const MAX_LIST_DEPTH: usize = 100;
/// The deepest `{|` table nesting the renderer tracks inside one table.
const MAX_TABLE_NESTING: usize = 100;
/// The deepest recursive block parse (a table cell inside a table cell).
const MAX_BLOCK_DEPTH: usize = 16;
/// The deepest `{{`/`[[` delimiter stack a single scan accepts.
const MAX_BRACE_DEPTH: i32 = 128;
/// The maximum number of categories collected from one page.
const MAX_CATEGORIES: usize = 5_000;
/// The maximum number of references collected from one page.
const MAX_REFS: usize = 1_000;
/// The widest thumbnail the renderer will emit, in pixels.
const MAX_IMAGE_WIDTH: u32 = 10_000;

/// One category a page adds itself to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    /// Category name without the namespace prefix.
    pub name: String,
    /// Sort key (`[[Category:X|key]]`), empty when the page uses its title.
    pub sortkey: String,
}

/// The output of one render.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseResult {
    /// The rendered HTML body.
    pub html: String,
    /// Categories the page adds itself to, in source order.
    pub categories: Vec<Category>,
    /// The value of `{{DISPLAYTITLE:...}}`, if the page set one.
    pub display_title: Option<String>,
    /// Whether the page requested `__NOINDEX__`.
    pub noindex: bool,
}

/// The MediaWiki-compatible renderer.
///
/// The type has no state; [`Parser::render`] is a pure function of its
/// arguments. Use [`Parser::render_cached`] when a server wants to reuse
/// template text and link colours across requests.
pub struct Parser;

impl Parser {
    /// Render `source` for `title`.
    ///
    /// Every resolver answer is queried directly; no cache survives the call.
    /// The output is bounded by [`ParserConfig`] and by the parser's fixed
    /// nesting limits.
    #[must_use]
    pub fn render(
        resolver: &dyn WikiResolver,
        config: &ParserConfig,
        messages: &dyn MessageSource,
        title: &Title,
        source: &str,
    ) -> ParseResult {
        let cache = ParserCache::disabled();
        Self::render_cached(&cache, resolver, config, messages, title, source)
    }

    /// Render `source` using a caller-owned [`ParserCache`].
    #[must_use]
    pub fn render_cached(
        cache: &ParserCache,
        resolver: &dyn WikiResolver,
        config: &ParserConfig,
        messages: &dyn MessageSource,
        title: &Title,
        source: &str,
    ) -> ParseResult {
        Self::render_with_revision(cache, resolver, config, messages, title, None, source)
    }

    /// Render `source` with the revision values behind `REVISIONID`,
    /// `REVISIONTIMESTAMP` and `REVISIONUSER`.
    #[must_use]
    pub fn render_with_revision(
        cache: &ParserCache,
        resolver: &dyn WikiResolver,
        config: &ParserConfig,
        messages: &dyn MessageSource,
        title: &Title,
        revision: Option<&RevisionInfo>,
        source: &str,
    ) -> ParseResult {
        let context = RenderContext::new(resolver, config, cache, title, revision, messages);
        Renderer::new(context).run(source)
    }
}

struct RenderContext<'a> {
    resolver: &'a dyn WikiResolver,
    config: &'a ParserConfig,
    cache: &'a ParserCache,
    title: &'a Title,
    revision: Option<&'a RevisionInfo>,
    formatter: MessageFormatter<'a>,
}

impl<'a> RenderContext<'a> {
    fn new(
        resolver: &'a dyn WikiResolver,
        config: &'a ParserConfig,
        cache: &'a ParserCache,
        title: &'a Title,
        revision: Option<&'a RevisionInfo>,
        messages: &'a dyn MessageSource,
    ) -> Self {
        let (year, month, day, hour, minute, _second, _seconds) = now_parts();
        let message_context = MessageContext {
            sitename: config.site_name.clone(),
            pagename: title.text.clone(),
            fullpagename: title.full_text(&config.namespaces),
            namespace: config.namespaces.name(title.ns).to_string(),
            year,
            month,
            day,
            hour,
            minute,
        };
        Self {
            resolver,
            config,
            cache,
            title,
            revision,
            formatter: MessageFormatter::new(messages, config, message_context),
        }
    }
}

#[derive(Default)]
struct State {
    refs: Vec<RefEntry>,
    ref_names: HashMap<(String, String), usize>,
    headings: Vec<Heading>,
    heading_ids: HashSet<String>,
    heading_counters: [u32; 7],
    categories: Vec<Category>,
    no_toc: bool,
    force_toc: bool,
    toc_explicit: bool,
    toc_placed: bool,
    toc_auto: bool,
    display_title: Option<String>,
    defaultsort: Option<String>,
    noindex: bool,
    expansion_bytes: usize,
    nowiki: Vec<String>,
    exists_cache: HashMap<TitleKey, PageFlags>,
    template_stack: Vec<String>,
    refs_rendered: HashSet<String>,
    source_section: usize,
    no_edit_section: bool,
    block_depth: usize,
    scan_budget: usize,
}

#[derive(Debug, Clone)]
struct Heading {
    level: u8,
    id: String,
    text: String,
    number: String,
}

#[derive(Debug, Clone)]
struct RefEntry {
    key: String,
    number: usize,
    group: String,
    content: String,
}

struct Frame {
    params: HashMap<String, String>,
}

struct Renderer<'a> {
    ctx: RenderContext<'a>,
    state: State,
    frame: Option<Frame>,
}

impl<'a> Renderer<'a> {
    fn new(ctx: RenderContext<'a>) -> Self {
        Self {
            ctx,
            state: State::default(),
            frame: None,
        }
    }

    fn run(mut self, source: &str) -> ParseResult {
        // Every brace and bracket scan draws from one budget proportional to
        // the source size, so a page made only of `{{` or `[[` cannot turn the
        // scanners into quadratic work.
        self.state.scan_budget = source.len().saturating_mul(64).saturating_add(1_000_000);
        let mut text = normalize_source(source);
        text = process_page_source(&text);
        text = self.protect_nowiki(&text);
        text = strip_comments(&text);
        text = self.handle_switches(&text);
        let expanded = self.expand_templates(&text, 0);
        self.prefetch_link_existence(&expanded);
        let mut html = self.parse_blocks(&expanded);

        // Determine whether the automatic TOC should be kept.
        let keep_toc = !self.state.no_toc
            && (self.state.toc_explicit || self.state.force_toc || self.state.headings.len() >= 4);
        if keep_toc {
            let toc = self.build_toc();
            html = html.replace(TOC_MARKER, &toc);
        } else {
            html = html.replace(TOC_MARKER, "");
        }
        html = self.finalize_refs(html);
        html = self.restore_nowiki(&html);

        ParseResult {
            html,
            categories: self.state.categories,
            display_title: self.state.display_title,
            noindex: self.state.noindex,
        }
    }

    // ------------------------------------------------------------- helpers

    fn namespaces(&self) -> &Namespaces {
        &self.ctx.config.namespaces
    }

    fn msg(&self, key: &str) -> String {
        self.ctx.formatter.text(key)
    }

    fn msg_args(&self, key: &str, args: &[&str]) -> String {
        self.ctx.formatter.format(key, args)
    }

    fn toc_placeholder(&mut self) -> String {
        self.state.toc_placed = true;
        self.state.toc_explicit = true;
        TOC_MARKER.to_string()
    }

    // ---------------------------------------------------------- preprocess

    fn protect_nowiki(&mut self, text: &str) -> String {
        let lower = text.to_ascii_lowercase();
        let mut out = String::with_capacity(text.len());
        let mut index = 0;
        while index < text.len() {
            if lower[index..].starts_with("<nowiki") {
                // Find the end of the opening tag.
                if let Some(gt) = text[index..].find('>') {
                    let tag = &text[index..index + gt + 1];
                    if tag.trim_end().ends_with("/>") {
                        index += gt + 1;
                        continue;
                    }
                    let content_start = index + gt + 1;
                    if let Some(close_rel) = lower[content_start..].find("</nowiki>") {
                        let content = &text[content_start..content_start + close_rel];
                        let id = self.state.nowiki.len();
                        self.state.nowiki.push(content.to_string());
                        out.push(NOWIKI_MARKER);
                        out.push_str(&id.to_string());
                        out.push(NOWIKI_MARKER);
                        index = content_start + close_rel + "</nowiki>".len();
                        continue;
                    }
                }
            }
            let character = text[index..].chars().next().unwrap_or(' ');
            out.push(character);
            index += character.len_utf8();
        }
        out
    }

    fn restore_nowiki(&self, html: &str) -> String {
        let mut out = String::with_capacity(html.len());
        let mut rest = html;
        while let Some(position) = rest.find(NOWIKI_MARKER) {
            out.push_str(&rest[..position]);
            let after = &rest[position + NOWIKI_MARKER.len_utf8()..];
            if let Some(end) = after.find(NOWIKI_MARKER) {
                if let Ok(id) = after[..end].parse::<usize>() {
                    if let Some(content) = self.state.nowiki.get(id) {
                        out.push_str(&escape_html(content));
                    }
                }
                rest = &after[end + NOWIKI_MARKER.len_utf8()..];
                continue;
            }
            out.push(NOWIKI_MARKER);
            rest = after;
        }
        out.push_str(rest);
        out
    }

    fn handle_switches(&mut self, text: &str) -> String {
        let switches = [
            ("__NOTOC__", "toc"),
            ("__FORCETOC__", "force"),
            ("__NOEDITSECTION__", "noeditsection"),
            ("__NOTITLECONVERT__", "drop"),
            ("__NOCACHE__", "drop"),
            ("__NOGALLERY__", "drop"),
            ("__HIDDENCAT__", "drop"),
            ("__INDEX__", "drop"),
            ("__NOINDEX__", "noindex"),
            ("__STATICREDIRECT__", "drop"),
            ("__EXPECTED_UNCONNECTED_PAGE__", "drop"),
            ("__DISAMBIG__", "drop"),
        ];
        let mut out = String::with_capacity(text.len());
        for (index, line) in text.split('\n').enumerate() {
            if index > 0 {
                out.push('\n');
            }
            if line.contains("__TOC__") && !line.contains('<') && !line.contains('>') {
                out.push_str(&line.replace("__TOC__", TOC_MARKER));
            } else {
                out.push_str(line);
            }
        }
        if out.contains(TOC_MARKER) {
            self.state.toc_explicit = true;
        }
        for (token, action) in switches {
            if out.contains(token) {
                match action {
                    "toc" => self.state.no_toc = true,
                    "force" => self.state.force_toc = true,
                    "noindex" => self.state.noindex = true,
                    "noeditsection" => self.state.no_edit_section = true,
                    _ => {}
                }
                out = out.replace(token, "");
            }
        }
        out
    }

    // ----------------------------------------------------------- templates

    fn expand_templates(&mut self, text: &str, depth: usize) -> String {
        if depth > self.ctx.config.max_template_depth {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut index = 0;
        while index < text.len() {
            // A single template body can be much larger than its source when
            // it repeats a parameter. Stop before the buffer grows past the
            // configured expansion budget.
            if out.len() > self.ctx.config.max_expansion_bytes {
                out.push_str(&escape_html(&self.msg("parser-template-recursion-error")));
                break;
            }
            if bytes[index] == b'{'
                && index + 2 < bytes.len()
                && bytes[index + 1] == b'{'
                && bytes[index + 2] == b'{'
            {
                if self.state.scan_budget == 0 {
                    out.push_str(&text[index..]);
                    break;
                }
                if let Some((content_end, close_len)) =
                    find_balanced(text, index + 3, BraceKind::Triple)
                {
                    self.state.scan_budget = self
                        .state
                        .scan_budget
                        .saturating_sub(content_end + close_len - index);
                    let inner = &text[index + 3..content_end];
                    let value = self.expand_parameter(inner, depth);
                    out.push_str(&value);
                    index = content_end + close_len;
                    continue;
                }
                self.state.scan_budget = self.state.scan_budget.saturating_sub(text.len() - index);
            } else if bytes[index] == b'{' && index + 1 < bytes.len() && bytes[index + 1] == b'{' {
                if self.state.scan_budget == 0 {
                    out.push_str(&text[index..]);
                    break;
                }
                if let Some((content_end, close_len)) =
                    find_balanced(text, index + 2, BraceKind::Double)
                {
                    self.state.scan_budget = self
                        .state
                        .scan_budget
                        .saturating_sub(content_end + close_len - index);
                    let inner = &text[index + 2..content_end];
                    let value = self.expand_template(inner, depth);
                    self.state.expansion_bytes =
                        self.state.expansion_bytes.saturating_add(value.len());
                    if self.state.expansion_bytes > self.ctx.config.max_expansion_bytes {
                        out.push_str(&escape_html(&self.msg("parser-template-recursion-error")));
                        index = content_end + close_len;
                        continue;
                    }
                    out.push_str(&value);
                    index = content_end + close_len;
                    continue;
                }
                self.state.scan_budget = self.state.scan_budget.saturating_sub(text.len() - index);
            }
            let character = text[index..].chars().next().unwrap_or(' ');
            out.push(character);
            index += character.len_utf8();
        }
        out
    }

    fn expand_parameter(&mut self, inner: &str, depth: usize) -> String {
        let frame = self.frame.as_ref().map(|frame| frame.params.clone());
        if let Some(frame) = frame {
            let parts = split_top_level(inner, '|');
            let name =
                self.expand_templates(parts.first().map(String::as_str).unwrap_or(""), depth + 1);
            let name = name.trim();
            if let Some(value) = frame.get(name) {
                let value = value.clone();
                return self.expand_templates(&value, depth + 1);
            }
            if let Some(default) = parts.get(1) {
                let default = default.clone();
                return self.expand_templates(&default, depth + 1);
            }
            return String::new();
        }
        inner.to_string()
    }

    fn expand_template(&mut self, inner: &str, depth: usize) -> String {
        let parts = split_top_level(inner, '|');
        let title_raw = parts.first().map(String::as_str).unwrap_or("").trim();
        if title_raw.is_empty() {
            return String::new();
        }
        let first = self.expand_templates(title_raw, depth + 1);
        let first = first.trim();
        // Common magic words and behaviour-like functions.
        if first == "!" || first == "!!" {
            return "|".to_string();
        }
        if first == "=" {
            return "=".to_string();
        }
        if let Some(rest) = first.strip_prefix("DEFAULTSORT:") {
            self.state.defaultsort = Some(rest.trim().to_string());
            return String::new();
        }
        if let Some(rest) = first.strip_prefix("DISPLAYTITLE:") {
            self.state.display_title = Some(strip_tags(&self.expand_templates(rest, depth + 1)));
            return String::new();
        }
        if let Some(rest) = first.strip_prefix("int:") {
            return self.ctx.formatter.raw(rest.trim());
        }
        if first.starts_with('#') {
            if self.ctx.config.enable_parser_functions {
                if let Some(value) = self.parser_function(first, &parts, depth) {
                    return value;
                }
            }
            return format!("{{{{{inner}}}}}");
        }
        if let Some(value) = self.magic_word(first, &parts[1..], depth) {
            return value;
        }

        // Determine the page to transclude.
        let (ns, page_text) = self.template_target(first);
        let title = Title::new(ns, page_text);
        let Some(source) = self.load_template(ns, &title, 0) else {
            // Missing template: MediaWiki emits a red link to the template.
            let display = if ns == 0 {
                title.full_text(self.namespaces())
            } else {
                format!("{}:{}", self.namespaces().name(ns), title.text)
            };
            return format!("[[{}]]", display.replace(']', ""));
        };
        let stack_key = format!("{ns}:{}", title.db_title());
        if self
            .state
            .template_stack
            .iter()
            .any(|key| key == &stack_key)
            || self.state.template_stack.len() >= self.ctx.config.max_template_depth
            || depth >= self.ctx.config.max_template_depth
        {
            let message = self.msg_args("parser-template-recursion-error", &[first]);
            return format!("<span class=\"error\">{}</span>", escape_html(&message));
        }
        self.state.template_stack.push(stack_key);

        let mut frame = Frame {
            params: HashMap::new(),
        };
        let mut positional = 0usize;
        for part in parts.iter().skip(1) {
            if let Some(eq) = find_top_level(part, '=') {
                let name = part[..eq].trim();
                let value = self.expand_templates(&part[eq + 1..], depth + 1);
                frame
                    .params
                    .insert(name.to_string(), value.trim().to_string());
            } else {
                positional += 1;
                let value = self.expand_templates(part, depth + 1);
                frame.params.insert(positional.to_string(), value);
            }
        }
        let old_frame = self.frame.replace(frame);
        let mut expanded = self.expand_templates(&source, depth + 1);
        self.frame = old_frame;
        self.state.template_stack.pop();
        let trimmed = expanded.trim_start();
        if (trimmed.starts_with("{|") || trimmed.starts_with("<table")) && !expanded.ends_with('\n')
        {
            expanded.push('\n');
        }
        expanded
    }

    fn load_template(&mut self, ns: i32, title: &Title, depth: usize) -> Option<String> {
        if depth > 8 {
            return None;
        }
        let key = (ns, title.db_title());
        if let Some(cached) = self.ctx.cache.templates.get(&key) {
            return cached;
        }
        let raw = self.ctx.resolver.page_wikitext(ns, &title.db_title())?;
        if raw.len() > self.ctx.config.max_page_bytes {
            return None;
        }
        let mut processed = if let Some((redirect_ns, redirect_text)) = self.redirect_target(&raw) {
            let target = Title::new(redirect_ns, redirect_text);
            self.load_template(redirect_ns, &target, depth + 1)
                .unwrap_or_else(|| process_template_source(&raw))
        } else {
            process_template_source(&raw)
        };
        processed = strip_comments(&normalize_source(
            processed.trim_start_matches('\u{feff}'),
        ));
        self.ctx.cache.templates.put(key, Some(processed.clone()));
        Some(processed)
    }

    fn redirect_target(&self, source: &str) -> Option<(i32, String)> {
        let trimmed = source.trim_start();
        let lower = trimmed.to_ascii_lowercase();
        if !lower.starts_with("#redirect") {
            return None;
        }
        let after = &trimmed["#redirect".len()..];
        let after = after.trim_start_matches(':').trim_start();
        let open = after.find("[[")?;
        let rest = &after[open + 2..];
        let end = rest.find("]]")?;
        let inner = &rest[..end];
        let target = split_top_level(inner, '|')
            .first()
            .cloned()
            .unwrap_or_default();
        let title = Title::parse(target.trim(), self.namespaces())?;
        Some((title.ns, title.text))
    }

    fn template_target(&self, first: &str) -> (i32, String) {
        let mut text = first.trim();
        let mut leading_colon = false;
        if let Some(rest) = text.strip_prefix(':') {
            leading_colon = true;
            text = rest.trim_start();
        }
        if let Some(rest) = text.strip_prefix("subst:") {
            text = rest;
        } else if let Some(rest) = text.strip_prefix("safesubst:") {
            text = rest;
        }
        if let Some(rest) = text.strip_prefix("msgnw:") {
            text = rest;
        }
        if let Some(colon) = text.find(':') {
            let prefix = &text[..colon];
            if let Some(ns) = self.namespaces().lookup(prefix) {
                let title = normalize_title_text(text[colon + 1..].trim())
                    .unwrap_or_else(|| text[colon + 1..].trim().to_string());
                return (ns, title);
            }
        }
        let title = normalize_title_text(text).unwrap_or_else(|| text.to_string());
        if leading_colon {
            (0, title)
        } else {
            (10, title)
        }
    }

    fn magic_word(&mut self, name: &str, raw_args: &[String], depth: usize) -> Option<String> {
        let raw_name = name.trim();
        let key = raw_name.to_ascii_uppercase().replace('_', " ");
        let args: Vec<String> = raw_args
            .iter()
            .map(|argument| self.expand_templates(argument, depth + 1))
            .collect();
        let namespaces = &self.ctx.config.namespaces;
        let title = self.ctx.title;
        let (year, month, day, hour, minute, second, seconds) = now_parts();
        if let Some(colon) = raw_name.find(':') {
            let base = raw_name[..colon].trim().to_ascii_uppercase();
            let arg = &raw_name[colon + 1..];
            match base.as_str() {
                "LOCALURL" | "FULLURL" => {
                    let target = Title::parse(arg.trim(), namespaces)
                        .unwrap_or_else(|| Title::new(0, arg.trim().to_string()));
                    let mut url = target.local_url(self.ctx.config, namespaces);
                    if let Some(query) = args.first() {
                        let query = query.trim().trim_start_matches('?');
                        if !query.is_empty() {
                            url = format!(
                                "{}/index.php?title={}&{}",
                                self.ctx.config.script_root(),
                                encode_title(&target.full_text(namespaces)),
                                query
                            );
                        }
                    }
                    if base == "FULLURL" {
                        if let Some(server) = &self.ctx.config.server_url {
                            url = format!("{}{url}", server.trim_end_matches('/'));
                        }
                    }
                    return Some(url);
                }
                "FILEPATH" => {
                    let target = Title::parse(arg.trim(), namespaces)
                        .unwrap_or_else(|| Title::new(6, arg.trim().to_string()));
                    let Some(info) = self.file_info(&target.db_title()) else {
                        return Some(String::new());
                    };
                    return Some(self.file_url(&info));
                }
                "URLENCODE" => return Some(encode_title(arg)),
                "ANCHORENCODE" => return Some(sanitize_anchor(arg)),
                "LC" => return Some(arg.to_lowercase()),
                "UC" => return Some(arg.to_uppercase()),
                "LCFIRST" => {
                    let mut characters = arg.chars();
                    return Some(match characters.next() {
                        Some(first) => {
                            first.to_lowercase().collect::<String>() + characters.as_str()
                        }
                        None => String::new(),
                    });
                }
                "UCFIRST" => {
                    let mut characters = arg.chars();
                    return Some(match characters.next() {
                        Some(first) => {
                            first.to_uppercase().collect::<String>() + characters.as_str()
                        }
                        None => String::new(),
                    });
                }
                "NS" => {
                    if let Some(id) = namespaces.lookup(arg.trim()) {
                        return Some(namespaces.name(id).replace(' ', "_"));
                    }
                    return Some(arg.to_string());
                }
                "NSE" => {
                    if let Some(id) = namespaces.lookup(arg.trim()) {
                        return Some(encode_title(namespaces.name(id)));
                    }
                    return Some(encode_title(arg));
                }
                "FORMATNUM" => return Some(format_number_fi(arg.trim())),
                "PLURAL" => {
                    let count = arg.trim().parse::<u64>().unwrap_or(0);
                    return Some(select_plural(&args, count, self.ctx.config.plural_rule));
                }
                "GRAMMAR" => {
                    let word = args.first().cloned().unwrap_or_default();
                    return Some(grammar_fi(&word));
                }
                "GENDER" => {
                    return Some(args.first().cloned().unwrap_or_default());
                }
                "PADLEFT" | "PADRIGHT" => {
                    let value = arg;
                    let width = args
                        .first()
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0)
                        .min(500);
                    let fill = args
                        .get(1)
                        .and_then(|value| value.chars().next())
                        .unwrap_or('0');
                    let count = value.chars().count();
                    if count >= width {
                        return Some(value.to_string());
                    }
                    let padding: String = std::iter::repeat_n(fill, width - count).collect();
                    return Some(if base == "PADLEFT" {
                        format!("{padding}{value}")
                    } else {
                        format!("{value}{padding}")
                    });
                }
                _ => {}
            }
        }
        if let Some(colon) = raw_name.find(':') {
            let base = raw_name[..colon].trim().to_ascii_uppercase();
            let arg = &raw_name[colon + 1..];
            match base.as_str() {
                "PAGESINCATEGORY" | "PAGESINCAT" => {
                    let category = Title::new(14, arg.trim().replace('_', " "));
                    let count = self
                        .ctx
                        .resolver
                        .category_count(&category.db_title())
                        .unwrap_or(0);
                    return Some(count.to_string());
                }
                "PAGESINNAMESPACE" => {
                    let Ok(ns) = arg.trim().parse::<i32>() else {
                        return Some("0".to_string());
                    };
                    let count = self.ctx.resolver.page_count_in_namespace(ns).unwrap_or(0);
                    return Some(count.to_string());
                }
                "NUMBERINGROUP" | "NUMBEROFGROUP" => {
                    return Some("0".to_string());
                }
                _ => {}
            }
        }
        let value = match key.as_str() {
            "PAGENAME" => title.text.clone(),
            "PAGENAMEE" => encode_title(&title.text),
            "FULLPAGENAME" => title.full_text(namespaces),
            "FULLPAGENAMEE" => encode_title(&title.full_text(namespaces)),
            "NAMESPACE" => namespaces.name(title.ns).to_string(),
            "NAMESPACEE" => encode_title(namespaces.name(title.ns)),
            "NAMESPACENUMBER" => title.ns.to_string(),
            "BASEPAGENAME" => title
                .text
                .rsplit_once('/')
                .map(|(base, _)| base)
                .unwrap_or(&title.text)
                .to_string(),
            "SUBPAGENAME" => title
                .text
                .rsplit_once('/')
                .map(|(_, subpage)| subpage)
                .unwrap_or(&title.text)
                .to_string(),
            "ROOTPAGENAME" => title.root_page(),
            "TALKPAGENAME" => title.talk().full_text(namespaces),
            "SUBJECTPAGENAME" | "ARTICLEPAGENAME" => title.subject().full_text(namespaces),
            "SITENAME" => self.ctx.config.site_name.clone(),
            "SERVER" => self.ctx.config.server_url.clone().unwrap_or_default(),
            "SERVERNAME" => self
                .ctx
                .config
                .server_url
                .as_deref()
                .map(strip_scheme)
                .unwrap_or_default()
                .to_string(),
            "SCRIPTPATH" => self.ctx.config.script_path.clone(),
            "STYLEPATH" => self.ctx.config.style_path.clone(),
            "UPLOADPATH" => self.ctx.config.upload_path.clone(),
            "ARTICLEPATH" => self.ctx.config.article_path.clone(),
            "CONTENTLANGUAGE" | "CONTENTLANG" => self.ctx.config.language.clone(),
            "CURRENTYEAR" => year.to_string(),
            "CURRENTMONTH" => format!("{month:02}"),
            "CURRENTMONTH1" => month.to_string(),
            "CURRENTMONTHNAME" => self.ctx.formatter.raw(&month_key(month)),
            "CURRENTMONTHNAMEGEN" => {
                let generated = format!("{}gen", month_key(month));
                let value = self.ctx.formatter.raw(&generated);
                if value == generated {
                    self.ctx.formatter.raw(&month_key(month))
                } else {
                    value
                }
            }
            "CURRENTDAY" => day.to_string(),
            "CURRENTDAY2" => format!("{day:02}"),
            "CURRENTDOW" => {
                let days = ((seconds / 86_400) % 7) as u32;
                ((days + 4) % 7).to_string()
            }
            "CURRENTDAYNAME" => {
                let days = ((seconds / 86_400) % 7) as usize;
                let names = [
                    "sunday",
                    "monday",
                    "tuesday",
                    "wednesday",
                    "thursday",
                    "friday",
                    "saturday",
                ];
                self.ctx.formatter.raw(names[(days + 4) % 7])
            }
            "CURRENTTIME" => format!("{hour:02}:{minute:02}"),
            "CURRENTHOUR" => format!("{hour:02}"),
            "CURRENTTIMESTAMP" => {
                format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}")
            }
            "CURRENTVERSION" => self.ctx.config.version.clone(),
            "REVISIONID" => self
                .ctx
                .revision
                .map(|revision| revision.id.to_string())
                .unwrap_or_default(),
            "REVISIONTIMESTAMP" => self
                .ctx
                .revision
                .map(|revision| revision.timestamp.clone())
                .unwrap_or_default(),
            "REVISIONUSER" => self
                .ctx
                .revision
                .map(|revision| revision.user.clone())
                .unwrap_or_default(),
            "NUMBEROFARTICLES"
            | "NUMBEROFPAGES"
            | "NUMBEROFUSERS"
            | "NUMBEROFFILES"
            | "NUMBEROFEDITS"
            | "NUMBEROFACTIVEUSERS" => {
                let stats = self.site_stats();
                match key.as_str() {
                    "NUMBEROFARTICLES" => format_number_fi(&stats.articles.to_string()),
                    "NUMBEROFPAGES" => format_number_fi(&stats.pages.to_string()),
                    "NUMBEROFUSERS" => format_number_fi(&stats.users.to_string()),
                    "NUMBEROFFILES" => format_number_fi(&stats.images.to_string()),
                    "NUMBEROFEDITS" => format_number_fi(&stats.edits.to_string()),
                    "NUMBEROFACTIVEUSERS" => format_number_fi(&stats.active_users.to_string()),
                    _ => String::new(),
                }
            }
            _ => return None,
        };
        Some(value)
    }

    fn site_stats(&self) -> SiteStats {
        if let Some(stats) = self.ctx.cache.stats.get(&()) {
            return stats;
        }
        let stats = self.ctx.resolver.site_stats();
        self.ctx.cache.stats.put((), stats);
        stats
    }

    fn parser_function(&mut self, name: &str, parts: &[String], depth: usize) -> Option<String> {
        // Only used when config.enable_parser_functions is true. The default
        // configuration mirrors a wiki that loads the ParserFunctions
        // extension.
        //
        // The function name and its first argument share the template name:
        // `{{#if:cond|then|else}}` splits into the function `#if`, the inline
        // argument `cond` and the remaining parts `then` and `else`. Treating
        // the whole `#if:cond` as the function name (as the source parser did)
        // never matches an arm, so the colon is split here.
        let (function, inline_argument) = match name.split_once(':') {
            Some((function, argument)) => (function.trim(), Some(argument)),
            None => (name.trim(), None),
        };
        let mut args: Vec<String> = Vec::new();
        if let Some(argument) = inline_argument {
            args.push(self.expand_templates(argument, depth + 1));
        }
        args.extend(
            parts
                .iter()
                .skip(1)
                .map(|part| self.expand_templates(part, depth + 1)),
        );
        match function.to_ascii_lowercase().as_str() {
            "#if" => Some(
                if args.first().is_some_and(|value| !value.trim().is_empty()) {
                    args.get(1).cloned().unwrap_or_default()
                } else {
                    args.get(2).cloned().unwrap_or_default()
                },
            ),
            "#ifeq" => {
                let left = args.first().map(|value| value.trim()).unwrap_or("");
                let right = args.get(1).map(|value| value.trim()).unwrap_or("");
                Some(if left == right {
                    args.get(2).cloned().unwrap_or_default()
                } else {
                    args.get(3).cloned().unwrap_or_default()
                })
            }
            "#switch" => {
                let value = args.first().map(|value| value.trim()).unwrap_or("");
                let mut default = String::new();
                let mut index = 1;
                while index < args.len() {
                    let case = args[index].trim();
                    if let Some((key, result)) = case.split_once('=') {
                        if key.trim() == "#default" {
                            default = result.trim().to_string();
                        } else if key.trim() == value {
                            return Some(result.trim().to_string());
                        }
                    } else if index + 1 < args.len() {
                        if case == value {
                            return Some(args[index + 1].clone());
                        }
                        index += 1;
                    } else if case == "#default" {
                        default = String::new();
                    } else {
                        default = case.to_string();
                    }
                    index += 1;
                }
                Some(default)
            }
            "#ifexist" => {
                let Some(title) = args
                    .first()
                    .and_then(|value| Title::parse(value.trim(), self.namespaces()))
                else {
                    return Some(String::new());
                };
                let exists = self.page_flags(&title).exists;
                Some(if exists {
                    args.get(1).cloned().unwrap_or_default()
                } else {
                    args.get(2).cloned().unwrap_or_default()
                })
            }
            "#expr" => {
                let expression = args.first().cloned().unwrap_or_default();
                Some(
                    eval_expr(&expression)
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                )
            }
            "#len" => Some(
                args.first()
                    .map(|value| value.chars().count())
                    .unwrap_or(0)
                    .to_string(),
            ),
            "#sub" => {
                let text = args.first().cloned().unwrap_or_default();
                let start: usize = args
                    .get(1)
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                let length: Option<usize> = args.get(2).and_then(|value| value.trim().parse().ok());
                let characters: Vec<char> = text.chars().collect();
                let end = length
                    .map(|length| start.saturating_add(length).min(characters.len()))
                    .unwrap_or(characters.len());
                Some(characters.get(start..end).unwrap_or(&[]).iter().collect())
            }
            _ => None,
        }
    }

    fn page_flags(&mut self, title: &Title) -> PageFlags {
        let key = (title.ns, title.db_title());
        if let Some(flags) = self.state.exists_cache.get(&key) {
            return *flags;
        }
        if let Some(flags) = self.ctx.cache.pages.get(&key) {
            self.state.exists_cache.insert(key, flags);
            return flags;
        }
        let flags = self.ctx.resolver.page_flags(title.ns, &title.db_title());
        self.state.exists_cache.insert(key.clone(), flags);
        self.ctx.cache.pages.put(key, flags);
        flags
    }

    fn prefetch_link_existence(&mut self, text: &str) {
        let mut wanted: Vec<TitleKey> = Vec::new();
        let mut seen: HashSet<TitleKey> = HashSet::new();
        let bytes = text.as_bytes();
        let mut index = 0;
        while index + 1 < bytes.len() {
            if bytes[index] == b'[' && bytes[index + 1] == b'[' {
                if self.state.scan_budget == 0 {
                    break;
                }
                if let Some(close) = find_link_end(&text[index..]) {
                    self.state.scan_budget = self.state.scan_budget.saturating_sub(close + 2);
                    let inner = &text[index + 2..index + close];
                    let target = split_top_level(inner, '|')
                        .first()
                        .cloned()
                        .unwrap_or_default();
                    let target = target.trim().trim_start_matches(':');
                    if !target.is_empty()
                        && !target.starts_with('#')
                        && !target.starts_with("http://")
                        && !target.starts_with("https://")
                    {
                        if let Some(title) = Title::parse(target, self.namespaces()) {
                            if title.ns >= 0 {
                                let key = (title.ns, title.db_title());
                                if seen.insert(key.clone())
                                    && self.ctx.cache.pages.get(&key).is_none()
                                {
                                    wanted.push(key);
                                }
                            }
                        }
                    }
                    index += close + 2;
                    continue;
                }
                self.state.scan_budget = self.state.scan_budget.saturating_sub(text.len() - index);
            }
            index += 1;
        }
        if wanted.is_empty() {
            return;
        }
        for (key, flags) in self.ctx.resolver.existing_titles(&wanted) {
            self.state.exists_cache.insert(key.clone(), flags);
            self.ctx.cache.pages.put(key, flags);
        }
    }

    fn file_info(&self, name_db: &str) -> Option<FileInfo> {
        if let Some(value) = self.ctx.cache.files.get(&name_db.to_string()) {
            return value;
        }
        let value = self.ctx.resolver.file_info(name_db);
        self.ctx.cache.files.put(name_db.to_string(), value.clone());
        value
    }

    // --------------------------------------------------------------- blocks

    fn build_toc(&self) -> String {
        if self.state.headings.is_empty() {
            return String::new();
        }
        let mut index = 0;
        let first_level = self.state.headings[0].level;
        let mut section = 1usize;
        let list = self.build_toc_level(&mut index, first_level, &mut section);
        let mut out = String::new();
        out.push_str(
            "<div id=\"toc\" class=\"toc\" role=\"navigation\" aria-labelledby=\"mw-toc-heading\">",
        );
        out.push_str("<input type=\"checkbox\" role=\"button\" id=\"toctogglecheckbox\" class=\"toctogglecheckbox\" style=\"display:none\" />");
        out.push_str("<div class=\"toctitle\" lang=\"");
        out.push_str(&escape_html(&self.ctx.config.language));
        out.push_str("\" dir=\"ltr\"><h2 id=\"mw-toc-heading\">");
        out.push_str(&escape_html(&self.msg("toc")));
        out.push_str("</h2><span class=\"toctogglespan\"><label class=\"toctogglelabel\" for=\"toctogglecheckbox\"></label></span></div>");
        out.push_str(&list);
        out.push_str("</div>");
        out
    }

    fn build_toc_level(&self, index: &mut usize, level: u8, section: &mut usize) -> String {
        let mut out = String::from("<ul>");
        while *index < self.state.headings.len() {
            let heading = &self.state.headings[*index];
            if heading.level != level {
                break;
            }
            out.push_str(&format!(
                "<li class=\"toclevel-{} tocsection-{}\"><a href=\"#{}\"><span class=\"tocnumber\">{}</span> <span class=\"toctext\">{}</span></a>",
                level.saturating_sub(1),
                *section,
                escape_html(&heading.id),
                escape_html(&heading.number),
                escape_html(&heading.text)
            ));
            *index += 1;
            *section += 1;
            if *index < self.state.headings.len() && self.state.headings[*index].level > level {
                let next_level = self.state.headings[*index].level;
                out.push_str(&self.build_toc_level(index, next_level, section));
            }
            out.push_str("</li>");
        }
        out.push_str("</ul>");
        out
    }

    fn parse_blocks(&mut self, text: &str) -> String {
        if self.state.block_depth >= MAX_BLOCK_DEPTH {
            return self.inline(text);
        }
        self.state.block_depth += 1;
        let lines: Vec<&str> = text.split('\n').collect();
        let out = self.parse_lines(&lines);
        self.state.block_depth -= 1;
        out
    }

    fn parse_lines(&mut self, lines: &[&str]) -> String {
        let mut out = String::with_capacity(lines.len() * 32);
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            if line.trim().is_empty() {
                index += 1;
                continue;
            }
            if line.trim() == TOC_MARKER {
                out.push_str(TOC_MARKER);
                out.push('\n');
                index += 1;
                continue;
            }
            if let Some((level, title)) = parse_heading(line) {
                self.push_heading(&mut out, level, &title);
                index += 1;
                continue;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("{|") {
                let (html, next) = self.parse_table(lines, index);
                out.push_str(&html);
                index = next;
                continue;
            }
            if is_list_line(line) {
                let (html, next) = self.parse_list(lines, index);
                out.push_str(&html);
                index = next;
                continue;
            }
            if trimmed.starts_with("----") && is_hr(trimmed) {
                out.push_str("<hr />\n");
                index += 1;
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                let mut pre = String::new();
                while index < lines.len()
                    && (lines[index].starts_with(' ') || lines[index].starts_with('\t'))
                    && !lines[index].trim().is_empty()
                {
                    pre.push_str(&lines[index][1..]);
                    pre.push('\n');
                    index += 1;
                }
                out.push_str("<pre>");
                out.push_str(&escape_html(&pre));
                out.push_str("</pre>\n");
                continue;
            }
            if starts_tag(trimmed, "pre") {
                let (html, next) = self.parse_pre_tag(lines, index);
                out.push_str(&html);
                index = next;
                continue;
            }
            if starts_tag(trimmed, "gallery") {
                let (html, next) = self.parse_gallery(lines, index);
                out.push_str(&html);
                index = next;
                continue;
            }
            if starts_tag(trimmed, "references") {
                let (html, next) = self.parse_references_tag(lines, index);
                out.push_str(&html);
                index = next;
                continue;
            }
            if is_block_html_line(trimmed) {
                out.push_str(&self.inline(trimmed));
                out.push('\n');
                index += 1;
                continue;
            }
            // Paragraph: gather until a blank line or a block construct.
            let mut paragraph = String::new();
            while index < lines.len() {
                let current = lines[index];
                if current.trim().is_empty() || is_block_boundary(current) {
                    break;
                }
                if !paragraph.is_empty() {
                    paragraph.push('\n');
                }
                paragraph.push_str(current);
                index += 1;
            }
            if paragraph.is_empty() {
                index += 1;
                continue;
            }
            let rendered = self.inline(&paragraph);
            let trimmed = rendered.trim();
            if trimmed.is_empty() {
                // Categories, magic words and empty templates produce no
                // visible paragraph in MediaWiki either.
            } else if trimmed == "<br />" || trimmed == "<br>" || trimmed == "<br/>" {
                out.push_str("<br />\n");
            } else {
                let mut rest = rendered.as_str();
                let mut emitted_block = false;
                while rest.starts_with("<div class=\"thumb") {
                    if let Some(end) = leading_div_len(rest) {
                        out.push_str(&rest[..end]);
                        out.push('\n');
                        rest = &rest[end..];
                        emitted_block = true;
                    } else {
                        break;
                    }
                }
                if !rest.trim().is_empty() {
                    let rest = rest.trim_start_matches('\n');
                    out.push_str("<p>");
                    out.push_str(rest);
                    out.push_str("</p>\n");
                } else if !emitted_block {
                    out.push_str("<p>");
                    out.push_str(rest);
                    out.push_str("</p>\n");
                }
            }
        }
        out
    }

    fn push_heading(&mut self, out: &mut String, level: u8, title: &str) {
        if !self.state.toc_placed && !self.state.no_toc && !self.state.toc_explicit {
            out.push_str(TOC_MARKER);
            out.push('\n');
            self.state.toc_placed = true;
            self.state.toc_auto = true;
        }
        let inline = self.inline(title);
        let plain = strip_tags(&inline);
        let base = sanitize_anchor(&plain);
        let html5 = anchor_html5(&plain);
        let mut id = base.clone();
        let mut suffix = 2;
        while self.state.heading_ids.contains(&id) {
            id = format!("{base}_{suffix}");
            suffix += 1;
        }
        self.state.heading_ids.insert(id.clone());
        let heading_level = level.clamp(1, 6) as usize;
        self.state.heading_counters[heading_level] += 1;
        for counter in (heading_level + 1)..=6 {
            self.state.heading_counters[counter] = 0;
        }
        let number = self
            .state
            .heading_counters
            .iter()
            .skip(1)
            .take(heading_level)
            .filter(|value| **value > 0)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(".");
        self.state.headings.push(Heading {
            level: heading_level as u8,
            id: id.clone(),
            text: plain.clone(),
            number,
        });
        let prefix = if html5 == id {
            String::new()
        } else {
            format!("<span id=\"{}\"></span>", escape_html(&html5))
        };
        let section = if self.state.template_stack.is_empty() {
            self.state.source_section += 1;
            Some(self.state.source_section)
        } else {
            None
        };
        let edit = if self.state.no_edit_section {
            String::new()
        } else {
            section
                .map(|section| {
                    let mut href = self
                        .ctx
                        .title
                        .local_url(self.ctx.config, self.namespaces());
                    href.push(if href.contains('?') { '&' } else { '?' });
                    href.push_str(&format!("action=edit&section={section}"));
                    let label = self.ctx.formatter.text("editsection");
                    let hint = self
                        .ctx
                        .formatter
                        .format("editsectionhint", &[&plain]);
                    format!(
                        "<span class=\"mw-editsection\">[<a href=\"{}\" title=\"{}\">{}</a>]</span>",
                        escape_html(&href),
                        escape_html(&hint),
                        escape_html(&label)
                    )
                })
                .unwrap_or_default()
        };
        out.push_str(&format!(
            "<h{heading_level}>{prefix}<span class=\"mw-headline\" id=\"{}\">{inline}</span>{edit}</h{heading_level}>\n",
            escape_html(&id)
        ));
    }

    fn parse_list(&mut self, lines: &[&str], start: usize) -> (String, usize) {
        let mut items: Vec<(String, String)> = Vec::new();
        let mut index = start;
        while index < lines.len() {
            let line = lines[index];
            if line.trim().is_empty() || !is_list_line(line) {
                break;
            }
            let marker_count = line
                .chars()
                .take_while(|character| matches!(character, '*' | '#' | ';' | ':'))
                .count();
            let depth = marker_count.min(MAX_LIST_DEPTH);
            let prefix: String = line.chars().take(depth).collect();
            let consumed: usize = line.chars().take(marker_count).map(char::len_utf8).sum();
            let content = line[consumed..].trim_start().to_string();
            items.push((prefix, content));
            index += 1;
        }
        let mut position = 0;
        let mut html = String::new();
        if !items.is_empty() {
            html = self.render_list_level(&items, &mut position, 0, "");
        }
        (html, index)
    }

    fn render_list_level(
        &mut self,
        items: &[(String, String)],
        position: &mut usize,
        depth: usize,
        parent: &str,
    ) -> String {
        let mut out = String::new();
        let mut open: Option<char> = None;
        while *position < items.len() {
            let (prefix, content) = &items[*position];
            if prefix.len() <= depth || !prefix.starts_with(parent) {
                break;
            }
            let marker = prefix.as_bytes()[depth] as char;
            let tag = match marker {
                '*' => 'u',
                '#' => 'o',
                ';' | ':' => 'd',
                _ => break,
            };
            if open != Some(tag) {
                if let Some(previous) = open {
                    out.push_str(match previous {
                        'u' => "</ul>",
                        'o' => "</ol>",
                        _ => "</dl>",
                    });
                }
                out.push_str(match tag {
                    'u' => "<ul>",
                    'o' => "<ol>",
                    _ => "<dl>",
                });
                open = Some(tag);
            }
            if prefix.len() > depth + 1 {
                // The item starts deeper than this level. Open an empty item
                // and recurse instead of dropping it; the marker cap keeps the
                // recursion bounded.
                let wrapper = match marker {
                    ';' => "dt",
                    ':' => "dd",
                    _ => "li",
                };
                out.push_str(&format!("<{wrapper}>"));
                let nested =
                    self.render_list_level(items, position, depth + 1, &prefix[..depth + 1]);
                out.push_str(&nested);
                out.push_str(&format!("</{wrapper}>"));
                continue;
            }
            *position += 1;
            match marker {
                ';' => {
                    let (term, definition) = split_term_definition(content);
                    out.push_str("<dt>");
                    out.push_str(&self.inline(&term));
                    out.push_str("</dt>");
                    if let Some(definition) = definition {
                        out.push_str("<dd>");
                        out.push_str(&self.inline(&definition));
                        out.push_str("</dd>");
                    }
                }
                ':' => {
                    out.push_str("<dd>");
                    out.push_str(&self.inline(content));
                    out.push_str("</dd>");
                }
                _ => {
                    out.push_str("<li>");
                    out.push_str(&self.inline(content));
                    let this_prefix = prefix.clone();
                    if *position < items.len()
                        && items[*position].0.len() > depth + 1
                        && items[*position].0.starts_with(&this_prefix)
                    {
                        let nested =
                            self.render_list_level(items, position, depth + 1, &this_prefix);
                        out.push_str(&nested);
                    }
                    out.push_str("</li>");
                }
            }
        }
        if let Some(previous) = open {
            out.push_str(match previous {
                'u' => "</ul>",
                'o' => "</ol>",
                _ => "</dl>",
            });
        }
        out
    }

    fn parse_table(&mut self, lines: &[&str], start: usize) -> (String, usize) {
        let first = lines[start].trim_start();
        let attrs = sanitize_attrs(first.trim_start_matches("{|").trim());
        let mut table = TableData {
            attrs,
            caption: None,
            rows: Vec::new(),
        };
        let mut index = start + 1;
        let mut current_row: Option<TableRow> = None;
        let mut current_cell: Option<TableCell> = None;
        let mut nested = 0usize;
        while index < lines.len() {
            let line = lines[index];
            let trimmed = line.trim_start();
            if nested == 0 && trimmed.starts_with("|}") {
                close_cell(&mut current_row, &mut current_cell);
                if let Some(row) = current_row.take() {
                    if !row.cells.is_empty() {
                        table.rows.push(row);
                    }
                }
                index += 1;
                break;
            }
            if trimmed.starts_with("{|") {
                if nested >= MAX_TABLE_NESTING {
                    if let Some(cell) = current_cell.as_mut() {
                        if !cell.content.is_empty() {
                            cell.content.push('\n');
                        }
                        cell.content.push_str(line);
                    }
                    index += 1;
                    continue;
                }
                nested += 1;
                if let Some(cell) = current_cell.as_mut() {
                    if !cell.content.is_empty() {
                        cell.content.push('\n');
                    }
                    cell.content.push_str(line);
                }
                index += 1;
                continue;
            }
            if trimmed.starts_with("|}") && nested > 0 {
                nested -= 1;
                if let Some(cell) = current_cell.as_mut() {
                    if !cell.content.is_empty() {
                        cell.content.push('\n');
                    }
                    cell.content.push_str(line);
                }
                index += 1;
                continue;
            }
            if nested > 0 {
                if let Some(cell) = current_cell.as_mut() {
                    if !cell.content.is_empty() {
                        cell.content.push('\n');
                    }
                    cell.content.push_str(line);
                }
                index += 1;
                continue;
            }
            if trimmed.starts_with("|-") {
                close_cell(&mut current_row, &mut current_cell);
                if let Some(row) = current_row.take() {
                    if !row.cells.is_empty() {
                        table.rows.push(row);
                    }
                }
                let row_attrs = sanitize_attrs(trimmed.trim_start_matches("|-").trim());
                current_row = Some(TableRow {
                    attrs: row_attrs,
                    cells: Vec::new(),
                });
                index += 1;
                continue;
            }
            if let Some(caption) = trimmed.strip_prefix("|+") {
                let (caption_attrs, caption_content) = split_cell_attrs(caption.trim());
                table.caption = Some((sanitize_attrs(&caption_attrs), caption_content));
                index += 1;
                continue;
            }
            if trimmed.starts_with('|') || trimmed.starts_with('!') {
                close_cell(&mut current_row, &mut current_cell);
                if current_row.is_none() {
                    current_row = Some(TableRow {
                        attrs: String::new(),
                        cells: Vec::new(),
                    });
                }
                let header = trimmed.starts_with('!');
                let body = &trimmed[1..];
                let segments = split_table_cells(body);
                for segment in &segments {
                    let (attrs, content) = split_cell_attrs(segment);
                    let cell = TableCell {
                        header,
                        attrs: sanitize_attrs(&attrs),
                        content,
                    };
                    if let Some(cell) = current_cell.take() {
                        if let Some(row) = current_row.as_mut() {
                            row.cells.push(cell);
                        }
                    }
                    current_cell = Some(cell);
                }
                index += 1;
                continue;
            }
            // Continuation of the current cell.
            if let Some(cell) = current_cell.as_mut() {
                if !cell.content.is_empty() {
                    cell.content.push('\n');
                }
                cell.content.push_str(line);
                index += 1;
                continue;
            }
            index += 1;
        }
        close_cell(&mut current_row, &mut current_cell);
        if let Some(row) = current_row.take() {
            if !row.cells.is_empty() {
                table.rows.push(row);
            }
        }
        (self.render_table(&table), index)
    }

    fn render_table(&mut self, table: &TableData) -> String {
        let mut out = format!("<table{}><tbody>\n", table.attrs);
        if let Some((attrs, caption)) = &table.caption {
            out.push_str(&format!(
                "<caption{}>{}</caption>\n",
                attrs,
                self.inline(caption)
            ));
        }
        for row in &table.rows {
            out.push_str(&format!("<tr{}>", row.attrs));
            for cell in &row.cells {
                let tag = if cell.header { "th" } else { "td" };
                out.push_str(&format!("<{tag}{}>", cell.attrs));
                let content = cell.content.trim_start();
                if content.contains('\n') {
                    if content.starts_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&self.parse_blocks(content));
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                } else {
                    out.push_str(&self.inline(content));
                    if !content.ends_with('\n') {
                        out.push('\n');
                    }
                }
                out.push_str(&format!("</{tag}>"));
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table>\n");
        out
    }

    fn parse_pre_tag(&mut self, lines: &[&str], start: usize) -> (String, usize) {
        let mut index = start;
        let mut inner = String::new();
        let open = lines[index].trim_start();
        let attrs = open
            .split_once('>')
            .map(|(attrs, _)| attrs.trim_start_matches("<pre").trim())
            .unwrap_or("");
        let attrs = sanitize_attrs(attrs);
        let mut first = true;
        while index < lines.len() {
            let line = lines[index];
            if first {
                if let Some((_, rest)) = line.split_once('>') {
                    inner.push_str(rest);
                }
                first = false;
            } else {
                inner.push('\n');
                inner.push_str(line);
            }
            if line.to_ascii_lowercase().contains("</pre>") {
                let position = inner
                    .to_ascii_lowercase()
                    .find("</pre>")
                    .unwrap_or(inner.len());
                inner.truncate(position);
                index += 1;
                break;
            }
            index += 1;
        }
        (
            format!("<pre{attrs}>{}</pre>\n", escape_html(&inner)),
            index,
        )
    }

    fn parse_gallery(&mut self, lines: &[&str], start: usize) -> (String, usize) {
        let mut items: Vec<(String, String)> = Vec::new();
        let mut width = 120u32;
        if let Some(gt) = lines[start].find('>') {
            let options = &lines[start][..gt];
            for part in options.split_whitespace() {
                if let Some(value) = part.strip_prefix("widths=") {
                    if let Some(width_text) = value
                        .trim_end_matches('"')
                        .trim_start_matches('"')
                        .split('p')
                        .next()
                    {
                        width = width_text.parse().unwrap_or(120).clamp(1, MAX_IMAGE_WIDTH);
                    }
                }
            }
            let rest = &lines[start][gt + 1..];
            if !rest.trim().is_empty() {
                if let Some((name, caption)) = rest.split_once('|') {
                    items.push((name.trim().to_string(), caption.trim().to_string()));
                }
            }
        }
        let mut index = start + 1;
        while index < lines.len() {
            let trimmed = lines[index].trim();
            if trimmed.to_ascii_lowercase().starts_with("</gallery") {
                index += 1;
                break;
            }
            if !trimmed.is_empty() {
                if let Some((name, caption)) = trimmed.split_once('|') {
                    items.push((name.trim().to_string(), caption.trim().to_string()));
                } else {
                    items.push((trimmed.to_string(), String::new()));
                }
            }
            index += 1;
        }
        let mut out = String::from("<ul class=\"gallery mw-gallery-traditional\">\n");
        for (raw_name, caption) in items {
            let name = gallery_file_name(&raw_name, self.namespaces());
            let name_db = name.replace(' ', "_");
            let Some(info) = self.file_info(&name_db) else {
                continue;
            };
            let title = Title::new(6, &name);
            let href = title.local_url(self.ctx.config, self.namespaces());
            let (display_width, display_height) = scaled_size(&info, width);
            out.push_str(&format!(
                "<li class=\"gallerybox\" style=\"width: {}px\"><div class=\"thumb\" style=\"width: {}px;\"><div style=\"margin:auto;\"><a class=\"image\" href=\"{}\"><img alt=\"{}\" src=\"{}\" width=\"{}\" height=\"{}\" /></a></div></div><div class=\"gallerytext\">{}</div></li>\n",
                width + 35,
                width,
                escape_html(&href),
                escape_html(&name),
                escape_html(&self.image_url(&info, width)),
                display_width,
                display_height,
                self.inline(&caption)
            ));
        }
        out.push_str("</ul>\n");
        (out, index)
    }

    fn parse_references_tag(&mut self, lines: &[&str], start: usize) -> (String, usize) {
        let line = lines[start].trim();
        let group = parse_tag_attr(line, "group").unwrap_or_default();
        (
            format!("{REFS_PREFIX}{}{REFS_SUFFIX}", escape_html(&group)),
            start + 1,
        )
    }

    // ---------------------------------------------------------------- inline

    fn inline(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len() + 32);
        let mut index = 0;
        let mut bold = false;
        let mut italic = false;
        while index < text.len() {
            let rest = &text[index..];
            if rest.starts_with(TOC_MARKER) {
                let marker = self.toc_placeholder();
                out.push_str(&marker);
                index += TOC_MARKER.len();
                continue;
            }
            if rest.starts_with(NOWIKI_MARKER) {
                if let Some(end) = rest[NOWIKI_MARKER.len_utf8()..].find(NOWIKI_MARKER) {
                    let length = NOWIKI_MARKER.len_utf8() + end + NOWIKI_MARKER.len_utf8();
                    out.push_str(&rest[..length]);
                    index += length;
                    continue;
                }
            }
            if let Some(comment) = rest.strip_prefix("<!--") {
                if let Some(end) = comment.find("-->") {
                    index += 4 + end + 3;
                    continue;
                }
                break;
            }
            if rest.starts_with("[[") && self.state.scan_budget > 0 {
                // A missing `]]` is the expensive case: the scanner would walk
                // the whole rest of the page. Check for one first, then let
                // the real scanner handle nesting.
                match rest.find("]]") {
                    Some(end) => {
                        self.state.scan_budget = self.state.scan_budget.saturating_sub(end + 2);
                        if let Some((html, consumed)) = self.wiki_link(rest) {
                            out.push_str(&html);
                            index += consumed;
                            continue;
                        }
                    }
                    None => {
                        self.state.scan_budget = self.state.scan_budget.saturating_sub(rest.len());
                    }
                }
            }
            if rest.starts_with("<ref") && is_tag_start(rest, "ref") {
                if let Some((html, consumed)) = self.cite_ref(rest) {
                    out.push_str(&html);
                    index += consumed;
                    continue;
                }
            }
            if is_tag_start(rest, "references") || rest.starts_with("</references") {
                if rest.starts_with("</references") {
                    if let Some(end) = rest.find('>') {
                        index += end + 1;
                        continue;
                    }
                }
                if let Some(end) = rest.find('>') {
                    let tag = &rest[..=end];
                    let group = parse_tag_attr(tag, "group").unwrap_or_default();
                    out.push_str(REFS_PREFIX);
                    out.push_str(&escape_html(&group));
                    out.push_str(REFS_SUFFIX);
                    index += end + 1;
                    continue;
                }
            }
            if rest.starts_with('<') {
                if let Some((html, consumed)) = self.raw_tag(rest) {
                    out.push_str(&html);
                    index += consumed;
                    continue;
                }
                out.push_str("&lt;");
                index += 1;
                continue;
            }
            // Apostrophe formatting. Five marks is bold+italic, four is bold
            // plus a literal apostrophe, as in MediaWiki.
            if rest.starts_with('\'') {
                // Count at most five marks: a run of ten thousand apostrophes
                // must be consumed five at a time, not recounted from every
                // offset.
                let run = rest
                    .chars()
                    .take(5)
                    .take_while(|character| *character == '\'')
                    .count();
                if run >= 5 {
                    let (want_bold, want_italic) = (!bold, !italic);
                    self.set_format(&mut out, &mut bold, &mut italic, want_bold, want_italic);
                    index += 5;
                    continue;
                }
                if run == 4 {
                    let want_bold = !bold;
                    let want_italic = italic;
                    self.set_format(&mut out, &mut bold, &mut italic, want_bold, want_italic);
                    out.push('\'');
                    index += 4;
                    continue;
                }
                if run == 3 {
                    let want_bold = !bold;
                    let want_italic = italic;
                    self.set_format(&mut out, &mut bold, &mut italic, want_bold, want_italic);
                    index += 3;
                    continue;
                }
                if run == 2 {
                    let want_bold = bold;
                    let want_italic = !italic;
                    self.set_format(&mut out, &mut bold, &mut italic, want_bold, want_italic);
                    index += 2;
                    continue;
                }
            }
            if rest.starts_with('[') && !rest.starts_with("[[") {
                if let Some((html, consumed)) = self.external_link(rest) {
                    out.push_str(&html);
                    index += consumed;
                    continue;
                }
            }
            if rest.starts_with("http://")
                || rest.starts_with("https://")
                || rest.starts_with("ftp://")
                || rest.starts_with("mailto:")
            {
                if let Some((html, consumed)) = self.free_link(rest) {
                    out.push_str(&html);
                    index += consumed;
                    continue;
                }
            }
            if rest.starts_with("{{") {
                // Unresolved template/parameter left after expansion.
                out.push_str("{{");
                index += 2;
                continue;
            }
            let character = rest.chars().next().unwrap_or(' ');
            if character == '&' {
                if let Some((entity, length)) = parse_entity(rest) {
                    out.push_str(&entity);
                    index += length;
                    continue;
                }
                out.push_str("&amp;");
                index += 1;
                continue;
            }
            match character {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                _ => out.push(character),
            }
            index += character.len_utf8();
        }
        self.set_format(&mut out, &mut bold, &mut italic, false, false);
        out
    }

    fn set_format(
        &self,
        out: &mut String,
        bold: &mut bool,
        italic: &mut bool,
        want_bold: bool,
        want_italic: bool,
    ) {
        // Close in reverse order so `<b><i>...</i></b>` stays well nested.
        if *italic && !want_italic {
            out.push_str("</i>");
            *italic = false;
        }
        if *bold && !want_bold {
            out.push_str("</b>");
            *bold = false;
        }
        if !*bold && want_bold {
            out.push_str("<b>");
            *bold = true;
        }
        if !*italic && want_italic {
            out.push_str("<i>");
            *italic = true;
        }
    }

    fn wiki_link(&mut self, rest: &str) -> Option<(String, usize)> {
        let close = find_link_end(rest)?;
        let inner = &rest[2..close];
        let consumed = close + 2;
        if inner.is_empty() {
            return None;
        }
        let parts = split_top_level(inner, '|');
        let target_raw = parts.first()?.trim();
        if target_raw.is_empty() {
            return None;
        }
        let force_link = target_raw.starts_with(':');
        let target_clean = target_raw.trim_start_matches(':').trim();
        // External image / file URL.
        if target_clean.starts_with("http://") || target_clean.starts_with("https://") {
            if self.external_images_allowed(target_clean) && looks_like_image(target_clean) {
                let label = parts.get(1).map(String::as_str).unwrap_or("");
                return Some((
                    format!(
                        "<img src=\"{}\" alt=\"{}\" />",
                        escape_html(target_clean),
                        escape_html(label)
                    ),
                    consumed,
                ));
            }
            return None;
        }
        if target_clean.starts_with('#') {
            let fragment = target_clean.trim_start_matches('#');
            let label = parts
                .get(1)
                .filter(|value| !value.is_empty())
                .cloned()
                .unwrap_or_else(|| fragment.to_string());
            return Some((
                format!(
                    "<a href=\"#{}\">{}</a>",
                    escape_html(&sanitize_anchor(fragment)),
                    self.inline(&label)
                ),
                consumed,
            ));
        }
        let title = Title::parse(target_clean, self.namespaces())?;
        if title.is_category() && !force_link {
            if self.state.categories.len() < MAX_CATEGORIES {
                let sortkey = parts.get(1).cloned().unwrap_or_default();
                self.state.categories.push(Category {
                    name: title.text.clone(),
                    sortkey,
                });
            }
            return Some((String::new(), consumed));
        }
        if title.is_file() && !force_link {
            let html = self.render_image(&title, &parts[1..]);
            return Some((html, consumed));
        }
        if title.ns == -2 && !force_link {
            // Media: link to the original file.
            let name = title.db_title();
            let Some(info) = self.file_info(&name) else {
                return Some((self.red_link(&title, None), consumed));
            };
            let label = parts.get(1).cloned().unwrap_or_else(|| title.text.clone());
            let href = self.file_url(&info);
            return Some((
                format!(
                    "<a href=\"{}\" class=\"internal\">{}</a>",
                    escape_html(&href),
                    self.inline(&label)
                ),
                consumed,
            ));
        }

        let full = title.full_text(self.namespaces());
        let mut label = parts.get(1).cloned();
        if let Some(value) = &label {
            if value.is_empty() {
                label = Some(pipe_trick(&title));
            }
        }
        let mut label_str = label.unwrap_or_else(|| match &title.fragment {
            Some(fragment) => format!("{full}#{fragment}"),
            None => full.clone(),
        });
        // Link trails: [[Naruto]]n links "Naruto" and displays "Naruton".
        // MediaWiki applies the trail to plain and piped labels.
        let mut trail = 0usize;
        for character in rest[consumed..].chars() {
            if is_link_trail_char(character) {
                trail += character.len_utf8();
                label_str.push(character);
            } else {
                break;
            }
        }
        let flags = if title.is_special() {
            PageFlags::new(true, false)
        } else {
            self.page_flags(&title)
        };
        let is_self = title.ns == self.ctx.title.ns
            && title.db_title() == self.ctx.title.db_title()
            && title.fragment.is_none();
        if is_self {
            return Some((
                format!(
                    "<a class=\"mw-selflink selflink\">{}</a>",
                    self.inline(&label_str)
                ),
                consumed + trail,
            ));
        }
        let href = title.local_url(self.ctx.config, self.namespaces());
        let href = if flags.exists {
            href
        } else {
            format!(
                "{}/index.php?title={}&action=edit&redlink=1",
                self.ctx.config.script_root(),
                encode_title(&full)
            )
        };
        let title_attr = if flags.exists {
            full.clone()
        } else {
            self.msg_args("red-link-title", &[&full])
        };
        let class = if !flags.exists {
            " class=\"new\"".to_string()
        } else if flags.redirect {
            " class=\"mw-redirect\"".to_string()
        } else {
            String::new()
        };
        Some((
            format!(
                "<a href=\"{}\"{} title=\"{}\">{}</a>",
                escape_html(&href),
                class,
                escape_html(&title_attr),
                self.inline(&label_str)
            ),
            consumed + trail,
        ))
    }

    fn red_link(&mut self, title: &Title, label: Option<&str>) -> String {
        let full = title.full_text(self.namespaces());
        let href = format!(
            "{}/index.php?title={}&action=edit&redlink=1",
            self.ctx.config.script_root(),
            encode_title(&full)
        );
        let text = label.unwrap_or(&full).to_string();
        format!(
            "<a href=\"{}\" class=\"new\" title=\"{}\">{}</a>",
            escape_html(&href),
            escape_html(&self.msg_args("red-link-title", &[&full])),
            self.inline(&text)
        )
    }

    fn render_image(&mut self, title: &Title, options: &[String]) -> String {
        let name_db = title.db_title();
        let Some(info) = self.file_info(&name_db) else {
            return self.red_link(title, None);
        };
        let mut thumb = false;
        let mut frame = false;
        let mut align = "right";
        let mut width: Option<u32> = None;
        let mut height: Option<u32> = None;
        let mut alt = String::new();
        let mut alt_explicit = false;
        let mut link_option: Option<String> = None;
        let mut caption = String::new();
        let mut last_plain = String::new();
        for option in options {
            let option = option.trim();
            let lower = option.to_ascii_lowercase();
            match lower.as_str() {
                "thumb" | "thumbnail" | "mini" | "miniatuur" => thumb = true,
                "frame" | "framed" | "frameen" | "kader" => frame = true,
                "frameless" => thumb = true,
                "left" | "links" => align = "left",
                "right" | "rechts" => align = "right",
                "center" | "centre" | "mittig" => align = "center",
                "none" => align = "none",
                "border" | "rand" | "upright" => {}
                _ => {
                    if lower.starts_with("alt=") {
                        alt = option[4..].to_string();
                        alt_explicit = true;
                    } else if lower.starts_with("link=") {
                        link_option = Some(option[5..].to_string());
                    } else if let Some(upright) = lower.strip_prefix("upright=") {
                        if let Ok(scale) = upright.parse::<f64>() {
                            width = Some(((220.0 * scale) as u32).clamp(1, MAX_IMAGE_WIDTH));
                        }
                    } else if lower.ends_with("px") {
                        let dimensions = &lower[..lower.len() - 2];
                        if let Some((width_text, height_text)) = dimensions.split_once('x') {
                            width = width_text
                                .parse()
                                .ok()
                                .map(|value: u32| value.clamp(1, MAX_IMAGE_WIDTH));
                            height = height_text
                                .parse()
                                .ok()
                                .map(|value: u32| value.clamp(1, MAX_IMAGE_WIDTH));
                        } else if let Some(height_text) = dimensions.strip_prefix('x') {
                            height = height_text
                                .parse()
                                .ok()
                                .map(|value: u32| value.clamp(1, MAX_IMAGE_WIDTH));
                        } else if let Ok(width_value) = dimensions.parse::<u32>() {
                            width = Some(width_value.clamp(1, MAX_IMAGE_WIDTH));
                        }
                    } else if !option.is_empty() {
                        last_plain = option.to_string();
                    }
                }
            }
        }
        if thumb || frame {
            caption = last_plain;
        }
        if !alt_explicit {
            alt = if caption.trim().is_empty() {
                info.name.replace('_', " ")
            } else {
                String::new()
            };
        }
        let default_thumb = 220u32;
        let display_width = if frame {
            info.width.max(1)
        } else if let Some(width) = width {
            width
        } else if thumb {
            default_thumb
        } else {
            info.width.max(1)
        }
        .clamp(1, MAX_IMAGE_WIDTH);
        let (display_w, display_h) = if let Some(height) = height {
            (display_width, height)
        } else {
            scaled_size(&info, display_width)
        };
        let is_resized = width.is_some_and(|width| width < info.width);
        let is_thumb = thumb || frame || is_resized;
        let is_thumbnail = thumb || frame;
        let file_url = self.file_url(&info);
        let use_original = info.width > 0 && display_width >= info.width;
        let src = if is_thumb && !use_original {
            self.image_url(&info, display_width)
        } else {
            file_url.clone()
        };
        let file_page = Title::new(6, title.text.clone());
        let file_href = file_page.local_url(self.ctx.config, self.namespaces());
        let link_html = match link_option.as_deref() {
            Some("") => None,
            Some(url) if url.starts_with("http://") || url.starts_with("https://") => {
                Some(escape_html(url))
            }
            Some(other) => {
                let title = Title::parse(other, self.namespaces());
                title.map(|title| title.local_url(self.ctx.config, self.namespaces()))
            }
            None => Some(file_href.clone()),
        };
        let srcset = if is_thumb && !frame && !use_original {
            let width_15 = ((display_w as f64) * 1.5).round() as u32;
            let width_2 = display_w * 2;
            let url_15 = if width_15 >= info.width {
                file_url.clone()
            } else {
                self.image_url(&info, width_15)
            };
            let url_2 = if width_2 >= info.width {
                file_url.clone()
            } else {
                self.image_url(&info, width_2)
            };
            format!(
                " srcset=\"{} 1.5x, {} 2x\"",
                escape_html(&url_15),
                escape_html(&url_2)
            )
        } else {
            String::new()
        };
        let image = format!(
            "<img alt=\"{}\" src=\"{}\" decoding=\"async\" width=\"{}\" height=\"{}\"{} />",
            escape_html(&alt),
            escape_html(&src),
            display_w,
            display_h,
            if is_thumbnail {
                format!(" class=\"thumbimage\"{srcset}")
            } else {
                srcset
            }
        );
        let linked_image = match link_html {
            Some(href) => format!(
                "<a href=\"{}\" class=\"image\">{}</a>",
                escape_html(&href),
                image
            ),
            None => image,
        };
        if thumb || frame {
            let align_class = match align {
                "left" => " tleft",
                "center" => " center",
                "none" => " none",
                _ => " tright",
            };
            let magnify = format!(
                "<div class=\"magnify\"><a href=\"{}\" class=\"internal\" title=\"{}\"></a></div>",
                escape_html(&file_href),
                escape_html(&self.msg("thumbnail-more"))
            );
            format!(
                "<div class=\"thumb{}\"><div class=\"thumbinner\" style=\"width:{}px;\">{} <div class=\"thumbcaption\">{}{}</div></div></div>",
                align_class,
                display_w + 2,
                linked_image,
                magnify,
                self.inline(&caption)
            )
        } else {
            linked_image
        }
    }

    fn external_link(&mut self, rest: &str) -> Option<(String, usize)> {
        let end = rest.find(']')?;
        let inner = &rest[1..end];
        let consumed = end + 1;
        let (url, label) = match inner.split_once(char::is_whitespace) {
            Some((url, label)) => (url.trim(), label.trim()),
            None => (inner.trim(), ""),
        };
        if !is_external_url(url) {
            return None;
        }
        let label_html = if label.is_empty() {
            escape_html(url)
        } else {
            self.inline(label)
        };
        Some((
            format!(
                "<a rel=\"nofollow\" class=\"external text\" href=\"{}\">{}</a>",
                escape_html(url),
                label_html
            ),
            consumed,
        ))
    }

    fn free_link(&mut self, rest: &str) -> Option<(String, usize)> {
        let mut end = 0;
        for (index, character) in rest.char_indices() {
            if character.is_whitespace() || matches!(character, '<' | '>' | '"' | '[' | ']') {
                break;
            }
            end = index + character.len_utf8();
        }
        if end == 0 {
            return None;
        }
        let mut url = &rest[..end];
        while url.ends_with(['.', ',', ';', ':', '!', '?']) {
            url = &url[..url.len() - 1];
        }
        if !is_external_url(url) {
            return None;
        }
        if self.external_images_allowed(url) && looks_like_image(url) {
            return Some((
                format!("<img src=\"{}\" alt=\"\" />", escape_html(url)),
                url.len(),
            ));
        }
        Some((
            format!(
                "<a rel=\"nofollow\" class=\"external free\" href=\"{}\">{}</a>",
                escape_html(url),
                escape_html(url)
            ),
            url.len(),
        ))
    }

    fn external_images_allowed(&self, url: &str) -> bool {
        let lower = url.to_ascii_lowercase();
        self.ctx
            .config
            .allow_external_images
            .iter()
            .any(|prefix| lower.starts_with(&prefix.to_ascii_lowercase()))
    }

    fn cite_ref(&mut self, rest: &str) -> Option<(String, usize)> {
        let gt = find_tag_end(rest)?;
        let open_tag = &rest[..=gt];
        let self_closing = open_tag.trim_end().ends_with("/>");
        let mut consumed = gt + 1;
        let mut content = String::new();
        if !self_closing {
            let lower = rest.to_ascii_lowercase();
            let close = lower[consumed..].find("</ref>")?;
            content = rest[consumed..consumed + close].to_string();
            consumed += close + "</ref>".len();
        }
        let name = parse_tag_attr(open_tag, "name").unwrap_or_default();
        let group = parse_tag_attr(open_tag, "group").unwrap_or_default();
        let group = sanitize_ref_part(&group);
        let name = sanitize_ref_part(&name);
        if !name.is_empty() {
            if let Some(&index) = self.state.ref_names.get(&(group.clone(), name.clone())) {
                let entry = &self.state.refs[index];
                let key = entry.key.clone();
                let number = entry.number;
                return Some((
                    format!(
                        "<sup id=\"cite_ref-{key}\" class=\"reference\"><a href=\"#cite_note-{key}\">&#91;{number}&#93;</a></sup>"
                    ),
                    consumed,
                ));
            }
            if self_closing {
                let message =
                    self.msg_args("cite_error_references_no_text", &[&escape_html(&name)]);
                return Some((
                    format!(
                        "<span class=\"error\">{}</span>",
                        self.msg_args("cite_error", &[&message])
                    ),
                    consumed,
                ));
            }
        }
        if content.trim().is_empty() {
            let message = self.msg("cite_error_ref_no_input");
            return Some((
                format!(
                    "<span class=\"error\">{}</span>",
                    self.msg_args("cite_error", &[&message])
                ),
                consumed,
            ));
        }
        if self.state.refs.len() >= MAX_REFS {
            let message = self.msg("cite_error_ref_no_input");
            return Some((
                format!(
                    "<span class=\"error\">{}</span>",
                    self.msg_args("cite_error", &[&message])
                ),
                consumed,
            ));
        }
        let number = self
            .state
            .refs
            .iter()
            .filter(|reference| reference.group == group)
            .count()
            + 1;
        let key_base = if name.is_empty() {
            number.to_string()
        } else {
            name.clone()
        };
        let mut key = if group.is_empty() {
            key_base.clone()
        } else {
            format!("{group}-{key_base}")
        };
        let mut suffix = 2;
        while self.state.refs.iter().any(|reference| reference.key == key) {
            key = format!("{key_base}-{suffix}");
            suffix += 1;
        }
        self.state.refs.push(RefEntry {
            key: key.clone(),
            number,
            group: group.clone(),
            content: content.clone(),
        });
        if !name.is_empty() {
            self.state
                .ref_names
                .insert((group, name), self.state.refs.len() - 1);
        }
        Some((
            format!(
                "<sup id=\"cite_ref-{key}\" class=\"reference\"><a href=\"#cite_note-{key}\">&#91;{number}&#93;</a></sup>"
            ),
            consumed,
        ))
    }

    fn raw_tag(&mut self, rest: &str) -> Option<(String, usize)> {
        let end = find_tag_end(rest)?;
        let tag = &rest[..=end];
        let consumed = end + 1;
        let inner = tag[1..tag.len() - 1].trim();
        if inner.starts_with('!') || inner.starts_with('?') {
            return None;
        }
        let closing = inner.starts_with('/');
        let inner = inner.trim_start_matches('/').trim();
        let name_end = inner
            .find(|character: char| {
                character.is_whitespace() || character == '/' || character == '>'
            })
            .unwrap_or(inner.len());
        let name = inner[..name_end].to_ascii_lowercase();
        if !is_allowed_tag(&name) {
            return None;
        }
        if closing {
            return Some((format!("</{name}>"), consumed));
        }
        let attrs = sanitize_attrs(&inner[name_end..]);
        if fador_markup::is_void_element(&name) {
            return Some((format!("<{name}{attrs} />"), consumed));
        }
        let self_closing = tag.trim_end().ends_with("/>");
        Some((
            if self_closing {
                format!("<{name}{attrs} />")
            } else {
                format!("<{name}{attrs}>")
            },
            consumed,
        ))
    }

    fn file_url(&self, info: &FileInfo) -> String {
        let hash = mw_file_hash(&info.name);
        format!(
            "{}/{}/{}/{}",
            self.ctx.config.upload_root(),
            &hash[0..1],
            &hash[0..2],
            encode_title(&info.name)
        )
    }

    fn image_url(&self, info: &FileInfo, width: u32) -> String {
        let hash = mw_file_hash(&info.name);
        let directory = format!("{}/{}", &hash[0..1], &hash[0..2]);
        format!(
            "{}/thumb/{}/{}/{}px-{}",
            self.ctx.config.upload_root(),
            directory,
            encode_title(&info.name),
            width,
            encode_title(&info.name)
        )
    }

    fn finalize_refs(&mut self, html: String) -> String {
        let mut out = html;
        let groups: Vec<String> = {
            let mut groups: Vec<String> = self
                .state
                .refs
                .iter()
                .map(|reference| reference.group.clone())
                .collect();
            groups.sort();
            groups.dedup();
            groups
        };
        let mut rendered_any = false;
        for group in &groups {
            let marker = format!("{REFS_PREFIX}{}{REFS_SUFFIX}", escape_html(group));
            if out.contains(&marker) {
                let list = self.render_refs_list(group);
                out = out.replacen(&marker, &list, 1);
                out = out.replace(&marker, "");
                rendered_any = true;
            }
        }
        // Remove markers for groups that have no refs.
        while let Some(position) = out.find(REFS_PREFIX) {
            if let Some(end) = out[position..].find(REFS_SUFFIX) {
                out.replace_range(position..position + end + REFS_SUFFIX.len(), "");
            } else {
                break;
            }
        }
        if !rendered_any && !self.state.refs.is_empty() {
            let group = self.state.refs[0].group.clone();
            out.push_str(&self.render_refs_list(&group));
        }
        out
    }

    fn render_refs_list(&mut self, group: &str) -> String {
        if !self.state.refs_rendered.insert(group.to_string()) {
            return String::new();
        }
        let refs: Vec<RefEntry> = self
            .state
            .refs
            .iter()
            .filter(|reference| reference.group == group)
            .cloned()
            .collect();
        if refs.is_empty() {
            return "<div class=\"mw-references-wrap\"><ol class=\"references\"></ol></div>"
                .to_string();
        }
        let mut out = String::from("<div class=\"mw-references-wrap\"><ol class=\"references\">");
        for reference in refs {
            out.push_str(&format!(
                "<li id=\"cite_note-{key}\"><span class=\"mw-cite-backlink\"><a href=\"#cite_ref-{key}\">↑</a></span> <span class=\"reference-text\">{}</span></li>",
                self.inline(&reference.content),
                key = escape_html(&reference.key)
            ));
        }
        out.push_str("</ol></div>");
        out
    }
}

// ---------------------------------------------------------------------------
// Brace-aware template scanning

#[derive(Clone, Copy, PartialEq, Eq)]
enum BraceKind {
    Double,
    Triple,
}

impl BraceKind {
    fn len(self) -> usize {
        match self {
            BraceKind::Double => 2,
            BraceKind::Triple => 3,
        }
    }
}

/// Find the matching close for a `{{`/`{{{` opened immediately before
/// `content_start`. Returns `(content_end, close_len)`.
fn find_balanced(text: &str, content_start: usize, initial: BraceKind) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut stack = vec![initial];
    let mut index = content_start;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            let mut run = 1;
            while index + run < bytes.len() && bytes[index + run] == b'{' {
                run += 1;
            }
            if run >= 3 {
                stack.push(BraceKind::Triple);
            } else if run == 2 {
                stack.push(BraceKind::Double);
            }
            if stack.len() > MAX_BRACE_DEPTH as usize {
                return None;
            }
            index += run;
            continue;
        }
        if bytes[index] == b'}' {
            let mut run = 1;
            while index + run < bytes.len() && bytes[index + run] == b'}' {
                run += 1;
            }
            let mut remaining = run;
            let mut consumed = 0usize;
            while !stack.is_empty() && remaining > 0 {
                let kind = *stack.last()?;
                if remaining >= kind.len() {
                    stack.pop();
                    remaining -= kind.len();
                    consumed += kind.len();
                    if stack.is_empty() {
                        let final_start = index + consumed - kind.len();
                        return Some((final_start, kind.len()));
                    }
                } else {
                    break;
                }
            }
            if consumed == 0 {
                index += run;
            } else {
                index += consumed;
                if remaining > 0 {
                    // Extra closing braces are literal content.
                    index += remaining;
                }
            }
            continue;
        }
        index += 1;
    }
    None
}

fn find_link_end(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut depth = 1i32;
    let mut index = 2usize;
    while index + 1 < bytes.len() {
        if bytes[index] == b'[' && bytes[index + 1] == b'[' {
            depth += 1;
            if depth > MAX_BRACE_DEPTH {
                return None;
            }
            index += 2;
            continue;
        }
        if bytes[index] == b']' && bytes[index + 1] == b']' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
            index += 2;
            continue;
        }
        index += 1;
    }
    None
}

fn split_top_level(text: &str, separator: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut brace = 0i32;
    let mut bracket = 0i32;
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < text.len() {
        let character = text[index..].chars().next().unwrap_or(' ');
        match character {
            '{' => {
                if bytes[index..].starts_with(b"{{{") {
                    brace += 1;
                    current.push_str("{{{");
                    index += 3;
                    continue;
                } else if bytes[index..].starts_with(b"{{") {
                    brace += 1;
                    current.push_str("{{");
                    index += 2;
                    continue;
                }
            }
            '}' => {
                if bytes[index..].starts_with(b"}}}") {
                    brace -= 1;
                    current.push_str("}}}");
                    index += 3;
                    continue;
                } else if bytes[index..].starts_with(b"}}") {
                    brace -= 1;
                    current.push_str("}}");
                    index += 2;
                    continue;
                }
            }
            '[' => bracket += 1,
            ']' => bracket -= 1,
            _ => {}
        }
        if character == separator && brace <= 0 && bracket <= 0 {
            out.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
        index += character.len_utf8();
    }
    out.push(current);
    out
}

fn find_top_level(text: &str, target: char) -> Option<usize> {
    let mut brace = 0i32;
    let mut bracket = 0i32;
    let mut index = 0;
    while index < text.len() {
        let character = text[index..].chars().next().unwrap_or(' ');
        match character {
            '{' => brace += 1,
            '}' => brace -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            _ => {}
        }
        if character == target && brace <= 0 && bracket <= 0 {
            return Some(index);
        }
        index += character.len_utf8();
    }
    None
}

fn normalize_source(source: &str) -> String {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut out = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            out.push('\n');
        } else if matches!(character, '\u{1}' | '\u{2}' | '\u{4}') {
            out.push(' ');
        } else {
            out.push(character);
        }
    }
    out
}

/// Remove HTML comments.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if text[index..].starts_with("<!--") {
            if let Some(end) = text[index + 4..].find("-->") {
                index += 4 + end + 3;
                continue;
            }
            break;
        }
        let character = text[index..].chars().next().unwrap_or(' ');
        out.push(character);
        index += character.len_utf8();
    }
    out
}

fn process_template_source(source: &str) -> String {
    let lower = source.to_ascii_lowercase();
    let text = if lower.contains("<onlyinclude") {
        let mut out = String::new();
        let mut position = 0;
        while let Some(open) = lower[position..].find("<onlyinclude") {
            let start = position + open;
            let Some(gt) = source[start..].find('>') else {
                break;
            };
            let content_start = start + gt + 1;
            let Some(close) = lower[content_start..].find("</onlyinclude>") else {
                out.push_str(&source[content_start..]);
                break;
            };
            out.push_str(&source[content_start..content_start + close]);
            position = content_start + close + "</onlyinclude>".len();
        }
        out
    } else {
        remove_tag_blocks(source, "noinclude")
    };
    strip_named_tags(&strip_named_tags(&text, "includeonly"), "onlyinclude")
}

fn process_page_source(source: &str) -> String {
    let text = remove_tag_blocks(source, "includeonly");
    strip_named_tags(&strip_named_tags(&text, "noinclude"), "onlyinclude")
}

fn strip_named_tags(source: &str, tag: &str) -> String {
    let lower = source.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = String::with_capacity(source.len());
    let mut position = 0;
    while position < source.len() {
        let next = lower[position..].find(&open).map(|found| position + found);
        let next_close = lower[position..].find(&close).map(|found| position + found);
        match (next, next_close) {
            (Some(open_at), Some(close_at)) if open_at < close_at => {
                out.push_str(&source[position..open_at]);
                match source[open_at..].find('>') {
                    Some(gt) => position = open_at + gt + 1,
                    None => break,
                }
            }
            (Some(open_at), None) => {
                out.push_str(&source[position..open_at]);
                match source[open_at..].find('>') {
                    Some(gt) => position = open_at + gt + 1,
                    None => break,
                }
            }
            (_, Some(close_at)) => {
                out.push_str(&source[position..close_at]);
                position = close_at + close.len();
            }
            (None, None) => {
                out.push_str(&source[position..]);
                break;
            }
        }
    }
    out
}

fn remove_tag_blocks(source: &str, tag: &str) -> String {
    let lower = source.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = String::with_capacity(source.len());
    let mut position = 0;
    while let Some(relative) = lower[position..].find(&open) {
        let start = position + relative;
        out.push_str(&source[position..start]);
        let Some(gt) = source[start..].find('>') else {
            position = source.len();
            break;
        };
        let tag_end = start + gt + 1;
        if source[start..tag_end].trim_end().ends_with("/>") {
            position = tag_end;
            continue;
        }
        if let Some(close_relative) = lower[tag_end..].find(&close) {
            position = tag_end + close_relative + close.len();
        } else {
            position = source.len();
            break;
        }
    }
    out.push_str(&source[position..]);
    out
}

fn strip_scheme(text: &str) -> &str {
    text.split_once("://").map(|(_, rest)| rest).unwrap_or(text)
}

fn month_key(month: u32) -> String {
    const MONTHS: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    MONTHS[(month.saturating_sub(1) as usize).min(11)].to_string()
}

fn format_number_fi(text: &str) -> String {
    let text = text.trim();
    let (sign, digits) = if let Some(rest) = text.strip_prefix('-') {
        ("-", rest)
    } else {
        ("", text)
    };
    if digits.is_empty() || !digits.chars().all(|character| character.is_ascii_digit()) {
        return text.to_string();
    }
    let mut out = String::new();
    let length = digits.len();
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (length - index) % 3 == 0 {
            out.push_str("&#160;");
        }
        out.push(character);
    }
    format!("{sign}{out}")
}

fn select_plural(forms: &[String], count: u64, rule: u8) -> String {
    if forms.is_empty() {
        return String::new();
    }
    let form = fador_i18n::plural_form(count as i64, rule);
    let index = (form as usize).saturating_sub(1).min(forms.len() - 1);
    forms[index].clone()
}

fn eval_expr(expression: &str) -> Option<f64> {
    // Small, safe arithmetic evaluator for #expr. No identifiers, no function
    // calls, bounded recursion.
    let mut evaluator = ExprEval {
        bytes: expression.as_bytes(),
        position: 0,
        depth: 0,
    };
    let value = evaluator.expr()?;
    evaluator.skip_whitespace();
    if evaluator.position == evaluator.bytes.len() {
        Some(value)
    } else {
        None
    }
}

struct ExprEval<'a> {
    bytes: &'a [u8],
    position: usize,
    depth: u32,
}

impl ExprEval<'_> {
    fn skip_whitespace(&mut self) {
        while self.position < self.bytes.len() && self.bytes[self.position].is_ascii_whitespace() {
            self.position += 1;
        }
    }

    fn expr(&mut self) -> Option<f64> {
        self.depth += 1;
        if self.depth > 32 {
            return None;
        }
        let mut value = self.term()?;
        loop {
            self.skip_whitespace();
            match self.bytes.get(self.position) {
                Some(b'+') => {
                    self.position += 1;
                    value += self.term()?;
                }
                Some(b'-') => {
                    self.position += 1;
                    value -= self.term()?;
                }
                _ => break,
            }
        }
        self.depth -= 1;
        Some(value)
    }

    fn term(&mut self) -> Option<f64> {
        let mut value = self.factor()?;
        loop {
            self.skip_whitespace();
            match self.bytes.get(self.position) {
                Some(b'*') => {
                    self.position += 1;
                    value *= self.factor()?;
                }
                Some(b'/') => {
                    self.position += 1;
                    let divisor = self.factor()?;
                    if divisor == 0.0 {
                        return None;
                    }
                    value /= divisor;
                }
                Some(b'%') => {
                    self.position += 1;
                    let divisor = self.factor()?;
                    if divisor == 0.0 {
                        return None;
                    }
                    value %= divisor;
                }
                _ => break,
            }
        }
        Some(value)
    }

    fn factor(&mut self) -> Option<f64> {
        self.skip_whitespace();
        if self.bytes.get(self.position) == Some(&b'(') {
            self.position += 1;
            let value = self.expr()?;
            self.skip_whitespace();
            if self.bytes.get(self.position) != Some(&b')') {
                return None;
            }
            self.position += 1;
            return Some(value);
        }
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
            return Some(-self.factor()?);
        }
        if self.bytes.get(self.position) == Some(&b'+') {
            self.position += 1;
            return self.factor();
        }
        let start = self.position;
        while self.position < self.bytes.len()
            && matches!(self.bytes[self.position], b'0'..=b'9' | b'.')
        {
            self.position += 1;
        }
        if start == self.position {
            return None;
        }
        std::str::from_utf8(&self.bytes[start..self.position])
            .ok()?
            .parse()
            .ok()
    }
}

fn is_tag_start(rest: &str, tag: &str) -> bool {
    let Some(after) = rest.strip_prefix('<') else {
        return false;
    };
    after.len() >= tag.len()
        && after.is_char_boundary(tag.len())
        && after[..tag.len()].eq_ignore_ascii_case(tag)
        && after[tag.len()..]
            .chars()
            .next()
            .map(|character| character.is_whitespace() || character == '>' || character == '/')
            .unwrap_or(false)
}

fn find_tag_end(text: &str) -> Option<usize> {
    let mut quote = 0u8;
    for (index, byte) in text.bytes().enumerate() {
        if quote != 0 {
            if byte == quote {
                quote = 0;
            }
        } else if byte == b'"' || byte == b'\'' {
            quote = byte;
        } else if byte == b'>' {
            return Some(index);
        }
    }
    None
}

fn pipe_trick(title: &Title) -> String {
    let mut text = title.text.clone();
    if let Some(position) = text.find(" (") {
        text.truncate(position);
    }
    if let Some(position) = text.rfind(',') {
        // MediaWiki's pipe trick removes a trailing comma phrase only when it
        // has no space after it; keep this conservative.
        if !text[position..].contains(' ') {
            text.truncate(position);
        }
    }
    text
}

fn is_link_trail_char(character: char) -> bool {
    character.is_alphabetic() && !character.is_uppercase()
}

fn is_external_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let has_scheme = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("mailto:")
        || lower.starts_with("irc://")
        || lower.starts_with("ircs://")
        || lower.starts_with("//");
    has_scheme && fador_markup::is_safe_url(url, &fador_markup::SchemePolicy::STRICT)
}

fn looks_like_image(url: &str) -> bool {
    let lower = url.split('?').next().unwrap_or(url).to_ascii_lowercase();
    [".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp"]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn gallery_file_name(raw: &str, namespaces: &Namespaces) -> String {
    let trimmed = raw.trim();
    if let Some(colon) = trimmed.find(':') {
        if namespaces.lookup(&trimmed[..colon]) == Some(6) {
            return trimmed[colon + 1..].trim().replace('_', " ");
        }
    }
    trimmed.replace('_', " ")
}

fn close_cell(row: &mut Option<TableRow>, cell: &mut Option<TableCell>) {
    if let Some(cell) = cell.take() {
        if let Some(row) = row.as_mut() {
            row.cells.push(cell);
        }
    }
}

struct TableData {
    attrs: String,
    caption: Option<(String, String)>,
    rows: Vec<TableRow>,
}

struct TableRow {
    attrs: String,
    cells: Vec<TableCell>,
}

struct TableCell {
    header: bool,
    attrs: String,
    content: String,
}

fn parse_heading(line: &str) -> Option<(u8, String)> {
    let trimmed = line.trim();
    let leading = trimmed
        .chars()
        .take_while(|character| *character == '=')
        .count();
    if leading == 0 || leading > 6 || trimmed.len() < leading * 2 + 1 {
        return None;
    }
    let trailing = trimmed
        .chars()
        .rev()
        .take_while(|character| *character == '=')
        .count();
    if trailing < leading {
        return None;
    }
    let inner = &trimmed[leading..trimmed.len() - leading];
    let inner = inner.trim();
    if inner.is_empty() {
        return None;
    }
    Some((leading as u8, inner.to_string()))
}

fn is_hr(text: &str) -> bool {
    text.chars().all(|character| character == '-')
}

fn is_list_line(line: &str) -> bool {
    matches!(line.chars().next(), Some('*' | '#' | ';' | ':'))
}

fn is_block_boundary(line: &str) -> bool {
    if line.trim().is_empty() {
        return true;
    }
    if is_list_line(line) {
        return true;
    }
    if parse_heading(line).is_some() {
        return true;
    }
    let trimmed = line.trim_start();
    if trimmed.starts_with("{|")
        || trimmed.starts_with("----")
        || line.starts_with(' ')
        || line.starts_with('\t')
        || trimmed == TOC_MARKER
    {
        return true;
    }
    if is_block_html_line(trimmed) {
        return true;
    }
    for tag in ["pre", "gallery", "references"] {
        if starts_tag(trimmed, tag) {
            return true;
        }
    }
    false
}

fn is_block_html_line(text: &str) -> bool {
    let stripped = text.strip_prefix("</").unwrap_or(text);
    let stripped = stripped.strip_prefix('<').unwrap_or(stripped);
    for tag in [
        "div",
        "blockquote",
        "center",
        "ul",
        "ol",
        "dl",
        "fieldset",
        "figure",
        "section",
        "article",
        "header",
        "footer",
        "nav",
        "aside",
        "table",
        "tr",
        "td",
        "th",
        "thead",
        "tbody",
        "tfoot",
        "caption",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "p",
    ] {
        if stripped.len() >= tag.len()
            && stripped.is_char_boundary(tag.len())
            && stripped[..tag.len()].eq_ignore_ascii_case(tag)
            && stripped[tag.len()..].starts_with(|character: char| {
                character.is_whitespace() || character == '>' || character == '/'
            })
        {
            return true;
        }
    }
    false
}

fn starts_tag(text: &str, tag: &str) -> bool {
    let text = text.trim_start();
    let Some(rest) = text.strip_prefix('<') else {
        return false;
    };
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    rest.len() >= tag.len()
        && rest.is_char_boundary(tag.len())
        && rest[..tag.len()].eq_ignore_ascii_case(tag)
        && rest[tag.len()..]
            .chars()
            .next()
            .map(|character| character.is_whitespace() || character == '>' || character == '/')
            .unwrap_or(false)
}

fn split_table_cells(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut brace = 0i32;
    let mut bracket = 0i32;
    let mut index = 0;
    while index < body.len() {
        let character = body[index..].chars().next().unwrap_or(' ');
        if body[index..].starts_with("{{") {
            brace += 1;
            current.push_str("{{");
            index += 2;
            continue;
        }
        if body[index..].starts_with("}}") {
            brace -= 1;
            current.push_str("}}");
            index += 2;
            continue;
        }
        if body[index..].starts_with("[[") {
            bracket += 1;
            current.push_str("[[");
            index += 2;
            continue;
        }
        if body[index..].starts_with("]]") {
            bracket -= 1;
            current.push_str("]]");
            index += 2;
            continue;
        }
        if (body[index..].starts_with("||") || body[index..].starts_with("!!"))
            && brace <= 0
            && bracket <= 0
        {
            out.push(std::mem::take(&mut current));
            index += 2;
            continue;
        }
        current.push(character);
        index += character.len_utf8();
    }
    out.push(current);
    out
}

fn split_cell_attrs(text: &str) -> (String, String) {
    if let Some(position) = text.find('|') {
        let attrs = &text[..position];
        if attrs.contains("[[") || attrs.contains("{{") || attrs.contains("]]") {
            return (String::new(), text.to_string());
        }
        let trimmed = attrs.trim();
        if !trimmed.is_empty()
            && (trimmed.contains('=')
                || trimmed.starts_with("style")
                || trimmed.starts_with("class")
                || trimmed.starts_with("align")
                || trimmed.starts_with("scope")
                || trimmed.starts_with("colspan")
                || trimmed.starts_with("rowspan"))
        {
            return (sanitize_attrs(trimmed), text[position + 1..].to_string());
        }
    }
    (String::new(), text.to_string())
}

fn split_term_definition(text: &str) -> (String, Option<String>) {
    // `; term : definition` — don't split URLs or links.
    let mut bracket = 0i32;
    let mut index = 0;
    while index < text.len() {
        let character = text[index..].chars().next().unwrap_or(' ');
        if text[index..].starts_with("[[") {
            bracket += 1;
            index += 2;
            continue;
        }
        if text[index..].starts_with("]]") {
            bracket -= 1;
            index += 2;
            continue;
        }
        if character == ':' && bracket == 0 && !text[index..].starts_with("://") {
            return (
                text[..index].trim().to_string(),
                Some(text[index + 1..].trim().to_string()),
            );
        }
        index += character.len_utf8();
    }
    (text.to_string(), None)
}

fn leading_div_len(text: &str) -> Option<usize> {
    if !text.starts_with("<div") {
        return None;
    }
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"<div") {
            depth += 1;
            while index < bytes.len() && bytes[index] != b'>' {
                index += 1;
            }
            index += 1;
            continue;
        }
        if bytes[index..].starts_with(b"</div>") {
            depth -= 1;
            index += 6;
            if depth == 0 {
                return Some(index);
            }
            continue;
        }
        index += 1;
    }
    None
}

fn scaled_size(info: &FileInfo, width: u32) -> (u32, u32) {
    if info.width == 0 {
        return (width, 0);
    }
    let width = width.min(info.width).max(1);
    let height =
        ((info.height as u64 * width as u64 + info.width as u64 / 2) / info.width as u64) as u32;
    (width, height.max(1))
}

#[cfg(test)]
mod parser_tests {
    use super::*;
    use crate::testutil::{Rng, MALICIOUS_STRINGS};

    #[test]
    fn table_cells_do_not_split_link_pipes() {
        let body = "colspan=2|Liittyvä tarina: [[Tarina:Sarjan esittely|Sarjan esittely]]";
        let cells = split_table_cells(body);
        assert_eq!(cells.len(), 1, "cells={cells:?}");
        let (attrs, content) = split_cell_attrs(&cells[0]);
        assert_eq!(attrs.trim(), "colspan=\"2\"");
        assert!(content.contains("[[Tarina:Sarjan esittely|Sarjan esittely]]"));
    }

    #[test]
    fn link_end_matches_outer_brackets() {
        assert_eq!(find_link_end("[[Malline:Spoiler-alku]]"), Some(22));
        assert_eq!(find_link_end("[[A|B]]"), Some(5));
        assert_eq!(find_link_end("[[File:X|thumb|cap [[A]] end]]"), Some(28));
    }

    #[test]
    fn balanced_braces_find_the_matching_close() {
        assert_eq!(find_balanced("{{a}}", 2, BraceKind::Double), Some((3, 2)));
        assert_eq!(
            find_balanced("{{a|{{b}}}}", 2, BraceKind::Double),
            Some((9, 2))
        );
        assert_eq!(find_balanced("{{a", 2, BraceKind::Double), None);
        let mut deep = String::new();
        for _ in 0..200 {
            deep.push_str("{{x");
        }
        deep.push_str(&"}}".repeat(200));
        assert_eq!(find_balanced(&deep, 2, BraceKind::Double), None);
    }

    #[test]
    fn headings_and_switches_parse() {
        assert_eq!(parse_heading("== A =="), Some((2, "A".to_string())));
        assert_eq!(parse_heading("=== A ==="), Some((3, "A".to_string())));
        assert_eq!(parse_heading("== A ="), None);
        assert_eq!(parse_heading("======= A ======="), None);
        assert!(is_hr("----"));
        assert!(!is_hr("---x"));
        assert!(is_list_line("* item"));
        assert!(!is_list_line(" item"));
    }

    #[test]
    fn arithmetic_evaluator_is_bounded() {
        assert_eq!(eval_expr("2+3*4"), Some(14.0));
        assert_eq!(eval_expr("(2+3)*4"), Some(20.0));
        assert_eq!(eval_expr("-2.5"), Some(-2.5));
        assert_eq!(eval_expr("1/0"), None);
        assert_eq!(eval_expr("1%0"), None);
        assert_eq!(eval_expr("abc"), None);
        assert_eq!(eval_expr(&"(".repeat(10_000)), None);
    }

    #[test]
    fn fuzz_low_level_scanners_survive_hostile_markup() {
        let mut rng = Rng::new(0x9a11_0003);
        for _ in 0..2_000 {
            let length = rng.below(300);
            let input = rng.text(length);
            let _ = find_balanced(&input, 0, BraceKind::Double);
            let _ = find_balanced(&input, 0, BraceKind::Triple);
            let _ = find_link_end(&input);
            let _ = split_top_level(&input, '|');
            let _ = find_top_level(&input, '=');
            let _ = parse_heading(&input);
            let _ = split_table_cells(&input);
            let _ = split_cell_attrs(&input);
            let _ = split_term_definition(&input);
            let _ = normalize_source(&input);
            let _ = strip_comments(&input);
            let _ = process_template_source(&input);
            let _ = process_page_source(&input);
            let _ = eval_expr(&input);
            let _ = is_external_url(&input);
        }
        for input in MALICIOUS_STRINGS {
            let _ = find_balanced(input, 0, BraceKind::Double);
            let _ = find_link_end(input);
            let _ = split_top_level(input, '|');
            let _ = process_template_source(input);
            let _ = process_page_source(input);
            let _ = eval_expr(input);
        }
    }
}
