//! RSS 0.92, RSS 2.0, Atom 1.0 and RDF (RSS 1.0) feed documents.
//!
//! The writer is a clean-room implementation: every text node is XML-escaped,
//! HTML content is wrapped in CDATA, a `]]>` terminator inside the content is
//! split across two sections, and a character that XML 1.0 does not allow is
//! dropped instead of producing a document a parser rejects.
//!
//! A feed is data, not a board event: the caller fills [`Feed`] and [`Entry`]
//! from whatever it has and picks a [`Format`].
//!
//! ```
//! use fador_services::feed::{render, Entry, Feed, Format};
//!
//! let mut feed = Feed::new("Example board", "https://example.test/");
//! feed.description = "Recent posts".into();
//! feed.entries.push(
//!     Entry::new("Hello", "https://example.test/viewtopic.php?t=1")
//!         .content("<p>Hello &amp; welcome</p>"),
//! );
//! let xml = render(Format::Rss2, &feed);
//! assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
//! assert!(xml.contains("<title>Hello</title>"));
//! ```
//!
//! # Bounds
//!
//! | item | limit |
//! | --- | --- |
//! | entries per document | 500 |
//! | categories per entry | 16 |
//! | one text field | 64 KiB (truncated at a character boundary) |

use fador_core::util::{civil_from_days, weekday_from_days};

/// Largest number of entries a rendered document contains.
pub const MAX_ENTRIES: usize = 500;
/// Largest number of categories attached to one entry.
pub const MAX_CATEGORIES: usize = 16;
/// Largest text field a rendered document contains, in bytes.
pub const MAX_FIELD_BYTES: usize = 64 * 1024;

const I1: &str = "  ";
const I2: &str = "    ";
const I3: &str = "      ";

/// A feed document format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// RSS 0.92.
    Rss,
    /// RSS 2.0.
    #[default]
    Rss2,
    /// Atom 1.0.
    Atom,
    /// RDF Site Summary (RSS 1.0).
    Rdf,
}

impl Format {
    /// Parse a `format` query value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rss" => Some(Self::Rss),
            "rss2" => Some(Self::Rss2),
            "atom" => Some(Self::Atom),
            "rdf" => Some(Self::Rdf),
            _ => None,
        }
    }

    /// The `Content-Type` for a response body.
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Rss | Self::Rss2 => "application/rss+xml; charset=UTF-8",
            Self::Atom => "application/atom+xml; charset=UTF-8",
            Self::Rdf => "application/rdf+xml; charset=UTF-8",
        }
    }

    /// The configuration name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rss => "rss",
            Self::Rss2 => "rss2",
            Self::Atom => "atom",
            Self::Rdf => "rdf",
        }
    }
}

/// One category of an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Category {
    /// Machine-readable term.
    pub term: String,
    /// Human-readable label.
    pub label: String,
    /// Optional scheme URI.
    pub scheme: String,
}

impl Category {
    /// A category with the term and label set to the same value.
    pub fn new(term: impl Into<String>) -> Self {
        let term = term.into();
        Self {
            label: term.clone(),
            term,
            scheme: String::new(),
        }
    }

    /// Set the label.
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Set the scheme URI.
    #[must_use]
    pub fn scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = scheme.into();
        self
    }
}

/// One feed entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// Entry title, plain text.
    pub title: String,
    /// The page a reader should open.
    pub link: String,
    /// Stable identifier. Empty falls back to [`Entry::link`].
    pub id: String,
    /// Short HTML summary.
    pub summary: String,
    /// Full HTML content.
    pub content: String,
    /// Author display name.
    pub author: String,
    /// Author email address, if the viewer may see it.
    pub author_email: String,
    /// Author profile URI.
    pub author_link: String,
    /// Publication time as a Unix timestamp, `0` when unknown.
    pub published: i64,
    /// Last change time as a Unix timestamp, `0` when unknown.
    pub updated: i64,
    /// Categories, bounded by [`MAX_CATEGORIES`] when rendered.
    pub categories: Vec<Category>,
}

impl Entry {
    /// An entry with a title and a link.
    pub fn new(title: impl Into<String>, link: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            link: link.into(),
            ..Self::default()
        }
    }

    /// Set the HTML summary.
    #[must_use]
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    /// Set the HTML content.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Set the author name.
    #[must_use]
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Set the author email.
    #[must_use]
    pub fn author_email(mut self, email: impl Into<String>) -> Self {
        self.author_email = email.into();
        self
    }

    /// Set the author profile URI.
    #[must_use]
    pub fn author_link(mut self, link: impl Into<String>) -> Self {
        self.author_link = link.into();
        self
    }

    /// Set the publication time.
    #[must_use]
    pub fn published(mut self, unix: i64) -> Self {
        self.published = unix;
        self
    }

    /// Set the last change time.
    #[must_use]
    pub fn updated(mut self, unix: i64) -> Self {
        self.updated = unix;
        self
    }

    /// Append a category.
    #[must_use]
    pub fn category(mut self, category: Category) -> Self {
        self.categories.push(category);
        self
    }
}

/// A feed document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Feed {
    /// Feed title, plain text.
    pub title: String,
    /// The site the feed belongs to.
    pub link: String,
    /// The feed's own URL.
    pub self_link: String,
    /// Feed description, plain text.
    pub description: String,
    /// Language tag such as `fi-FI`. Empty means `en`.
    pub language: String,
    /// Last change time as a Unix timestamp, `0` when unknown.
    pub updated: i64,
    /// Feed author display name.
    pub author: String,
    /// Stable feed identifier. Empty falls back to [`Feed::self_link`].
    pub id: String,
    /// Generator name.
    pub generator: String,
    /// Entries, bounded by [`MAX_ENTRIES`] when rendered.
    pub entries: Vec<Entry>,
}

impl Feed {
    /// A feed with a title and a site link. The self link and the id default to
    /// the same link.
    pub fn new(title: impl Into<String>, link: impl Into<String>) -> Self {
        let link = link.into();
        Self {
            title: title.into(),
            self_link: link.clone(),
            link,
            language: "en".into(),
            ..Self::default()
        }
    }

    /// Set the feed description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the feed's own URL.
    #[must_use]
    pub fn self_link(mut self, self_link: impl Into<String>) -> Self {
        self.self_link = self_link.into();
        self
    }

    /// Set the language tag.
    #[must_use]
    pub fn language(mut self, language: impl Into<String>) -> Self {
        self.language = language.into();
        self
    }

    /// Set the last change time.
    #[must_use]
    pub fn updated(mut self, unix: i64) -> Self {
        self.updated = unix;
        self
    }

    /// Set the feed author.
    #[must_use]
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Set the stable feed identifier.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set the generator name.
    #[must_use]
    pub fn generator(mut self, generator: impl Into<String>) -> Self {
        self.generator = generator.into();
        self
    }

    /// Append an entry.
    #[must_use]
    pub fn entry(mut self, entry: Entry) -> Self {
        self.entries.push(entry);
        self
    }
}

/// Render a feed document.
///
/// The output is a complete XML document with a declaration and a final
/// newline. At most [`MAX_ENTRIES`] entries and [`MAX_CATEGORIES`] categories
/// per entry are written; every text field is truncated to
/// [`MAX_FIELD_BYTES`].
pub fn render(format: Format, feed: &Feed) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    match format {
        Format::Rss | Format::Rss2 => render_rss(&mut out, format, feed),
        Format::Atom => render_atom(&mut out, feed),
        Format::Rdf => render_rdf(&mut out, feed),
    }
    out
}

/// Escape a string for an XML text node.
///
/// `&`, `<`, `>`, `"` and `'` become references and a character that XML 1.0
/// does not allow is removed.
pub fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            character if is_xml_char(character) => out.push(character),
            _ => {}
        }
    }
    out
}

/// Escape a string for a quoted XML attribute.
///
/// Like [`xml_escape`], and a tab, a line feed or a carriage return becomes a
/// numeric reference so an attribute-value normalisation cannot change it.
pub fn xml_escape_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            character if is_xml_char(character) => out.push(character),
            _ => {}
        }
    }
    out
}

/// Prepare a string for the inside of a CDATA section.
///
/// A `]]>` terminator is split into two sections, so the returned text can be
/// placed between `<![CDATA[` and `]]>` without ending the section early. A
/// character that XML 1.0 does not allow is removed.
pub fn cdata(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if is_xml_char(character) {
            sanitized.push(character);
        }
    }
    sanitized.replace("]]>", "]]]]><![CDATA[>")
}

/// Format a Unix timestamp as an RFC 822 date with a `GMT` zone.
pub fn rfc822_date(unix: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = weekday_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[weekday % 7],
        day,
        MONTHS[(month as usize).saturating_sub(1)],
        year,
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

/// Format a Unix timestamp as an RFC 3339 date in UTC.
pub fn rfc3339_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

fn render_rss(out: &mut String, format: Format, feed: &Feed) {
    let version = if format == Format::Rss2 {
        "2.0"
    } else {
        "0.92"
    };
    out.push_str(&format!(
        "<rss version=\"{version}\" xml:lang=\"{}\">\n",
        xml_escape_attr(feed_language(feed))
    ));
    out.push_str("<channel>\n");
    push_text(out, I1, "title", &feed.title);
    push_text(out, I1, "link", &feed.link);
    push_cdata(out, I1, "description", &feed.description);
    push_text(out, I1, "language", feed_language(feed));
    if feed.updated > 0 {
        push_text(out, I1, "lastBuildDate", &rfc822_date(feed.updated));
    }
    if !feed.generator.is_empty() {
        push_text(out, I1, "generator", &feed.generator);
    }
    for entry in feed.entries.iter().take(MAX_ENTRIES) {
        render_rss_item(out, entry, feed, format == Format::Rss2);
    }
    out.push_str("</channel>\n</rss>\n");
}

fn render_rss_item(out: &mut String, entry: &Entry, feed: &Feed, with_guid: bool) {
    out.push_str(I1);
    out.push_str("<item>\n");
    push_text(out, I2, "title", &entry.title);
    push_text(out, I2, "link", &entry.link);
    if with_guid {
        out.push_str(&format!(
            "{I2}<guid isPermaLink=\"true\">{}</guid>\n",
            xml_escape(entry_id(entry, feed))
        ));
    }
    let description = if entry.content.is_empty() {
        &entry.summary
    } else {
        &entry.content
    };
    push_cdata(out, I2, "description", description);
    let date = entry_date(entry, feed);
    if date > 0 {
        push_text(out, I2, "pubDate", &rfc822_date(date));
    }
    if !entry.author_email.is_empty() {
        let author = if entry.author.is_empty() {
            entry.author_email.clone()
        } else {
            format!("{} ({})", entry.author_email, entry.author)
        };
        push_text(out, I2, "author", &author);
    }
    for category in entry.categories.iter().take(MAX_CATEGORIES) {
        push_cdata(out, I2, "category", category_label(category));
    }
    out.push_str(I1);
    out.push_str("</item>\n");
}

fn render_atom(out: &mut String, feed: &Feed) {
    out.push_str(&format!(
        "<feed xmlns=\"http://www.w3.org/2005/Atom\" xml:lang=\"{}\">\n",
        xml_escape_attr(feed_language(feed))
    ));
    push_text(out, I1, "id", feed_id(feed));
    push_text(out, I1, "title", &feed.title);
    if !feed.description.is_empty() {
        push_text(out, I1, "subtitle", &feed.description);
    }
    if !feed.self_link.is_empty() {
        out.push_str(&format!(
            "{I1}<link rel=\"self\" type=\"application/atom+xml\" href=\"{}\" />\n",
            xml_escape_attr(&feed.self_link)
        ));
    }
    if !feed.link.is_empty() {
        out.push_str(&format!(
            "{I1}<link rel=\"alternate\" type=\"text/html\" href=\"{}\" />\n",
            xml_escape_attr(&feed.link)
        ));
    }
    push_text(out, I1, "updated", &rfc3339_date(feed.updated));
    if !feed.author.is_empty() {
        out.push_str(I1);
        out.push_str("<author>\n");
        push_text(out, I2, "name", &feed.author);
        out.push_str(I1);
        out.push_str("</author>\n");
    }
    if !feed.generator.is_empty() {
        push_text(out, I1, "generator", &feed.generator);
    }
    for entry in feed.entries.iter().take(MAX_ENTRIES) {
        render_atom_entry(out, entry, feed);
    }
    out.push_str("</feed>\n");
}

fn render_atom_entry(out: &mut String, entry: &Entry, feed: &Feed) {
    out.push_str(I1);
    out.push_str("<entry>\n");
    push_text(out, I2, "id", entry_id(entry, feed));
    push_text(out, I2, "title", &entry.title);
    if !entry.link.is_empty() {
        out.push_str(&format!(
            "{I2}<link rel=\"alternate\" type=\"text/html\" href=\"{}\" />\n",
            xml_escape_attr(&entry.link)
        ));
    }
    let published = entry_date(entry, feed);
    if published > 0 {
        push_text(out, I2, "published", &rfc3339_date(published));
    }
    push_text(
        out,
        I2,
        "updated",
        &rfc3339_date(entry_updated(entry, feed)),
    );
    if !entry.author.is_empty() {
        out.push_str(I2);
        out.push_str("<author>\n");
        push_text(out, I3, "name", &entry.author);
        if !entry.author_email.is_empty() {
            push_text(out, I3, "email", &entry.author_email);
        }
        if !entry.author_link.is_empty() {
            push_text(out, I3, "uri", &entry.author_link);
        }
        out.push_str(I2);
        out.push_str("</author>\n");
    }
    for category in entry.categories.iter().take(MAX_CATEGORIES) {
        let mut attributes = format!(" term=\"{}\"", xml_escape_attr(&category.term));
        if !category.scheme.is_empty() {
            attributes.push_str(&format!(
                " scheme=\"{}\"",
                xml_escape_attr(&category.scheme)
            ));
        }
        if !category.label.is_empty() {
            attributes.push_str(&format!(" label=\"{}\"", xml_escape_attr(&category.label)));
        }
        out.push_str(&format!("{I2}<category{attributes} />\n"));
    }
    push_html(out, I2, "summary", &entry.summary);
    push_html(out, I2, "content", &entry.content);
    out.push_str(I1);
    out.push_str("</entry>\n");
}

fn render_rdf(out: &mut String, feed: &Feed) {
    out.push_str(
        "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" \
         xmlns=\"http://purl.org/rss/1.0/\" \
         xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\n",
    );
    out.push_str(&format!(
        "{I1}<channel rdf:about=\"{}\">\n",
        xml_escape_attr(feed_id(feed))
    ));
    push_text(out, I2, "title", &feed.title);
    push_text(out, I2, "link", &feed.link);
    push_cdata(out, I2, "description", &feed.description);
    push_text(out, I2, "dc:language", feed_language(feed));
    push_text(out, I2, "dc:date", &rfc3339_date(feed.updated));
    out.push_str(I2);
    out.push_str("<items>\n");
    out.push_str(I3);
    out.push_str("<rdf:Seq>\n");
    for entry in feed.entries.iter().take(MAX_ENTRIES) {
        out.push_str(&format!(
            "{I3}  <rdf:li rdf:resource=\"{}\" />\n",
            xml_escape_attr(entry_id(entry, feed))
        ));
    }
    out.push_str(I3);
    out.push_str("</rdf:Seq>\n");
    out.push_str(I2);
    out.push_str("</items>\n");
    out.push_str(I1);
    out.push_str("</channel>\n");
    for entry in feed.entries.iter().take(MAX_ENTRIES) {
        render_rdf_item(out, entry, feed);
    }
    out.push_str("</rdf:RDF>\n");
}

fn render_rdf_item(out: &mut String, entry: &Entry, feed: &Feed) {
    out.push_str(&format!(
        "{I1}<item rdf:about=\"{}\">\n",
        xml_escape_attr(entry_id(entry, feed))
    ));
    push_text(out, I2, "title", &entry.title);
    push_text(out, I2, "link", &entry.link);
    let description = if entry.content.is_empty() {
        &entry.summary
    } else {
        &entry.content
    };
    push_cdata(out, I2, "description", description);
    push_text(
        out,
        I2,
        "dc:date",
        &rfc3339_date(entry_updated(entry, feed)),
    );
    if !entry.author.is_empty() {
        push_text(out, I2, "dc:creator", &entry.author);
    }
    for category in entry.categories.iter().take(MAX_CATEGORIES) {
        push_text(out, I2, "dc:subject", category_label(category));
    }
    out.push_str(I1);
    out.push_str("</item>\n");
}

fn push_text(out: &mut String, indent: &str, name: &str, value: &str) {
    let value = truncate(value);
    if value.is_empty() {
        out.push_str(&format!("{indent}<{name} />\n"));
    } else {
        out.push_str(&format!("{indent}<{name}>{}</{name}>\n", xml_escape(value)));
    }
}

fn push_cdata(out: &mut String, indent: &str, name: &str, value: &str) {
    let value = truncate(value);
    let content = cdata(value);
    if content.is_empty() {
        out.push_str(&format!("{indent}<{name} />\n"));
    } else {
        out.push_str(&format!("{indent}<{name}><![CDATA[{content}]]></{name}>\n"));
    }
}

fn push_html(out: &mut String, indent: &str, name: &str, value: &str) {
    let value = truncate(value);
    let content = cdata(value);
    if content.is_empty() {
        out.push_str(&format!("{indent}<{name} type=\"html\" />\n"));
    } else {
        out.push_str(&format!(
            "{indent}<{name} type=\"html\"><![CDATA[{content}]]></{name}>\n"
        ));
    }
}

/// Truncate a string at a UTF-8 boundary and at most [`MAX_FIELD_BYTES`] bytes.
fn truncate(value: &str) -> &str {
    if value.len() <= MAX_FIELD_BYTES {
        return value;
    }
    let mut end = MAX_FIELD_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn feed_id(feed: &Feed) -> &str {
    if !feed.id.is_empty() {
        &feed.id
    } else if !feed.self_link.is_empty() {
        &feed.self_link
    } else {
        &feed.link
    }
}

fn feed_language(feed: &Feed) -> &str {
    if feed.language.is_empty() {
        "en"
    } else {
        &feed.language
    }
}

fn entry_id<'a>(entry: &'a Entry, feed: &'a Feed) -> &'a str {
    if !entry.id.is_empty() {
        &entry.id
    } else if !entry.link.is_empty() {
        &entry.link
    } else {
        feed_id(feed)
    }
}

fn entry_date(entry: &Entry, feed: &Feed) -> i64 {
    if entry.published != 0 {
        entry.published
    } else if entry.updated != 0 {
        entry.updated
    } else {
        feed.updated
    }
}

fn entry_updated(entry: &Entry, feed: &Feed) -> i64 {
    if entry.updated != 0 {
        entry.updated
    } else {
        entry_date(entry, feed)
    }
}

fn category_label(category: &Category) -> &str {
    if category.label.is_empty() {
        &category.term
    } else {
        &category.label
    }
}

fn is_xml_char(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{D7FF}').contains(&character)
        || ('\u{E000}'..='\u{FFFD}').contains(&character)
        || ('\u{10000}'..='\u{10FFFF}').contains(&character)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_feed() -> Feed {
        Feed::new("Example board", "https://example.test/")
            .description("Recent posts")
            .self_link("https://example.test/feed.php")
            .language("fi-FI")
            .updated(1_792_890_000)
            .author("Example")
            .generator("fador-services")
            .entry(
                Entry::new("Hello & <world>", "https://example.test/t=1")
                    .content("<p>Hello &amp; welcome</p>")
                    .summary("<p>Hello</p>")
                    .author("Alice")
                    .author_email("alice@example.test")
                    .author_link("https://example.test/u=1")
                    .published(1_792_800_000)
                    .updated(1_792_850_000)
                    .category(Category::new("news").label("News")),
            )
    }

    #[test]
    fn rss2_document_has_the_expected_shape() {
        let xml = render(Format::Rss2, &sample_feed());
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(xml.contains("<rss version=\"2.0\" xml:lang=\"fi-FI\">"));
        assert!(xml.contains("<channel>"));
        assert!(xml.contains("<title>Example board</title>"));
        assert!(xml.contains("<link>https://example.test/</link>"));
        assert!(xml.contains("<description><![CDATA[Recent posts]]></description>"));
        assert!(xml.contains("<language>fi-FI</language>"));
        assert!(xml.contains("<lastBuildDate>Sun, 25 Oct 2026 01:00:00 GMT</lastBuildDate>"));
        assert!(xml.contains("<item>"));
        assert!(xml.contains("<title>Hello &amp; &lt;world&gt;</title>"));
        assert!(xml.contains("<guid isPermaLink=\"true\">https://example.test/t=1</guid>"));
        assert!(xml.contains("<description><![CDATA[<p>Hello &amp; welcome</p>]]></description>"));
        assert!(xml.contains("<author>alice@example.test (Alice)</author>"));
        assert!(xml.contains("<category><![CDATA[News]]></category>"));
        assert!(xml.contains("</channel>\n</rss>\n"));
        assert_eq!(
            Format::Rss2.content_type(),
            "application/rss+xml; charset=UTF-8"
        );
    }

    #[test]
    fn rss_0_92_has_no_guid() {
        let xml = render(Format::Rss, &sample_feed());
        assert!(xml.contains("<rss version=\"0.92\""));
        assert!(!xml.contains("<guid"));
    }

    #[test]
    fn atom_document_has_links_author_and_html_content() {
        let xml = render(Format::Atom, &sample_feed());
        assert!(xml.contains("<feed xmlns=\"http://www.w3.org/2005/Atom\" xml:lang=\"fi-FI\">"));
        assert!(xml.contains("<id>https://example.test/feed.php</id>"));
        assert!(xml.contains("<link rel=\"self\" type=\"application/atom+xml\" href=\"https://example.test/feed.php\" />"));
        assert!(xml.contains(
            "<link rel=\"alternate\" type=\"text/html\" href=\"https://example.test/\" />"
        ));
        assert!(xml.contains("<updated>2026-10-25T01:00:00Z</updated>"));
        assert!(xml.contains("<entry>"));
        assert!(xml.contains("<author>"));
        assert!(xml.contains("<name>Alice</name>"));
        assert!(xml.contains("<email>alice@example.test</email>"));
        assert!(xml.contains("<uri>https://example.test/u=1</uri>"));
        assert!(xml.contains("<category term=\"news\" label=\"News\" />"));
        assert!(xml.contains("<summary type=\"html\"><![CDATA[<p>Hello</p>]]></summary>"));
        assert!(
            xml.contains("<content type=\"html\"><![CDATA[<p>Hello &amp; welcome</p>]]></content>")
        );
        assert!(xml.contains("<published>2026-10-24T00:00:00Z</published>"));
        assert_eq!(
            Format::Atom.content_type(),
            "application/atom+xml; charset=UTF-8"
        );
    }

    #[test]
    fn rdf_document_lists_items_in_a_sequence() {
        let xml = render(Format::Rdf, &sample_feed());
        assert!(xml.contains("<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\""));
        assert!(xml.contains("<channel rdf:about=\"https://example.test/feed.php\">"));
        assert!(xml.contains("<rdf:Seq>"));
        assert!(xml.contains("<rdf:li rdf:resource=\"https://example.test/t=1\" />"));
        assert!(xml.contains("<item rdf:about=\"https://example.test/t=1\">"));
        assert!(xml.contains("<dc:creator>Alice</dc:creator>"));
        assert!(xml.contains("<dc:subject>News</dc:subject>"));
        assert!(xml.ends_with("</rdf:RDF>\n"));
        assert_eq!(
            Format::Rdf.content_type(),
            "application/rdf+xml; charset=UTF-8"
        );
    }

    #[test]
    fn format_names_and_parsing_round_trip() {
        for format in [Format::Rss, Format::Rss2, Format::Atom, Format::Rdf] {
            assert_eq!(Format::parse(format.name()), Some(format));
        }
        assert_eq!(Format::parse("webslice"), None);
        assert_eq!(Format::default(), Format::Rss2);
    }

    #[test]
    fn cdata_splits_terminators_and_keeps_the_text() {
        assert_eq!(cdata("plain"), "plain");
        assert_eq!(cdata("a]]>b"), "a]]]]><![CDATA[>b");
        assert_eq!(
            extract_cdata(&format!("<![CDATA[{}]]>", cdata("a]]>b"))),
            "a]]>b"
        );
        assert_eq!(cdata("a\0b\u{1}c"), "abc");
        assert_eq!(cdata(""), "");
    }

    fn extract_cdata(wrapped: &str) -> String {
        let mut out = String::new();
        let mut rest = wrapped;
        while let Some(start) = rest.find("<![CDATA[") {
            rest = &rest[start + 9..];
            let Some(end) = rest.find("]]>") else {
                break;
            };
            out.push_str(&rest[..end]);
            rest = &rest[end + 3..];
        }
        out
    }

    #[test]
    fn xml_escaping_covers_every_special_character() {
        assert_eq!(
            xml_escape("a & b < c > d \" e ' f"),
            "a &amp; b &lt; c &gt; d &quot; e &apos; f"
        );
        assert_eq!(xml_escape_attr("a\nb\tc\rd"), "a&#10;b&#9;c&#13;d");
        assert_eq!(xml_escape("a\0b\u{1}c"), "abc");
        assert_eq!(xml_escape("\u{10FFFF}"), "\u{10FFFF}");
        assert_eq!(xml_escape("\u{FFFE}"), "");
    }

    #[test]
    fn dates_use_the_documented_formats() {
        assert_eq!(rfc822_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(rfc822_date(1_792_890_000), "Sun, 25 Oct 2026 01:00:00 GMT");
        assert_eq!(rfc3339_date(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_date(1_792_890_000), "2026-10-25T01:00:00Z");
    }

    #[test]
    fn hostile_fields_are_escaped_and_cannot_break_the_document() {
        let mut feed = Feed::new(
            "</title><script>alert(1)</script>",
            "https://example.test/\"",
        );
        feed.description = "a]]>b\u{0}c".into();
        feed.language = "\" onload=\"x".into();
        feed.entries.push(
            Entry::new("<b>t</b>", "https://example.test/?a=1&b=2")
                .content("<p>]]></content></feed>")
                .author("A\u{0}B")
                .category(Category::new("x\"><y")),
        );
        for format in [Format::Rss, Format::Rss2, Format::Atom, Format::Rdf] {
            let xml = render(format, &feed);
            assert!(!xml.contains("<script>"), "{format:?}");
            assert!(!xml.contains('\u{0}'), "{format:?}");
            assert!(xml.ends_with('\n'));
            assert_eq!(
                xml.matches("<feed").count()
                    + xml.matches("<rss").count()
                    + xml.matches("<rdf:RDF").count(),
                1
            );
        }
        let atom = render(Format::Atom, &feed);
        assert!(atom.contains("<id>https://example.test/&quot;</id>"));
        assert!(atom.contains(
            "<link rel=\"alternate\" type=\"text/html\" href=\"https://example.test/&quot;\" />"
        ));
    }

    #[test]
    fn entries_and_fields_are_bounded() {
        let mut feed = Feed::new("Bounded", "https://example.test/");
        for index in 0..(MAX_ENTRIES + 25) {
            feed.entries.push(Entry::new(
                format!("Entry {index}"),
                format!("https://example.test/{index}"),
            ));
        }
        let xml = render(Format::Rss2, &feed);
        assert_eq!(xml.matches("<item>").count(), MAX_ENTRIES);
        assert!(!xml.contains("Entry 525"));

        let mut feed = Feed::new("Bounded", "https://example.test/");
        let huge = "x".repeat(MAX_FIELD_BYTES * 2);
        feed.entries
            .push(Entry::new("t", "https://example.test/").content(huge));
        let xml = render(Format::Rss2, &feed);
        assert!(xml.len() < MAX_FIELD_BYTES * 2);
        assert!(xml.contains(&"x".repeat(MAX_FIELD_BYTES)));

        let mut feed = Feed::new("Bounded", "https://example.test/");
        let mut entry = Entry::new("t", "https://example.test/");
        for index in 0..(MAX_CATEGORIES + 5) {
            entry = entry.category(Category::new(format!("c{index}")));
        }
        feed.entries.push(entry);
        let xml = render(Format::Rss2, &feed);
        assert_eq!(xml.matches("<category>").count(), MAX_CATEGORIES);
    }

    #[test]
    fn rendering_is_deterministic() {
        let feed = sample_feed();
        for format in [Format::Rss, Format::Rss2, Format::Atom, Format::Rdf] {
            assert_eq!(render(format, &feed), render(format, &feed));
        }
    }

    #[test]
    fn feed_writer_never_panics_on_hostile_input() {
        let mut rng = fador_testutil::Rng::new(0xfeed_beef);
        for text in fador_testutil::MALICIOUS_STRINGS {
            let escaped = xml_escape(text);
            assert!(!escaped.contains(['<', '>']));
            let attr = xml_escape_attr(text);
            assert!(!attr.contains('"'));
            let wrapped = format!("<![CDATA[{}]]>", cdata(text));
            let expected: String = text
                .chars()
                .filter(|character| is_xml_char(*character))
                .collect();
            assert_eq!(extract_cdata(&wrapped), expected);
        }
        for _ in 0..fador_testutil::iterations(400) {
            let length = 1 + rng.below(120);
            let title = rng.text(length);
            let content = rng.text(length);
            let mut feed = Feed::new(title.clone(), "https://example.test/");
            feed.description = content.clone();
            feed.entries.push(Entry::new(title, content));
            for format in [Format::Rss, Format::Rss2, Format::Atom, Format::Rdf] {
                let xml = render(format, &feed);
                assert!(xml.starts_with("<?xml"));
                assert!(!xml.contains('\u{0}'));
            }
        }
    }
}
