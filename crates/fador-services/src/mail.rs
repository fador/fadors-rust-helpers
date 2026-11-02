//! Bounded plain-text mail transport.
//!
//! Three transports share one renderer: a development logger, a local
//! `sendmail` binary and a plain SMTP client. TLS is deliberately not
//! implemented; the SMTP transport is meant for a submission relay on the same
//! host or a trusted network, and TLS terminates in front of it.
//!
//! The renderer produces a single-part RFC 5322 message with a CRLF body,
//! RFC 2047 encoded non-ASCII subjects and display names, and folded header
//! lines. It never emits a line break that the caller did not put in the body:
//! an address, subject or extra header that contains a CR, LF or other control
//! character is rejected instead of being silently rewritten.
//!
//! ```no_run
//! use fador_services::mail::{send, Message, SmtpConfig, Transport};
//!
//! let message = Message::new(
//!     "Forum <forum@example.test>",
//!     "user@example.test",
//!     "New reply",
//!     "Hello\n.leading dot\n",
//! );
//! let transport = Transport::Smtp(
//!     SmtpConfig::new("127.0.0.1", 25).credentials("forum", "secret"),
//! );
//! send(&transport, &message).expect("mail transport");
//! ```
//!
//! # Bounds
//!
//! | item | limit |
//! | --- | --- |
//! | rendered message | 2 MiB body |
//! | address (display form) | 320 bytes |
//! | addr-spec | 254 bytes, local part 64, domain 253 |
//! | recipients | 32 |
//! | subject | 500 characters |
//! | extra headers | 32, each value 900 bytes |
//! | SMTP reply | 64 lines, 4,096 bytes per line, 16 KiB total |

use fador_core::crypto::base64_encode;
use fador_core::util::{civil_from_days, weekday_from_days};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Largest rendered body this crate will send, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
/// Largest accepted display-form address, in bytes.
pub const MAX_ADDRESS_BYTES: usize = 320;
/// Largest accepted addr-spec, in bytes (RFC 5321 path limit).
pub const MAX_ADDR_SPEC_BYTES: usize = 254;
/// Largest accepted subject, in characters.
pub const MAX_SUBJECT_CHARS: usize = 500;
/// Largest number of recipients in one message.
pub const MAX_RECIPIENTS: usize = 32;
/// Largest number of caller-supplied headers in one message.
pub const MAX_HEADERS: usize = 32;
/// Largest accepted caller-supplied header value, in bytes.
pub const MAX_HEADER_VALUE_BYTES: usize = 900;
/// Largest accepted SMTP reply line, in bytes.
pub const MAX_SMTP_LINE: usize = 4_096;
/// Largest number of lines in one SMTP reply.
pub const MAX_SMTP_REPLY_LINES: usize = 64;
/// Largest accepted SMTP reply, in bytes.
pub const MAX_SMTP_REPLY_BYTES: usize = 16 * 1024;

/// Header names the renderer generates itself.
const RESERVED_HEADERS: &[&str] = &[
    "date",
    "from",
    "to",
    "subject",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "list-unsubscribe",
];

/// A mail failure.
///
/// Messages never contain a password, an authentication token or a full
/// address; they name the reason instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailError {
    /// An address is empty, too long or not a plain `local@domain` addr-spec.
    InvalidAddress(&'static str),
    /// A header name or value could break the message framing.
    InvalidHeader(&'static str),
    /// The body or the subject exceeds the configured bound.
    TooLarge,
    /// The message has no recipient.
    NoRecipients,
    /// The SMTP server offered no authentication mechanism this client speaks.
    UnsupportedAuth,
    /// The SMTP server answered something this client will not accept.
    Protocol(String),
    /// A socket, file or process operation failed.
    Io(String),
    /// The SMTP host did not resolve to an address.
    Resolve(String),
    /// The transport configuration is unusable.
    Config(&'static str),
    /// `Transport::Sendmail` has no executable path.
    EmptyPath,
    /// The sendmail child exited unsuccessfully.
    SendmailFailed(String),
}

impl fmt::Display for MailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress(reason) => write!(formatter, "invalid mail address: {reason}"),
            Self::InvalidHeader(reason) => write!(formatter, "invalid mail header: {reason}"),
            Self::TooLarge => write!(formatter, "the message exceeds the size limit"),
            Self::NoRecipients => write!(formatter, "the message has no recipient"),
            Self::UnsupportedAuth => {
                write!(
                    formatter,
                    "the SMTP server offered no supported AUTH mechanism"
                )
            }
            Self::Protocol(reason) => write!(formatter, "SMTP protocol error: {reason}"),
            Self::Io(reason) => write!(formatter, "mail transport I/O error: {reason}"),
            Self::Resolve(reason) => write!(formatter, "cannot resolve the SMTP host: {reason}"),
            Self::Config(reason) => write!(formatter, "invalid mail configuration: {reason}"),
            Self::EmptyPath => write!(formatter, "the sendmail path is empty"),
            Self::SendmailFailed(reason) => write!(formatter, "sendmail failed: {reason}"),
        }
    }
}

impl std::error::Error for MailError {}

/// A parsed mailbox: an optional display name and a validated addr-spec.
///
/// ```no_run
/// use fador_services::mail::Address;
///
/// let address = Address::parse("\"Doe, Jane\" <jane@example.test>").unwrap();
/// assert_eq!(address.addr_spec(), "jane@example.test");
/// assert_eq!(address.to_header(), "\"Doe, Jane\" <jane@example.test>");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    display: Option<String>,
    address: String,
}

impl Address {
    /// Parse a display-form address such as `Name <user@example.test>` or a
    /// bare `user@example.test`.
    ///
    /// The display name may be quoted; it is unquoted and re-quoted on output.
    /// An address with a control character, a second `@`, an empty label, a
    /// label longer than 63 bytes or a non-ASCII domain is rejected. An
    /// internationalised domain must be given in its ACE (`xn--`) form.
    pub fn parse(value: &str) -> Result<Self, MailError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(MailError::InvalidAddress("the address is empty"));
        }
        if value.len() > MAX_ADDRESS_BYTES {
            return Err(MailError::InvalidAddress("the address is too long"));
        }
        if value.chars().any(is_header_control) {
            return Err(MailError::InvalidAddress(
                "the address has a control character",
            ));
        }
        let (display, address) = match value.rfind('<') {
            Some(open) => {
                let close = value[open + 1..]
                    .find('>')
                    .map(|offset| open + 1 + offset)
                    .ok_or(MailError::InvalidAddress("the angle address is not closed"))?;
                if !value[close + 1..].trim().is_empty() {
                    return Err(MailError::InvalidAddress("text follows the angle address"));
                }
                let head = &value[..open];
                if head.contains('<') || head.contains('>') {
                    return Err(MailError::InvalidAddress(
                        "the display name has an angle bracket",
                    ));
                }
                (Some(head.trim()), value[open + 1..close].trim())
            }
            None => {
                if value.contains('>') {
                    return Err(MailError::InvalidAddress(
                        "the angle address has no opening",
                    ));
                }
                (None, value)
            }
        };
        validate_addr_spec(address)?;
        let display = match display {
            Some(display) if !display.is_empty() => Some(unquote_display(display)?),
            _ => None,
        };
        Ok(Self {
            display,
            address: address.to_string(),
        })
    }

    /// The bare `local@domain` part.
    pub fn addr_spec(&self) -> &str {
        &self.address
    }

    /// The display name without quotes, when the input had one.
    pub fn display(&self) -> Option<&str> {
        self.display.as_deref()
    }

    /// Render the mailbox for a `From:` or `To:` header.
    pub fn to_header(&self) -> String {
        match &self.display {
            Some(display) => format!("{} <{}>", encode_display(display), self.address),
            None => self.address.clone(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_header())
    }
}

/// One message handed to a transport.
///
/// The fields are public so a caller can fill them from its own rows; the
/// renderer validates everything again, so a hostile database value cannot
/// reach the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Sender in display form (`Name <user@example.test>`).
    pub from: String,
    /// Recipients in display form.
    pub to: Vec<String>,
    /// Subject, UTF-8. Non-ASCII text is RFC 2047 encoded.
    pub subject: String,
    /// UTF-8 body. `\r\n` and `\r` are normalised to `\n` and re-emitted as CRLF.
    pub body: String,
    /// `true` selects `text/html`, `false` `text/plain`.
    pub html: bool,
    /// Extra headers, validated before rendering.
    pub headers: Vec<(String, String)>,
    /// Optional `List-Unsubscribe` URL.
    pub unsubscribe: Option<String>,
    /// Unix timestamp for the `Date:` header. `None` uses the system clock.
    pub date: Option<i64>,
}

impl Message {
    /// Create a message with one recipient and no extra headers.
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        subject: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: vec![to.into()],
            subject: subject.into(),
            body: body.into(),
            html: false,
            headers: Vec::new(),
            unsubscribe: None,
            date: None,
        }
    }

    /// Select the `text/html` content type.
    #[must_use]
    pub fn html(mut self, html: bool) -> Self {
        self.html = html;
        self
    }

    /// Append one recipient.
    #[must_use]
    pub fn recipient(mut self, to: impl Into<String>) -> Self {
        self.to.push(to.into());
        self
    }

    /// Append one extra header. The value is validated by the renderer.
    ///
    /// The value is emitted as-is, so a non-ASCII value must already be
    /// RFC 2047 encoded by the caller; the renderer only encodes the subject
    /// and the display names it parses from an address.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the `List-Unsubscribe` URL.
    #[must_use]
    pub fn unsubscribe(mut self, url: impl Into<String>) -> Self {
        self.unsubscribe = Some(url.into());
        self
    }

    /// Pin the `Date:` header to a Unix timestamp.
    #[must_use]
    pub fn date(mut self, unix: i64) -> Self {
        self.date = Some(unix);
        self
    }
}

/// SMTP submission settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpConfig {
    /// Host name or address of the submission relay.
    pub host: String,
    /// TCP port. `587` is the usual submission port, `25` the relay port.
    pub port: u16,
    /// AUTH user name; empty disables authentication.
    pub username: String,
    /// AUTH password.
    pub password: String,
    /// Name sent in `EHLO`. Empty means `localhost`.
    pub helo_name: String,
    /// Connect, read and write timeout.
    pub timeout: Duration,
    /// Refuse a rendered message larger than this many bytes.
    pub max_message_bytes: usize,
}

impl SmtpConfig {
    /// A configuration with no credentials, the `localhost` HELO name and a
    /// 30-second timeout.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            username: String::new(),
            password: String::new(),
            helo_name: String::new(),
            timeout: Duration::from_secs(30),
            max_message_bytes: MAX_MESSAGE_BYTES,
        }
    }

    /// Set the AUTH credentials.
    #[must_use]
    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = username.into();
        self.password = password.into();
        self
    }

    /// Set the `EHLO` name.
    #[must_use]
    pub fn helo_name(mut self, name: impl Into<String>) -> Self {
        self.helo_name = name.into();
        self
    }

    /// Set the connect/read/write timeout. It is clamped to 1-300 seconds.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self::new("localhost", 25)
    }
}

/// Where a rendered message goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Write one metadata line to stderr and drop the message. Useful in
    /// development and tests.
    Log,
    /// Pipe the message to a `sendmail`-compatible binary with `-i -t -f`.
    Sendmail {
        /// Executable path.
        path: PathBuf,
    },
    /// Submit the message to an SMTP relay.
    Smtp(SmtpConfig),
}

impl Transport {
    /// The development logger.
    pub fn log() -> Self {
        Self::Log
    }

    /// A sendmail-compatible binary.
    pub fn sendmail(path: impl Into<PathBuf>) -> Self {
        Self::Sendmail { path: path.into() }
    }

    /// An SMTP relay.
    pub fn smtp(config: SmtpConfig) -> Self {
        Self::Smtp(config)
    }
}

/// A validated message ready for a transport.
struct Prepared {
    from: Address,
    to: Vec<Address>,
    subject: String,
    body: String,
    headers: Vec<(String, String)>,
    unsubscribe: Option<String>,
    date: i64,
}

/// Render a message as an RFC 5322 document.
///
/// The result uses CRLF line endings and ends with the last body line, so a
/// transport appends its own terminator. Dot-stuffing is not part of the
/// document; [`dot_stuff`] applies it for the SMTP `DATA` command.
pub fn render_rfc5322(message: &Message) -> Result<String, MailError> {
    let prepared = prepare(message)?;
    Ok(render_prepared(&prepared, message.html))
}

/// Validate and send a message with the given transport.
///
/// `Transport::Log` writes one line with the recipient and subject to stderr;
/// the body, the password and the credentials are never logged.
pub fn send(transport: &Transport, message: &Message) -> Result<(), MailError> {
    let prepared = prepare(message)?;
    let wire = render_prepared(&prepared, message.html);
    match transport {
        Transport::Log => {
            let recipients = prepared
                .to
                .iter()
                .map(Address::to_header)
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!("mail (log): to={recipients} subject={}", prepared.subject);
            Ok(())
        }
        Transport::Sendmail { path } => sendmail(path, &prepared.from, &wire),
        Transport::Smtp(config) => smtp_send(config, &prepared, &wire),
    }
}

/// Apply SMTP dot-stuffing and append the end-of-data terminator.
///
/// A line that starts with `.` is prefixed with one more dot, the message is
/// terminated with CRLF when it does not already end with one, and the final
/// `.\r\n` is appended.
pub fn dot_stuff(message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 8);
    let mut at_line_start = true;
    for byte in message.bytes() {
        if at_line_start && byte == b'.' {
            out.push(b'.');
        }
        out.push(byte);
        at_line_start = byte == b'\n';
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Format a Unix timestamp as an RFC 5322 date with a numeric UTC zone.
///
/// ```no_run
/// use fador_services::mail::mail_date;
///
/// assert_eq!(mail_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
/// ```
pub fn mail_date(now: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = now.div_euclid(86_400);
    let seconds = now.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = weekday_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        DAYS[weekday % 7],
        day,
        MONTHS[(month as usize).saturating_sub(1)],
        year,
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

/// Parse the `AUTH` mechanisms advertised in an `EHLO` reply.
///
/// Both `AUTH PLAIN LOGIN` and `AUTH=PLAIN LOGIN` are understood, matching is
/// case-insensitive, and the result is de-duplicated in advertisement order.
pub fn parse_auth_mechanisms(lines: &[String]) -> Vec<String> {
    let mut mechanisms: Vec<String> = Vec::new();
    for line in lines {
        let line = line.trim();
        let (keyword, rest) = match line.split_once([' ', '=']) {
            Some((keyword, rest)) => (keyword, rest),
            None => (line, ""),
        };
        if !keyword.eq_ignore_ascii_case("AUTH") {
            continue;
        }
        for token in rest.split([' ', '=']) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let token = token.to_ascii_uppercase();
            if !mechanisms.contains(&token) {
                mechanisms.push(token);
            }
        }
    }
    mechanisms
}

/// One SMTP reply: the status code and the text lines.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn text(&self) -> String {
        self.lines.join(" ")
    }
}

fn prepare(message: &Message) -> Result<Prepared, MailError> {
    let from = Address::parse(&message.from)?;
    if message.to.is_empty() {
        return Err(MailError::NoRecipients);
    }
    if message.to.len() > MAX_RECIPIENTS {
        return Err(MailError::TooLarge);
    }
    let to = message
        .to
        .iter()
        .map(|value| Address::parse(value))
        .collect::<Result<Vec<_>, _>>()?;
    let subject = prepare_subject(&message.subject)?;
    let body = prepare_body(&message.body)?;
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(MailError::TooLarge);
    }
    if message.headers.len() > MAX_HEADERS {
        return Err(MailError::TooLarge);
    }
    let mut headers = Vec::with_capacity(message.headers.len());
    for (name, value) in &message.headers {
        validate_header(name, value)?;
        if RESERVED_HEADERS
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(MailError::InvalidHeader(
                "the renderer generates this header itself",
            ));
        }
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    let unsubscribe = match &message.unsubscribe {
        Some(url) => {
            validate_unsubscribe(url)?;
            Some(url.trim().to_string())
        }
        None => None,
    };
    Ok(Prepared {
        from,
        to,
        subject,
        body,
        headers,
        unsubscribe,
        date: message.date.unwrap_or_else(unix_now),
    })
}

fn render_prepared(prepared: &Prepared, html: bool) -> String {
    let mut out = String::with_capacity(prepared.body.len() + 512);
    push_header(&mut out, "Date", &mail_date(prepared.date));
    push_header(&mut out, "From", &prepared.from.to_header());
    push_header(&mut out, "To", &format_address_list(&prepared.to));
    push_header(&mut out, "Subject", &prepared.subject);
    out.push_str("MIME-Version: 1.0\r\n");
    if html {
        out.push_str("Content-Type: text/html; charset=UTF-8\r\n");
    } else {
        out.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
    }
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    if let Some(url) = &prepared.unsubscribe {
        push_header(&mut out, "List-Unsubscribe", &format!("<{url}>"));
    }
    for (name, value) in &prepared.headers {
        push_header(&mut out, name, value);
    }
    out.push_str("\r\n");
    out.push_str(&prepared.body);
    out
}

fn push_header(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push_str(": ");
    let mut first = true;
    for part in value.split("\r\n ") {
        if !first {
            out.push_str("\r\n ");
        }
        out.push_str(part);
        first = false;
    }
    out.push_str("\r\n");
}

fn format_address_list(addresses: &[Address]) -> String {
    let mut out = String::new();
    let mut line_length = 0usize;
    for (index, address) in addresses.iter().enumerate() {
        let header = address.to_header();
        if index == 0 {
            line_length = header.len();
            out.push_str(&header);
        } else if line_length + 2 + header.len() > 78 {
            out.push_str(",\r\n ");
            line_length = 1 + header.len();
            out.push_str(&header);
        } else {
            out.push_str(", ");
            line_length += 2 + header.len();
            out.push_str(&header);
        }
    }
    out
}

fn prepare_subject(subject: &str) -> Result<String, MailError> {
    if subject.chars().any(is_header_control) {
        return Err(MailError::InvalidHeader(
            "the subject has a control character",
        ));
    }
    let subject = subject.trim();
    if subject.chars().count() > MAX_SUBJECT_CHARS {
        return Err(MailError::TooLarge);
    }
    if subject.is_ascii() {
        return Ok(subject.to_string());
    }
    Ok(encode_subject(subject))
}

fn prepare_body(body: &str) -> Result<String, MailError> {
    if body
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\t' | '\n' | '\r'))
    {
        return Err(MailError::InvalidHeader("the body has a control character"));
    }
    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(normalized.len() + normalized.len() / 32 + 2);
    out.push_str(&normalized.replace('\n', "\r\n"));
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }
    Ok(out)
}

fn validate_header(name: &str, value: &str) -> Result<(), MailError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 78 {
        return Err(MailError::InvalidHeader("the header name has a bad length"));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(MailError::InvalidHeader(
            "the header name has an illegal character",
        ));
    }
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return Err(MailError::InvalidHeader("the header value is too long"));
    }
    if value.chars().any(is_header_control) {
        return Err(MailError::InvalidHeader(
            "the header value has a control character",
        ));
    }
    Ok(())
}

fn validate_unsubscribe(url: &str) -> Result<(), MailError> {
    let url = url.trim();
    if url.is_empty() || url.len() > MAX_HEADER_VALUE_BYTES - 2 {
        return Err(MailError::InvalidHeader(
            "the List-Unsubscribe URL has a bad length",
        ));
    }
    if url
        .chars()
        .any(|ch| is_header_control(ch) || ch.is_whitespace())
    {
        return Err(MailError::InvalidHeader(
            "the List-Unsubscribe URL has a control character",
        ));
    }
    if url.contains(['<', '>']) {
        return Err(MailError::InvalidHeader(
            "the List-Unsubscribe URL has an angle bracket",
        ));
    }
    if !(url.starts_with("https://") || url.starts_with("http://") || url.starts_with("mailto:")) {
        return Err(MailError::InvalidHeader(
            "the List-Unsubscribe URL has an unsupported scheme",
        ));
    }
    Ok(())
}

fn validate_addr_spec(address: &str) -> Result<(), MailError> {
    if address.is_empty() {
        return Err(MailError::InvalidAddress("the addr-spec is empty"));
    }
    if address.len() > MAX_ADDR_SPEC_BYTES {
        return Err(MailError::InvalidAddress("the addr-spec is too long"));
    }
    if !address.is_ascii() {
        return Err(MailError::InvalidAddress(
            "the addr-spec is not ASCII; use an ACE domain",
        ));
    }
    let mut parts = address.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err(MailError::InvalidAddress(
            "the addr-spec has more than one @",
        ));
    }
    if local.is_empty() || domain.is_empty() {
        return Err(MailError::InvalidAddress(
            "the addr-spec is missing a local part or a domain",
        ));
    }
    if local.len() > 64 {
        return Err(MailError::InvalidAddress("the local part is too long"));
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(MailError::InvalidAddress(
            "the local part has an empty label",
        ));
    }
    if !local
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&byte))
    {
        return Err(MailError::InvalidAddress(
            "the local part has an illegal character",
        ));
    }
    if domain.len() > 253 {
        return Err(MailError::InvalidAddress("the domain is too long"));
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(MailError::InvalidAddress("the domain has an empty label"));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(MailError::InvalidAddress("a domain label has a bad length"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(MailError::InvalidAddress(
                "a domain label starts or ends with a hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(MailError::InvalidAddress(
                "a domain label has an illegal character",
            ));
        }
    }
    Ok(())
}

fn unquote_display(display: &str) -> Result<String, MailError> {
    let display = display.trim();
    let inner = if display.len() >= 2 && display.starts_with('"') && display.ends_with('"') {
        &display[1..display.len() - 1]
    } else {
        if display.contains('"') {
            return Err(MailError::InvalidAddress(
                "the display name has a stray quote",
            ));
        }
        display
    };
    if inner.contains(['"', '\\', '<', '>']) {
        return Err(MailError::InvalidAddress(
            "the display name has an illegal character",
        ));
    }
    if inner.chars().any(is_header_control) {
        return Err(MailError::InvalidAddress(
            "the display name has a control character",
        ));
    }
    Ok(inner.trim().to_string())
}

fn encode_display(display: &str) -> String {
    if display.is_ascii() {
        if display
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.'))
        {
            return display.to_string();
        }
        return format!("\"{}\"", display.replace('\\', "\\\\").replace('"', "\\\""));
    }
    encode_subject(display)
}

fn encode_subject(value: &str) -> String {
    let mut words = Vec::new();
    let mut chunk = String::new();
    for character in value.chars() {
        if !chunk.is_empty() && chunk.len() + character.len_utf8() > 45 {
            words.push(encoded_word(&chunk));
            chunk.clear();
        }
        chunk.push(character);
    }
    if !chunk.is_empty() {
        words.push(encoded_word(&chunk));
    }
    words.join("\r\n ")
}

fn encoded_word(value: &str) -> String {
    format!("=?UTF-8?B?{}?=", base64_encode(value.as_bytes()))
}

fn is_header_control(character: char) -> bool {
    character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// SMTP transport
// ---------------------------------------------------------------------------

fn smtp_send(config: &SmtpConfig, prepared: &Prepared, wire: &str) -> Result<(), MailError> {
    let host = config.host.trim();
    if host.is_empty() {
        return Err(MailError::Config("the SMTP host is empty"));
    }
    if host
        .chars()
        .any(|ch| ch.is_whitespace() || is_header_control(ch))
    {
        return Err(MailError::Config("the SMTP host has a control character"));
    }
    if config.port == 0 {
        return Err(MailError::Config("the SMTP port is zero"));
    }
    let helo = config.helo_name.trim();
    let helo = if helo.is_empty() { "localhost" } else { helo };
    if helo.len() > 255
        || helo
            .chars()
            .any(|ch| ch.is_whitespace() || is_header_control(ch))
    {
        return Err(MailError::Config("the EHLO name is invalid"));
    }
    if wire.len() > config.max_message_bytes.min(MAX_MESSAGE_BYTES) {
        return Err(MailError::TooLarge);
    }
    let timeout = config
        .timeout
        .clamp(Duration::from_secs(1), Duration::from_secs(300));
    let mut stream = connect(host, config.port, timeout)?;
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|error| MailError::Io(error.to_string()))?,
    );

    let greeting = read_reply(&mut reader)?;
    if greeting.code != 220 {
        return Err(MailError::Protocol(format!(
            "the greeting was {}",
            greeting.code
        )));
    }
    let mut capabilities = Vec::new();
    send_command(&mut stream, &format!("EHLO {helo}"))?;
    let ehlo = read_reply(&mut reader)?;
    if ehlo.code == 250 {
        capabilities = parse_auth_mechanisms(&ehlo.lines);
    } else {
        send_command(&mut stream, &format!("HELO {helo}"))?;
        expect_reply(&mut reader, &[250])?;
    }
    if !config.username.is_empty() {
        authenticate(config, &mut stream, &mut reader, &capabilities)?;
    }
    send_command(
        &mut stream,
        &format!("MAIL FROM:<{}>", prepared.from.addr_spec()),
    )?;
    expect_reply(&mut reader, &[250])?;
    for recipient in &prepared.to {
        send_command(&mut stream, &format!("RCPT TO:<{}>", recipient.addr_spec()))?;
        expect_reply(&mut reader, &[250, 251])?;
    }
    send_command(&mut stream, "DATA")?;
    expect_reply(&mut reader, &[354])?;
    stream
        .write_all(&dot_stuff(wire))
        .map_err(|error| MailError::Io(error.to_string()))?;
    expect_reply(&mut reader, &[250])?;
    let _ = send_command(&mut stream, "QUIT");
    Ok(())
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, MailError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| MailError::Resolve(error.to_string()))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(MailError::Resolve("the host has no address".into()));
    }
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|error| MailError::Io(error.to_string()))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|error| MailError::Io(error.to_string()))?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(MailError::Io(
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "connect failed".into()),
    ))
}

fn authenticate(
    config: &SmtpConfig,
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    mechanisms: &[String],
) -> Result<(), MailError> {
    if config.username.contains(['\0', '\r', '\n']) || config.password.contains(['\0', '\r', '\n']) {
        return Err(MailError::Protocol(
            "SMTP credentials must not contain NUL, CR, or LF".into(),
        ));
    }
    let advertised = |name: &str| mechanisms.iter().any(|mechanism| mechanism == name);
    let have_capabilities = !mechanisms.is_empty();
    let mut attempts = 0usize;
    if !have_capabilities || advertised("PLAIN") {
        attempts += 1;
        let token =
            base64_encode(format!("\0{}\0{}", config.username.trim(), config.password).as_bytes());
        send_command(writer, &format!("AUTH PLAIN {token}"))?;
        let reply = read_reply(reader)?;
        if reply.code == 235 {
            return Ok(());
        }
    }
    if !have_capabilities || advertised("LOGIN") {
        attempts += 1;
        send_command(writer, "AUTH LOGIN")?;
        let reply = read_reply(reader)?;
        if reply.code == 334 {
            send_command(writer, &base64_encode(config.username.trim().as_bytes()))?;
            let reply = read_reply(reader)?;
            if reply.code == 334 {
                send_command(writer, &base64_encode(config.password.as_bytes()))?;
                let reply = read_reply(reader)?;
                if reply.code == 235 {
                    return Ok(());
                }
            }
        }
    }
    if attempts == 0 {
        Err(MailError::UnsupportedAuth)
    } else {
        Err(MailError::Protocol(
            "the server rejected every AUTH attempt".into(),
        ))
    }
}

fn send_command(writer: &mut TcpStream, command: &str) -> Result<(), MailError> {
    if command.contains(['\r', '\n']) {
        return Err(MailError::Protocol(
            "refusing to send a command with a line break".into(),
        ));
    }
    writer
        .write_all(command.as_bytes())
        .and_then(|()| writer.write_all(b"\r\n"))
        .map_err(|error| MailError::Io(error.to_string()))
}

fn expect_reply(reader: &mut BufReader<TcpStream>, expected: &[u16]) -> Result<(), MailError> {
    let reply = read_reply(reader)?;
    if expected.contains(&reply.code) {
        Ok(())
    } else {
        Err(MailError::Protocol(format!(
            "the server replied {} instead of {expected:?}: {}",
            reply.code,
            reply.text()
        )))
    }
}

fn read_reply<R: BufRead>(reader: &mut R) -> Result<Reply, MailError> {
    let mut lines = Vec::new();
    let mut code = 0u16;
    let mut total = 0usize;
    for _ in 0..MAX_SMTP_REPLY_LINES {
        let mut buffer = Vec::new();
        let read = reader
            .by_ref()
            .take(MAX_SMTP_LINE as u64 + 1)
            .read_until(b'\n', &mut buffer)
            .map_err(|error| MailError::Io(error.to_string()))?;
        if read == 0 {
            return Err(MailError::Protocol(
                "the server closed the connection".into(),
            ));
        }
        if buffer.len() > MAX_SMTP_LINE {
            return Err(MailError::Protocol("a reply line is too long".into()));
        }
        total = total.saturating_add(read);
        if total > MAX_SMTP_REPLY_BYTES {
            return Err(MailError::Protocol("the reply is too large".into()));
        }
        let line = String::from_utf8_lossy(&buffer);
        let line = line.trim_end_matches(['\r', '\n']);
        if line.len() < 3 {
            return Err(MailError::Protocol("a reply line is too short".into()));
        }
        let status = line
            .as_bytes()
            .get(..3)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|status| status.parse::<u16>().ok())
            .ok_or_else(|| MailError::Protocol("a reply line has no status code".into()))?;
        if code == 0 {
            code = status;
        } else if status != code {
            return Err(MailError::Protocol(format!(
                "inconsistent status code in multiline reply: expected {code}, got {status}"
            )));
        }
        let continuation = line.as_bytes().get(3) == Some(&b'-');
        lines.push(line.get(4..).unwrap_or("").to_string());
        if !continuation {
            return Ok(Reply { code, lines });
        }
    }
    Err(MailError::Protocol("the reply has too many lines".into()))
}

// ---------------------------------------------------------------------------
// Sendmail transport
// ---------------------------------------------------------------------------

fn sendmail(path: &PathBuf, from: &Address, wire: &str) -> Result<(), MailError> {
    if path.as_os_str().is_empty() {
        return Err(MailError::EmptyPath);
    }
    let mut child = Command::new(path)
        .arg("-i")
        .arg("-t")
        .arg("-f")
        .arg(from.addr_spec())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| MailError::SendmailFailed(error.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(wire.as_bytes())
            .map_err(|error| MailError::SendmailFailed(error.to_string()))?;
    }
    let status = child
        .wait()
        .map_err(|error| MailError::SendmailFailed(error.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(MailError::SendmailFailed(format!("exited with {status}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;

    fn sample_message() -> Message {
        Message::new(
            "Forum <forum@example.test>",
            "friend@example.test",
            "Topic reply",
            "Hello\n.leading dot\n",
        )
        .date(0)
    }

    #[test]
    fn renders_rfc5322_headers_and_crlf_body() {
        let wire = render_rfc5322(&sample_message()).expect("render");
        assert!(wire.starts_with("Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"));
        assert!(wire.contains("From: Forum <forum@example.test>\r\n"));
        assert!(wire.contains("To: friend@example.test\r\n"));
        assert!(wire.contains("Subject: Topic reply\r\n"));
        assert!(wire.contains("MIME-Version: 1.0\r\n"));
        assert!(wire.contains("Content-Type: text/plain; charset=UTF-8\r\n"));
        assert!(wire.contains("Content-Transfer-Encoding: 8bit\r\n"));
        assert!(wire.ends_with("\r\nHello\r\n.leading dot\r\n"));
        assert!(!wire.contains("\n\nHello"));
    }

    #[test]
    fn html_content_type_and_extra_headers() {
        let message = sample_message()
            .html(true)
            .header("Reply-To", "reply@example.test")
            .unsubscribe("https://example.test/unsubscribe");
        let wire = render_rfc5322(&message).expect("render");
        assert!(wire.contains("Content-Type: text/html; charset=UTF-8\r\n"));
        assert!(wire.contains("Reply-To: reply@example.test\r\n"));
        assert!(wire.contains("List-Unsubscribe: <https://example.test/unsubscribe>\r\n"));
    }

    #[test]
    fn encodes_non_ascii_subjects_and_display_names() {
        let wire = render_rfc5322(
            &Message::new(
                "Hyvää päivää <a@example.test>",
                "b@example.test",
                "Hyvää päivää",
                "Hei",
            )
            .date(0),
        )
        .expect("render");
        assert!(wire.contains("Subject: =?UTF-8?B?"));
        assert!(wire.contains("From: =?UTF-8?B?"));
        assert!(!wire.contains("Subject: Hyvää"));
    }

    #[test]
    fn rejects_header_injection_in_addresses() {
        for hostile in [
            "a@example.test\r\nBcc: x@example.test",
            "a@example.test\nBcc: x@example.test",
            "a@example.test\0",
            "a@example.test trailing",
        ] {
            let error = render_rfc5322(&Message::new(
                "forum@example.test",
                hostile,
                "Subject",
                "Body",
            ))
            .expect_err("hostile recipient");
            assert!(matches!(error, MailError::InvalidAddress(_)));
        }
        let error = render_rfc5322(&Message::new(
            "forum@example.test\r\nBcc: x@example.test",
            "user@example.test",
            "Subject",
            "Body",
        ))
        .expect_err("hostile sender");
        assert!(matches!(error, MailError::InvalidAddress(_)));
    }

    #[test]
    fn rejects_header_injection_in_subject_and_headers() {
        let mut message = sample_message();
        message.subject = "Hi\r\nBcc: x@example.test".into();
        assert!(matches!(
            render_rfc5322(&message),
            Err(MailError::InvalidHeader(_))
        ));

        let mut message = sample_message();
        message
            .headers
            .push(("X-Test".into(), "a\r\nBcc: x@example.test".into()));
        assert!(matches!(
            render_rfc5322(&message),
            Err(MailError::InvalidHeader(_))
        ));

        let mut message = sample_message();
        message
            .headers
            .push(("X-Test: evil".into(), "value".into()));
        assert!(matches!(
            render_rfc5322(&message),
            Err(MailError::InvalidHeader(_))
        ));

        let mut message = sample_message();
        message.headers.push(("Subject".into(), "duplicate".into()));
        assert!(matches!(
            render_rfc5322(&message),
            Err(MailError::InvalidHeader(_))
        ));

        let mut message = sample_message();
        message.unsubscribe = Some("https://example.test/\r\nBcc: x".into());
        assert!(matches!(
            render_rfc5322(&message),
            Err(MailError::InvalidHeader(_))
        ));
    }

    #[test]
    fn validates_addresses() {
        for valid in [
            "user@example.test",
            "User Name <user@example.test>",
            "\"Doe, Jane\" <jane@example.test>",
            "first.last+tag@sub.example.test",
        ] {
            assert!(Address::parse(valid).is_ok(), "{valid} should parse");
        }
        for invalid in [
            "",
            "no-at-sign",
            "@example.test",
            "user@",
            "user@@example.test",
            "user name@example.test",
            "user@example..test",
            "user@-example.test",
            "user@example.test.",
            ".user@example.test",
            "user..name@example.test",
            "user@exa mple.test",
            "user@example.test\r\nBcc: x@example.test",
            "<a@example.test> trailing",
        ] {
            assert!(Address::parse(invalid).is_err(), "{invalid} should fail");
        }
        assert_eq!(
            Address::parse("\"Doe, Jane\" <jane@example.test>")
                .unwrap()
                .to_header(),
            "\"Doe, Jane\" <jane@example.test>"
        );
        assert_eq!(
            Address::parse("User Name <user@example.test>")
                .unwrap()
                .to_header(),
            "User Name <user@example.test>"
        );
    }

    #[test]
    fn address_parser_never_panics_on_hostile_input() {
        let mut rng = fador_testutil::Rng::new(0x5eed);
        for text in fador_testutil::MALICIOUS_STRINGS {
            let _ = Address::parse(text);
        }
        for _ in 0..fador_testutil::iterations(2_000) {
            let length = 1 + rng.below(80);
            let value = rng.text(length);
            if let Ok(address) = Address::parse(&value) {
                assert!(!address.addr_spec().is_empty());
                assert!(!address.to_header().contains(['\r', '\n']));
            }
        }
    }

    #[test]
    fn dot_stuffing_prefixes_only_line_starts() {
        let stuffed = dot_stuff("Subject: x\r\n\r\n.one\r\n..two\r\nthree\r\n");
        assert_eq!(
            String::from_utf8(stuffed).unwrap(),
            "Subject: x\r\n\r\n..one\r\n...two\r\nthree\r\n.\r\n"
        );
        assert_eq!(
            String::from_utf8(dot_stuff("no terminator")).unwrap(),
            "no terminator\r\n.\r\n"
        );
        assert_eq!(String::from_utf8(dot_stuff("")).unwrap(), "\r\n.\r\n");
    }

    #[test]
    fn date_uses_a_numeric_utc_offset() {
        assert_eq!(mail_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(mail_date(1_792_890_000), "Sun, 25 Oct 2026 01:00:00 +0000");
        assert_eq!(mail_date(-1), "Wed, 31 Dec 1969 23:59:59 +0000");
    }

    #[test]
    fn parses_ehlo_auth_mechanisms() {
        let lines = vec![
            "example.test".to_string(),
            "AUTH PLAIN LOGIN".to_string(),
            "AUTH=XOAUTH2".to_string(),
            "SIZE 10240000".to_string(),
            "STARTTLS".to_string(),
        ];
        assert_eq!(
            parse_auth_mechanisms(&lines),
            vec!["PLAIN", "LOGIN", "XOAUTH2"]
        );
        assert!(parse_auth_mechanisms(&["SIZE 1".to_string()]).is_empty());
        assert_eq!(
            parse_auth_mechanisms(&["auth=plain login".to_string()]),
            vec!["PLAIN", "LOGIN"]
        );
    }

    #[test]
    fn reply_reader_is_bounded_and_multiline() {
        let mut cursor = Cursor::new(b"250-first\r\n250 second\r\n".to_vec());
        let reply = read_reply(&mut cursor).expect("reply");
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines, vec!["first", "second"]);

        let endless = b"250-continued\r\n".repeat(MAX_SMTP_REPLY_LINES + 1);
        let mut cursor = Cursor::new(endless);
        assert!(matches!(
            read_reply(&mut cursor),
            Err(MailError::Protocol(_))
        ));

        let long_line = format!("250 {}\r\n", "x".repeat(MAX_SMTP_LINE + 10));
        let mut cursor = Cursor::new(long_line.into_bytes());
        assert!(matches!(
            read_reply(&mut cursor),
            Err(MailError::Protocol(_))
        ));

        let mut cursor = Cursor::new(b"2\r\n".to_vec());
        assert!(matches!(
            read_reply(&mut cursor),
            Err(MailError::Protocol(_))
        ));

        let mut cursor = Cursor::new(Vec::new());
        assert!(matches!(
            read_reply(&mut cursor),
            Err(MailError::Protocol(_))
        ));
    }

    #[test]
    fn reply_parser_never_panics_on_hostile_input() {
        let mut rng = fador_testutil::Rng::new(0xfeed);
        for text in fador_testutil::MALICIOUS_STRINGS {
            let mut cursor = Cursor::new(text.as_bytes().to_vec());
            let _ = read_reply(&mut cursor);
        }
        for _ in 0..fador_testutil::iterations(2_000) {
            let length = 1 + rng.below(256);
            let bytes = rng.bytes(length);
            let mut cursor = Cursor::new(bytes);
            let _ = read_reply(&mut cursor);
        }
    }

    #[test]
    fn oversized_messages_and_recipients_are_rejected() {
        let mut message = sample_message();
        message.body = "x".repeat(MAX_MESSAGE_BYTES + 1);
        assert_eq!(render_rfc5322(&message), Err(MailError::TooLarge));

        let mut message = sample_message();
        message.subject = "x".repeat(MAX_SUBJECT_CHARS + 1);
        assert_eq!(render_rfc5322(&message), Err(MailError::TooLarge));

        let mut message = sample_message();
        message.to = (0..=MAX_RECIPIENTS)
            .map(|index| format!("user{index}@example.test"))
            .collect();
        assert_eq!(render_rfc5322(&message), Err(MailError::TooLarge));

        let mut message = sample_message();
        message.body = "a\0b".into();
        assert!(matches!(
            render_rfc5322(&message),
            Err(MailError::InvalidHeader(_))
        ));
    }

    #[test]
    fn long_recipient_lists_are_folded() {
        let message = Message::new(
            "forum@example.test",
            "first@example.test",
            "Subject",
            "Body",
        )
        .recipient("second-recipient@example.test")
        .recipient("third-recipient@example.test")
        .recipient("fourth-recipient@example.test")
        .recipient("fifth-recipient@example.test")
        .date(0);
        let wire = render_rfc5322(&message).expect("render");
        for line in wire.lines() {
            assert!(line.len() <= 998, "line is too long: {line}");
        }
        assert!(wire.contains(",\r\n "));
    }

    #[test]
    fn log_transport_never_needs_a_network() {
        send(&Transport::Log, &sample_message()).expect("log transport");
    }

    #[test]
    fn sendmail_errors_are_reported() {
        assert_eq!(
            send(&Transport::sendmail(""), &sample_message()),
            Err(MailError::EmptyPath)
        );
        let missing = if cfg!(windows) {
            "C:\\fador-services-missing-sendmail.exe"
        } else {
            "/nonexistent/fador-services-sendmail"
        };
        assert!(matches!(
            send(&Transport::sendmail(missing), &sample_message()),
            Err(MailError::SendmailFailed(_))
        ));
    }

    /// One scripted SMTP server. The handler receives the reader and writer and
    /// returns the command transcript and the `DATA` payload.
    fn serve<F>(handler: F) -> (u16, thread::JoinHandle<(Vec<String>, String)>)
    where
        F: FnOnce(&mut BufReader<TcpStream>, &mut TcpStream) -> (Vec<String>, String)
            + Send
            + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut writer = stream;
            handler(&mut reader, &mut writer)
        });
        (port, handle)
    }

    fn read_line(reader: &mut BufReader<TcpStream>) -> Option<String> {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        Some(line.trim_end_matches(['\r', '\n']).to_string())
    }

    fn read_data(reader: &mut BufReader<TcpStream>) -> String {
        let mut body = String::new();
        while let Some(line) = read_line(reader) {
            if line == "." {
                break;
            }
            body.push_str(&line);
            body.push('\n');
        }
        body
    }

    #[test]
    fn smtp_submits_a_dot_stuffed_message_with_auth_plain() {
        let (port, server) = serve(|reader, writer| {
            writer.write_all(b"220 fake ESMTP\r\n").expect("greeting");
            let mut transcript = Vec::new();
            let mut body = String::new();
            while let Some(line) = read_line(reader) {
                transcript.push(line.clone());
                let upper = line.to_ascii_uppercase();
                if upper.starts_with("EHLO") {
                    writer
                        .write_all(b"250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10240000\r\n")
                        .expect("ehlo");
                } else if upper.starts_with("AUTH PLAIN") {
                    writer.write_all(b"235 2.7.0 accepted\r\n").expect("auth");
                } else if upper.starts_with("MAIL FROM") || upper.starts_with("RCPT TO") {
                    writer.write_all(b"250 OK\r\n").expect("ok");
                } else if upper == "DATA" {
                    writer.write_all(b"354 go ahead\r\n").expect("data");
                    body = read_data(reader);
                    writer.write_all(b"250 queued\r\n").expect("queued");
                } else if upper == "QUIT" {
                    writer.write_all(b"221 bye\r\n").expect("bye");
                    break;
                } else {
                    writer.write_all(b"250 OK\r\n").expect("ok");
                }
            }
            (transcript, body)
        });
        let transport = Transport::Smtp(
            SmtpConfig::new("127.0.0.1", port)
                .credentials("forum", "secret")
                .timeout(Duration::from_secs(5)),
        );
        send(&transport, &sample_message()).expect("send");
        let (transcript, body) = server.join().expect("server");
        assert!(transcript
            .iter()
            .any(|line| line == "MAIL FROM:<forum@example.test>"));
        assert!(transcript
            .iter()
            .any(|line| line == "RCPT TO:<friend@example.test>"));
        assert!(transcript.iter().any(|line| line == "QUIT"));
        assert!(transcript
            .iter()
            .any(|line| line.starts_with("AUTH PLAIN ")));
        assert!(body.contains("..leading dot"), "dot-stuffing: {body}");
        assert!(body.contains("Subject: Topic reply"));
    }

    #[test]
    fn smtp_falls_back_to_helo_and_auth_login() {
        let (port, server) = serve(|reader, writer| {
            writer.write_all(b"220 fake ESMTP\r\n").expect("greeting");
            let mut transcript = Vec::new();
            let mut login_step = 0u8;
            while let Some(line) = read_line(reader) {
                transcript.push(line.clone());
                let upper = line.to_ascii_uppercase();
                if login_step == 1 {
                    writer.write_all(b"334 UGFzc3dvcmQ6\r\n").expect("pass");
                    login_step = 2;
                    continue;
                }
                if login_step == 2 {
                    writer.write_all(b"235 authenticated\r\n").expect("ok");
                    login_step = 0;
                    continue;
                }
                if upper.starts_with("EHLO") {
                    writer.write_all(b"502 not implemented\r\n").expect("ehlo");
                } else if upper.starts_with("HELO") {
                    writer.write_all(b"250 hello\r\n").expect("helo");
                } else if upper == "AUTH LOGIN" {
                    writer.write_all(b"334 VXNlcm5hbWU6\r\n").expect("user");
                    login_step = 1;
                } else if upper == "DATA" {
                    writer.write_all(b"354 go ahead\r\n").expect("data");
                    let _ = read_data(reader);
                    writer.write_all(b"250 queued\r\n").expect("queued");
                } else if upper == "QUIT" {
                    writer.write_all(b"221 bye\r\n").expect("bye");
                    break;
                } else {
                    writer.write_all(b"250 OK\r\n").expect("ok");
                }
            }
            (transcript, String::new())
        });
        let transport = Transport::Smtp(
            SmtpConfig::new("127.0.0.1", port)
                .credentials("forum", "secret")
                .timeout(Duration::from_secs(5)),
        );
        send(&transport, &sample_message()).expect("send");
        let (transcript, _) = server.join().expect("server");
        assert!(transcript.iter().any(|line| line.starts_with("EHLO")));
        assert!(transcript.iter().any(|line| line.starts_with("HELO")));
        assert!(transcript.iter().any(|line| line == "AUTH LOGIN"));
    }

    #[test]
    fn smtp_rejects_an_unsupported_authentication_offer() {
        let (port, server) = serve(|reader, writer| {
            writer.write_all(b"220 fake ESMTP\r\n").expect("greeting");
            while let Some(line) = read_line(reader) {
                if line.to_ascii_uppercase().starts_with("EHLO") {
                    writer
                        .write_all(b"250-fake\r\n250 AUTH XOAUTH2\r\n")
                        .expect("ehlo");
                } else {
                    writer.write_all(b"250 OK\r\n").expect("ok");
                }
            }
            (Vec::new(), String::new())
        });
        let transport = Transport::Smtp(
            SmtpConfig::new("127.0.0.1", port)
                .credentials("forum", "secret")
                .timeout(Duration::from_secs(5)),
        );
        let error = send(&transport, &sample_message()).expect_err("auth");
        assert_eq!(error, MailError::UnsupportedAuth);
        let _ = server.join();
    }

    #[test]
    fn smtp_reports_a_refused_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        drop(listener);
        let transport =
            Transport::Smtp(SmtpConfig::new("127.0.0.1", port).timeout(Duration::from_secs(1)));
        assert!(matches!(
            send(&transport, &sample_message()),
            Err(MailError::Io(_))
        ));
    }

    #[test]
    fn smtp_configuration_is_validated() {
        let mut config = SmtpConfig::new("127.0.0.1", 25);
        config.host = "bad host".into();
        assert!(matches!(
            send(&Transport::Smtp(config), &sample_message()),
            Err(MailError::Config(_))
        ));
        let mut config = SmtpConfig::new("127.0.0.1", 0);
        config.host = "127.0.0.1".into();
        assert!(matches!(
            send(&Transport::Smtp(config), &sample_message()),
            Err(MailError::Config(_))
        ));
    }
}
