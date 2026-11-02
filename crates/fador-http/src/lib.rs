//! A small, hardened, dependency-free HTTP/1.1 server.
//!
//! The crate implements bounded request parsing, keep-alive, response framing,
//! configurable security headers and optional reverse-proxy handling. It has no
//! knowledge of an application's routes, templates, sessions or static asset
//! policy: callers provide a [`Handler`] and an [`HttpConfig`].
//!
//! There is deliberately no TLS, chunked upload, CGI, directory listing, rate
//! limiting or access logging.
//!
//! # Response framing
//!
//! * `1xx`, `204` and `304` responses are bodyless: neither `Content-Length`
//!   nor `Transfer-Encoding` is sent.
//! * An in-memory body on HTTP/1.1 is sent with `Transfer-Encoding: chunked`,
//!   so no length has to be predicted and the body is never copied twice.
//! * A body that already carries `Content-Encoding`, a `206` or any response
//!   with `Content-Range`, an empty body and every HTTP/1.0 response keep
//!   `Content-Length`.
//! * A file body keeps `Content-Length` unless
//!   [`HttpConfig::file_content_length_limit`] is raised to at least the body
//!   length; the reference board uses [`FILE_CONTENT_LENGTH_LIMIT`].
//! * `HEAD` keeps the headers of the equivalent `GET` and drops the body.
//! * A file that turns out shorter than its declared length aborts the
//!   response instead of ending it as if it were complete.
//!
//! # Example
//!
//! ```no_run
//! use fador_http::{Handler, HttpConfig, Response, Server};
//! use std::sync::Arc;
//!
//! let handler: Arc<Handler> = Arc::new(|_request| {
//!     Response::text(200, "OK", "hello".to_string())
//! });
//! let server = Server::new(HttpConfig::default(), handler);
//! server.run().unwrap();
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod util;

#[cfg(test)]
mod security_tests;

#[cfg(test)]
pub(crate) use fador_testutil as testutil;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use util::{now_http_date, parse_multipart_form};
pub use util::{parse_form, parse_form_with};

/// Upper bound for one chunk of a `Transfer-Encoding: chunked` response body.
///
/// The encoder streams from the response body in slices of this size, so a
/// large body is never copied into a second buffer.
pub const RESPONSE_CHUNK_SIZE: usize = 16 * 1024;

/// The file-body threshold the reference board uses for chunked framing.
///
/// [`HttpConfig::file_content_length_limit`] defaults to `0`, which keeps
/// `Content-Length` on every file body. Assign this constant to reproduce the
/// reference board's policy: a `200` file body of at most 4 MiB is re-framed as
/// chunks, a larger one keeps its length.
pub const FILE_CONTENT_LENGTH_LIMIT: u64 = 4 * 1024 * 1024;

/// Which bytes separate fields in a query string or a form body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormSeparators {
    /// Split on `&`.
    pub ampersand: bool,
    /// Split on `;`, the legacy PHP `arg_separator.input` behaviour.
    pub semicolon: bool,
}

impl FormSeparators {
    /// Only `&`, the modern form encoding.
    pub const AMPERSAND: Self = Self {
        ampersand: true,
        semicolon: false,
    };
    /// Both `&` and `;`, for boards that kept PHP's legacy separator.
    pub const AMPERSAND_AND_SEMICOLON: Self = Self {
        ampersand: true,
        semicolon: true,
    };
}

impl Default for FormSeparators {
    fn default() -> Self {
        Self::AMPERSAND
    }
}

/// A parsed HTTP request.
pub struct Request {
    /// Uppercase method: `GET`, `HEAD` or `POST`.
    pub method: String,
    /// The request target exactly as received, including the query string.
    pub target: String,
    /// Request headers in arrival order. Names keep their original case.
    pub headers: Vec<(String, String)>,
    /// The request body, bounded by [`HttpConfig::max_request_bytes`].
    pub body: Vec<u8>,
    /// `http` or `https`, resolved from a trusted proxy header or
    /// [`HttpConfig::canonical_scheme`].
    pub scheme: String,
    /// The client address after proxy resolution: [`Request::peer_ip`] unless a
    /// trusted (or local) proxy supplied `X-Forwarded-For`.
    pub client_ip: IpAddr,
    /// The socket peer address, before any proxy header is considered.
    pub peer_ip: IpAddr,
    /// `true` when the request line carried `HTTP/1.1`.
    pub http11: bool,
    /// The connection may be reused after this request.
    pub keep_alive: bool,
    /// The request method was `HEAD`; the response must not carry a body.
    pub head: bool,
    /// Separators used by [`Request::query_params`] and [`Request::form_params`].
    pub form_separators: FormSeparators,
}

impl Request {
    /// The first header with `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The path part of the request target, without the query string.
    pub fn path(&self) -> &str {
        match self.target.split_once('?') {
            Some((p, _)) => p,
            None => &self.target,
        }
    }

    /// The raw query string, or an empty string when there is none.
    pub fn query(&self) -> &str {
        match self.target.split_once('?') {
            Some((_, q)) => q,
            None => "",
        }
    }

    /// The first query parameter called `name`, percent-decoded once.
    pub fn query_param(&self, name: &str) -> Option<String> {
        for (k, v) in parse_form_with(self.query().as_bytes(), self.form_separators) {
            if k == name {
                return Some(v);
            }
        }
        None
    }

    /// Every query parameter in request order, percent-decoded once.
    pub fn query_params(&self) -> Vec<(String, String)> {
        parse_form_with(self.query().as_bytes(), self.form_separators)
    }

    /// Parse the request body as form fields.
    ///
    /// A `multipart/form-data` body is parsed as multipart and only its text
    /// fields are returned; file parts are skipped. Any other body is parsed as
    /// `application/x-www-form-urlencoded` when the content type is that media
    /// type or absent, and an empty vector is returned for any other content
    /// type, so a multipart or binary body is never silently decoded as
    /// urlencoded.
    ///
    /// For file parts use [`Request::body`] and [`Request::content_type`] with a
    /// multipart parser (for example `fador_core::multipart`).
    pub fn form_params(&self) -> Vec<(String, String)> {
        let Some(content_type) = self.content_type() else {
            return parse_form_with(&self.body, self.form_separators);
        };
        if is_multipart_media_type(content_type) {
            return parse_multipart_form(content_type, &self.body);
        }
        if is_urlencoded_media_type(content_type) {
            return parse_form_with(&self.body, self.form_separators);
        }
        Vec::new()
    }

    /// The `Content-Type` header, trimmed, or `None` when absent or empty.
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// `true` when the body is declared as `multipart/form-data`.
    pub fn is_multipart_form(&self) -> bool {
        self.content_type()
            .map(is_multipart_media_type)
            .unwrap_or(false)
    }

    /// The protocol version exactly as it appears on the request line.
    pub fn http_version(&self) -> &'static str {
        if self.http11 {
            "HTTP/1.1"
        } else {
            "HTTP/1.0"
        }
    }

    /// Return a raw cookie value without percent-decoding it.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        for (header, value) in &self.headers {
            if !header.eq_ignore_ascii_case("cookie") {
                continue;
            }
            for pair in value.split(';') {
                let pair = pair.trim();
                if let Some((key, val)) = pair.split_once('=') {
                    if key.trim() == name {
                        return Some(val.trim());
                    }
                }
            }
        }
        None
    }
}

/// The payload of a [`Response`].
pub enum Body {
    /// A complete in-memory body.
    Bytes(Vec<u8>),
    /// A slice of an open file, streamed to the socket.
    File {
        /// The open file. The server clones the handle before reading.
        file: File,
        /// Offset of the first byte to send.
        start: u64,
        /// Number of bytes to send from `start`.
        len: u64,
    },
    /// No body at all.
    Empty,
}

/// A response produced by a [`Handler`], before framing.
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Reason phrase written after the status code.
    pub reason: &'static str,
    /// Response headers in the order they should be emitted.
    pub headers: Vec<(String, String)>,
    /// The response payload.
    pub body: Body,
    /// `HEAD` requests carry the headers of the equivalent `GET` and no body.
    pub head_only: bool,
    /// Omit the configured `X-Powered-By` header for this response.
    pub suppress_powered_by: bool,
}

impl Response {
    /// A response with an in-memory body and no headers.
    pub fn new(status: u16, reason: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: Body::Bytes(body),
            head_only: false,
            suppress_powered_by: false,
        }
    }

    /// A `text/html; charset=UTF-8` response.
    pub fn html(status: u16, reason: &'static str, body: String) -> Self {
        let mut r = Self::new(status, reason, body.into_bytes());
        r.headers
            .push(("Content-Type".into(), "text/html; charset=UTF-8".into()));
        r
    }

    /// A `text/plain; charset=UTF-8` response.
    pub fn text(status: u16, reason: &'static str, body: String) -> Self {
        let mut r = Self::new(status, reason, body.into_bytes());
        r.headers
            .push(("Content-Type".into(), "text/plain; charset=UTF-8".into()));
        r
    }

    /// A response with no body.
    pub fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: Body::Empty,
            head_only: false,
            suppress_powered_by: false,
        }
    }

    /// Omit the configured `X-Powered-By` header for this response.
    pub fn without_powered_by(mut self) -> Self {
        self.suppress_powered_by = true;
        self
    }

    /// Append a header without replacing an existing one of the same name.
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// Replace every header with this name.
    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.into()));
    }

    /// A `302 Found` redirect to `location`.
    ///
    /// The target is cut at the first byte that cannot appear in a header and
    /// falls back to `/` when nothing is left, so a value remembered from a
    /// request can never split the response head.
    pub fn redirect(location: &str) -> Self {
        let location = redirect_target(location);
        let location = if location.trim().is_empty() {
            "/".to_string()
        } else {
            location
        };
        Self::empty(302, "Found")
            .header("Location", location)
            .header("Content-Type", "text/html; charset=UTF-8")
    }

    /// A `304 Not Modified` response: no body, no framing header.
    pub fn not_modified() -> Self {
        Self::empty(304, "Not Modified")
    }

    /// The number of body bytes this response declares.
    pub fn content_length(&self) -> u64 {
        match &self.body {
            Body::Bytes(bytes) => bytes.len() as u64,
            Body::File { len, .. } => *len,
            Body::Empty => 0,
        }
    }
}

/// How the body of a response is delimited on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// `Content-Length: n` followed by exactly `n` body bytes.
    ContentLength(u64),
    /// `Transfer-Encoding: chunked`; the body is a sequence of hex-sized
    /// chunks terminated by `0\r\n\r\n`.
    Chunked,
    /// No body and no framing header: `304`, `204` and informational replies.
    Bodyless,
}

/// Request-level facts the framing logic needs.
#[derive(Debug, Clone, Copy)]
pub struct FramingOptions {
    /// The request arrived as HTTP/1.1, so chunked framing is legal.
    pub http11: bool,
    /// The connection closes after this response.
    pub close: bool,
}

impl Default for FramingOptions {
    fn default() -> Self {
        Self {
            http11: true,
            close: true,
        }
    }
}

/// The body of a prepared response, still owned by the server so a file body
/// can be streamed instead of buffered.
pub enum WireBody {
    /// An in-memory body.
    Bytes(Vec<u8>),
    /// A slice of an open file.
    File {
        /// The open file.
        file: File,
        /// Offset of the first byte to send.
        start: u64,
        /// Number of bytes to send from `start`.
        len: u64,
    },
    /// No body.
    Empty,
}

/// A complete response ready for the socket: status line, headers and body.
pub struct WireResponse {
    /// The status line and headers, each line terminated by CRLF.
    pub head: String,
    /// The body the framing describes.
    pub body: WireBody,
    /// How the body is delimited on the wire.
    pub framing: Framing,
    /// `HEAD` requests carry the headers of the equivalent `GET` and no body.
    pub head_only: bool,
}

impl WireResponse {
    /// The number of body bytes the response represents, before chunk framing.
    pub fn body_len(&self) -> u64 {
        match &self.body {
            WireBody::Bytes(bytes) => bytes.len() as u64,
            WireBody::File { len, .. } => *len,
            WireBody::Empty => 0,
        }
    }

    /// Encode the response exactly as it goes on the wire and split the
    /// result into the head and the (still chunk-framed) body.
    ///
    /// This is the same encoder the server uses; tests decode the body from
    /// it to prove the framing round trips.
    pub fn collect(self) -> io::Result<(String, Vec<u8>)> {
        let mut wire = Vec::with_capacity(self.head.len() + self.body_len() as usize + 64);
        write_wire(&mut wire, &self)?;
        let head_len = self.head.len();
        debug_assert_eq!(&wire[..head_len], self.head.as_bytes());
        Ok((self.head, wire[head_len..].to_vec()))
    }
}

/// Runtime settings for the HTTP server.
///
/// This type is deliberately independent of any application configuration
/// format. Callers can build it from TOML, environment variables, command-line
/// flags or constants in their own project.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Display name used in the startup log.
    pub name: String,
    /// Address passed to `TcpListener::bind`, for example `127.0.0.1:8080`.
    pub bind: String,
    /// Number of request-handling threads. `0` selects two per logical CPU,
    /// clamped to 8..128.
    pub workers: usize,
    /// Advertised keep-alive timeout in seconds.
    pub keep_alive_seconds: u64,
    /// Socket read timeout in seconds, clamped to at least one.
    pub read_timeout_seconds: u64,
    /// Socket write timeout in seconds, clamped to at least one.
    pub write_timeout_seconds: u64,
    /// Maximum request body size in bytes.
    pub max_request_bytes: usize,
    /// Maximum total size of the request header block. The request line has
    /// its own 8 KiB limit.
    pub max_header_bytes: usize,
    /// Maximum number of request headers.
    pub max_headers: usize,
    /// Maximum requests served on one keep-alive connection.
    pub max_requests_per_connection: usize,
    /// Only trust `X-Forwarded-*` when the direct peer is in `trusted_proxies`.
    pub trust_proxy_headers: bool,
    /// Honour `X-Forwarded-For` from a loopback or private peer even when
    /// `trust_proxy_headers` is off. A local reverse proxy otherwise hides
    /// every visitor behind its own address.
    pub trust_local_proxy: bool,
    /// Addresses and IPv4 CIDR ranges whose forwarded headers are trusted.
    pub trusted_proxies: Vec<String>,
    /// If non-empty, only these `Host` values are accepted. Ports are ignored.
    pub allowed_hosts: Vec<String>,
    /// Scheme to report when the request did not arrive through a trusted
    /// proxy. Useful when TLS is terminated upstream without proxy headers.
    pub canonical_scheme: Option<String>,
    /// Largest `200` file body that is re-framed as chunks on HTTP/1.1.
    ///
    /// The default `0` keeps `Content-Length` on every file body, which is the
    /// right choice for an application that streams downloads. Set it to
    /// [`FILE_CONTENT_LENGTH_LIMIT`] for the reference board's behaviour, or to
    /// `u64::MAX` to chunk every file body.
    pub file_content_length_limit: u64,
    /// Chunk an in-memory HTTP/1.1 body instead of sending `Content-Length`.
    ///
    /// Defaults to `true`. Set it to `false` when the application must keep the
    /// old `Content-Length` wire shape for dynamic pages.
    pub chunk_in_memory_bodies: bool,
    /// Separators accepted in query strings and urlencoded form bodies.
    pub form_separators: FormSeparators,
    /// `Content-Security-Policy` header. Empty omits it.
    pub content_security_policy: String,
    /// `X-Frame-Options` header. Empty omits it.
    pub frame_options: String,
    /// `Referrer-Policy` header. Empty omits it.
    pub referrer_policy: String,
    /// `Strict-Transport-Security` header, emitted only for `https` requests.
    pub hsts: Option<String>,
    /// Fixed `Server` header. Empty omits it.
    pub server_header: String,
    /// Fixed `X-Powered-By` header. Empty omits it.
    pub powered_by: String,
    /// Emit `Connection: keep-alive` and `Keep-Alive` headers.
    pub emit_connection_headers: bool,
    /// Emit `X-Content-Type-Options: nosniff`.
    pub emit_nosniff: bool,
    /// Additional `Name: value` response headers.
    pub extra_headers: Vec<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            name: "http".into(),
            bind: "127.0.0.1:8080".into(),
            workers: 0,
            keep_alive_seconds: 15,
            read_timeout_seconds: 30,
            write_timeout_seconds: 30,
            max_request_bytes: 2 * 1024 * 1024,
            max_header_bytes: 64 * 1024,
            max_headers: 200,
            max_requests_per_connection: 100,
            trust_proxy_headers: false,
            trust_local_proxy: true,
            trusted_proxies: Vec::new(),
            allowed_hosts: Vec::new(),
            canonical_scheme: None,
            file_content_length_limit: 0,
            chunk_in_memory_bodies: true,
            form_separators: FormSeparators::default(),
            content_security_policy: String::new(),
            frame_options: String::new(),
            referrer_policy: String::new(),
            hsts: None,
            server_header: String::new(),
            powered_by: String::new(),
            emit_connection_headers: true,
            emit_nosniff: true,
            extra_headers: Vec::new(),
        }
    }
}

/// The application callback: one request in, one response out.
pub type Handler = dyn Fn(&Request) -> Response + Send + Sync + 'static;

/// A blocking, thread-per-connection HTTP/1.1 server.
pub struct Server {
    config: Arc<HttpConfig>,
    handler: Arc<Handler>,
    workers: usize,
}

impl Server {
    /// Build a server from an owned configuration.
    pub fn new(config: HttpConfig, handler: Arc<Handler>) -> Self {
        Self::from_shared(Arc::new(config), handler)
    }

    /// Build a server from a shared configuration.
    ///
    /// Useful when the caller keeps the configuration for its own use, for
    /// example to reload it or to read it back in a status page.
    pub fn from_shared(config: Arc<HttpConfig>, handler: Arc<Handler>) -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        // Two workers per logical CPU: most requests are memory copies, and the
        // database-bound remainder does not get faster with a larger pool.
        // `workers` still overrides this.
        let workers = if config.workers == 0 {
            (cpus * 2).clamp(8, 128)
        } else {
            config.workers.clamp(1, 1024)
        };
        Self {
            config,
            handler,
            workers,
        }
    }

    /// The number of request-handling threads this server starts.
    pub fn workers(&self) -> usize {
        self.workers
    }

    /// Bind the configured address and serve until the listener fails.
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(&self.config.bind)?;
        eprintln!(
            "{} listening on http://{} ({} workers)",
            self.config.name, self.config.bind, self.workers
        );
        let (tx, rx) = mpsc::sync_channel::<TcpStream>(1024);
        let rx = Arc::new(std::sync::Mutex::new(rx));
        for _ in 0..self.workers {
            let rx = Arc::clone(&rx);
            let config = Arc::clone(&self.config);
            let handler = Arc::clone(&self.handler);
            std::thread::spawn(move || loop {
                let stream = {
                    let guard = rx.lock().unwrap_or_else(|e| e.into_inner());
                    guard.recv()
                };
                let Ok(stream) = stream else { break };
                handle_connection(stream, &config, &handler);
            });
        }
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(e) = tx.try_send(stream) {
                        eprintln!("server busy: {e}");
                    }
                }
                Err(e) => eprintln!("accept error: {e}"),
            }
        }
        Ok(())
    }
}

fn handle_connection(stream: TcpStream, config: &HttpConfig, handler: &Arc<Handler>) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(
        config.read_timeout_seconds.max(1),
    )));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(
        config.write_timeout_seconds.max(1),
    )));
    let peer = match stream.peer_addr() {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut writer = stream;
    let mut served = 0usize;
    loop {
        if served > 0 {
            let _ = writer.set_read_timeout(Some(Duration::from_secs(
                config.keep_alive_seconds.clamp(1, 30),
            )));
        } else {
            let _ = writer.set_read_timeout(Some(Duration::from_secs(
                config.read_timeout_seconds.max(1),
            )));
        }
        let req = match read_request_with_stream(&mut reader, Some(&writer), peer, config) {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(resp) => {
                // The protocol version of a malformed request is unknown, so
                // the error reply uses the framing every client understands.
                let opts = FramingOptions {
                    http11: false,
                    close: true,
                };
                let _ = write_response(&mut writer, config, resp, opts);
                break;
            }
        };
        let head = req.head;
        let keep = req.keep_alive && served + 1 < config.max_requests_per_connection.max(1);
        let mut resp = (handler)(&req);
        resp.head_only = head;
        if config.content_security_policy.is_empty() {
            if config.emit_nosniff {
                resp.set_header("X-Content-Type-Options", "nosniff");
            }
        } else {
            resp.set_header(
                "Content-Security-Policy",
                config.content_security_policy.clone(),
            );
            if config.emit_nosniff {
                resp.set_header("X-Content-Type-Options", "nosniff");
            }
        }
        if !config.frame_options.is_empty() {
            resp.set_header("X-Frame-Options", config.frame_options.clone());
        }
        if !config.referrer_policy.is_empty() {
            resp.set_header("Referrer-Policy", config.referrer_policy.clone());
        }
        if let Some(hsts) = &config.hsts {
            if req.scheme == "https" {
                resp.set_header("Strict-Transport-Security", hsts.clone());
            }
        }
        let opts = FramingOptions {
            http11: req.http11,
            close: !keep,
        };
        if write_response(&mut writer, config, resp, opts).is_err() {
            break;
        }
        served += 1;
        if !keep {
            break;
        }
    }
}

#[cfg(test)]
fn read_request<R: BufRead>(
    reader: &mut R,
    peer: SocketAddr,
    config: &HttpConfig,
) -> Result<Option<Request>, Response> {
    read_request_with_stream(reader, None, peer, config)
}

fn strip_line_ending(line: &mut Vec<u8>) {
    if line.ends_with(b"\n") {
        line.pop();
        if line.ends_with(b"\r") {
            line.pop();
        }
    }
}

fn read_request_with_stream<R: BufRead>(
    reader: &mut R,
    stream: Option<&TcpStream>,
    peer: SocketAddr,
    config: &HttpConfig,
) -> Result<Option<Request>, Response> {
    let read_budget = Duration::from_secs(config.read_timeout_seconds.max(1));
    let mut deadline: Option<Instant> = None;
    let mut line = Vec::new();
    match read_line_bounded(reader, &mut line, 8192, &mut deadline, read_budget, stream) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(LineError::TooLong) => {
            return Err(Response::text(
                414,
                "URI Too Long",
                "Request line too long".into(),
            ))
        }
        Err(LineError::Io) => return Ok(None),
    }
    strip_line_ending(&mut line);
    if line.is_empty() {
        return Ok(None);
    }
    if line.contains(&b'\r') || line.contains(&b'\t') {
        return Err(bad_request("invalid character in request line"));
    }
    let line = String::from_utf8_lossy(&line);
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or_else(|| bad_request("missing method"))?;
    let target = parts.next().ok_or_else(|| bad_request("missing target"))?;
    let version = parts
        .next()
        .ok_or_else(|| bad_request("missing HTTP version"))?;
    if parts.next().is_some() {
        return Err(bad_request("malformed request line"));
    }
    if !matches!(method, "GET" | "HEAD" | "POST") {
        return Err(
            Response::text(405, "Method Not Allowed", "Method not allowed".into())
                .header("Allow", "GET, HEAD, POST"),
        );
    }
    if !target.starts_with('/') {
        return Err(bad_request("invalid request target"));
    }
    // A scheme-relative `//host/path` target is normalised differently by
    // proxies and browsers (some treat it as `http://host/path`). There is no
    // such route, and rejecting it removes another request-smuggling
    // ambiguity at the reverse proxy.
    if target.starts_with("//") {
        return Err(bad_request("ambiguous request target"));
    }
    if target.len() > 16384 {
        return Err(bad_request("request target too long"));
    }
    if target.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(bad_request("control character in request target"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Response::text(
            505,
            "HTTP Version Not Supported",
            "HTTP version not supported".into(),
        ));
    }
    let http11 = version == "HTTP/1.1";
    let mut headers = Vec::new();
    let mut header_bytes = 0usize;
    loop {
        if headers.len() >= config.max_headers.max(1) {
            return Err(Response::text(
                431,
                "Request Header Fields Too Large",
                "Too many request headers".into(),
            ));
        }
        let mut h = Vec::new();
        let remaining = config
            .max_header_bytes
            .saturating_sub(header_bytes)
            .max(1024);
        let n = match read_line_bounded(reader, &mut h, remaining, &mut deadline, read_budget, stream) {
            Ok(n) => n,
            Err(LineError::TooLong) => {
                return Err(Response::text(
                    431,
                    "Request Header Fields Too Large",
                    "Request headers too large".into(),
                ))
            }
            Err(LineError::Io) => return Err(bad_request("header read error")),
        };
        if n == 0 {
            return Err(bad_request("unexpected end of headers"));
        }
        header_bytes += n;
        if header_bytes > config.max_header_bytes {
            return Err(Response::text(
                431,
                "Request Header Fields Too Large",
                "Request headers too large".into(),
            ));
        }
        strip_line_ending(&mut h);
        if h.is_empty() {
            break;
        }
        if h.contains(&b'\r') {
            return Err(bad_request("bare CR in header"));
        }
        if h[0] == b' ' || h[0] == b'\t' {
            return Err(bad_request("obsolete header folding"));
        }
        let text = String::from_utf8_lossy(&h);
        let Some((raw_name, value)) = text.split_once(':') else {
            return Err(bad_request("malformed header"));
        };
        if raw_name.trim() != raw_name {
            return Err(bad_request("whitespace before header colon"));
        }
        let name = raw_name.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        {
            return Err(bad_request("invalid header name"));
        }
        let value = value.trim();
        if value
            .chars()
            .any(|c| c == '\0' || (c.is_control() && c != '\t'))
        {
            return Err(bad_request("invalid header value"));
        }
        headers.push((name.to_string(), value.to_string()));
    }

    let host_headers: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .collect();
    if host_headers.len() > 1 {
        return Err(bad_request("duplicate Host header"));
    }
    if let Some(host) = host_headers.first() {
        let host = host.trim();
        if host.is_empty()
            || !host.is_ascii()
            || host.chars().any(|c| {
                c.is_control()
                    || c.is_whitespace()
                    || matches!(
                        c,
                        '/' | '\\' | '?' | '#' | '@' | ',' | '"' | '\'' | '<' | '>'
                    )
            })
        {
            return Err(bad_request("invalid Host header"));
        }
    }

    let content_lengths: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect();
    if content_lengths.len() > 1 {
        return Err(bad_request("duplicate content-length"));
    }
    let content_length = match content_lengths.first() {
        Some(value) => {
            // RFC 7230 allows only 1*DIGIT. In particular do not accept a
            // leading '+' or whitespace variants that some clients parse
            // inconsistently.
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad_request("invalid content-length"));
            }
            value
                .parse::<usize>()
                .map_err(|_| bad_request("invalid content-length"))?
        }
        None => 0,
    };
    if content_length > config.max_request_bytes {
        return Err(Response::text(
            413,
            "Payload Too Large",
            "Request body too large".into(),
        ));
    }
    let transfer_encodings: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.as_str())
        .collect();
    if !transfer_encodings.is_empty() {
        if !content_lengths.is_empty() {
            return Err(bad_request("both transfer-encoding and content-length"));
        }
        // There is no chunked or other transfer-coding support. Reject every
        // Transfer-Encoding value, including `identity`: accepting one value
        // while reading only Content-Length is a classic request-smuggling
        // ambiguity at reverse proxies.
        return Err(Response::text(
            501,
            "Not Implemented",
            "Transfer-Encoding is not supported".into(),
        ));
    }
    if method == "POST" && content_length == 0 {
        return Err(bad_request("POST without content-length"));
    }
    let mut body = vec![0u8; content_length];
    let mut read_body = 0usize;
    while read_body < content_length {
        if let Some(dl) = deadline {
            let now = Instant::now();
            if now > dl {
                return Err(bad_request("request body read timed out"));
            }
            if let Some(s) = stream {
                let _ = s.set_read_timeout(Some(
                    dl.saturating_duration_since(now)
                        .max(Duration::from_millis(1)),
                ));
            }
        }
        let n = reader
            .read(&mut body[read_body..])
            .map_err(|_| bad_request("truncated request body"))?;
        if n == 0 {
            return Err(bad_request("truncated request body"));
        }
        read_body += n;
    }
    let mut keep_alive = http11;
    let mut has_close = false;
    let mut has_keep_alive = false;
    for (_, conn) in headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
    {
        for token in conn.split(',').map(str::trim) {
            if token.eq_ignore_ascii_case("close") {
                has_close = true;
            } else if token.eq_ignore_ascii_case("keep-alive") {
                has_keep_alive = true;
            }
        }
    }
    if has_close {
        keep_alive = false;
    } else if has_keep_alive {
        keep_alive = true;
    }
    let trusted =
        config.trust_proxy_headers && is_trusted_proxy(peer.ip(), &config.trusted_proxies);
    // A reverse proxy on the same host or LAN is the normal deployment. Without
    // honouring its header every visitor is recorded as the proxy, which also
    // makes an IP ban hit the proxy instead of the client.
    let local_proxy = !trusted && config.trust_local_proxy && is_local_peer(peer.ip());
    let mut scheme = String::from("http");
    if trusted {
        scheme = headers
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-proto"))
            .and_then(|(_, value)| value.rsplit(',').next())
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| value == "http" || value == "https")
            .unwrap_or_else(|| "http".into());
    } else if let Some(canonical) = &config.canonical_scheme {
        if canonical.eq_ignore_ascii_case("https") {
            // TLS may be terminated upstream even when proxy headers are not
            // trusted. Report the configured canonical scheme to handlers.
            scheme = "https".into();
        }
    }
    let forwarded_values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
        .map(|(_, value)| value.as_str())
        .collect();
    let client_ip = if (trusted || local_proxy) && !forwarded_values.is_empty() {
        let combined = forwarded_values.join(", ");
        forwarded_client_ip(&combined, peer.ip(), &config.trusted_proxies)
    } else {
        peer.ip()
    };
    if !config.allowed_hosts.is_empty() {
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let host_no_port = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
        let allowed = config
            .allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&host_no_port));
        if !allowed {
            return Err(bad_request("host not allowed"));
        }
    }
    if http11 && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        return Err(bad_request("missing Host header"));
    }
    Ok(Some(Request {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        body,
        scheme,
        client_ip,
        peer_ip: peer.ip(),
        http11,
        keep_alive,
        head: method == "HEAD",
        form_separators: config.form_separators,
    }))
}

fn bad_request(msg: &str) -> Response {
    Response::text(400, "Bad Request", msg.to_string())
}

enum LineError {
    TooLong,
    Io,
}

fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    max: usize,
    deadline: &mut Option<Instant>,
    budget: Duration,
    stream: Option<&TcpStream>,
) -> Result<usize, LineError> {
    // Read through the buffered reader instead of one byte at a time. The
    // length and deadline checks keep a hostile peer from making us allocate an
    // unbounded line or trickle one byte per timeout window.
    let mut total = 0usize;
    loop {
        if let Some(dl) = *deadline {
            let now = Instant::now();
            if now > dl {
                return Err(LineError::Io);
            }
            if let Some(s) = stream {
                let _ = s.set_read_timeout(Some(
                    dl.saturating_duration_since(now)
                        .max(Duration::from_millis(1)),
                ));
            }
        }
        let available = reader.fill_buf().map_err(|_| LineError::Io)?;
        if available.is_empty() {
            return Ok(total);
        }
        if deadline.is_none() {
            *deadline = Some(Instant::now() + budget);
        }
        let limit = (max + 1).saturating_sub(total);
        let window = &available[..available.len().min(limit)];
        let (used, done) = match window.iter().position(|&b| b == b'\n') {
            Some(pos) => (pos + 1, true),
            None => (window.len(), window.len() == limit && limit > 0),
        };
        out.extend_from_slice(&window[..used]);
        reader.consume(used);
        total += used;
        if total > max || (total == max && !out.ends_with(b"\n")) {
            return Err(LineError::TooLong);
        }
        if done {
            return Ok(total);
        }
    }
}

fn media_type(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

fn is_multipart_media_type(content_type: &str) -> bool {
    media_type(content_type).eq_ignore_ascii_case("multipart/form-data")
}

fn is_urlencoded_media_type(content_type: &str) -> bool {
    let media = media_type(content_type);
    media.is_empty() || media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_header_value(value: &str) -> bool {
    value.len() <= 8192
        && !value
            .chars()
            .any(|c| c == '\0' || c == '\r' || c == '\n' || (c.is_control() && c != '\t'))
}

fn status_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "OK",
    }
}

/// Cut a redirect target at the first byte that cannot appear in a header value.
/// This is the caller-side counterpart of the check in [`response_head`]:
/// generated values stay valid instead of causing the header to be dropped.
fn redirect_target(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(8192));
    for character in value.chars() {
        if character == '\0'
            || character == '\r'
            || character == '\n'
            || (character.is_control() && character != '\t')
        {
            break;
        }
        out.push(character);
        if out.len() >= 8192 {
            break;
        }
    }
    out.trim().to_string()
}

/// Headers the framing and connection logic owns; a caller (or an
/// `extra_headers` line) must never set them.
fn is_reserved_response_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length" | "transfer-encoding" | "connection" | "keep-alive" | "date"
    )
}

/// Build the status line and headers, including the framing header selected by
/// [`prepare_response`].
fn response_head(
    config: &HttpConfig,
    resp: &Response,
    opts: &FramingOptions,
    framing: Framing,
) -> String {
    let mut head = String::with_capacity(512);
    let reason = if valid_header_value(resp.reason) {
        resp.reason
    } else {
        status_reason(resp.status)
    };
    head.push_str(&format!("HTTP/1.1 {} {}\r\n", resp.status, reason));
    head.push_str(&format!("Date: {}\r\n", now_http_date()));
    let mut seen: Vec<String> = Vec::new();
    if !config.server_header.is_empty() && valid_header_value(&config.server_header) {
        head.push_str("Server: ");
        head.push_str(&config.server_header);
        head.push_str("\r\n");
        seen.push("server".into());
    }
    if !config.powered_by.is_empty()
        && valid_header_value(&config.powered_by)
        && !resp.suppress_powered_by
    {
        head.push_str("X-Powered-By: ");
        head.push_str(&config.powered_by);
        head.push_str("\r\n");
        seen.push("x-powered-by".into());
    }
    let mut has_type = false;
    for raw in &config.extra_headers {
        let Some((name, value)) = raw.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        let lower = name.to_ascii_lowercase();
        if !valid_header_name(name)
            || is_reserved_response_header(name)
            || seen.contains(&lower)
            || resp
                .headers
                .iter()
                .any(|(header, _)| header.eq_ignore_ascii_case(name))
            || !valid_header_value(value)
        {
            continue;
        }
        if lower == "content-type" {
            has_type = true;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
        seen.push(lower);
    }
    for (k, v) in &resp.headers {
        // Defence in depth: no response header may split the response or
        // override the framing headers written below. Values that reach a
        // header are normally generated internally, but a future caller must
        // not be able to turn user data into a header injection.
        if !valid_header_name(k) || !valid_header_value(v) || is_reserved_response_header(k) {
            continue;
        }
        if k.eq_ignore_ascii_case("content-type") {
            has_type = true;
        }
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    if !has_type && resp.status != 304 {
        head.push_str("Content-Type: application/octet-stream\r\n");
    }
    match framing {
        Framing::Bodyless => {}
        Framing::Chunked => head.push_str("Transfer-Encoding: chunked\r\n"),
        Framing::ContentLength(len) => {
            head.push_str(&format!("Content-Length: {len}\r\n"));
        }
    }
    if opts.close {
        head.push_str("Connection: close\r\n");
    } else if config.emit_connection_headers {
        head.push_str("Connection: keep-alive\r\n");
        head.push_str(&format!(
            "Keep-Alive: timeout={}\r\n",
            config.keep_alive_seconds
        ));
    }
    head.push_str("\r\n");
    head
}

/// Decide the framing of one response and render its head.
///
/// Dynamic bodies are chunked on HTTP/1.1: a chunked response needs no buffer
/// copy and no length prediction. The exceptions are the cases the HTTP
/// contract fixes:
///
/// * `304`, `204` and `1xx` never carry a body or a framing header;
/// * a body that is already content-encoded (gzip) carries `Content-Length`;
/// * `206` and any response carrying `Content-Range` keep `Content-Length`,
///   because a byte range must not be re-framed;
/// * HTTP/1.0 clients get `Content-Length`;
/// * an empty body keeps `Content-Length: 0` rather than an empty chunk list;
/// * a file body keeps `Content-Length` until it is no larger than
///   [`HttpConfig::file_content_length_limit`].
///
/// `HEAD` keeps the framing headers a `GET` would produce and drops the body.
pub fn prepare_response(
    config: &HttpConfig,
    resp: Response,
    opts: &FramingOptions,
) -> WireResponse {
    let bodyless = resp.status < 200 || resp.status == 204 || resp.status == 304;
    let len = resp.content_length();
    let encoded = resp
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-encoding"));
    let ranged = resp.status == 206
        || resp
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-range"));
    let chunked = opts.http11
        && !bodyless
        && !encoded
        && !ranged
        && len > 0
        && match &resp.body {
            Body::Bytes(_) => config.chunk_in_memory_bodies,
            // A small file body is re-framed as chunks when the application
            // opted into the reference board's policy; a large download keeps
            // its length so the client can show progress and resume.
            Body::File { .. } => resp.status == 200 && len <= config.file_content_length_limit,
            Body::Empty => false,
        };
    let framing = if bodyless {
        Framing::Bodyless
    } else if chunked {
        Framing::Chunked
    } else {
        Framing::ContentLength(len)
    };
    let head = response_head(config, &resp, opts, framing);
    let body = match resp.body {
        Body::Bytes(bytes) => WireBody::Bytes(bytes),
        Body::File { file, start, len } => WireBody::File { file, start, len },
        Body::Empty => WireBody::Empty,
    };
    WireResponse {
        head,
        body,
        framing,
        head_only: resp.head_only,
    }
}

fn write_chunk(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
    writer.write_all(format!("{:x}\r\n", data.len()).as_bytes())?;
    writer.write_all(data)?;
    writer.write_all(b"\r\n")
}

fn write_body(writer: &mut impl Write, body: &WireBody) -> io::Result<()> {
    match body {
        WireBody::Bytes(bytes) => writer.write_all(bytes),
        WireBody::File { file, start, len } => {
            let mut file = file.try_clone()?;
            file.seek(SeekFrom::Start(*start))?;
            // `Content-Length` promised `len` bytes. Copying fewer would end
            // the response early and let the client accept a truncated body as
            // complete, so a short file is a transport error and the
            // connection is closed.
            let copied = io::copy(&mut file.take(*len), writer)?;
            if copied != *len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "response body file is shorter than its declared length",
                ));
            }
            Ok(())
        }
        WireBody::Empty => Ok(()),
    }
}

fn write_chunked_body(writer: &mut impl Write, body: &WireBody) -> io::Result<()> {
    match body {
        WireBody::Bytes(bytes) => {
            for chunk in bytes.chunks(RESPONSE_CHUNK_SIZE) {
                write_chunk(writer, chunk)?;
            }
        }
        WireBody::File { file, start, len } => {
            let mut file = file.try_clone()?;
            file.seek(SeekFrom::Start(*start))?;
            let mut remaining = *len;
            let mut buffer = vec![0u8; RESPONSE_CHUNK_SIZE];
            while remaining > 0 {
                let want = remaining.min(buffer.len() as u64) as usize;
                let read = file.read(&mut buffer[..want])?;
                if read == 0 {
                    // Never emit a terminating chunk for a body that was
                    // shorter than declared: the client would accept a
                    // truncated response as complete.
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "response body file is shorter than its declared length",
                    ));
                }
                write_chunk(writer, &buffer[..read])?;
                remaining -= read as u64;
            }
        }
        WireBody::Empty => {}
    }
    writer.write_all(b"0\r\n\r\n")
}

/// Write a prepared response: head, then the body framed as decided.
///
/// A chunked response is complete once the terminating chunk is written, so
/// the connection is reusable immediately. A file body that is shorter than
/// its declared length returns [`io::ErrorKind::UnexpectedEof`] after a partial
/// body has been written; the caller must close the connection and must not
/// continue with the next request.
pub fn write_wire(writer: &mut impl Write, wire: &WireResponse) -> io::Result<()> {
    writer.write_all(wire.head.as_bytes())?;
    if wire.head_only || wire.framing == Framing::Bodyless {
        return writer.flush();
    }
    match wire.framing {
        Framing::Chunked => write_chunked_body(writer, &wire.body)?,
        Framing::ContentLength(_) => write_body(writer, &wire.body)?,
        Framing::Bodyless => {}
    }
    writer.flush()
}

fn write_response(
    writer: &mut impl Write,
    config: &HttpConfig,
    resp: Response,
    opts: FramingOptions,
) -> io::Result<()> {
    write_wire(writer, &prepare_response(config, resp, &opts))
}

/// Parse a request `Accept-Encoding` header and report whether `gzip` may be
/// used for the response.
///
/// The parser follows RFC 9110's content-coding negotiation for the single
/// coding this server can produce: `gzip`, `*`, an explicit `q=0` refusal and
/// malformed parameters. A missing header means the client did not ask for a
/// compressed response.
pub fn accepts_gzip(header: Option<&str>) -> bool {
    let Some(value) = header else {
        return false;
    };
    let mut gzip: Option<bool> = None;
    let mut wildcard: Option<bool> = None;
    for part in value.split(',') {
        let mut pieces = part.split(';');
        let encoding = pieces.next().unwrap_or("").trim();
        if encoding.is_empty() {
            continue;
        }
        let mut quality = 1.0f32;
        for parameter in pieces {
            let parameter = parameter.trim();
            if let Some(rest) = parameter.strip_prefix("q=") {
                // An unparsable quality is treated as the default (1.0) rather
                // than silently disabling compression for a broken client.
                quality = rest.trim().parse::<f32>().unwrap_or(1.0);
            }
        }
        let acceptable = quality > 0.0;
        if encoding.eq_ignore_ascii_case("gzip") {
            gzip = Some(acceptable);
        } else if encoding == "*" {
            wildcard = Some(acceptable);
        }
    }
    // An explicit gzip entry always wins over the wildcard.
    gzip.or(wildcard).unwrap_or(false)
}

/// Resolve the client address from an `X-Forwarded-For` header.
///
/// Proxies append the address they received the request from, so the right-most
/// entry is the one closest to us. Walking right to left and skipping addresses
/// that are themselves trusted proxies prevents a client from spoofing its
/// address by sending its own header value.
fn forwarded_client_ip(value: &str, peer: IpAddr, trusted: &[String]) -> IpAddr {
    for entry in value.rsplit(',').take(64) {
        let entry = entry.trim();
        let Ok(ip) = entry.parse::<IpAddr>() else {
            continue;
        };
        if !is_trusted_proxy(ip, trusted) {
            return ip;
        }
    }
    peer
}

/// Addresses that can only be a reverse proxy on the same host or LAN.
fn is_local_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_local_peer_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                // IPv4-mapped addresses reach the same private ranges.
                || v6.to_ipv4_mapped().map(is_local_peer_v4).unwrap_or(false)
        }
    }
}

fn is_local_peer_v4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
}

fn is_trusted_proxy(ip: IpAddr, list: &[String]) -> bool {
    for entry in list {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(parsed) = entry.parse::<IpAddr>() {
            if parsed == ip {
                return true;
            }
            continue;
        }
        // Very small CIDR matcher (IPv4 only; IPv6 proxies should be listed
        // individually).
        if let Some((net, bits)) = entry.split_once('/') {
            if let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u8>()) {
                if let (IpAddr::V4(net), IpAddr::V4(ip)) = (net, ip) {
                    if bits <= 32 {
                        let mask = if bits == 0 {
                            0
                        } else {
                            u32::MAX << (32 - bits)
                        };
                        if (u32::from(net) & mask) == (u32::from(ip) & mask) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rng, MALICIOUS_STRINGS};
    use std::io::Cursor;
    use std::path::PathBuf;

    fn test_config() -> HttpConfig {
        HttpConfig {
            server_header: "Apache/2.4.57 (Debian)".into(),
            powered_by: "PHP/7.4.33".into(),
            ..HttpConfig::default()
        }
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    fn parse(raw: &[u8], cfg: &HttpConfig) -> Result<Option<Request>, Response> {
        parse_from(raw, peer(), cfg)
    }

    fn parse_from(
        raw: &[u8],
        peer: SocketAddr,
        cfg: &HttpConfig,
    ) -> Result<Option<Request>, Response> {
        let mut reader = Cursor::new(raw.to_vec());
        read_request(&mut reader, peer, cfg)
    }

    /// Render a response head with the default (HTTP/1.1, closing) framing.
    fn render_head(cfg: &HttpConfig, resp: Response) -> String {
        prepare_response(cfg, resp, &FramingOptions::default()).head
    }

    fn temp_file(name: &str, len: u64) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("fador-http-{name}-{}.bin", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(len).unwrap();
        path
    }

    fn file_response(path: &std::path::Path, start: u64, len: u64) -> Response {
        let mut response = Response::empty(200, "OK");
        response.body = Body::File {
            file: std::fs::File::open(path).unwrap(),
            start,
            len,
        };
        response
    }

    #[test]
    fn compatibility_headers_are_configurable() {
        let mut cfg = test_config();
        cfg.extra_headers = vec!["X-Compat: yes".into()];
        let rendered = render_head(&cfg, Response::text(200, "OK", "hello".into()));
        assert!(rendered.contains("Server: Apache/2.4.57 (Debian)\r\n"));
        assert!(rendered.contains("X-Powered-By: PHP/7.4.33\r\n"));
        assert!(rendered.contains("X-Compat: yes\r\n"));
        assert!(!rendered.contains("fador-http"));

        cfg.server_header.clear();
        cfg.powered_by.clear();
        let rendered = render_head(&cfg, Response::text(200, "OK", "hello".into()));
        assert!(!rendered.contains("Server:"));
        assert!(!rendered.contains("X-Powered-By:"));
    }

    #[test]
    fn canonical_scheme_applies_without_a_trusted_proxy() {
        let cfg = HttpConfig {
            canonical_scheme: Some("https".into()),
            ..test_config()
        };
        let request = parse(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", &cfg)
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(request.scheme, "https");
    }

    #[test]
    fn forwarded_headers_require_a_trusted_proxy() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n";
        let untrusted = HttpConfig {
            trust_local_proxy: false,
            ..test_config()
        };
        let request = parse(raw, &untrusted).ok().flatten().unwrap();
        assert_eq!(request.scheme, "http");
        assert_eq!(request.client_ip, peer().ip());
        assert_eq!(request.peer_ip, peer().ip());

        let trusted = HttpConfig {
            trust_proxy_headers: true,
            trusted_proxies: vec!["127.0.0.1".into()],
            ..test_config()
        };
        let request = parse(raw, &trusted).ok().flatten().unwrap();
        assert_eq!(request.scheme, "https");
        assert_eq!(request.client_ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_for_uses_the_rightmost_untrusted_address() {
        let mut cfg = test_config();
        cfg.trust_proxy_headers = true;
        cfg.trusted_proxies = vec!["127.0.0.1".into()];
        let cases = [
            ("203.0.113.9, 198.51.100.7", "198.51.100.7"),
            ("1.1.1.1, 203.0.113.9, 127.0.0.1", "203.0.113.9"),
            ("203.0.113.9", "203.0.113.9"),
            ("unknown, 203.0.113.9", "203.0.113.9"),
            ("127.0.0.1, 127.0.0.1", "127.0.0.1"),
        ];
        for (header, expected) in cases {
            let raw = format!(
                "GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: {header}\r\n\r\n"
            );
            let request = parse(raw.as_bytes(), &cfg)
                .ok()
                .flatten()
                .expect("valid request");
            let expected_ip: IpAddr = expected.parse().unwrap();
            assert_eq!(request.client_ip, expected_ip, "{header}");
        }
        let raw = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert_eq!(
            parse(raw.as_bytes(), &cfg)
                .ok()
                .flatten()
                .expect("valid request")
                .client_ip,
            peer().ip()
        );

        for (header, expected) in [("https, http", "http"), ("http, https", "https")] {
            let raw = format!(
                "GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-Proto: {header}\r\n\r\n"
            );
            let request = parse(raw.as_bytes(), &cfg)
                .ok()
                .flatten()
                .expect("valid request");
            assert_eq!(request.scheme, expected, "{header}");
        }
    }

    #[test]
    fn a_local_proxy_supplies_the_client_address_without_explicit_trust() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 8.8.4.4\r\n\r\n";
        let request = parse(raw, &test_config()).ok().flatten().unwrap();
        assert_eq!(request.client_ip, "8.8.4.4".parse::<IpAddr>().unwrap());
        assert_eq!(request.peer_ip, peer().ip());
        // The scheme still comes from the canonical configuration.
        assert_eq!(request.scheme, "http");

        let private_peer: SocketAddr = "10.0.0.5:443".parse().unwrap();
        let request = parse_from(raw, private_peer, &test_config())
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(request.client_ip, "8.8.4.4".parse::<IpAddr>().unwrap());

        let public_peer = "198.51.100.10:443".parse().unwrap();
        let request = parse_from(raw, public_peer, &test_config())
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(request.client_ip, public_peer.ip());
    }

    #[test]
    fn the_rightmost_forwarded_address_wins_for_a_local_proxy() {
        let raw =
            b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 1.1.1.1, 8.8.4.4\r\n\r\n";
        let request = parse(raw, &test_config()).ok().flatten().unwrap();
        assert_eq!(request.client_ip, "8.8.4.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn allowed_hosts_are_enforced() {
        let cfg = HttpConfig {
            allowed_hosts: vec!["example.test".into()],
            ..test_config()
        };
        assert!(parse(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", &cfg)
            .ok()
            .flatten()
            .is_some());
        assert!(parse(b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n", &cfg).is_err());
    }

    #[test]
    fn accepts_a_well_formed_request() {
        let cfg = test_config();
        let raw = b"POST /wiki/Test?x=1 HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=b%20c";
        let request = parse(raw, &cfg)
            .ok()
            .flatten()
            .expect("well-formed request must parse");
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/wiki/Test?x=1");
        assert_eq!(request.body, b"a=b%20c");
        assert_eq!(request.path(), "/wiki/Test");
        assert_eq!(request.query_param("x").as_deref(), Some("1"));
        assert_eq!(request.query_params(), vec![("x".into(), "1".into())]);
        assert_eq!(request.form_params(), vec![("a".into(), "b c".into())]);
        assert_eq!(
            request.content_type(),
            Some("application/x-www-form-urlencoded")
        );
        assert!(!request.is_multipart_form());
    }

    #[test]
    fn form_separators_are_configurable() {
        let cfg = HttpConfig {
            form_separators: FormSeparators::AMPERSAND_AND_SEMICOLON,
            ..test_config()
        };
        let request = parse(b"GET /?a=1;b=2&c=3 HTTP/1.1\r\nHost: x\r\n\r\n", &cfg)
            .ok()
            .flatten()
            .expect("valid request");
        assert_eq!(
            request.query_params(),
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "2".into()),
                ("c".into(), "3".into()),
            ]
        );

        let default = parse(b"GET /?a=1;b=2 HTTP/1.1\r\nHost: x\r\n\r\n", &test_config())
            .ok()
            .flatten()
            .expect("valid request");
        assert_eq!(default.query_params(), vec![("a".into(), "1;b=2".into())]);
    }

    #[test]
    fn in_memory_bodies_can_keep_content_length() {
        let cfg = HttpConfig {
            chunk_in_memory_bodies: false,
            ..test_config()
        };
        let wire = prepare_response(
            &cfg,
            Response::html(200, "OK", "hello".into()),
            &FramingOptions::default(),
        );
        assert_eq!(wire.framing, Framing::ContentLength(5));
        assert!(wire.head.contains("Content-Length: 5\r\n"));
        assert!(!wire.head.contains("Transfer-Encoding:"));
    }

    #[test]
    fn request_exposes_the_protocol_version() {
        let cfg = test_config();
        let request = parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", &cfg)
            .ok()
            .flatten()
            .unwrap();
        assert!(request.http11);
        assert_eq!(request.http_version(), "HTTP/1.1");
        assert!(request.keep_alive);

        let request = parse(b"GET / HTTP/1.0\r\n\r\n", &cfg)
            .ok()
            .flatten()
            .unwrap();
        assert!(!request.http11);
        assert_eq!(request.http_version(), "HTTP/1.0");
        assert!(!request.keep_alive);
    }

    #[test]
    fn form_params_returns_multipart_text_fields_only() {
        let cfg = test_config();
        let body = "--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\nPNGDATA\r\n--XyZ--\r\n";
        let raw = format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=XyZ\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let request = parse(raw.as_bytes(), &cfg).ok().flatten().unwrap();
        assert!(request.is_multipart_form());
        assert_eq!(
            request.form_params(),
            vec![("title".into(), "Hello".into())],
            "a file part is not a form field"
        );

        // The same bytes with a non-form content type are not decoded at all,
        // and in particular not as urlencoded.
        let raw = format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let request = parse(raw.as_bytes(), &cfg).ok().flatten().unwrap();
        assert!(!request.is_multipart_form());
        assert!(request.form_params().is_empty());

        // An absent content type keeps the urlencoded compatibility path.
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 7\r\n\r\na=b%20c";
        let request = parse(raw, &cfg).ok().flatten().unwrap();
        assert_eq!(request.form_params(), vec![("a".into(), "b c".into())]);
    }

    #[test]
    fn rejects_smuggling_and_malformed_framing() {
        let cfg = test_config();
        let cases: &[&[u8]] = &[
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\naaaa",
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: identity\r\n\r\naaaa",
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +4\r\n\r\naaaa",
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4x\r\n\r\naaaa",
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4",
            b"POST / HTTP/1.1\r\nHost: x\r\nHost: y\r\nContent-Length: 0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\n folded: value\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: /evil\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: evil@example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: exa mple\r\n\r\n",
            b"GET / HTTP/1.1\r\nX-Test: a\0b\r\n\r\n",
            b"GET /\0 HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET / HTTP/9.9\r\nHost: x\r\n\r\n",
            b"PATCH / HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET //evil.example/ HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET //evil.example HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET http://evil.example/ HTTP/1.1\r\nHost: x\r\n\r\n",
        ];
        for case in cases {
            assert!(
                parse(case, &cfg).is_err(),
                "malicious request was accepted: {:?}",
                String::from_utf8_lossy(case)
            );
        }
    }

    #[test]
    fn rejects_oversized_and_ambiguous_requests() {
        let cfg = test_config();
        let mut many_headers = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
        for _ in 0..205 {
            many_headers.extend_from_slice(b"X-Test: value\r\n");
        }
        many_headers.extend_from_slice(b"\r\n");
        assert!(parse(&many_headers, &cfg).is_err());

        let huge_body = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            cfg.max_request_bytes + 1
        );
        assert!(parse(huge_body.as_bytes(), &cfg).is_err());

        let mut long_line = b"GET /".to_vec();
        long_line.extend_from_slice(&[b'a'; 9000]);
        long_line.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(parse(&long_line, &cfg).is_err());
    }

    #[test]
    fn fuzz_request_parser_with_malicious_inputs() {
        let cfg = test_config();
        let mut rng = Rng::new(0x5eed_1234_abcd_0001);
        let methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "get", ""];
        let versions = ["HTTP/1.1", "HTTP/1.0", "HTTP/2", "http/1.1", ""];
        let header_names = [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Cookie",
            "X-Test",
            "Content-Length ",
            "Bad Name",
            "X-\0",
        ];

        for iteration in 0..3_000 {
            let raw = if iteration % 2 == 0 {
                let len = rng.below(512);
                rng.bytes(len)
            } else {
                let method = *rng.pick(&methods);
                let target = if rng.below(4) == 0 {
                    let len = rng.below(60);
                    format!("/{}", rng.text(len))
                } else {
                    (*rng.pick(MALICIOUS_STRINGS)).to_string()
                };
                let version = *rng.pick(&versions);
                let mut raw = format!("{method} {target} {version}\r\n").into_bytes();
                let header_count = rng.below(14);
                for _ in 0..header_count {
                    let name = *rng.pick(&header_names);
                    let value = if rng.below(3) == 0 {
                        (*rng.pick(MALICIOUS_STRINGS)).to_string()
                    } else {
                        let len = rng.below(80);
                        rng.text(len)
                    };
                    raw.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
                }
                if rng.below(2) == 0 {
                    let length = rng.below(32);
                    raw.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
                    raw.extend_from_slice(b"\r\n");
                    raw.extend(rng.bytes(length));
                } else {
                    raw.extend_from_slice(b"\r\n");
                }
                raw
            };

            // The parser must reject or normalize any of this without
            // panicking, allocating an unbounded body, or accepting invalid
            // framing in a successful request.
            if let Ok(Some(request)) = parse(&raw, &cfg) {
                assert!(matches!(request.method.as_str(), "GET" | "HEAD" | "POST"));
                assert!(request.target.starts_with('/'));
                assert!(
                    !request.target.bytes().any(|b| b < 0x20 || b == 0x7f),
                    "control byte in accepted target: {:?}",
                    request.target
                );
                assert!(request.body.len() <= cfg.max_request_bytes);
                if request.header("transfer-encoding").is_some() {
                    assert!(
                        request.header("content-length").is_none(),
                        "accepted both Transfer-Encoding and Content-Length"
                    );
                }
                for (name, value) in &request.headers {
                    assert!(
                        !name.is_empty()
                            && name
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')),
                        "accepted invalid header name {name:?}"
                    );
                    assert!(
                        !value
                            .chars()
                            .any(|c| c == '\0' || (c.is_control() && c != '\t')),
                        "accepted control byte in header value {value:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn fuzz_request_parser_framing_and_truncation() {
        let cfg = test_config();
        let base = b"POST /index.php?action=post HTTP/1.1\r\nHost: example.test\r\n\
                     Content-Length: 4\r\n\r\nabcd"
            .to_vec();
        let mut rng = Rng::new(0x5eed_1234_abcd_0002);
        for _ in 0..2_000 {
            let mut raw = base.clone();
            for _ in 0..1 + rng.below(4) {
                let position = rng.below(raw.len());
                raw[position] = rng.byte();
            }
            if let Ok(Some(request)) = parse(&raw, &cfg) {
                assert!(request.body.len() <= cfg.max_request_bytes);
                assert!(request.target.starts_with('/'));
                assert!(!request.target.bytes().any(|b| b < 0x20 || b == 0x7f));
            }
        }
        // Every truncation of a well-formed request is either an error or an
        // incomplete request; nothing may panic or read past the body.
        for cut in 0..base.len() {
            let _ = parse(&base[..cut], &cfg);
        }
        // Duplicate and oversized headers.
        let mut duplicate = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
        for _ in 0..300 {
            duplicate.extend_from_slice(b"X-Dup: v\r\n");
        }
        duplicate.extend_from_slice(b"\r\n");
        assert!(parse(&duplicate, &cfg).is_err());

        let mut long_value = b"GET / HTTP/1.1\r\nHost: x\r\nX-Long: ".to_vec();
        long_value.extend_from_slice(&[b'a'; 70_000]);
        long_value.extend_from_slice(b"\r\n\r\n");
        assert!(parse(&long_value, &cfg).is_err());

        // NUL, CR and bare LF inside a header value or the target.
        for raw in [
            b"GET / HTTP/1.1\r\nHost: x\r\nX: a\0b\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: x\r\nX: a\rb\r\n\r\n".as_slice(),
            b"GET /a\tb HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
            b"GET /a\rb HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nab".as_slice(),
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999999999999999\r\n\r\n"
                .as_slice(),
        ] {
            assert!(
                parse(raw, &cfg).is_err(),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn response_headers_cannot_inject_lines_or_framing() {
        let cfg = test_config();
        let resp = Response::text(200, "OK", "hello".into())
            .header("X-Test", "ok\r\nX-Evil: 1")
            .header("Content-Length", "999")
            .header("X-Good", "value");
        let rendered = render_head(&cfg, resp);
        assert!(!rendered.contains("X-Evil"));
        assert!(!rendered.contains("X-Test"));
        assert!(rendered.contains("X-Good: value\r\n"));
        assert!(!rendered.contains("Content-Length: 999"));
        // Five body bytes are chunked on HTTP/1.1; a Content-Length must not
        // appear at all when the framing is chunked.
        assert!(rendered.contains("Transfer-Encoding: chunked\r\n"));
        assert!(!rendered.contains("Content-Length:"));
    }

    #[test]
    fn method_not_allowed_advertises_every_supported_method() {
        let cfg = test_config();
        let response = match parse(b"PATCH / HTTP/1.1\r\nHost: x\r\n\r\n", &cfg) {
            Err(response) => response,
            Ok(_) => panic!("PATCH must be refused"),
        };
        assert_eq!(response.status, 405);
        let allow = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("allow"))
            .map(|(_, value)| value.as_str());
        assert_eq!(allow, Some("GET, HEAD, POST"));
        assert!(parse(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
            &cfg
        )
        .is_err());
        assert!(parse(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\na",
            &cfg
        )
        .is_ok());
    }

    #[test]
    fn redirects_cannot_split_headers_or_point_nowhere() {
        let cfg = test_config();
        let resp = Response::redirect("/forums/index.php?action=login\r\nX-Evil: 1");
        let rendered = render_head(&cfg, resp);
        assert!(
            !rendered.lines().any(|line| line.starts_with("X-Evil:")),
            "a redirect value must not introduce a header line"
        );
        assert_eq!(rendered.matches("\r\nLocation:").count(), 1);
        assert_eq!(
            rendered
                .lines()
                .find(|line| line.starts_with("Location: "))
                .unwrap(),
            "Location: /forums/index.php?action=login"
        );

        let empty = Response::redirect(" \r\n\t ");
        let rendered = render_head(&cfg, empty);
        assert!(rendered.contains("Location: /\r\n"));
        // An empty redirect body is delimited by Content-Length, not by an
        // empty chunk list.
        assert!(rendered.contains("Content-Length: 0\r\n"));
        assert!(!rendered.contains("Transfer-Encoding"));
    }

    #[test]
    fn extra_headers_cannot_override_framing_or_duplicate_content_type() {
        let cfg = HttpConfig {
            extra_headers: vec![
                "Content-Length: 0".into(),
                "Transfer-Encoding: chunked".into(),
                "Connection: close".into(),
                "Date: Thu, 01 Jan 1970 00:00:00 GMT".into(),
                "Content-Type: text/plain".into(),
                "Vary: Accept-Encoding".into(),
                "Vary: Accept-Encoding".into(),
                "Bad Name: value".into(),
                "X_Underscore: value".into(),
            ],
            ..test_config()
        };
        // A response that already carries a Content-Type keeps its own.
        let resp = Response::text(200, "OK", "hello".into());
        let rendered = render_head(&cfg, resp);
        assert_eq!(rendered.matches("Content-Type:").count(), 1);
        assert!(rendered.contains("Content-Type: text/plain; charset=UTF-8"));
        assert_eq!(rendered.matches("Vary: Accept-Encoding\r\n").count(), 1);
        assert_eq!(
            rendered.matches("Transfer-Encoding: chunked\r\n").count(),
            1
        );
        assert!(!rendered.contains("Bad Name:"));
        assert!(!rendered.contains("X_Underscore:"));

        // A response without one gets exactly the configured type, not the
        // default octet-stream on top.
        let resp = Response::empty(200, "OK");
        let rendered = render_head(&cfg, resp);
        assert_eq!(rendered.matches("Content-Type:").count(), 1);
        assert!(rendered.contains("Content-Type: text/plain\r\n"));
        assert!(!rendered.contains("application/octet-stream"));
    }

    #[test]
    fn the_powered_by_header_can_be_suppressed_per_response() {
        let cfg = test_config();
        let rendered = render_head(
            &cfg,
            Response::text(200, "OK", "hello".into()).without_powered_by(),
        );
        assert!(!rendered.contains("X-Powered-By:"));
        assert!(rendered.contains("Server: Apache/2.4.57 (Debian)\r\n"));
    }

    /// Decode a chunked body, failing on any framing defect.
    fn decode_chunked(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = raw;
        loop {
            let end = rest
                .iter()
                .position(|byte| *byte == b'\n')
                .expect("chunk size line");
            let line = std::str::from_utf8(&rest[..end]).expect("ascii chunk size");
            let line = line.trim_end_matches('\r');
            let size = usize::from_str_radix(line, 16).expect("hex chunk size");
            rest = &rest[end + 1..];
            if size == 0 {
                assert_eq!(rest, b"\r\n", "the last chunk must be `0\\r\\n\\r\\n`");
                return out;
            }
            assert!(rest.len() >= size + 2, "truncated chunk body");
            out.extend_from_slice(&rest[..size]);
            assert_eq!(&rest[size..size + 2], b"\r\n", "chunk data terminator");
            rest = &rest[size + 2..];
        }
    }

    #[test]
    fn chunked_framing_round_trips_single_and_multiple_chunks() {
        let cfg = test_config();
        let small = b"hello".to_vec();
        let large = vec![b'x'; RESPONSE_CHUNK_SIZE * 2 + 7];
        for (body, chunks) in [(small, 1usize), (large.clone(), 3usize)] {
            let wire = prepare_response(
                &cfg,
                Response::text(200, "OK", String::from_utf8_lossy(&body).into_owned()),
                &FramingOptions::default(),
            );
            assert_eq!(wire.framing, Framing::Chunked);
            let (rendered, framed) = wire.collect().unwrap();
            assert!(rendered.contains("Transfer-Encoding: chunked\r\n"));
            assert!(!rendered.contains("Content-Length:"));
            assert_eq!(
                framed.iter().filter(|b| **b == b'\n').count(),
                chunks * 2 + 2
            );
            assert_eq!(decode_chunked(&framed), body);
        }
    }

    #[test]
    fn chunk_boundaries_and_empty_bodies_are_framed_correctly() {
        let cfg = test_config();
        for len in [
            0usize,
            1,
            RESPONSE_CHUNK_SIZE - 1,
            RESPONSE_CHUNK_SIZE,
            RESPONSE_CHUNK_SIZE + 1,
            RESPONSE_CHUNK_SIZE * 4,
        ] {
            let body = vec![b'a'; len];
            let wire = prepare_response(
                &cfg,
                Response::new(200, "OK", body.clone()),
                &FramingOptions::default(),
            );
            let framing = wire.framing;
            let (rendered, framed) = wire.collect().unwrap();
            if len == 0 {
                assert_eq!(framing, Framing::ContentLength(0));
                assert!(rendered.contains("Content-Length: 0\r\n"));
                assert!(framed.is_empty());
            } else {
                assert_eq!(framing, Framing::Chunked);
                assert_eq!(decode_chunked(&framed), body);
            }
        }
    }

    #[test]
    fn file_body_framing_follows_the_configured_limit() {
        let large = FILE_CONTENT_LENGTH_LIMIT + 1;
        let large_path = temp_file("file-framing-large", large);
        let small_path = temp_file("file-framing-small", 1024);

        // The default keeps Content-Length on every file body.
        let wire = prepare_response(
            &test_config(),
            file_response(&large_path, 0, large),
            &FramingOptions::default(),
        );
        assert_eq!(wire.framing, Framing::ContentLength(large));

        // The reference-board threshold chunks the small body and keeps the
        // length of the large one.
        let cfg = HttpConfig {
            file_content_length_limit: FILE_CONTENT_LENGTH_LIMIT,
            ..test_config()
        };
        let wire = prepare_response(
            &cfg,
            file_response(&small_path, 0, 1024),
            &FramingOptions::default(),
        );
        assert_eq!(wire.framing, Framing::Chunked);
        let wire = prepare_response(
            &cfg,
            file_response(&large_path, 0, large),
            &FramingOptions::default(),
        );
        assert_eq!(wire.framing, Framing::ContentLength(large));

        // `u64::MAX` chunks every non-empty file body.
        let cfg = HttpConfig {
            file_content_length_limit: u64::MAX,
            ..test_config()
        };
        let wire = prepare_response(
            &cfg,
            file_response(&large_path, 0, large),
            &FramingOptions::default(),
        );
        assert_eq!(wire.framing, Framing::Chunked);

        let _ = std::fs::remove_file(&large_path);
        let _ = std::fs::remove_file(&small_path);
    }

    #[test]
    fn a_short_file_body_is_an_error_not_a_complete_response() {
        let cfg = test_config();
        let path = temp_file("short-file", 10);

        let wire = prepare_response(
            &cfg,
            file_response(&path, 0, 100),
            &FramingOptions::default(),
        );
        assert_eq!(wire.framing, Framing::ContentLength(100));
        let error = wire
            .collect()
            .expect_err("a short Content-Length file body must fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

        // The chunked path rejects it too, before the terminating chunk.
        let chunked_cfg = HttpConfig {
            file_content_length_limit: u64::MAX,
            ..test_config()
        };
        let wire = prepare_response(
            &chunked_cfg,
            file_response(&path, 0, 100),
            &FramingOptions::default(),
        );
        assert_eq!(wire.framing, Framing::Chunked);
        let error = wire
            .collect()
            .expect_err("a short chunked file body must fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_file_longer_than_declared_sends_only_the_declared_range() {
        let cfg = test_config();
        let path = temp_file("long-file", 64);
        let wire = prepare_response(
            &cfg,
            file_response(&path, 8, 16),
            &FramingOptions::default(),
        );
        assert_eq!(wire.framing, Framing::ContentLength(16));
        let (head, body) = wire.collect().unwrap();
        assert!(head.contains("Content-Length: 16\r\n"));
        assert_eq!(body.len(), 16);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn head_keeps_the_get_framing_and_drops_the_body() {
        let cfg = test_config();
        let body = "x".repeat(RESPONSE_CHUNK_SIZE / 2);
        let get = prepare_response(
            &cfg,
            Response::html(200, "OK", body.clone()),
            &FramingOptions::default(),
        );
        let mut head_response = Response::html(200, "OK", body);
        head_response.head_only = true;
        let head = prepare_response(&cfg, head_response, &FramingOptions::default());
        assert_eq!(head.head, get.head);
        assert_eq!(head.framing, Framing::Chunked);
        let (_, framed) = head.collect().unwrap();
        assert!(
            framed.is_empty(),
            "HEAD must not write a body or a terminator"
        );
    }

    #[test]
    fn bodyless_and_encoded_responses_keep_content_length() {
        let cfg = test_config();
        for response in [
            Response::not_modified(),
            Response::empty(204, "No Content"),
            Response::empty(101, "Switching Protocols"),
        ] {
            let status = response.status;
            let wire = prepare_response(&cfg, response, &FramingOptions::default());
            assert_eq!(wire.framing, Framing::Bodyless, "{status}");
            assert!(!wire.head.contains("Content-Length:"), "{status}");
            assert!(!wire.head.contains("Transfer-Encoding:"), "{status}");
            let (_, body) = wire.collect().unwrap();
            assert!(body.is_empty(), "{status} must not write a body");
        }
        assert!(
            !prepare_response(&cfg, Response::not_modified(), &FramingOptions::default())
                .head
                .contains("Content-Type:")
        );

        let encoded = prepare_response(
            &cfg,
            Response::html(200, "OK", "compressed".into()).header("Content-Encoding", "gzip"),
            &FramingOptions::default(),
        );
        assert_eq!(encoded.framing, Framing::ContentLength(10));
        assert!(encoded.head.contains("Content-Length: 10\r\n"));
        assert!(!encoded.head.contains("Transfer-Encoding:"));

        let ranged = prepare_response(
            &cfg,
            Response::new(206, "Partial Content", b"abcd".to_vec())
                .header("Content-Range", "bytes 0-3/10"),
            &FramingOptions::default(),
        );
        assert_eq!(ranged.framing, Framing::ContentLength(4));
        assert!(!ranged.head.contains("Transfer-Encoding:"));

        let http10 = prepare_response(
            &cfg,
            Response::html(200, "OK", "hello".into()),
            &FramingOptions {
                http11: false,
                close: true,
            },
        );
        assert_eq!(http10.framing, Framing::ContentLength(5));
        assert!(http10.head.contains("Content-Length: 5\r\n"));
    }

    #[test]
    fn a_partial_response_keeps_its_length_even_with_a_file_body() {
        let cfg = HttpConfig {
            file_content_length_limit: u64::MAX,
            ..test_config()
        };
        let path = temp_file("partial-file", 64);
        let mut response = file_response(&path, 16, 8);
        response.status = 206;
        response.reason = "Partial Content";
        response
            .headers
            .push(("Content-Range".into(), "bytes 16-23/64".into()));
        let wire = prepare_response(&cfg, response, &FramingOptions::default());
        assert_eq!(wire.framing, Framing::ContentLength(8));
        let (head, body) = wire.collect().unwrap();
        assert!(head.contains("Content-Range: bytes 16-23/64\r\n"));
        assert_eq!(body.len(), 8);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn keep_alive_reuses_the_connection_after_a_chunked_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(test_config());
        let handler: Arc<Handler> =
            Arc::new(|_request| Response::html(200, "OK", "<html>ok</html>".to_string()));
        let worker = {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                handle_connection(stream, &config, &handler);
            })
        };
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: x\r\n\r\n\
                  GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).unwrap();
        worker.join().unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert_eq!(text.matches("HTTP/1.1 200 OK\r\n").count(), 2);
        assert_eq!(
            text.matches("Transfer-Encoding: chunked\r\n").count(),
            2,
            "both responses are chunked"
        );
        assert_eq!(
            text.matches("f\r\n<html>ok</html>\r\n0\r\n\r\n").count(),
            2,
            "each response ends with its terminating chunk"
        );
        assert!(text.contains("Connection: close\r\n"));
    }

    /// Send one request over a real socket and split the reply into head/body.
    fn one_exchange(request: &[u8], handler: Arc<Handler>) -> (String, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(test_config());
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &config, &handler);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(request).unwrap();
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).unwrap();
        worker.join().unwrap();
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("a response head");
        (
            String::from_utf8_lossy(&raw[..split]).into_owned(),
            raw[split + 4..].to_vec(),
        )
    }

    #[test]
    fn head_204_304_and_206_write_the_expected_body_bytes() {
        let handler: Arc<Handler> = Arc::new(|request| match request.path() {
            "/head" => Response::html(200, "OK", "<html>body</html>".to_string()),
            "/204" => Response::empty(204, "No Content"),
            "/304" => Response::not_modified(),
            "/206" => Response::new(206, "Partial Content", b"abcd".to_vec())
                .header("Content-Range", "bytes 0-3/10"),
            _ => Response::empty(404, "Not Found"),
        });

        let (head, body) = one_exchange(
            b"HEAD /head HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            Arc::clone(&handler),
        );
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains("Transfer-Encoding: chunked\r\n"), "{head}");
        assert!(!head.contains("Content-Length:"), "{head}");
        assert!(
            body.is_empty(),
            "HEAD must not write a body or a terminator"
        );

        for (path, status) in [
            ("/204", "HTTP/1.1 204 No Content"),
            ("/304", "HTTP/1.1 304 Not Modified"),
        ] {
            let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let (head, body) = one_exchange(request.as_bytes(), Arc::clone(&handler));
            assert!(head.starts_with(&format!("{status}\r\n")), "{head}");
            assert!(!head.contains("Content-Length:"), "{head}");
            assert!(!head.contains("Transfer-Encoding:"), "{head}");
            assert!(body.is_empty(), "{path} must not write a body");
        }

        let (head, body) = one_exchange(
            b"GET /206 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            handler,
        );
        assert!(
            head.starts_with("HTTP/1.1 206 Partial Content\r\n"),
            "{head}"
        );
        assert!(head.contains("Content-Length: 4\r\n"), "{head}");
        assert!(!head.contains("Transfer-Encoding:"), "{head}");
        assert_eq!(body, b"abcd");
    }

    #[test]
    fn accepts_gzip_header_negotiation() {
        assert!(!accepts_gzip(None));
        assert!(!accepts_gzip(Some("")));
        assert!(!accepts_gzip(Some("identity")));
        assert!(accepts_gzip(Some("gzip")));
        assert!(accepts_gzip(Some("GZIP")));
        assert!(accepts_gzip(Some("br, gzip")));
        assert!(accepts_gzip(Some("gzip;q=0.5")));
        assert!(accepts_gzip(Some("gzip ; q=1.0")));
        assert!(!accepts_gzip(Some("gzip;q=0")));
        assert!(!accepts_gzip(Some("gzip;q=0.0")));
        assert!(!accepts_gzip(Some("gzip;q=0.000")));
        assert!(!accepts_gzip(Some("gzip;q=0, *")));
        assert!(accepts_gzip(Some("*")));
        assert!(accepts_gzip(Some("*;q=0.5")));
        assert!(!accepts_gzip(Some("*;q=0")));
        assert!(accepts_gzip(Some("br, *")));
        assert!(!accepts_gzip(Some("def, br")));
        assert!(accepts_gzip(Some("gzip;q=abc")));
        assert!(!accepts_gzip(Some(";;;")));
        assert!(!accepts_gzip(Some(",,")));
        assert!(!accepts_gzip(Some("x-gzip")));
        assert!(accepts_gzip(Some(" gzip , deflate ")));
        assert!(!accepts_gzip(Some("gzip-malformed;q=1")));
    }

    #[test]
    fn fuzz_chunk_encoder_round_trips_random_bodies() {
        let cfg = test_config();
        let mut rng = Rng::new(0x0c0f_fee1_2345_6789);
        for _ in 0..200 {
            let len = rng.below(3 * RESPONSE_CHUNK_SIZE + 5);
            let body = rng.bytes(len);
            let wire = prepare_response(
                &cfg,
                Response::new(200, "OK", body.clone()),
                &FramingOptions::default(),
            );
            let (rendered, framed) = wire.collect().unwrap();
            assert!(!rendered.contains("Content-Length:"));
            assert_eq!(decode_chunked(&framed), body);
        }
    }

    #[test]
    fn worker_default_is_two_per_cpu_clamped_to_8_128() {
        let handler: Arc<Handler> = Arc::new(|_| Response::empty(204, "No Content"));
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let server = Server::new(HttpConfig::default(), Arc::clone(&handler));
        assert_eq!(server.workers(), (cpus * 2).clamp(8, 128));
        let server = Server::new(
            HttpConfig {
                workers: 3,
                ..HttpConfig::default()
            },
            Arc::clone(&handler),
        );
        assert_eq!(server.workers(), 3);
        let server = Server::new(
            HttpConfig {
                workers: 100_000,
                ..HttpConfig::default()
            },
            handler,
        );
        assert_eq!(server.workers(), 1024);
    }

    #[test]
    fn local_peers_and_trusted_proxies_are_classified() {
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                is_local_peer(local.parse().unwrap()),
                "{local} is a local peer"
            );
        }
        for public in ["8.8.8.8", "203.0.113.9", "2001:db8::1"] {
            assert!(
                !is_local_peer(public.parse().unwrap()),
                "{public} is not a local peer"
            );
        }

        let trusted = vec!["10.0.0.0/8".to_string(), "192.0.2.7".to_string()];
        assert!(is_trusted_proxy("10.9.9.9".parse().unwrap(), &trusted));
        assert!(is_trusted_proxy("192.0.2.7".parse().unwrap(), &trusted));
        assert!(!is_trusted_proxy("192.0.2.8".parse().unwrap(), &trusted));
        assert!(!is_trusted_proxy("::1".parse().unwrap(), &trusted));
    }
}
