//! A small MySQL/MariaDB client speaking the wire protocol directly.
//!
//! Only the classic text protocol is implemented. Parameters are emulated with
//! strictly escaped values, and there are no local files, multi-statements or
//! compression. This keeps the attack surface small and avoids a large
//! dependency tree.
//!
//! Authentication supports `mysql_native_password` and the *fast* path of
//! `caching_sha2_password`. If a server demands the full RSA exchange for
//! `caching_sha2_password`, connection setup fails with an actionable error
//! (use a private network, `mysql_native_password`, or an stunnel proxy).

#![deny(unsafe_code)]

use fador_core::crypto;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg(test)]
pub(crate) use fador_testutil as testutil;

#[cfg(test)]
mod security_tests;

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_FOUND_ROWS: u32 = 0x0000_0002;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_MULTI_STATEMENTS: u32 = 0x0001_0000;
const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
const SERVER_STATUS_IN_TRANS: u16 = 0x0001;
const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

const MAX_PACKET: usize = 0x00ff_ffff;
/// Hard cap on one reassembled logical packet, including continuation packets.
const MAX_TOTAL_PACKET_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum MysqlError {
    Io(String),
    Protocol(String),
    Server {
        code: u16,
        state: String,
        message: String,
    },
    Auth(String),
    Unsupported(String),
}

impl fmt::Display for MysqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MysqlError::Io(e) => write!(f, "database I/O: {e}"),
            MysqlError::Protocol(e) => write!(f, "database protocol: {e}"),
            MysqlError::Server {
                code,
                state,
                message,
            } => write!(f, "database error {code} ({state}): {message}"),
            MysqlError::Auth(e) => write!(f, "database authentication: {e}"),
            MysqlError::Unsupported(e) => write!(f, "unsupported database feature: {e}"),
        }
    }
}

impl std::error::Error for MysqlError {}

impl From<io::Error> for MysqlError {
    fn from(e: io::Error) -> Self {
        MysqlError::Io(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SqlValue<'a> {
    Null,
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(&'a str),
    Bytes(&'a [u8]),
}

fn quote_sql_value(v: &SqlValue<'_>) -> String {
    match v {
        SqlValue::Null => "NULL".to_string(),
        SqlValue::Int(i) => i.to_string(),
        SqlValue::UInt(u) => u.to_string(),
        SqlValue::Float(f) => {
            if f.is_finite() {
                format!("{f:.10}")
            } else {
                "NULL".to_string()
            }
        }
        SqlValue::Str(s) => {
            // Hex literals are immune to NO_BACKSLASH_ESCAPES and to any
            // quoting mistakes.  CONVERT gives the value the connection
            // charset so comparisons and fulltext search behave normally.
            let mut out = String::with_capacity(20 + s.len() * 2);
            out.push_str("CONVERT(X'");
            for &b in s.as_bytes() {
                out.push_str(&format!("{b:02x}"));
            }
            out.push_str("' USING utf8mb4)");
            out
        }
        SqlValue::Bytes(b) => {
            let mut out = String::with_capacity(3 + b.len() * 2);
            out.push_str("X'");
            for &byte in *b {
                out.push_str(&format!("{byte:02x}"));
            }
            out.push('\'');
            out
        }
    }
}

/// Replace `?` placeholders outside of quoted SQL text with escaped values.
///
/// The scanner understands single-quoted, double-quoted and backtick-quoted
/// SQL text, `--` line comments and `/* ... */` block comments. It never
/// rewrites bytes inside those regions. The original UTF-8 text is preserved;
/// only placeholder values are encoded.
pub fn format_sql(sql: &str, params: &[SqlValue<'_>]) -> String {
    let mut out = String::with_capacity(sql.len() + params.len() * 20);
    let mut idx = 0;
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut quote = 0u8;
    while i < bytes.len() {
        let b = bytes[i];
        if quote != 0 {
            if b == b'\\' && quote != b'`' && i + 1 < bytes.len() {
                push_char(&mut out, sql, &mut i);
                push_char(&mut out, sql, &mut i);
            } else {
                push_char(&mut out, sql, &mut i);
                if b == quote {
                    quote = 0;
                }
            }
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quote = b;
                push_char(&mut out, sql, &mut i);
            }
            b'-' if i + 1 < bytes.len()
                && bytes[i + 1] == b'-'
                && (i + 2 >= bytes.len()
                    || bytes[i + 2].is_ascii_whitespace()
                    || bytes[i + 2] < 0x20
                    || bytes[i + 2] == 0x7f) =>
            {
                while i < bytes.len() && bytes[i] != b'\n' {
                    push_char(&mut out, sql, &mut i);
                }
            }
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    push_char(&mut out, sql, &mut i);
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                let is_live = i + 2 < bytes.len() && (bytes[i + 2] == b'!' || bytes[i + 2] == b'+');
                out.push_str("/*");
                i += 2;
                if !is_live {
                    while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                        push_char(&mut out, sql, &mut i);
                    }
                    if i + 1 < bytes.len() {
                        out.push_str("*/");
                        i += 2;
                    }
                }
            }
            b'*' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                out.push_str("*/");
                i += 2;
            }
            b'?' => {
                if idx < params.len() {
                    out.push_str(&quote_sql_value(&params[idx]));
                    idx += 1;
                } else {
                    out.push('?');
                }
                i += 1;
            }
            _ => push_char(&mut out, sql, &mut i),
        }
    }
    out
}

fn push_char(out: &mut String, sql: &str, index: &mut usize) {
    let ch = sql[*index..]
        .chars()
        .next()
        .expect("SQL scanner stays on a UTF-8 boundary");
    out.push(ch);
    *index += ch.len_utf8();
}

#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct Row {
    values: Vec<Option<Vec<u8>>>,
}

impl Row {
    pub fn get(&self, idx: usize) -> Option<&[u8]> {
        self.values.get(idx).and_then(|v| v.as_deref())
    }

    pub fn get_str(&self, idx: usize) -> Option<&str> {
        self.get(idx).and_then(|b| std::str::from_utf8(b).ok())
    }

    pub fn get_string(&self, idx: usize) -> Option<String> {
        self.get(idx)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    pub fn get_i64(&self, idx: usize) -> Option<i64> {
        self.get_str(idx).and_then(|s| s.parse().ok())
    }

    pub fn get_u64(&self, idx: usize) -> Option<u64> {
        self.get_str(idx).and_then(|s| s.parse().ok())
    }
}

#[derive(Debug, Clone, Default)]
pub struct QueryResult {
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
    pub last_insert_id: u64,
    pub affected_rows: u64,
}

impl QueryResult {
    pub fn first(&self) -> Option<&Row> {
        self.rows.first()
    }
}

#[derive(Debug, Clone)]
pub struct MysqlParams {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    pub charset: u8,
    pub connect_timeout: Duration,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
}

struct PacketIo {
    stream: TcpStream,
    seq: u8,
}

impl PacketIo {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), MysqlError> {
        self.stream.read_exact(buf)?;
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>, MysqlError> {
        let mut payload = Vec::new();
        loop {
            let mut header = [0u8; 4];
            self.read_exact(&mut header)?;
            let len =
                header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
            let seq = header[3];
            if seq != self.seq {
                // The classic protocol requires strict sequencing.  Be
                // forgiving only for the very first packet after connect,
                // where some proxies rewrite the sequence number.
                if self.seq != 0 {
                    return Err(MysqlError::Protocol(format!(
                        "packet sequence mismatch (got {seq}, expected {})",
                        self.seq
                    )));
                }
            }
            self.seq = seq.wrapping_add(1);
            let start = payload.len();
            let end = start
                .checked_add(len)
                .ok_or_else(|| MysqlError::Protocol("oversized MySQL packet".into()))?;
            if end > MAX_TOTAL_PACKET_BYTES {
                return Err(MysqlError::Protocol("oversized MySQL packet".into()));
            }
            payload.resize(end, 0);
            self.read_exact(&mut payload[start..end])?;
            if len < MAX_PACKET {
                break;
            }
        }
        Ok(payload)
    }

    fn write_packet(&mut self, payload: &[u8]) -> Result<(), MysqlError> {
        let mut offset = 0;
        loop {
            let remaining = payload.len() - offset;
            let chunk = remaining.min(MAX_PACKET);
            let mut header = [0u8; 4];
            header[0] = (chunk & 0xff) as u8;
            header[1] = ((chunk >> 8) & 0xff) as u8;
            header[2] = ((chunk >> 16) & 0xff) as u8;
            header[3] = self.seq;
            self.seq = self.seq.wrapping_add(1);
            self.stream.write_all(&header)?;
            self.stream.write_all(&payload[offset..offset + chunk])?;
            offset += chunk;
            if chunk < MAX_PACKET {
                break;
            }
        }
        self.stream.flush()?;
        Ok(())
    }

    fn reset_sequence(&mut self) {
        self.seq = 0;
    }
}

pub struct Connection {
    io: PacketIo,
    pub last_used: Instant,
    pub broken: bool,
    pub in_transaction: bool,
}

impl Connection {
    pub fn connect(params: &MysqlParams) -> Result<Self, MysqlError> {
        let addr = format!("{}:{}", params.host, params.port);
        let addrs: Vec<_> = addr
            .to_socket_addrs()
            .map_err(|e| MysqlError::Io(format!("resolve {addr}: {e}")))?
            .collect();
        if addrs.is_empty() {
            return Err(MysqlError::Io(format!("no address found for {addr}")));
        }
        let mut last_err = None;
        let mut stream = None;
        for a in addrs {
            match TcpStream::connect_timeout(&a, params.connect_timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let stream = stream.ok_or_else(|| {
            MysqlError::Io(format!(
                "connect {addr}: {}",
                last_err.map(|e| e.to_string()).unwrap_or_default()
            ))
        })?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(params.read_timeout)?;
        stream.set_write_timeout(params.write_timeout)?;
        let mut io = PacketIo { stream, seq: 0 };
        let handshake = io.read_packet()?;
        let hs = parse_handshake(&handshake)?;
        let mut caps = CLIENT_LONG_PASSWORD
            | CLIENT_FOUND_ROWS
            | CLIENT_LONG_FLAG
            | CLIENT_PROTOCOL_41
            | CLIENT_TRANSACTIONS
            | CLIENT_SECURE_CONNECTION;
        if !params.database.is_empty() {
            caps |= CLIENT_CONNECT_WITH_DB;
        }
        if hs.capabilities & CLIENT_PLUGIN_AUTH != 0 {
            caps |= CLIENT_PLUGIN_AUTH;
        }
        // Explicitly avoid CLIENT_MULTI_STATEMENTS and CLIENT_MULTI_RESULTS:
        // user input must never be able to smuggle a second statement or leave
        // trailing result sets.
        let _ = (CLIENT_MULTI_STATEMENTS, CLIENT_MULTI_RESULTS);
        caps &= hs.capabilities | CLIENT_LONG_PASSWORD;

        let plugin = if hs.auth_plugin.is_empty() {
            "mysql_native_password".to_string()
        } else {
            hs.auth_plugin.clone()
        };
        let token = auth_token(&plugin, params.password.as_bytes(), &hs.scramble)?;

        let mut resp = Vec::with_capacity(128 + token.len());
        resp.extend_from_slice(&caps.to_le_bytes());
        resp.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes());
        resp.push(params.charset);
        resp.extend_from_slice(&[0u8; 23]);
        resp.extend_from_slice(params.user.as_bytes());
        resp.push(0);
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            write_lenenc_int(&mut resp, token.len() as u64);
            resp.extend_from_slice(&token);
        } else if caps & CLIENT_SECURE_CONNECTION != 0 {
            resp.push(token.len() as u8);
            resp.extend_from_slice(&token);
        } else {
            resp.extend_from_slice(&token);
            resp.push(0);
        }
        if !params.database.is_empty() {
            resp.extend_from_slice(params.database.as_bytes());
            resp.push(0);
        }
        if caps & CLIENT_PLUGIN_AUTH != 0 {
            resp.extend_from_slice(plugin.as_bytes());
            resp.push(0);
        }
        io.write_packet(&resp)?;

        // Authentication conversation bounded to prevent infinite server loops.
        let mut auth_plugin = plugin;
        let mut auth_ok = false;
        for _ in 0..8 {
            let packet = io.read_packet()?;
            match packet.first().copied() {
                Some(0x00) => {
                    auth_ok = true;
                    break;
                }
                Some(0xff) => return Err(parse_error(&packet)),
                Some(0xfe) => {
                    // AuthSwitchRequest
                    let rest = &packet[1..];
                    let nul = rest
                        .iter()
                        .position(|&b| b == 0)
                        .ok_or_else(|| MysqlError::Protocol("bad auth switch request".into()))?;
                    let new_plugin = String::from_utf8_lossy(&rest[..nul]).into_owned();
                    let mut nonce = rest[nul + 1..].to_vec();
                    while nonce.last() == Some(&0) {
                        nonce.pop();
                    }
                    let new_token = auth_token(&new_plugin, params.password.as_bytes(), &nonce)?;
                    io.write_packet(&new_token)?;
                    auth_plugin = new_plugin;
                }
                Some(0x01) => {
                    // AuthMoreData (caching_sha2_password / sha256_password)
                    match packet.get(1).copied() {
                        Some(0x03) => {
                            // fast auth succeeded; an OK packet follows
                            continue;
                        }
                        Some(0x04) => {
                            return Err(MysqlError::Auth(format!(
                                "server requires full authentication for {auth_plugin}; \
                                 use mysql_native_password or connect over a trusted private network"
                            )));
                        }
                        _ => {
                            return Err(MysqlError::Unsupported(format!(
                                "authentication continuation for {auth_plugin}"
                            )));
                        }
                    }
                }
                _ => {
                    return Err(MysqlError::Protocol(
                        "unexpected packet during authentication".into(),
                    ));
                }
            }
        }
        if !auth_ok {
            return Err(MysqlError::Protocol(
                "authentication exchange exceeded packet limit".into(),
            ));
        }

        let mut conn = Self {
            io,
            last_used: Instant::now(),
            broken: false,
            in_transaction: false,
        };
        // Make sure client and server agree on UTF-8.  Failure is not fatal:
        // some old MySQL versions use different names, and the handshake
        // charset already selected utf8mb4_general_ci.
        let _ = conn.execute("SET NAMES utf8mb4");
        if conn.broken {
            return Err(MysqlError::Protocol("initial SET NAMES utf8mb4 failed".into()));
        }
        Ok(conn)
    }

    pub fn ping(&mut self) -> Result<(), MysqlError> {
        self.io.reset_sequence();
        self.io.write_packet(&[0x0e])?;
        let p = self.io.read_packet()?;
        match p.first() {
            Some(0x00) => {
                self.last_used = Instant::now();
                Ok(())
            }
            Some(0xff) => Err(parse_error(&p)),
            _ => Err(MysqlError::Protocol("bad ping response".into())),
        }
    }

    pub fn execute(&mut self, sql: &str) -> Result<QueryResult, MysqlError> {
        self.execute_params(sql, &[])
    }

    pub fn execute_params(
        &mut self,
        sql: &str,
        params: &[SqlValue<'_>],
    ) -> Result<QueryResult, MysqlError> {
        if self.broken {
            return Err(MysqlError::Io("connection is marked broken".into()));
        }
        let query = if params.is_empty() {
            sql.to_string()
        } else {
            format_sql(sql, params)
        };
        self.io.reset_sequence();
        let mut payload = Vec::with_capacity(1 + query.len());
        payload.push(0x03); // COM_QUERY
        payload.extend_from_slice(query.as_bytes());
        if let Err(e) = self.io.write_packet(&payload) {
            self.broken = true;
            return Err(e);
        }
        let result = self.read_query_result();
        if result.is_err() {
            if matches!(
                result,
                Err(MysqlError::Io(_)) | Err(MysqlError::Protocol(_))
            ) {
                self.broken = true;
            }
        } else {
            self.last_used = Instant::now();
        }
        result
    }

    fn read_query_result(&mut self) -> Result<QueryResult, MysqlError> {
        let packet = match self.io.read_packet() {
            Ok(p) => p,
            Err(e) => {
                self.broken = true;
                return Err(e);
            }
        };
        let first = *packet
            .first()
            .ok_or_else(|| {
                self.broken = true;
                MysqlError::Protocol("empty query response".into())
            })?;
        match first {
            0x00 => {
                let (affected, insert_id, status_flags) = parse_ok(&packet);
                self.in_transaction = status_flags & SERVER_STATUS_IN_TRANS != 0;
                if status_flags & SERVER_MORE_RESULTS_EXISTS != 0 {
                    self.broken = true;
                }
                Ok(QueryResult {
                    last_insert_id: insert_id,
                    affected_rows: affected,
                    ..Default::default()
                })
            }
            0xff => Err(parse_error(&packet)),
            0xfb => {
                self.broken = true;
                Err(MysqlError::Unsupported(
                    "LOCAL INFILE requests are disabled".into(),
                ))
            }
            _ => {
                let mut pos = 0;
                let count = match read_lenenc_int(&packet, &mut pos) {
                    Some(c) => c as usize,
                    None => {
                        self.broken = true;
                        return Err(MysqlError::Protocol("bad column count".into()));
                    }
                };
                if count > 4096 {
                    self.broken = true;
                    return Err(MysqlError::Protocol("too many result columns".into()));
                }
                let mut columns = Vec::with_capacity(count);
                for _ in 0..count {
                    let p = match self.io.read_packet() {
                        Ok(p) => p,
                        Err(e) => {
                            self.broken = true;
                            return Err(e);
                        }
                    };
                    if p.first() == Some(&0xff) {
                        self.broken = true;
                        return Err(parse_error(&p));
                    }
                    match parse_column(&p) {
                        Ok(col) => columns.push(col),
                        Err(e) => {
                            self.broken = true;
                            return Err(e);
                        }
                    }
                }
                // EOF after column definitions.
                let eof = match self.io.read_packet() {
                    Ok(p) => p,
                    Err(e) => {
                        self.broken = true;
                        return Err(e);
                    }
                };
                if !is_eof(&eof) {
                    self.broken = true;
                    return Err(MysqlError::Protocol(
                        "expected EOF after result columns".into(),
                    ));
                }
                let mut rows = Vec::new();
                loop {
                    let p = match self.io.read_packet() {
                        Ok(p) => p,
                        Err(e) => {
                            self.broken = true;
                            return Err(e);
                        }
                    };
                    if p.first() == Some(&0xff) {
                        self.broken = true;
                        return Err(parse_error(&p));
                    }
                    if is_eof(&p) {
                        let status_flags = eof_status_flags(&p);
                        self.in_transaction = status_flags & SERVER_STATUS_IN_TRANS != 0;
                        if status_flags & SERVER_MORE_RESULTS_EXISTS != 0 {
                            self.broken = true;
                        }
                        break;
                    }
                    // Do not treat a leading 0x00 as an OK packet here.  This
                    // client does not negotiate CLIENT_DEPRECATE_EOF, so a
                    // result set is terminated by an EOF packet only.  A row
                    // whose first column is an empty string starts with 0x00
                    // too, and dropping it silently lost whole rows.
                    match parse_row(&p, count) {
                        Ok(row) => rows.push(row),
                        Err(e) => {
                            self.broken = true;
                            return Err(e);
                        }
                    }
                    if rows.len() > 1_000_000 {
                        self.broken = true;
                        return Err(MysqlError::Protocol("result set too large".into()));
                    }
                }
                Ok(QueryResult {
                    columns,
                    rows,
                    ..Default::default()
                })
            }
        }
    }
}

fn auth_token(plugin: &str, password: &[u8], scramble: &[u8]) -> Result<Vec<u8>, MysqlError> {
    match plugin {
        "mysql_native_password" => Ok(crypto::mysql_native_token(password, scramble)),
        "caching_sha2_password" => Ok(crypto::mysql_sha2_token(password, scramble)),
        "mysql_clear_password" => Err(MysqlError::Auth(
            "mysql_clear_password requires TLS, which this build does not provide".into(),
        )),
        "sha256_password" => Err(MysqlError::Auth(
            "sha256_password requires TLS or an RSA key exchange".into(),
        )),
        other => Err(MysqlError::Unsupported(format!(
            "authentication plugin {other}"
        ))),
    }
}

struct Handshake {
    capabilities: u32,
    scramble: Vec<u8>,
    auth_plugin: String,
}

fn parse_handshake(packet: &[u8]) -> Result<Handshake, MysqlError> {
    let mut pos = 0;
    let protocol = read_u8(packet, &mut pos)?;
    if protocol != 10 {
        return Err(MysqlError::Protocol(format!(
            "unsupported MySQL protocol version {protocol}"
        )));
    }
    let _server_version = read_nul_string(packet, &mut pos)?;
    let _connection_id = read_u32_le(packet, &mut pos)?;
    let mut scramble = Vec::with_capacity(20);
    let part1 = read_bytes(packet, &mut pos, 8)?;
    scramble.extend_from_slice(part1);
    let _filler = read_u8(packet, &mut pos)?;
    let caps_low = read_u16_le(packet, &mut pos)? as u32;
    let mut capabilities = caps_low;
    let mut auth_plugin = String::new();
    if pos < packet.len() {
        let _charset = read_u8(packet, &mut pos)?;
        let _status = read_u16_le(packet, &mut pos)?;
        let caps_high = read_u16_le(packet, &mut pos)? as u32;
        capabilities |= caps_high << 16;
        let auth_len = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
            read_u8(packet, &mut pos)? as usize
        } else {
            0
        };
        if capabilities & CLIENT_SECURE_CONNECTION != 0 {
            let _reserved = read_bytes(packet, &mut pos, 10)?;
            let part2_len = std::cmp::max(13, auth_len.saturating_sub(8));
            let available = packet.len().saturating_sub(pos);
            let take = part2_len.min(available);
            let part2 = read_bytes(packet, &mut pos, take)?;
            for &b in part2 {
                if b == 0 {
                    break;
                }
                scramble.push(b);
                if scramble.len() >= 20 {
                    break;
                }
            }
        }
        if capabilities & CLIENT_PLUGIN_AUTH != 0 && pos < packet.len() {
            auth_plugin = read_nul_string(packet, &mut pos)?;
        }
    }
    if scramble.len() < 20 {
        // Some old servers only send 8 bytes; pad deterministically.  This
        // still works with native auth on ancient versions.
        scramble.resize(20, 0);
    }
    Ok(Handshake {
        capabilities,
        scramble,
        auth_plugin,
    })
}

fn parse_error(packet: &[u8]) -> MysqlError {
    if packet.len() < 3 {
        return MysqlError::Protocol("truncated error packet".into());
    }
    let code = u16::from_le_bytes([packet[1], packet[2]]);
    let mut state = String::new();
    let mut msg_start = 3;
    if packet.len() >= 9 && packet[3] == b'#' {
        state = String::from_utf8_lossy(&packet[4..9]).into_owned();
        msg_start = 9;
    }
    let message = String::from_utf8_lossy(&packet[msg_start..]).into_owned();
    MysqlError::Server {
        code,
        state,
        message,
    }
}

fn parse_ok(packet: &[u8]) -> (u64, u64, u16) {
    let mut pos = 1;
    let affected = read_lenenc_int(packet, &mut pos).unwrap_or(0);
    let insert_id = read_lenenc_int(packet, &mut pos).unwrap_or(0);
    let status_flags = if pos + 2 <= packet.len() {
        u16::from_le_bytes([packet[pos], packet[pos + 1]])
    } else {
        0
    };
    (affected, insert_id, status_flags)
}

fn is_eof(packet: &[u8]) -> bool {
    packet.first() == Some(&0xfe) && packet.len() < 9
}

fn eof_status_flags(packet: &[u8]) -> u16 {
    if packet.len() >= 5 && packet.first() == Some(&0xfe) {
        u16::from_le_bytes([packet[3], packet[4]])
    } else {
        0
    }
}

fn parse_column(packet: &[u8]) -> Result<Column, MysqlError> {
    let mut pos = 0;
    let _catalog = read_lenenc_bytes(packet, &mut pos)?;
    let _schema = read_lenenc_bytes(packet, &mut pos)?;
    let _table = read_lenenc_bytes(packet, &mut pos)?;
    let _org_table = read_lenenc_bytes(packet, &mut pos)?;
    let name = String::from_utf8_lossy(read_lenenc_bytes(packet, &mut pos)?).into_owned();
    let _org_name = read_lenenc_bytes(packet, &mut pos)?;
    let _fixed = read_lenenc_int(packet, &mut pos)
        .ok_or_else(|| MysqlError::Protocol("bad column definition".into()))?;
    let _charset = read_u16_le(packet, &mut pos)?;
    let _length = read_u32_le(packet, &mut pos)?;
    let _column_type = read_u8(packet, &mut pos)?;
    let _flags = read_u16_le(packet, &mut pos)?;
    let _decimals = read_u8(packet, &mut pos)?;
    Ok(Column { name })
}

fn parse_row(packet: &[u8], count: usize) -> Result<Row, MysqlError> {
    let mut pos = 0;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        if pos >= packet.len() {
            return Err(MysqlError::Protocol("truncated row packet".into()));
        }
        if packet[pos] == 0xfb {
            values.push(None);
            pos += 1;
            continue;
        }
        let len = read_lenenc_int(packet, &mut pos)
            .ok_or_else(|| MysqlError::Protocol("bad row value length".into()))?
            as usize;
        if pos + len > packet.len() {
            return Err(MysqlError::Protocol("truncated row value".into()));
        }
        values.push(Some(packet[pos..pos + len].to_vec()));
        pos += len;
    }
    Ok(Row { values })
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, MysqlError> {
    if *pos >= data.len() {
        return Err(MysqlError::Protocol("unexpected end of packet".into()));
    }
    let v = data[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u16_le(data: &[u8], pos: &mut usize) -> Result<u16, MysqlError> {
    let b = read_bytes(data, pos, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(data: &[u8], pos: &mut usize) -> Result<u32, MysqlError> {
    let b = read_bytes(data, pos, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], MysqlError> {
    if *pos + n > data.len() {
        return Err(MysqlError::Protocol("unexpected end of packet".into()));
    }
    let s = &data[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

fn read_nul_string(data: &[u8], pos: &mut usize) -> Result<String, MysqlError> {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    if *pos >= data.len() {
        return Err(MysqlError::Protocol("unterminated string in packet".into()));
    }
    let s = String::from_utf8_lossy(&data[start..*pos]).into_owned();
    *pos += 1;
    Ok(s)
}

fn read_lenenc_int(data: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *data.get(*pos)?;
    *pos += 1;
    match first {
        0x00..=0xfa => Some(first as u64),
        0xfb => None,
        0xfc => {
            let b = data.get(*pos..*pos + 2)?;
            *pos += 2;
            Some(u16::from_le_bytes([b[0], b[1]]) as u64)
        }
        0xfd => {
            let b = data.get(*pos..*pos + 3)?;
            *pos += 3;
            Some(b[0] as u64 | ((b[1] as u64) << 8) | ((b[2] as u64) << 16))
        }
        0xfe => {
            let b = data.get(*pos..*pos + 8)?;
            *pos += 8;
            Some(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        }
        _ => None,
    }
}

fn read_lenenc_bytes<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], MysqlError> {
    let len = read_lenenc_int(data, pos)
        .ok_or_else(|| MysqlError::Protocol("bad length-encoded value".into()))?
        as usize;
    read_bytes(data, pos, len)
}

fn write_lenenc_int(out: &mut Vec<u8>, v: u64) {
    if v < 251 {
        out.push(v as u8);
    } else if v < 65536 {
        out.push(0xfc);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v < 16_777_216 {
        out.push(0xfd);
        let b = (v as u32).to_le_bytes();
        out.extend_from_slice(&b[..3]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Connection pool

pub struct Pool {
    inner: Mutex<PoolInner>,
    available: Condvar,
    params: MysqlParams,
    max_size: usize,
}

struct PoolInner {
    idle: Vec<Connection>,
    total: usize,
    shutting_down: bool,
}

pub struct PooledConnection<'a> {
    pool: &'a Pool,
    conn: Option<Connection>,
    reusable: bool,
}

impl Pool {
    pub fn new(params: MysqlParams, max_size: usize) -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                idle: Vec::new(),
                total: 0,
                shutting_down: false,
            }),
            available: Condvar::new(),
            params,
            max_size: max_size.max(1),
        }
    }

    /// Open one pooled connection and run the protocol-level ping.
    pub fn ping(&self) -> Result<(), MysqlError> {
        let mut guard = self.acquire()?;
        guard.conn_mut().ping()
    }

    pub fn acquire(&self) -> Result<PooledConnection<'_>, MysqlError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.shutting_down {
                return Err(MysqlError::Io("pool is shutting down".into()));
            }
            if let Some(mut conn) = inner.idle.pop() {
                drop(inner);
                // Validate idle connections before handing them out.
                if conn.last_used.elapsed() > Duration::from_secs(30) && conn.ping().is_err() {
                    let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    inner.total = inner.total.saturating_sub(1);
                    self.available.notify_one();
                    continue;
                }
                return Ok(PooledConnection {
                    pool: self,
                    conn: Some(conn),
                    reusable: true,
                });
            }
            if inner.total < self.max_size {
                inner.total += 1;
                drop(inner);
                match Connection::connect(&self.params) {
                    Ok(conn) => {
                        return Ok(PooledConnection {
                            pool: self,
                            conn: Some(conn),
                            reusable: true,
                        })
                    }
                    Err(e) => {
                        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                        inner.total = inner.total.saturating_sub(1);
                        self.available.notify_one();
                        return Err(e);
                    }
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(MysqlError::Io(
                    "timed out waiting for a database connection".into(),
                ));
            }
            let (guard, _timeout) = self
                .available
                .wait_timeout(inner, deadline.saturating_duration_since(now))
                .unwrap_or_else(|e| e.into_inner());
            drop(guard);
        }
    }

    /// Execute a statement without replaying it on a transport failure.
    ///
    /// Use this (or [`execute`](Self::execute)) for every write. A transport
    /// error after the server executed the statement must not be retried,
    /// because that can insert or update twice.
    pub fn query(&self, sql: &str, params: &[SqlValue<'_>]) -> Result<QueryResult, MysqlError> {
        self.query_inner(sql, params, false)
    }

    /// Execute a read-only statement with one retry on a transport failure.
    pub fn query_read(
        &self,
        sql: &str,
        params: &[SqlValue<'_>],
    ) -> Result<QueryResult, MysqlError> {
        self.query_inner(sql, params, true)
    }

    /// Execute a statement without replaying it on a transport failure.
    ///
    /// This is an alias for [`query`](Self::query) with a write-path name.
    pub fn execute(&self, sql: &str, params: &[SqlValue<'_>]) -> Result<QueryResult, MysqlError> {
        self.query_inner(sql, params, false)
    }

    fn query_inner(
        &self,
        sql: &str,
        params: &[SqlValue<'_>],
        retry: bool,
    ) -> Result<QueryResult, MysqlError> {
        let mut guard = self.acquire()?;
        let result = {
            let conn = guard.conn_mut();
            conn.execute_params(sql, params)
        };
        match result {
            Ok(r) => Ok(r),
            Err(MysqlError::Io(_)) | Err(MysqlError::Protocol(_)) if retry => {
                guard.discard();
                self.query_inner(sql, params, false)
            }
            Err(e) => {
                if matches!(e, MysqlError::Io(_) | MysqlError::Protocol(_)) {
                    guard.discard();
                }
                Err(e)
            }
        }
    }

    pub fn with_connection<F, T>(&self, f: F) -> Result<T, MysqlError>
    where
        F: FnOnce(&mut Connection) -> Result<T, MysqlError>,
    {
        let mut guard = self.acquire()?;
        f(guard.conn_mut())
    }
}

impl PooledConnection<'_> {
    pub fn conn_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("pooled connection missing")
    }

    pub fn discard(&mut self) {
        self.reusable = false;
        self.conn = None;
    }
}

impl Drop for PooledConnection<'_> {
    fn drop(&mut self) {
        let mut conn = self.conn.take();
        if self.reusable {
            if let Some(ref mut c) = conn {
                if c.in_transaction && !c.broken {
                    let _ = c.execute("ROLLBACK");
                }
            }
        }
        let mut inner = self.pool.inner.lock().unwrap_or_else(|e| e.into_inner());
        if self.reusable {
            if let Some(c) = conn {
                if !c.broken && !c.in_transaction && inner.idle.len() < self.pool.max_size {
                    inner.idle.push(c);
                } else {
                    inner.total = inner.total.saturating_sub(1);
                }
            } else {
                inner.total = inner.total.saturating_sub(1);
            }
        } else {
            inner.total = inner.total.saturating_sub(1);
        }
        self.pool.available.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rng, MALICIOUS_STRINGS};

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn fuzz_sql_parameters_are_always_hex_literals() {
        let mut rng = Rng::new(0x5a17_0001);
        for _ in 0..2_000 {
            let len = rng.below(256);
            let bytes = rng.bytes(len);
            let formatted = format_sql("SELECT ?", &[SqlValue::Bytes(&bytes)]);
            assert_eq!(formatted, format!("SELECT X'{}'", hex(&bytes)));

            let len = rng.below(128);
            let text = rng.text(len);
            let formatted = format_sql("SELECT ?", &[SqlValue::Str(&text)]);
            assert_eq!(
                formatted,
                format!("SELECT CONVERT(X'{}' USING utf8mb4)", hex(text.as_bytes()))
            );
        }
        for value in MALICIOUS_STRINGS {
            let formatted = format_sql("SELECT ?", &[SqlValue::Str(value)]);
            assert!(formatted.starts_with("SELECT CONVERT(X'"));
            assert!(formatted.ends_with("' USING utf8mb4)"));
            assert!(!formatted.contains(" OR "));
            assert!(!formatted.contains("--"));
        }
    }

    #[test]
    fn fuzz_sql_templates_do_not_panic_or_expand_quoted_placeholders() {
        let mut rng = Rng::new(0x5a17_0002);
        let fragments = [
            "SELECT", " ", "?", "'", "\"", "`", "--", "/*", "*/", "\\", "\n", "\r", "\0", "a", "=",
            ";", "(", ")", "0", "💣",
        ];
        for _ in 0..2_000 {
            let mut sql = String::new();
            for _ in 0..rng.below(30) {
                sql.push_str(fragments[rng.below(fragments.len())]);
            }
            let params = [SqlValue::Str("x' OR 1=1 --"), SqlValue::Bytes(b"\0'\\")];
            let formatted = format_sql(&sql, &params);
            assert!(formatted.len() <= sql.len() + 256);
            // A placeholder inside a quoted SQL literal must remain SQL text,
            // never be replaced with a parameter.
            let quoted = format_sql("SELECT '?' AS literal", &[SqlValue::Int(1)]);
            assert_eq!(quoted, "SELECT '?' AS literal");
        }
        assert_eq!(format_sql("SELECT ?", &[]), "SELECT ?");
        assert_eq!(
            format_sql("SELECT ?", &[SqlValue::Float(f64::NAN)]),
            "SELECT NULL"
        );
        assert_eq!(
            format_sql("SELECT ?", &[SqlValue::Float(f64::INFINITY)]),
            "SELECT NULL"
        );
    }

    #[test]
    fn sql_formatting_is_injection_safe() {
        let sql = format_sql(
            "SELECT * FROM t WHERE a = ? AND b = ?",
            &[SqlValue::Str("x' OR 1=1 --"), SqlValue::Int(42)],
        );
        assert!(sql.contains("CONVERT(X'7827204f5220313d31202d2d' USING utf8mb4)"));
        assert!(sql.contains("b = 42"));
        assert!(!sql.contains("' OR"));
    }

    #[test]
    fn skips_placeholders_in_strings() {
        let sql = format_sql("SELECT '?' AS q, ? AS v", &[SqlValue::Int(1)]);
        assert_eq!(sql, "SELECT '?' AS q, 1 AS v");
    }

    #[test]
    fn lenenc_roundtrip() {
        for v in [0u64, 250, 251, 65535, 65536, 16_777_216] {
            let mut b = Vec::new();
            write_lenenc_int(&mut b, v);
            let mut pos = 0;
            assert_eq!(read_lenenc_int(&b, &mut pos), Some(v));
        }
    }

    #[test]
    fn a_row_with_an_empty_first_column_is_not_an_ok_packet() {
        // Length-encoded empty string followed by a six-byte string.  The
        // packet starts with 0x00 and is longer than seven bytes; it is a
        // normal row, not the OK packet that terminates a DEPRECATE_EOF result
        // set.  This client does not negotiate that capability.
        let packet = b"\x00\x06groups";
        assert!(!is_eof(packet));
        let row = parse_row(packet, 2).expect("row parses");
        assert_eq!(row.get_str(0), Some(""));
        assert_eq!(row.get_str(1), Some("groups"));
    }
}
