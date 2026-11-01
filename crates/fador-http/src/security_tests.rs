//! Seeded fuzz tests for the HTTP framing and form parsers.
//!
//! These tests extend `fuzz_request_parser_with_malicious_inputs` in `lib.rs`
//! with the structured smuggling cases and the form/multipart parser. Every
//! generated case is deterministic: the corpus is fixed and the only variable
//! is the seed. Set `FADOR_FUZZ_ITERATIONS` to run a deeper pass.

use super::*;
use crate::testutil::{iterations, Rng, MALICIOUS_STRINGS};
use crate::util::{parse_form, parse_multipart_form};
use std::io::Cursor;

fn config() -> HttpConfig {
    HttpConfig::default()
}

fn peer() -> SocketAddr {
    "127.0.0.1:43210".parse().unwrap()
}

fn parse(raw: &[u8], cfg: &HttpConfig) -> Result<Option<Request>, Response> {
    let mut reader = Cursor::new(raw.to_vec());
    read_request(&mut reader, peer(), cfg)
}

fn expect_status(raw: &[u8], status: u16) {
    match parse(raw, &config()) {
        Err(response) => assert_eq!(
            response.status,
            status,
            "unexpected status for {:?}",
            String::from_utf8_lossy(raw)
        ),
        Ok(_) => panic!(
            "hostile request was accepted: {:?}",
            String::from_utf8_lossy(raw)
        ),
    }
}

#[test]
fn request_framing_rejects_smuggling_and_control_bytes() {
    expect_status(
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        501,
    );
    expect_status(
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\naaaa",
        400,
    );
    expect_status(
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\naaaa",
        400,
    );
    expect_status(
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 9999999999999999999999\r\n\r\n",
        400,
    );
    expect_status(
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n",
        400,
    );
    expect_status(
        b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: folded\r\n\tvalue\r\n\r\n",
        400,
    );
    expect_status(b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: a\rb\r\n\r\n", 400);
    expect_status(b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: a\x7fb\r\n\r\n", 400);
    expect_status(b"GET / HTTP/1.1\r\nX-Test: value\r\n\r\n", 400);
    expect_status(b"GET http://evil.example/ HTTP/1.1\r\nHost: x\r\n\r\n", 400);
    expect_status(b"GET //evil.example/ HTTP/1.1\r\nHost: x\r\n\r\n", 400);
    expect_status(b"GET / HTTP/1.1\r\nHost: /evil\r\n\r\n", 400);
    expect_status(b"GET / HTTP/1.1\r\nHost: evil@example\r\n\r\n", 400);
    expect_status(b"GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n", 400);
    // Duplicate ordinary headers are preserved; only framing headers and Host
    // are ambiguous enough to reject.
    let request = parse(
        b"GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nX-A: 2\r\n\r\n",
        &config(),
    )
    .ok()
    .flatten()
    .expect("duplicate ordinary headers are allowed");
    assert_eq!(request.headers.len(), 3);

    // A header name with a space before the colon would be parsed differently
    // by a proxy that trims it; reject it before the value is interpreted.
    expect_status(b"GET / HTTP/1.1\r\nHost : x\r\n\r\n", 400);
    // A bare CR inside a header name must not survive as a value.
    expect_status(b"GET / HTTP/1.1\r\nX-\rTest: v\r\nHost: x\r\n\r\n", 400);

    let mut many_headers = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
    for _ in 0..512 {
        many_headers.extend_from_slice(b"X-Test: value\r\n");
    }
    many_headers.extend_from_slice(b"\r\n");
    expect_status(&many_headers, 431);

    let mut long_target = b"GET /".to_vec();
    long_target.extend(std::iter::repeat_n(b'a', 20_000));
    long_target.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\n\r\n");
    expect_status(&long_target, 414);
}

#[test]
fn a_hostile_host_never_reaches_the_request() {
    for host in MALICIOUS_STRINGS {
        if host.is_empty() {
            continue;
        }
        let raw = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        if let Ok(Some(request)) = parse(raw.as_bytes(), &config()) {
            let value = request.header("host").unwrap_or("");
            assert!(
                value.is_ascii()
                    && !value.chars().any(|ch| ch.is_control()
                        || ch.is_whitespace()
                        || matches!(
                            ch,
                            '/' | '\\' | '?' | '#' | '@' | ',' | '"' | '\'' | '<' | '>'
                        )),
                "accepted a hostile Host value {value:?}"
            );
        }
    }
}

#[test]
fn fuzz_request_framing_and_headers() {
    let cfg = config();
    let mut rng = Rng::new(0x4854_5450_4655_5a5a);
    let methods = ["GET", "HEAD", "POST", "PUT", "OPTIONS", ""];
    let versions = ["HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/1.1 ", ""];
    let names = [
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Cookie",
        "X-Test",
        "X-\u{7f}",
        "Bad Name",
        "\u{0}",
    ];

    for _ in 0..iterations(6_000) {
        let method = *rng.pick(&methods);
        let target_len = rng.below(80);
        let query_len = rng.below(40);
        let target = match rng.below(4) {
            0 => format!("/{}", rng.text(target_len)),
            1 => format!(
                "/{}",
                (*rng.pick(MALICIOUS_STRINGS)).replace(['\r', '\n'], "")
            ),
            2 => format!("/x?{}", rng.text(query_len)),
            _ => "/".to_string(),
        };
        let version = *rng.pick(&versions);
        let mut raw = format!("{method} {target} {version}\r\n").into_bytes();
        for _ in 0..rng.below(8) {
            let name = *rng.pick(&names);
            let value_len = rng.below(60);
            let value = if rng.below(3) == 0 {
                (*rng.pick(MALICIOUS_STRINGS)).replace(['\r', '\n'], "")
            } else {
                rng.text(value_len)
            };
            raw.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        let body = match rng.below(4) {
            0 => {
                raw.extend_from_slice(b"\r\n");
                Vec::new()
            }
            1 => {
                let len = rng.below(64);
                raw.extend_from_slice(format!("Content-Length: {len}\r\n\r\n").as_bytes());
                rng.bytes(len)
            }
            2 => {
                raw.extend_from_slice(b"Content-Length: 999999999\r\n\r\n");
                Vec::new()
            }
            _ => {
                raw.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n");
                Vec::new()
            }
        };
        let mut payload = raw;
        payload.extend(body);

        // A hostile request may be rejected, but an accepted one must obey the
        // framing contract.
        if let Ok(Some(request)) = parse(&payload, &cfg) {
            assert!(matches!(request.method.as_str(), "GET" | "HEAD" | "POST"));
            assert!(request.target.starts_with('/'));
            assert!(request.target.len() <= 16_384);
            assert!(!request
                .target
                .bytes()
                .any(|byte| byte < 0x20 || byte == 0x7f));
            assert!(request.body.len() <= cfg.max_request_bytes);
            assert!(request.headers.len() <= cfg.max_headers);
            assert!(request.header("transfer-encoding").is_none());
            if request.method == "POST" {
                assert!(!request.body.is_empty() || request.header("content-length").is_some());
            }
            for (name, value) in &request.headers {
                assert!(!name.is_empty());
                assert!(name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')));
                assert!(!value
                    .chars()
                    .any(|ch| ch == '\0' || (ch.is_control() && ch != '\t')));
            }
            if request.client_ip.is_ipv6() || request.client_ip.is_ipv4() {
                // The forwarded address parser only returns parsed addresses.
            }
            assert!(request.peer_ip == peer().ip());
        }
    }
}

#[test]
fn form_parser_is_bounded_and_preserves_php_quirks() {
    assert_eq!(
        parse_form(b"a=1&a=2"),
        vec![("a".into(), "1".into()), ("a".into(), "2".into())]
    );
    assert_eq!(parse_form(b"bare"), vec![("bare".into(), String::new())]);
    assert_eq!(parse_form(b"a=%00b"), vec![("a".into(), "\0b".into())]);
    assert_eq!(parse_form(b"a=%2e%2e%2f"), vec![("a".into(), "../".into())]);
    assert_eq!(parse_form(b"a=1;b=2"), vec![("a".into(), "1;b=2".into())]);

    // A separator-only body cannot create an unbounded number of fields.
    let separators = vec![b'&'; 20_000];
    let fields = parse_form(&separators);
    assert!(fields.len() <= 4_096);

    // A very long value is still one field; the request body limit, not the
    // parser, bounds its size.
    let long = format!("a={}", "x".repeat(200_000));
    let fields = parse_form(long.as_bytes());
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].1.len(), 200_000);

    let mut rng = Rng::new(0x464f_524d_5f46_555a);
    for _ in 0..iterations(4_000) {
        let body = if rng.below(2) == 0 {
            let len = rng.below(512);
            rng.bytes(len)
        } else {
            let len = rng.below(512);
            rng.ascii(len, b"aZ09 %&=+?#;:/\\\"'<>\0\n\r\t\xc3\xa4")
                .into_bytes()
        };
        let fields = parse_form(&body);
        assert!(fields.len() <= 4_096);
        let total = fields
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>();
        // Percent decoding can shrink, never expand. Splitting keeps the
        // decoded text no larger than the input plus one replacement character
        // per invalid byte, so the UTF-8 lossy conversion bounds it at 3x.
        assert!(total <= body.len() * 3 + 16);
    }
}

fn part(name: &str, value: &str) -> String {
    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
}

#[test]
fn multipart_parser_rejects_mismatches_and_bounds_parts() {
    let boundary = "multipart/form-data; boundary=XyZ";
    assert!(parse_multipart_form(boundary, b"").is_empty());
    assert!(parse_multipart_form("multipart/form-data; boundary=XyZ", b"--wrong\r\n").is_empty());
    assert!(parse_multipart_form(
        "multipart/form-data; boundary=XyZ",
        b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nunterminated"
    )
    .is_empty());
    assert!(parse_multipart_form(
        "multipart/form-data; boundary=\"bad\r\nboundary\"",
        b"--bad\r\n"
    )
    .is_empty());

    // Duplicate names are preserved in order; the caller decides which wins.
    let body = format!(
        "--XyZ\r\n{}--XyZ\r\n{}--XyZ--\r\n",
        part("a", "first"),
        part("a", "second")
    );
    let fields = parse_multipart_form(boundary, body.as_bytes());
    assert_eq!(
        fields,
        vec![("a".into(), "first".into()), ("a".into(), "second".into())]
    );

    // A file part is skipped even when a second `name` parameter or a nested
    // `filename` appears in the disposition.
    let body = "--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.png\"; name=\"g\"\r\nContent-Type: image/png\r\n\r\nPNG\r\n--XyZ\r\nContent-Disposition: form-data; name=\"ok\"\r\n\r\n1\r\n--XyZ--\r\n";
    let fields = parse_multipart_form(boundary, body.as_bytes());
    assert_eq!(fields, vec![("ok".into(), "1".into())]);

    // NUL bytes and overlong names do not break the parser.
    let body = format!(
        "--XyZ\r\n--XyZ\r\n{}--XyZ--\r\n",
        part(&"n".repeat(300), "v\0x")
    );
    let fields = parse_multipart_form(boundary, body.as_bytes());
    assert!(fields.is_empty(), "overlong part names are skipped");

    // A part-count bomb is truncated at the field limit instead of growing
    // without bound.
    let mut bomb = Vec::new();
    for index in 0..5_000 {
        bomb.extend_from_slice(b"--XyZ\r\n");
        bomb.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"f{index}\"\r\n\r\nv\r\n").as_bytes(),
        );
    }
    bomb.extend_from_slice(b"--XyZ--\r\n");
    let fields = parse_multipart_form(boundary, &bomb);
    assert_eq!(fields.len(), 4_096);
}

#[test]
fn fuzz_form_and_multipart_parsers() {
    let boundary = "multipart/form-data; boundary=b0undary";
    let mut rng = Rng::new(0x4d55_4c54_4950_4152);
    let alphabet = b"--b0undary\r\nContent-Disposition: form-data; name=\"a\"; filename=\"f\"\r\n\r\n&=%\0\x7f\xff";
    for _ in 0..iterations(4_000) {
        let len = rng.below(700);
        let body = rng.ascii(len, alphabet).into_bytes();
        let fields = parse_multipart_form(boundary, &body);
        assert!(fields.len() <= 4_096);
        for (name, value) in &fields {
            assert!(name.len() <= 255);
            assert!(value.len() <= body.len());
            assert!(name.chars().count() <= name.len());
            assert!(!name.is_empty());
        }

        let boundary_len = rng.below(90);
        let content_type = format!(
            "multipart/form-data; boundary={}",
            rng.ascii(boundary_len, b"abcXYZ09-_ \";\\\0\r\n")
        );
        let _ = parse_multipart_form(&content_type, &body);

        let query_len = rng.below(400);
        let query = rng.ascii(query_len, b"aZ09%&=+?#;:/\\\"'<>\0\n\r\t\xc3\xa4");
        let fields = parse_form(query.as_bytes());
        assert!(fields.len() <= 4_096);
        for (key, value) in fields {
            assert!(key.len() + value.len() <= query.len() * 3 + 16);
        }
    }
}
