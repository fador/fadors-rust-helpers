# fador-http

A small, hardened, dependency-free HTTP/1.1 server.

- Bounded request parsing: request line, header count and size, body size and
  target length all have hard limits.
- Strict framing: duplicate `Host`/`Content-Length`, any `Transfer-Encoding`,
  obsolete line folding and control bytes are rejected.
- Response framing engine with `Content-Length`, chunked bodies, `HEAD`, `204`,
  `304` and `206` handling.
- Reserved response headers cannot be overridden and caller values cannot split
  the response head.
- Optional reverse-proxy handling with rightmost-untrusted `X-Forwarded-For`
  resolution and a local-proxy fallback.
- `multipart/form-data` text fields in `form_params()`; file parts stay in
  `Request::body` for an upload handler.
- No `unsafe`, no external crates, MSRV 1.88.

## Usage

```rust
use fador_http::{Handler, HttpConfig, Response, Server};
use std::sync::Arc;

let handler: Arc<Handler> = Arc::new(|request| {
    if request.path() == "/" {
        Response::html(200, "OK", "<h1>hello</h1>".to_string())
    } else {
        Response::text(404, "Not Found", "no such page".to_string())
    }
});
let server = Server::new(HttpConfig::default(), handler);
// server.run().unwrap();
```

`HttpConfig::workers = 0` starts two threads per logical CPU, clamped to 8..128.
Every other field has a documented default and can be left alone.

## Response framing

| response | framing |
|---|---|
| `1xx`, `204`, `304` | no body, no `Content-Length`, no `Transfer-Encoding` |
| in-memory body, HTTP/1.1 | `Transfer-Encoding: chunked` |
| empty body | `Content-Length: 0` |
| `Content-Encoding` set | `Content-Length` |
| `206` or `Content-Range` | `Content-Length` |
| HTTP/1.0 | `Content-Length` |
| file body | `Content-Length` (chunked when `file_content_length_limit` allows) |
| `HEAD` | the headers of the equivalent `GET`, no body |

A file body that is shorter than its declared length aborts the response with
`UnexpectedEof` instead of ending it as if it were complete.

`file_content_length_limit` defaults to `0`, which keeps `Content-Length` on
every file body. Set it to `FILE_CONTENT_LENGTH_LIMIT` (4 MiB) to reproduce the
reference board's policy of re-framing small attachment bodies as chunks.

## Requests

- Methods: `GET`, `HEAD`, `POST`. Anything else gets `405` with `Allow`.
- Targets must start with `/`; `//host/path` is rejected as ambiguous.
- `Host` is required on HTTP/1.1, validated, and may appear only once.
- `Content-Length` must be `1*DIGIT` and at most `max_request_bytes`.
- `Transfer-Encoding` is rejected with `501`; a request with both framing
  headers is rejected with `400`.
- Duplicate ordinary headers are preserved; duplicate framing headers and
  `Host` are not.

`Request::form_params()` returns `multipart/form-data` text fields for a
multipart body and urlencoded fields otherwise. Any other content type returns
an empty vector, so a multipart or binary body is never silently decoded as
urlencoded.

## Proxies

`trust_proxy_headers` requires the peer to be listed in `trusted_proxies`
(addresses or IPv4 CIDR ranges). `trust_local_proxy` (default on) additionally
honours `X-Forwarded-For` from a loopback or private peer, which is the normal
single-host reverse-proxy deployment. The client address is resolved from the
rightmost entry that is not itself a trusted proxy, so a client-supplied header
cannot spoof its address. `X-Forwarded-Proto` is read only through
`trust_proxy_headers`; `canonical_scheme` covers TLS terminated upstream.

## Not included

TLS, chunked uploads, CGI, directory listing, static asset serving, rate
limiting and access logging. Those belong in separate modules.

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
