# fadors-rust-helpers

Shared, dependency-free Rust helpers extracted from the
[keskustelu](https://github.com/fador/keskustelu),
[smf](https://github.com/fador/smf) and
[wiki](https://github.com/fador/wiki) servers.

The repository is a Cargo workspace: each crate is published independently,
but all of them share one history, one CI pipeline and one release process.

**Status: foundation complete.** Eight crates are present today. The remaining
work is the optional services crate, the facade, and the SMF/wikitext dialect
engines.

## Crates

| Crate | Contents | Status |
|---|---|---|
| `fador-compress` | gzip, zlib and raw DEFLATE codec | available |
| `fador-core` | crypto, random, JSON, PHP serialization, multipart, image headers, utilities, cache, path sandbox | available |
| `fador-mysql` | MySQL/MariaDB wire client, authentication and connection pool | available |
| `fador-http` | hardened HTTP/1.1 server, response framing, request smuggling defenses, proxy/IP resolution, gzip negotiation | available |
| `fador-auth` | cookies, sessions, CSRF, password formats, bans, throttling, permission primitives | available |
| `fador-i18n` | language packs, plural rules, PHP/strftime dates, embedded timezone database | available |
| `fador-markup` | escaping, URL policy, censors, smiley matching, Unicode search highlighting | available |
| `fador-phpbb-template` | phpBB template compiler and sandboxed template loader | available |
| `fador-testutil` | seeded fuzz helpers used only by the workspace tests | internal |
| `fador-services` | SMTP, captcha, cron, feeds, webhook spool, thumbnails | planned |
| `fador` | facade and prelude | planned |
| `fador-smf-theme` | SMF PHP-subset theme engine | planned |
| `fador-wikitext` | MediaWiki wikitext parser | planned |

## Design rules

- **Standard library only** unless a crate explicitly opts into an optional
  dependency (`image` for thumbnails, `ureq` for HTTPS webhooks).
- **Bounded parsers.** Every untrusted input has an explicit size, depth or
  output limit. A malformed input returns an error; it never exhausts a worker.
- **No schema knowledge.** Table names, template dialects, routes and board
  settings stay in the application repositories.
- **One codec.** `fador-compress` is the only DEFLATE implementation used by
  the HTTP, backup and PNG paths.
- **MSRV 1.88**, edition 2021, `#![deny(unsafe_code)]`. The only exception is
  the isolated Windows CSPRNG FFI in `fador-core::random`.

## Using a crate

```toml
[dependencies]
fador-compress = { git = "https://github.com/fador/fadors-rust-helpers", tag = "v0.1.0" }
```

Once a crate is stable it is published on crates.io:

```toml
[dependencies]
fador-compress = "0.1"
```

## Releases

Versions are lockstep while the workspace is `0.x`: all crates share one
version, one tag and one changelog entry. Each crate is published separately in
dependency order.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for provenance and
third-party attribution.
