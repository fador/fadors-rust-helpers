# fadors-rust-helpers

Shared, dependency-free Rust helpers extracted from the
[keskustelu](https://github.com/fador/keskustelu),
[smf](https://github.com/fador/smf) and
[wiki](https://github.com/fador/wiki) servers.

The repository is a Cargo workspace: each crate is published independently,
but all of them share one history, one CI pipeline and one release process.

**Status: early.** Three crates are present today: `fador-compress`,
`fador-core` and `fador-mysql`. The rest are extracted one at a time, with the
original test suites and fuzz corpora.

## Crates

| Crate | Contents | Status |
|---|---|---|
| `fador-compress` | gzip, zlib and raw DEFLATE codec | available |
| `fador-core` | crypto, random, JSON, PHP serialization, multipart, image headers, utilities, cache, path sandbox | available |
| `fador-mysql` | MySQL/MariaDB wire client, authentication and connection pool | available |
| `fador-testutil` | seeded fuzz helpers used only by the workspace tests | internal |
| `fador-http` | hardened HTTP/1.1 server, framing, proxy handling, static assets, limits, access log | planned |
| `fador-auth` | sessions, cookies, CSRF, password formats, bans, throttling | planned |
| `fador-i18n` | language packs, plural rules, dates, timezone data | planned |
| `fador-markup` | escaping, URL policy, censors, smileys, search highlighting | planned |
| `fador-services` | SMTP, captcha, cron, feeds, webhook spool, thumbnails | planned |
| `fador` | facade and prelude | planned |
| `fador-phpbb-template` | phpBB template compiler | planned |
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
- **MSRV 1.88**, edition 2021, `#![forbid(unsafe_code)]`.

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
