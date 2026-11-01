# fador-services

Dependency-free mail, captcha, cron and feed services.

The crate collects the parts of a web application that talk to the outside
world but do not depend on a database schema, an HTTP framework or a template
dialect. Configuration, the clock and the work itself are supplied by the
caller.

## Modules

| Module | Contents |
| --- | --- |
| `mail` | `Message`, `Address`, `SmtpConfig`, `Transport::{Log,Sendmail,Smtp}`, `send`, `render_rfc5322`, `dot_stuff`, `mail_date` |
| `captcha` | `friendly_code`, `render_png`, `render_wav`, `Difficulty`, `CaptchaOptions`, `Provider`, `ProviderConfig`, `verify_provider`, `accepts` |
| `cron` | `LeaderLock`, `RunLock`, `CronStatus`, `run_once`, `spawn`, `SchedulerConfig`, `SchedulerHandle`, `clamp_interval` |
| `feed` | `Feed`, `Entry`, `Category`, `Format::{Rss,Rss2,Atom,Rdf}`, `render`, `cdata`, `xml_escape`, `xml_escape_attr`, RFC 822/3339 dates |

## Usage

A message is validated and rendered without a network, then handed to a
transport:

```rust
use fador_services::mail::{render_rfc5322, Message};

let message = Message::new(
    "Forum <forum@example.test>",
    "user@example.test",
    "New reply",
    "Hello\n.leading dot\n",
)
.date(0);
let wire = render_rfc5322(&message).unwrap();
assert!(wire.starts_with("Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"));
assert!(wire.ends_with("Hello\r\n.leading dot\r\n"));
```

`Transport::Smtp` speaks EHLO with HELO fallback, `AUTH PLAIN` and `AUTH LOGIN`,
tries every resolved address with a connect timeout, and dot-stuffs the body
only for the `DATA` command. `Transport::Sendmail` pipes the same document to
`sendmail -i -t -f`. `Transport::Log` writes one metadata line to stderr and
never logs the body or a credential.

A captcha code and its image are deterministic for a seed:

```rust
use fador_services::captcha::{friendly_code_from, render_png, CaptchaOptions};

let code = friendly_code_from(&[0, 0, 1, 2, 3]); // "ABCD"
let png = render_png(&code, &CaptchaOptions::new(7)).unwrap();
assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
```

The cron module owns locks and a status file, not a task:

```rust
use fador_services::cron::{read_status, run_once, RunOutcome, RunSource};
use std::path::Path;

let lock = Path::new("temp/example-cron.lock");
match run_once(lock, RunSource::Manual, 1_000, || 3) {
    RunOutcome::Done(run) => assert_eq!(run.sent, 3),
    RunOutcome::Locked => { /* another trigger holds the run lock */ }
    RunOutcome::Panicked => { /* the status file records `panic` */ }
}
assert_eq!(read_status(lock).unwrap().sent, 3);
```

`spawn(SchedulerConfig, task)` starts the internal thread. Every tick refreshes
the heartbeat leader lock; the leader runs the task through the same run lock
as `run_once`. `SchedulerHandle::stop()` and `join()` shut it down.

Feeds are data, not board events:

```rust
use fador_services::feed::{render, Entry, Feed, Format};

let mut feed = Feed::new("Example", "https://example.test/");
feed.entries.push(Entry::new("Hello", "https://example.test/t=1").content("<p>Hi</p>"));
let xml = render(Format::Atom, &feed);
assert!(xml.contains("<content type=\"html\"><![CDATA[<p>Hi</p>]]></content>"));
```

## Features

All features are enabled by default. Each module is independent.

| Feature | Contents | Default |
| --- | --- | --- |
| `mail` | SMTP, sendmail and log transport, RFC 5322 rendering | yes |
| `captcha` | PNG and WAV challenges, provider verification (pulls in `fador-compress`) | yes |
| `cron` | leader lock, run lock, status file, scheduler thread | yes |
| `feed` | RSS 0.92/2.0, Atom 1.0, RDF documents | yes |

`cargo test -p fador-services --no-default-features` compiles an empty library
and passes; a module's tests are skipped with its feature. `fador-compress` is
only compiled when `captcha` is on.

## Bounds

Every parser and writer has an explicit limit.

| Area | Limit |
| --- | --- |
| mail body | 2 MiB |
| mail address | 320 bytes display form, 254 bytes addr-spec, 64-byte local part, 253-byte domain |
| mail recipients / headers | 32 recipients, 32 headers, 900-byte header values, 500-character subject |
| SMTP reply | 64 lines, 4,096 bytes per line, 16 KiB total |
| captcha code | 4-7 characters, 8 rendered glyphs |
| captcha image | 64-1024 x 24-256 pixels, at most 1,000,000 pixels |
| captcha WAV | 8 tones, 8,000 Hz mono, 8-bit |
| provider answer | 16 KiB, 1-60 second timeout |
| cron interval | 5-3,600 seconds |
| leader stale window | at least 120 seconds, or three intervals |
| run lock stale window | 900 seconds |
| cron status file | 8 KiB |
| feed | 500 entries, 16 categories per entry, 64 KiB per field |

## Deliberate deviations

- **Dot-stuffing is a transport step, not part of the message.** A message
  rendered once can go to sendmail (which uses `-i` and must not see doubled
  dots) or to SMTP `DATA` (which must). `render_rfc5322` produces the document;
  `dot_stuff` prepares the SMTP payload.
- **A control character is rejected, not rewritten.** An address, subject or
  header containing CR, LF, NUL or another control character fails with an
  error. Silently replacing it with a space hides an injection attempt.
- **No TLS and no STARTTLS.** The SMTP transport is for a submission relay on
  the same host or a trusted network; TLS terminates in front of it. The same
  rule applies to the challenge verifier, which must be a plain `http://` URL.
- **AUTH is capability-driven.** `EHLO` is parsed for `AUTH PLAIN` / `AUTH
  LOGIN` (both `AUTH PLAIN LOGIN` and `AUTH=PLAIN` forms). When the server
  answers `HELO` only, both mechanisms are tried once each.
- **Every resolved address is tried.** A host that resolves to an unreachable
  address family still works when another address accepts the connection.
- **The provider is fail-closed.** A rejected token is always rejected; a
  transport failure is accepted only with `ProviderConfig::fail_open`; a
  configuration error is never accepted.
- **The captcha is grayscale and local.** No GD, no font file, no decoder and
  no image crate. The PNG writer emits filter type 0 rows and a single `IDAT`
  chunk compressed by `fador-compress`.
- **The scheduler has no process-global state.** The old server kept a global
  "this process is the leader" token for an ACP display; here the caller owns
  the `LeaderLock` and can ask it directly.
- **A panic is contained.** `run_once` catches a panicking task, records
  `panic` in the status file and returns `RunOutcome::Panicked`, so the
  scheduler thread keeps running.
- **The feed writer is clean-room.** It is not SMF's `dumpTags()` /
  `cdata_parse()` and it does not reproduce their entity break-outs. A `]]>`
  inside content is split in the standard way, XML 1.0 forbids only characters
  that are actually invalid, and every text field is bounded.
- **No board knowledge.** There are no feed event types, email templates,
  routes, Discord payloads or database rows in this crate.

## Provenance

MIT. The code is the copyright holder's original work, extracted from the
`keskustelu`, `smf` and `wiki` servers and relicensed here. The SMTP client,
the captcha font, the lock/status design and the Atom feed shape come from
those servers; the XML writer and CDATA handling in `feed` are new and were not
copied from SMF's BSD-3-Clause `News.php`. No Simple Machines Forum, phpBB or
MediaWiki source is included, so this crate needs no additional `NOTICE` file.

See the repository `LICENSE` and `NOTICE` files.

## Tests

```sh
cargo fmt --all
cargo clippy -p fador-services --all-targets -- -D warnings
cargo test -p fador-services
cargo test -p fador-services --no-default-features
cargo doc -p fador-services --no-deps
```

The suite covers RFC 5322 construction, header-injection rejection, address
validation, dot-stuffing, EHLO capability parsing, bounded SMTP replies, a
scripted SMTP submission with AUTH PLAIN and the HELO/AUTH LOGIN fallback, PNG
signature/dimensions/CRC/zlib, WAV headers, provider verification against a
local server, leader/run lock exclusivity and stale recovery, status round
trips, panic containment, the scheduler thread, and the RSS/Atom/RDF shapes
with XML escaping and CDATA splitting. Seeded fuzz tests cover the address
parser, the SMTP reply reader, the status parser, the challenge renderers and
the feed writer. Set `FADOR_FUZZ_ITERATIONS` to raise the generated case count.
