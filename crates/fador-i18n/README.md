# fador-i18n

Dependency-free language packs, plural rules, date formatting and time-zone
lookup for the fador servers.

- **Language packs.** Bounded JSON packs with a primary/fallback
  `LanguageSet`, per-file and per-page key resolution, nested values, help
  entries and time-zone labels. No pack data ships with the crate: the
  application embeds its own JSON with `include_str!` or loads it from a
  directory.
- **Plural rules.** All sixteen phpBB plural rules, plus the nullar-entry and
  "greatest defined form below" selection phpBB's `lang()` performs.
- **Placeholders.** A bounded `sprintf` subset: `%s`, `%d`, `%u`, `%f`, `%x`,
  `%X`, positional `%1$s`, precision (`%.2f`), width, flags and `%%`.
- **Dates.** PHP `date()` tokens (escaped literals, localized day and month
  names, ISO week, UTC offsets, zone abbreviations) and SMF's `strftime`
  subset with `TimeStrings`.
- **Time zones.** An embedded `KTZ1` archive of the IANA database, TZif
  parsing, and POSIX-footer extrapolation so dates after the last stored
  transition (2037 and later) still follow the zone's summer-time rule.

The crate uses the standard library only; `fador-core` supplies the bounded
JSON reader and the Gregorian calendar helpers. There is no `unsafe`.

## Usage

```rust
use fador_i18n::{format_placeholders, LanguagePack, LanguageSet};

let en = LanguagePack::from_json(
    r#"{
        "code": "en",
        "messages": {
            "PLURAL_RULE": 1,
            "POSTS": ["no posts", "1 post", "%d posts"],
            "WELCOME": "Welcome, %1$s! You have %2$d new messages."
        }
    }"#,
    "en",
)
.unwrap();

assert_eq!(en.lang("POSTS", &["0".to_string()]), "no posts");
assert_eq!(en.lang("POSTS", &["7".to_string()]), "7 posts");
assert_eq!(
    en.lang("WELCOME", &["Ada".to_string(), "2".to_string()]),
    "Welcome, Ada! You have 2 new messages."
);
assert_eq!(format_placeholders("%.2f", &["3.14159".to_string()]), "3.14");

// The Finnish pack defines nothing, so every key comes from the fallback.
let fi = LanguagePack::from_json(r#"{"code":"fi"}"#, "fi").unwrap();
let set = LanguageSet::new(fi, en);
assert_eq!(set.lang("POSTS", &["1".to_string()]), "1 post");
assert_eq!(set.lang("MISSING", &[]), "MISSING");
```

### Dates and zones

```rust
use fador_i18n::{format_date_php, DateTimeNames, Tzdb};

let names = DateTimeNames::english();
let tz = Tzdb::embedded();

// 2026-07-01T12:00:00Z in Helsinki is 15:00 EEST.
assert_eq!(
    format_date_php(&tz, &names, true, 1_782_907_200, "Europe/Helsinki", "D d.m.Y H:i T"),
    "Wed 01.07.2026 15:00 EEST"
);

// 2040 is past the last stored transition; the POSIX footer keeps the rule.
assert_eq!(tz.offset_for("Europe/Helsinki", 2_225_966_400), Some(10_800));
```

### SMF `strftime`

```rust
use fador_i18n::{format_strftime, TimeStrings};

let strings = TimeStrings::english();
assert_eq!(
    format_strftime("%A %e. %B %Y, %H:%M", 0, &strings),
    "Thursday  1. January 1970, 00:00"
);
```

## Loading packs

A pack is either a compiled-in JSON string or a file:

```rust
use fador_i18n::{EmbeddedPacks, LanguageSet};
use std::path::Path;

let embedded = EmbeddedPacks::new()
    .add("en", r#"{"code":"en","messages":{"POSTS":["no posts","1 post","%d posts"]}}"#)
    .add("fi", r#"{"code":"fi","messages":{"POSTS":{"0":"ei viestejä","1":"1 viesti","2":"%d viestiä"}}}"#);

let set = LanguageSet::load_with_embedded("fi", Path::new("languages"), &embedded).unwrap();
assert_eq!(set.lang("POSTS", &["2".to_string()]), "2 viestiä");
```

`LanguagePack::load` reads `<dir>/<code>.json` only; `load_with_embedded` falls
back to the registry when the file is absent. `LanguageSet` uses the requested
pack as the primary language and `en` as the fallback, and `select("en_us")`
switches an existing set to another installed pack.

## Time-zone data

`data/tzdata.bin` is a `KTZ1` archive: a little-endian count followed by
`(name length, name, blob length, TZif blob)` records. It contains 497 zones
copied from the IANA time-zone database, including each TZif v2 POSIX footer,
so [`Tzdb`] can extrapolate summer time past the last stored transition
(2037 in this build).

The IANA time-zone database is **public domain**: the data is not copyrightable
and is distributed without conditions. The archive is a verbatim repackaging of
those public-domain TZif files, not a derived work of any application.

`Tzdb::from_archive` parses any archive in the same format, and
`Tzdb::load_dir` reads a system `/usr/share/zoneinfo` tree when the deployment
wants newer rules than the embedded copy.

## Deliberate differences from the ported code

The crate is extracted from the keskustelu (`forum-i18n`), smf (`smf-core`,
`smf-php`) and wiki (`rustwiki-core`) servers. Most of it is a direct port;
these choices differ on purpose and are covered by tests:

- `Tzdb` keeps the TZif local-time types, so `date('T')` returns the real
  abbreviation (`EEST`) and `date('I')` reports daylight time instead of the
  zone identifier and a constant zero.
- The POSIX footer is used for every instant at or after the last stored
  transition, and for a zone with no transitions at all. Without it, 2038+
  dates would freeze at the last transition's offset.
- `date('r')` follows PHP (`Thu, 01 Jan 1970 00:00:00 +0000`) instead of the
  abbreviated `Thu Jan 1 1970 ...` form, `date('p')` returns `Z` at UTC, and
  `date('B')` computes Swatch beats instead of printing `000`.
- `%f` uses PHP's default of six decimals (`3.500000`) rather than Rust's
  shortest representation, and `%u` casts a negative argument to `u64` the way
  PHP's `%u` does.
- Width, flags and integer precision are honoured, a trailing `%` and an
  unknown conversion are preserved, and width/precision are clamped.
- `LanguagePack::from_json` normalizes the pack's own `code`, so a pack that
  says `EN` is still found by `select("en")`.
- Numeric-keyed plural objects are sorted before selection instead of relying
  on JSON member order.

## Limits

Every parser is bounded: the archive accepts at most 4096 zones, a TZif block
at most 100 000 transitions and 256 local-time types, a pack at most 128 JSON
nesting levels (the JSON reader's own bound), 1000 help entries per file and a
100-character zone name. Placeholder width and precision are capped at 65 535
characters, so a hostile format string cannot allocate without limit.

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
