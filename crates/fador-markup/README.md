# fador-markup

Dependency-free markup leaf helpers: the small decisions every markup pipeline
makes at its edges, without a BBCode, wikitext or stored-XML renderer.

| Module | Contents |
|---|---|
| `escape` | `EscapePolicy::{Text, Attribute, CompatAttr, XsltText}`, `escape`, `unescape_compat`, `decode_entities_bounded` |
| `url` | `SchemePolicy`, `is_safe_url`, `sanitize_url`, `neutralise_url` |
| `censor` | `Censor`: case-insensitive, whole-word, longest-match-first replacement |
| `code` | `match_longest_code`, `replace_codes`, `strtr` and the smiley boundary rules |
| `strip` | `strip_markup`: tag-free plain text with decoded entities |
| `highlight` | `highlight_html`, `highlight_segment`, `excerpt` |
| `html` | `is_void_element`, `is_url_attribute`, `is_allowed_attr`, `sanitize_style` |

## Design rules

- Standard library only.
- No parser state, no I/O and no database, template or HTTP knowledge.
- Every scanner is bounded: tag length, character-reference length, highlight
  ranges and excerpt snippets all have a cap.
- Case-insensitive matching keeps byte offsets in the original string, so a
  lowercasing that changes byte length (`İ`, `ẞ`) can never split a `&str`.
- `#![deny(unsafe_code)]`, `#![warn(missing_docs)]`, MSRV 1.88.

## Example

```rust
use fador_markup::{escape, highlight_html, is_safe_url, EscapePolicy, SchemePolicy};

assert_eq!(escape(EscapePolicy::Attribute, "\"x\""), "&quot;x&quot;");
assert!(!is_safe_url("javascript:alert(1)", &SchemePolicy::WEB));
assert_eq!(
    highlight_html("<p>a fox</p>", &["fox"]),
    "<p>a <strong class=\"highlight\">fox</strong></p>"
);
```

## What is not here

The phpBB stored-XML renderer, the SMF BBCode renderer, the wikitext parser and
the MonoBook skin. Those are applications of these helpers, not leaves, and they
belong to the server that owns their data model.

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
