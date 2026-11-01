# fador-core

Bounded, dependency-free primitives shared by the fador servers.

| Module | Contents |
|---|---|
| `cache` | bounded TTL cache |
| `crypto` | SHA-1/256/512, MD5, HMAC, PBKDF2, BLAKE2b, CRC-32, base64, hex |
| `imageinfo` | PNG/JPEG/GIF header and dimension checks |
| `json` | bounded JSON reader and writer |
| `multipart` | bounded `multipart/form-data` parser |
| `path` | platform-aware path sandbox and `Content-Disposition` names |
| `random` | OS-backed random bytes with a fallible API |

## Design rules

- Standard library only.
- Every parser has an explicit size, depth or count limit.
- No database schema, HTTP or template knowledge.
- `#![deny(unsafe_code)]`; the only exception is the isolated Windows CSPRNG
  FFI in `random`, marked with `#[allow(unsafe_code)]`.

## Example

```rust
use fador_core::json::{parse, write_compact};

let value = parse(r#"{"ok":true,"items":[1,2,3]}"#).unwrap();
assert_eq!(write_compact(&value), r#"{"ok":true,"items":[1,2,3]}"#);
```

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
