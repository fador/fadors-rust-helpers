# fador

Facade and prelude for the fador Rust helpers.

```toml
[dependencies]
fador = "0.2"
```

Enable only what you need:

```toml
[dependencies]
fador = { version = "0.2", default-features = false, features = ["http", "mysql"] }
```

| Feature | Re-exported crate |
|---|---|
| `core` | `fador-core` |
| `compress` | `fador-compress` |
| `http` | `fador-http` |
| `mysql` | `fador-mysql` |
| `auth` | `fador-auth` |
| `i18n` | `fador-i18n` |
| `markup` | `fador-markup` |
| `services` | `fador-services` |
| `thumbnails` | `fador-thumb` |
| `phpbb-template` | `fador-phpbb-template` |
| `smf-theme` | `fador-smf-theme` |
| `wikitext` | `fador-wikitext` |

The default features are `core`, `compress`, `http`, `mysql`, `auth`, `i18n`
and `markup`. `all` enables every crate, including the optional `image`
dependency behind `thumbnails`.

## Example

```rust
use fador::prelude::*;

let response = Response::text(200, "OK", "hello".to_string());
assert_eq!(response.status, 200);
```

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
