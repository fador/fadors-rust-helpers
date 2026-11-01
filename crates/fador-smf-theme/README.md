# fador-smf-theme

A sandboxed PHP-subset evaluator and the SMF theme resolver, extracted from the
Naruto.fi SMF rewrite. It renders the original SMF 2.x `*.template.php` files
without an interpreter, a PHP runtime or a database.

The crate has three layers:

| layer | what it does |
| --- | --- |
| [`parse`] | lexes and parses a template into a `Stmt` tree |
| `Evaluator` | executes the tree under `EvalLimits` with a fixed function allow-list |
| `TemplateEngine` | resolves a theme directory, falls back to the default theme per file, caches parsed templates and renders pages in SMF's layer order |

The language core is independent of SMF. PHP's standard functions (`count`,
`implode`, `sprintf`, `substr`, `preg_replace`, ...) are built in; everything
SMF adds (`create_button`, `allowedTo`, `theme_copyright`, `timeformat`,
`comma_format`, `cleanXml`, `JavaScriptEscape`) lives in `SmfFunctions` behind
the `HostFunctions` trait.

- No external crates beyond `fador-core` and `fador-i18n`, no `unsafe`,
  MSRV 1.88.
- Templates are untrusted input and every limit ends in an error.

## Usage

```rust
use fador_smf_theme::{parse, EvalLimits, Evaluator, Value};

let mut evaluator = Evaluator::new(EvalLimits::default());
evaluator.set_global("txt", Value::Str("Hello".into()));

let statements =
    parse("<?php function template_main() { global $txt; echo $txt, '!'; } ?>").unwrap();
evaluator.execute(&statements).unwrap();
evaluator.call("template_main", Vec::new()).unwrap();

assert_eq!(evaluator.take_output(), "Hello!");
```

Rendering an installed theme is the engine's job:

```rust,no_run
use fador_smf_theme::{EvalLimits, TemplateEngine, Theme};
use std::path::PathBuf;

let engine = TemplateEngine::new("/srv/board/original", "default", EvalLimits::default())?;
engine.add_theme(Theme {
    name: "default".into(),
    directory: PathBuf::from("Themes/default"),
    url: "/Themes/default".into(),
    images_url: "/Themes/default/images".into(),
    layers: vec!["html".into(), "body".into()],
    templates: vec!["index".into()],
})?;
let html = engine.render_page(
    "default",
    &["index", "BoardIndex"],
    &["html".into(), "body".into()],
    "template_main",
    Vec::new(),
)?;
```

`TemplateEngine::new` installs `SmfFunctions` by default because an SMF theme
cannot render without it. `without_host()` renders with the language core only,
and `with_host_factory(...)` installs a different set. A factory builds one host
per render, so the engine stays `Send + Sync` and several threads can render at
once.

## The supported PHP subset

The parser accepts what the installed themes use and nothing else:

- inline HTML, `<?php ... ?>` and `<?= ... ?>`
- `echo`, `if`/`elseif`/`else`, `foreach` (with key and by-reference forms),
  `for`, `while`, `switch`/`case`/`default`, `break`, `continue`, `return`
- `function` declarations with by-reference and default parameters, `global`,
  `unset`
- `array(...)`, `[...]`, indexing, appending, `isset`, `empty`, `@`, casts
- the usual operators, with PHP 8 precedence (`.` binds like `+`)
- double-quoted interpolation of `$name`, `$arr[key]` and `{$expr}`

There is no object system, no `include`, no namespace, no class, no `eval`, no
`list()`, no reference to the filesystem, network, process table or database.

## Security contract

- **Bounded execution.** `EvalLimits` caps statements and expressions
  (`max_steps`), nested template calls (`max_call_depth`), rendered output
  (`max_output_bytes`), any single string (`max_string_bytes`) and any array
  (`max_array_entries`). Exceeding a limit is an error.
- **Closed allow-list.** A call reaches a template-declared function, a PHP
  standard function implemented by the evaluator, or a host function whose
  `has()` returns true. Anything else is `function ... is not in the template
  allow-list`. `call_user_func()` only dispatches to template functions.
- **No regular-expression engine.** `preg_replace()` implements exactly three
  hard-coded patterns; any other pattern is an error, so a template cannot make
  the server backtrack.
- **Path sandbox.** Theme and template names may only use `[A-Za-z0-9_.-]`, may
  not contain `..`, and must be a single path component. Every directory and
  file is canonicalised and must stay inside the content root, so a symlink
  cannot escape the theme tree.
- **Bounded cache.** The parse cache holds at most 512 templates and is keyed by
  canonical path, modification time and size, so an edited template is reloaded
  and an unchanged one is parsed once.
- **No leakage.** Errors carry a message with the file name, never rendered
  output or file contents.

## API

| item | purpose |
| --- | --- |
| `parse`, `tokenize` | template source to `Stmt` / `Token` |
| `Stmt`, `Expr`, `Param`, `BinOp`, `UnOp`, `AssignOp`, `CastType` | the parsed representation |
| `Evaluator` | run a template, seed globals and constants, install a host |
| `EvalLimits`, `EvalError` | bounds and diagnostics |
| `Value`, `PhpArray`, `Key`, `FunctionValue` | PHP-like values |
| `HostFunctions`, `HostContext` | the application function interface |
| `SmfFunctions` | the SMF theme functions and constants |
| `TemplateEngine`, `Theme` | theme registration, resolution, rendering |
| `TemplateCacheStats`, `TemplateError` | cache counters and diagnostics |
| `format_time`, `TimeSettings`, `TimeStrings` | SMF's `timeformat()` |
| `array`, `str_key`, `int_key` | helpers for building controller globals |

## Time formatting

`format_time` keeps SMF's `timeformat()` semantics — user plus forum hour
offsets, applied before the board time zone, plus the "Today"/"Yesterday"
labels — while the `strftime` tokens, localized names and the IANA time-zone
database come from [`fador-i18n`]. Only the wrapper is SMF-specific.

## Testing

```sh
cargo test -p fador-smf-theme
```

The suite covers the lexer, parser, evaluator, expressions, arrays and
references, loops and functions, every limit, theme layer order, the per-file
default-theme fallback, parse-cache invalidation, the host-function allow-list
and a fixed-seed fuzz pass. To parse a real SMF theme tree, point the optional
corpus test at one:

```sh
FADOR_SMF_THEME_CORPUS=/path/to/original/Themes/default \
  cargo test -p fador-smf-theme
```

The test is skipped when the variable is unset, so no SMF template, style, image
or language-pack content is vendored in this crate.

## Provenance

The code is extracted from the author's own `smf` server and relicensed under
the MIT license. `format_time()` re-implements the behaviour of SMF's
`timeformat()`/`strftime()` subset; no SMF source code or template content is
copied. See the repository `NOTICE` and `crates/fador-smf-theme/NOTICE` for the
BSD-3-Clause attribution of the SMF behaviour this crate reproduces.

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).

[`parse`]: https://docs.rs/fador-smf-theme/latest/fador_smf_theme/fn.parse.html
[`fador-i18n`]: https://docs.rs/fador-i18n
