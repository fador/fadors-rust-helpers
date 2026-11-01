# fador-phpbb-template

Compiler and renderer for the phpBB template dialect, extracted from the
Naruto.fi board rewrite. It understands phpBB's legacy control comments and
variables plus the small Twig subset phpBB 3.3 templates use:

- `<!-- IF -->`, `<!-- ELSEIF -->`, `<!-- ELSE -->`, `<!-- ENDIF -->`
- `<!-- BEGIN -->`, `<!-- BEGINELSE -->`, `<!-- END -->`
- `<!-- INCLUDE -->`, `<!-- INCLUDEJS -->`, `<!-- INCLUDECSS -->`, `<!-- EVENT -->`
- `<!-- DEFINE -->`, `<!-- UNDEFINE -->`, `{NAME}`, `{$NAME}`, `{L_KEY}`, `{LA_KEY}`
- `{% if %}`, `{% for %}`, `{% set %}`, `{% DEFINE %}`, `{% include %}`,
  `{% apply spaceless %}`, `{% INCLUDEJS %}`, `{% INCLUDECSS %}`, `{{ ... }}`

Compilation is separate from rendering. An [`Engine`] compiles a file once,
caches the AST and renders many pages from it; `parse` and `validate_source`
expose the same compiler without rendering.

- No external crates, no `unsafe`, MSRV 1.88.
- Templates are compiled as untrusted input and every limit ends in an error.

## Usage

```rust
use fador_phpbb_template::{Context, Engine, Runtime, Value};

struct Strings;

impl Runtime for Strings {
    fn lang(&self, key: &str, _args: &[Value]) -> String {
        if key == "HELLO" { "Hello".into() } else { key.into() }
    }
    fn lang_defined(&self, key: &str) -> bool { key == "HELLO" }
    fn path(&self, route: &str, _params: &Value) -> String { format!("/app.php/{route}") }
    fn url(&self, route: &str, _params: &Value) -> String { format!("/{route}") }
}

let mut context = Context::new();
context.set("NAME", Value::Str("<b>Naruto</b>".into()));
context.set("S_IS_BOT", Value::Bool(false));

let output = Engine::new(Vec::new())
    .render_source(
        "page.html",
        "{L_HELLO} {NAME}<!-- IF S_IS_BOT -->bot<!-- ELSE -->human<!-- ENDIF --> {{ NAME|e }}",
        &mut context,
        &Strings,
    )
    .unwrap();

assert_eq!(output.html, "Hello <b>Naruto</b>human &lt;b&gt;Naruto&lt;/b&gt;");
```

`Engine::new` takes the template roots in priority order and
`with_event_dirs` adds the directories searched by `<!-- EVENT name -->`.
`Engine::render` reads `<root>/<name>`; `Engine::render_source` compiles an
inline string, which is what the ACP uses for administrator-supplied tag
templates.

## Escaping: raw by default, exactly like phpBB

Values are inserted **without escaping**. `{NAME}` and `{{ NAME }}` emit the
bytes the context holds. A template that emits user-controlled text must opt
into escaping:

| template | result for `<b>"x" & 'y'</b>` |
| --- | --- |
| `{VALUE}` / `{{ VALUE }}` | `<b>"x" & 'y'</b>` (raw) |
| `{{ VALUE\|e }}` | `&lt;b&gt;&quot;x&quot; &amp; &#039;y&#039;&lt;/b&gt;` |
| `{{ VALUE\|e('html_attr') }}` | `&lt;b&gt;&quot;x&quot;&#x20;&amp;&#x20;&#x27;y&#x27;...` |
| `{{ VALUE\|e('js') }}` | `\u003Cb\u003E\"x\" \u0026 \'y\'...` |

`{LA_KEY}` applies the JavaScript strategy automatically, because that legacy
form exists to embed a string in script. `{L_KEY}` does not escape.

This mirrors phpBB: the board escapes post text in its renderer, not in the
template engine, and templates that build attributes or scripts escape at the
point of use.

## Security contract

The compiler treats its input as untrusted (the ACP compiles template source an
administrator can paste), so every recursion and every name is bounded:

- **Template names** are rejected when empty or containing NUL, backslashes,
  drive letters, UNC prefixes or any component other than a normal path
  segment. A name is resolved inside a root and the canonical path must stay
  inside the canonical root, so a symlink cannot escape the tree.
- **Include depth** is limited to 64 frames; self-inclusion and include cycles
  fail with `template include depth exceeded`.
- **Block nesting** is limited to 64 levels at compile time and 64 levels at
  render time, so a source accepted by `parse` cannot overflow the stack.
- **Expression depth** is limited to 64 and **expression size** to 4,096
  tokens, checked while tokenizing.
- **Language keys** in `{L_KEY}` / `{LA_KEY}` must be upper-case ASCII
  identifiers, so a quote cannot splice an expression into the synthetic
  `lang(...)` call.
- **Event names** cannot contain `/`, `\`, `..` or NUL; each event directory is
  still canonicalised before the file is read.
- `INCLUDEPHP` is rejected at compile time. There is no PHP interpreter and no
  outbound request anywhere in the crate.
- Errors carry a message, never file contents or rendered output.

## API

| item | purpose |
| --- | --- |
| `Engine` | template roots, AST cache, render/validate entry points |
| `Context` | globals, locals, loop frames and dotted-path lookup |
| `Value` | null, bool, int, float, string, array and object values |
| `Runtime` | host services: `lang`, `lang_defined`, `path`, `url` |
| `Node`, `Expr`, `AssetKind`, `parse` | the compiled representation |
| `RenderOutput`, `AssetBag` | rendered HTML plus requested JS/CSS |
| `TemplateError`, `ParseError` | diagnostics |

## Testing

```sh
cargo test -p fador-phpbb-template
```

The suite covers the parser, expressions, includes, event assets, escaping,
the path sandbox, recursion/depth limits and a fixed-seed fuzz pass. To compile
a real phpBB style tree, point the optional corpus test at one:

```sh
FADOR_PHPBB_TEMPLATE_CORPUS=/path/to/styles/prosilver/template \
  cargo test -p fador-phpbb-template
```

The test is skipped when the variable is unset, so no GPL template content is
vendored in this crate.

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
