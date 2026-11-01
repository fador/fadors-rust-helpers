//! Deterministic pseudo-random input generators for security regression tests.
//!
//! The project intentionally has no external crates, so fuzz-style tests use a
//! small fixed-seed PRNG.  Fixed seeds keep failures reproducible while still
//! exercising thousands of malformed inputs in normal `cargo test`.

#![allow(dead_code)]
#![allow(missing_docs)]

/// Case count for a seeded fuzz test.
///
/// The default keeps the workspace suite fast. A deeper pass is opt-in through
/// `FADOR_FUZZ_ITERATIONS` (or the legacy `KESKUSTELU_FUZZ_ITERATIONS`), for
/// example `FADOR_FUZZ_ITERATIONS=200000 cargo test --workspace`.
pub fn iterations(default: usize) -> usize {
    std::env::var("FADOR_FUZZ_ITERATIONS")
        .or_else(|_| std::env::var("KESKUSTELU_FUZZ_ITERATIONS"))
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .min(2_000_000)
}

pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        // xorshift64*, good enough for input generation (not cryptography).
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() as usize) % n
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.byte());
        }
        out
    }

    pub fn ascii(&mut self, len: usize, alphabet: &[u8]) -> String {
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            out.push(alphabet[self.below(alphabet.len())] as char);
        }
        out
    }

    pub fn text(&mut self, len: usize) -> String {
        const ALPHABET: &[char] = &[
            'a', 'Z', '0', ' ', '\\', '/', '.', '%', '?', '#', '&', '=', '<', '>', '"', '\'', '\0',
            '\n', '\r', '\t', '|', '[', ']', '{', '}', ':', '-', '_', 'ä', '中', '💣',
        ];
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            out.push(ALPHABET[self.below(ALPHABET.len())]);
        }
        out
    }

    pub fn pick<'a, T>(&mut self, values: &'a [T]) -> &'a T {
        &values[self.below(values.len())]
    }
}

/// Strings commonly used to probe parsers, URL handling and HTML escaping.
pub const MALICIOUS_STRINGS: &[&str] = &[
    "",
    "..",
    "../",
    "..\\",
    "%2e%2e",
    "%2e%2e%2f",
    "%252e%252e%252f",
    "%00",
    "a%00b",
    "\\",
    "\\\\server\\share",
    "/etc/passwd",
    "../../../../etc/passwd",
    "../skins/MonoBook/main.css",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "vbscript:msgbox(1)",
    "data:text/html,<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "{{{{{{{{{{",
    "}}}}}}}}}}",
    "[[[[[[[[[[",
    "]]]]]]]]]]",
    "<!--",
    "-->",
    "<script>alert(1)</script>",
    "</script>",
    "\r\nSet-Cookie: pwned=1",
    "\r\nLocation: https://evil.example/",
    "a\r\nb",
    "a\nb",
    "\0",
    "\u{202e}evil\u{202c}",
    "\u{200b}\u{feff}",
    "%%%",
    "%",
    "%zz",
    "%41%42%43",
    "?a=b&c=d",
    "#fragment",
    ":",
    "::",
    "a:b:c",
    "Luokka:Testi",
    "Tiedosto:../x.png",
    "Tiedosto:..%2fx.png",
    "特殊:テスト",
    "💣",
    "a b\tc",
    "a+b=c&d=e",
    "CONVERT(X'' USING utf8mb4)",
    "1' OR '1'='1",
    "1; DROP TABLE page; --",
    "/* comment */",
    "-- comment",
    "?",
    "????",
];
