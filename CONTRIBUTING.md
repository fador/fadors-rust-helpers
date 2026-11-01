# Contributing

Thanks for taking a look. This workspace is extracted from three production
servers, so the bar for changes is:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo doc --workspace --no-deps`

Please keep the design rules from the README: standard library first, bounded
parsers, no schema knowledge, and no new dependency without a clear reason.

## License

By submitting a contribution you agree that it is licensed under the MIT
license used by this repository. If a contribution contains code from another
project, state its origin and license in the pull request so it can be added to
`NOTICE`.
