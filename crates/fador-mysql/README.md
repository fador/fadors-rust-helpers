# fador-mysql

A dependency-free MySQL/MariaDB wire client and connection pool.

- Classic text protocol, with `?` placeholders expanded to escaped values.
- `mysql_native_password` and the fast path of `caching_sha2_password`.
- No TLS, no local files, no multi-statements, no compression.
- Pooled connections with a bounded acquire deadline and idle health check.
- `query_read` retries a read once on a transport failure; `query`/`execute`
  never replay a write.

## Example

```rust,no_run
use fador_mysql::{MysqlParams, Pool, SqlValue};

let pool = Pool::new(
    MysqlParams {
        host: "localhost".into(),
        port: 3306,
        user: "board".into(),
        password: "secret".into(),
        database: "board".into(),
        charset: 45,
        connect_timeout: std::time::Duration::from_secs(5),
        read_timeout: Some(std::time::Duration::from_secs(30)),
        write_timeout: Some(std::time::Duration::from_secs(30)),
    },
    8,
);
let rows = pool.query_read("SELECT 1", &[]).unwrap();
assert_eq!(rows.first().and_then(|row| row.get_i64(0)), Some(1));
```

## Scope

This crate is a protocol client, not an ORM. Table names, joins and row mapping
belong to the application. The optional `sql` helper module in the repository
will add prefix/placeholder helpers, but the schema stays app-local.

## License

MIT. See the repository
[LICENSE](https://github.com/fador/fadors-rust-helpers/blob/main/LICENSE) and
[NOTICE](https://github.com/fador/fadors-rust-helpers/blob/main/NOTICE).
