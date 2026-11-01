# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately to
**fador@iki.fi** with:

- the affected crate and version,
- a minimal reproducer or the malformed input,
- the impact you observed.

You will get an acknowledgement as soon as possible. A fix and a coordinated
disclosure date will be agreed before any public write-up.

## Scope

The most security-sensitive crates are `fador-http`, `fador-mysql`,
`fador-auth` and `fador-compress`. Parser panics, unbounded allocations,
checksum bypasses, request-smuggling differentials and authentication bypasses
are in scope. Application routes, templates and board configuration are not part
of this repository.

## Supported versions

While the workspace is `0.x`, only the latest published minor version receives
security fixes.
