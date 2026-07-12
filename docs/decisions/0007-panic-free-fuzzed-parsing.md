# 7. Panic-free, fuzzed parsing of untrusted artifacts

## Context

Every input this suite parses is attacker-controllable: SQLite pages, SNSS
session files, mozLz4 blobs, LevelDB records, and raw memory. A length field that
lies, a truncated record, or a malformed page must never crash the tool or, worse,
produce silently wrong output. A forensic tool that panics on a crafted artifact
is a denial-of-service on the investigation.

## Decision

Enforce a panic-free posture statically and dynamically. Statically, the
workspace sets `unsafe_code = "forbid"` and denies `clippy::unwrap_used` and
`expect_used` in production code; length, offset, and count fields are
bounds-checked before use. Dynamically, every untrusted-input parser carries a
`cargo-fuzz` target — Firefox session, SQLite history, carving, integrity, and
the forensic catalog — each built and smoke-run in CI, with the invariant that no
input may panic.

## Consequences

Malformed evidence degrades to an error or a partial result, never a crash or a
raw-pointer path. The static lints occasionally require more verbose,
bounds-checked code than a quick `unwrap` would. The fuzz targets are part of the
maintained surface and run in CI.

## Status

Accepted.
