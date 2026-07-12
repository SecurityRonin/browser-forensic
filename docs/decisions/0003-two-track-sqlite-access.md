# 3. Two-track SQLite access: read-only live reads, pure-Rust carving

## Context

Browser artifacts are SQLite databases, and they are evidence. Two conflicting
needs apply. Live-table reads want a correct, complete SQLite query engine.
Deleted-record recovery needs to reach free pages and WAL frames that a query
engine deliberately hides. And in both cases the original file, its timestamps,
and its free pages must survive unaltered for re-examination. An early design
opened databases read-write, and opening with SQLite's `immutable=1` flag while a
`-wal` sidecar is present silently ignores the WAL — either path corrupts or
misreads the evidence.

## Decision

Use two tracks. Live-table reads go through `browser-forensic-core`'s
`open_evidence_db`, which opens the file with bundled rusqlite using
`SQLITE_OPEN_READ_ONLY`. When no `-wal` sidecar exists it adds the `immutable=1`
URI flag for a copy-free read; when a `-wal` is present it copies the database and
its WAL to a temporary location and opens the copy read-only, so the WAL is
honored without ever writing to the original. Deleted-record recovery goes
through `browser-forensic-carve`, which delegates to the pure-Rust
`sqlite-forensic` engine to walk the freelist and scan WAL frames — the paths the
live engine cannot see.

## Consequences

Live reads get a complete, correct query engine; carving gets byte-level access
to deleted data; and the evidence file is never mutated. The WAL-present case
costs a temporary copy. Two SQLite implementations are in the dependency graph
(bundled rusqlite and `sqlite-forensic`), each earning its place by what it can
reach.

## Status

Accepted.
