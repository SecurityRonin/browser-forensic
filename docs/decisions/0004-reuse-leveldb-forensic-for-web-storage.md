# 4. Reuse leveldb-forensic for Chromium web storage

## Context

Chromium keeps Local Storage, Session Storage, and IndexedDB in LevelDB, not
SQLite. LevelDB stores type-prefixed values (UTF-16-LE / Latin-1), tombstones,
and orphaned records; a naive reader either panics on malformed data or silently
drops recoverable records. Writing a bespoke forensic LevelDB reader inside this
suite would duplicate a solved problem.

## Decision

Consume the published `leveldb-forensic` crate (built on `leveldb-core`) for
Local and Session Storage, and `leveldb-core` for IndexedDB, mapping their output
to `BrowserEvent`s in `browser-forensic-storage`. `leveldb-forensic` is
panic-free and oracle-tested against `rusty-leveldb`, and it surfaces malformed
values and tombstones rather than hiding them. IndexedDB values, being
Blink/v8-serialized, are surfaced as opaque raw key/value records.

## Consequences

Web-storage decoding rides a separately maintained, independently validated
crate, keeping this suite free of a bespoke LevelDB implementation. IndexedDB
values are not decoded into structured fields — a deliberate limit rather than a
fabricated decode. Firefox web storage, being plain SQLite, uses the standard
read-only path instead.

## Status

Accepted.
