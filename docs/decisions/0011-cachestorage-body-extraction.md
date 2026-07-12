# 11. Service Worker CacheStorage body extraction

## Context

Progressive web apps and Electron apps store full offline responses through the
Cache API (`caches.open(name)` → `cache.put(request, response)`). These live in
`<profile>/Service Worker/CacheStorage/` and survive a history/cookie wipe, so
they are a rich evidence source for "what a web app actually fetched". The
on-disk layout (Chromium `content/browser/cache_storage/`) is:

- `<origin-hash>/index.txt` — a serialized `CacheStorageIndex` proto mapping each
  cache name to its cache-directory UUID, plus the storage-key / origin.
- `<origin-hash>/<uuid>/` — one `disk_cache` (SimpleCache) instance per named
  cache. Each `<hash>_0` entry keys on the request URL; **stream 0** holds a
  `CacheMetadata` proto (request method + request/response headers + status +
  times), **stream 1** holds the response body.

Two format facts had to be resolved against real bytes rather than assumed:
whether the top index is LevelDB or a proto, and whether stream-1 bodies are
stored wire-compressed.

## Decision

Add a `cachestorage` module to `browser-forensic-cache` that **reuses** the
existing SimpleCache reader (`parse_simple_entry`) for entry framing and the
published, fuzz-tested `protobuf-forensic-core` schemaless decoder for both
protos (`cache_storage.proto` field numbers are applied schema-side). The public
surface is `parse_cachestorage_dir[_with]` → `Vec<CacheStorageResource>`, each
carrying URL, cache name, storage-key origin, request method/headers, response
status/headers/mime/times, and the body.

The index is a **proto file** (`index.txt`), not LevelDB — confirmed on real
Slack/Notion/Electron data. So no LevelDB dependency is taken for CacheStorage.

## Body handling — the Cache API stores the delivered (decoded) body

Tier-1 finding on real data (Slack, Notion, VS Code, Discord): the body in
stream 1 is the **already-decoded delivered body**, even when the response
metadata still advertises a `Content-Encoding`. Measured: 1684/1684
`br`/`gzip`-declaring Slack entries and 10134/10134 Notion entries stored their
bodies plaintext; 0 were actually compressed. This mirrors the crate's earlier
Safari `CFURLCache` finding.

Therefore a declared `Content-Encoding` is surfaced as metadata but is **not**
blindly applied. `decode_body` is attempted; it is used only if the bytes are
genuinely wire-compressed and the decode changes them, otherwise the stored
bytes are the usable body and a note records the declared-but-not-applied
encoding — never a silent decode failure.

## Honesty notes

- A recovered entry is a *cached* response, consistent with the app having
  fetched the URL; cached is not the same as rendered.
- The `CacheMetadata` proto has **no request-entity-body field**: the Cache API
  does not persist POST request bodies. The request method and headers are
  surfaced; a request body is not recoverable from this artifact.

## Validation

- Authoritative spec: Chromium `content/browser/cache_storage/cache_storage.proto`
  and `cache_storage_cache.cc`.
- Independent oracles: `protoc --decode_raw` and `blackboxprotobuf` agreed with
  the schema-side field decode on real entries; response/entry times
  (base::Time µs since 1601) decoded to sane dates.
- End-to-end: the env-gated `cachestorage_oracle` test recovered 100% of on-disk
  `_0` entries across Slack (1884), Notion (13066), VS Code, and Discord, with a
  structural cross-check against the directory layout.
