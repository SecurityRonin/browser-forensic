//! Env-gated tier-1 oracle against a REAL Safari / `CFURLCache` `Cache.db`.
//!
//! Skipped unless `BFCACHE_SAFARI_DB` points at a `Cache.db` (Safari's own, or
//! any macOS/iOS `NSURLSession` client's), e.g.:
//!
//! ```sh
//! export BFCACHE_SAFARI_DB=~/Library/Caches/com.apple.Safari/Cache.db
//! ```
//!
//! Provenance / ground truth: during development a `Content-Encoding: br`
//! response whose stored `receiver_data` was plain JSON (`{ "name" : …`) and a
//! sibling `Content-Encoding: gzip` entry whose stored body carried the gzip
//! magic `1f 8b` were both examined across 273 real `Cache.db` files (15 836
//! bodies). That established the crate's finding — `CFURLCache` usually stores
//! the already-decoded body, occasionally the wire-compressed one — which this
//! oracle asserts holds without a decode ever silently failing. The database is
//! opened read-only + immutable and never committed.

use std::path::Path;

use browser_forensic_cache::parse_safari_cache_db;

#[test]
fn safari_cache_db_real_enumerates_and_decodes() {
    let Ok(db) = std::env::var("BFCACHE_SAFARI_DB") else {
        eprintln!("skip: set BFCACHE_SAFARI_DB to a Safari/CFURLCache Cache.db");
        return;
    };

    let resources = parse_safari_cache_db(Path::new(&db));
    assert!(
        !resources.is_empty(),
        "expected recoverable cached resources in {db}"
    );

    let mut with_body = 0usize;
    let mut wire_decoded = 0usize;

    for r in &resources {
        assert!(!r.url.is_empty(), "resource URL must not be empty");
        // Every recovered body is usable content (Safari stores it decoded, or
        // this crate decoded it) unless a note explains why not.
        assert!(
            r.body_decoded || r.decode_note.is_some(),
            "body of {} neither decoded nor explained: {:?}",
            r.url,
            r.decode_note
        );
        if !r.raw_body.is_empty() || !r.decoded_body.is_empty() {
            with_body += 1;
        }
        // A body that actually carried gzip magic AND decoded is a wire-decode.
        if r.content_encoding.as_deref() == Some("gzip")
            && r.body_decoded
            && r.raw_body.starts_with(&[0x1f, 0x8b])
        {
            wire_decoded += 1;
        }
    }

    assert!(with_body > 0, "expected at least one body");
    eprintln!(
        "safari oracle: {} resources, {} with bodies, {} wire-compressed bodies decoded",
        resources.len(),
        with_body,
        wire_decoded
    );
}
