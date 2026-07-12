#![no_main]
//! Fuzz the Service Worker CacheStorage parsers. Invariant: arbitrary bytes must
//! never panic — the `index.txt` proto, the stream-0 `CacheMetadata` proto, and
//! the full SimpleCache-entry pipeline (framing + metadata + bounded body
//! decode) all bounds-check every offset/length and return partial/empty on
//! malformed input.

use std::path::PathBuf;

use browser_forensic_cache::{
    parse_cachestorage_index, parse_cachestorage_metadata, resource_from_cachestorage_entry,
    DecompressLimits,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // index.txt (CacheStorageIndex proto)
    let _ = parse_cachestorage_index(data);
    // stream 0 (CacheMetadata proto)
    let _ = parse_cachestorage_metadata(data);
    // full entry: SimpleCache framing -> metadata -> bounded body decode
    let _ = resource_from_cachestorage_entry(
        data,
        "fuzz-cache",
        "fuzz-uuid",
        Some("https://fuzz.test/"),
        PathBuf::from("fuzz_0"),
        &DecompressLimits::default(),
    );
});
