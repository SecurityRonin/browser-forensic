#![no_main]
//! Fuzz the Firefox `cache2` entry parser. Invariant: arbitrary bytes must
//! never panic — the trailing metadata offset, chunk-hash array size, header
//! fields, keySize, and every derived offset are bounds- and overflow-checked,
//! and a malformed entry returns `Err`.

use browser_forensic_cache::{resource_from_cache2_bytes, DecompressLimits};
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    let _ = resource_from_cache2_bytes(
        data,
        PathBuf::from("/fuzz/entry"),
        &DecompressLimits::default(),
    );
});
