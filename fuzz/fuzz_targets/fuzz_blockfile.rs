#![no_main]
//! Fuzz the Chromium legacy Blockfile cache backend (`index` + `data_N` +
//! `EntryStore` walk + stream-0 `HttpResponseInfo` + stream-1 body decode).
//! Invariant: arbitrary bytes must never panic — every `CacheAddr`, `key_len`,
//! stream size and block offset is bounds-checked; malformed input degrades to
//! a skipped entry.

use browser_forensic_cache::{
    parse_blockfile_cache_dir, parse_blockfile_index, BLOCK_MAGIC, INDEX_MAGIC,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. The raw index-header + table parser on arbitrary bytes.
    let _ = parse_blockfile_index(data);

    // 2. The full directory pipeline. Shape the bytes into a plausible cache so
    //    the entry walker, key resolution, stream reads, HTTP-meta parse and
    //    body decode are all exercised on adversarial data: force the index and
    //    block magics, then feed the fuzz bytes as the hash table and blocks.
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };

    let mut index = vec![0u8; 368];
    index[0..4].copy_from_slice(&INDEX_MAGIC.to_le_bytes());
    index[28..32].copy_from_slice(&8i32.to_le_bytes()); // a few table slots
    index.extend_from_slice(data);
    if std::fs::write(dir.path().join("index"), &index).is_err() {
        return;
    }

    for n in 0..4 {
        let mut df = vec![0u8; 8192];
        df[0..4].copy_from_slice(&BLOCK_MAGIC.to_le_bytes());
        df[12..16].copy_from_slice(&256i32.to_le_bytes()); // entry_size
        df.extend_from_slice(data);
        let _ = std::fs::write(dir.path().join(format!("data_{n}")), &df);
    }

    let _ = parse_blockfile_cache_dir(dir.path());
});
