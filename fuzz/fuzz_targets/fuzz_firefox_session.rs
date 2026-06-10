#![no_main]
//! Fuzz the Firefox `sessionstore.jsonlz4` parser: mozLz4 magic check, attacker-
//! controlled uncompressed-size header, LZ4 block decode, then JSON. The size header
//! is an allocation-bomb vector — this target must never panic or OOM-abort.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    let _ = browser_firefox::session::parse_session(tmp.path());
});
