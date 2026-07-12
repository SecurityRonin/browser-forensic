#![no_main]
//! Fuzz the Chromium SimpleCache `_0` entry parser (and the stream-0 HTTP
//! metadata parser it feeds). Invariant: arbitrary bytes must never panic —
//! every offset/size is bounds-checked, malformed input returns `Err`.

use browser_forensic_cache::{parse_http_meta, parse_simple_entry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entry) = parse_simple_entry(data) {
        // The recovered streams are still attacker-controlled: parse them too.
        let _ = parse_http_meta(&entry.stream0);
    }
});
