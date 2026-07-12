#![no_main]
//! Fuzz the panic-free Content-Encoding decompression dispatch. Invariant:
//! arbitrary bytes under any encoding must never panic or exhaust memory —
//! the output/ratio caps bound allocation, malformed input returns `Err`.

use browser_forensic_cache::{decode_body, DecompressLimits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let encoding = match selector % 7 {
        0 => Some("gzip"),
        1 => Some("deflate"),
        2 => Some("br"),
        3 => Some("zstd"),
        4 => Some("identity"),
        5 => Some("unknown-codec"),
        _ => None,
    };
    // Modest caps keep the fuzzer's own memory/time bounded.
    let limits = DecompressLimits {
        max_output: 8 * 1024 * 1024,
        max_ratio: 10_000,
    };
    let _ = decode_body(encoding, body, &limits);
});
