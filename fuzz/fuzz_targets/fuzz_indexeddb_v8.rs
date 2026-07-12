#![no_main]
//! Fuzz the panic-free V8 `ValueSerializer` decoder used for IndexedDB record
//! values. Invariant: arbitrary bytes must never panic, read out of bounds, or
//! exhaust memory — the depth/length caps and bounds checks bound every read,
//! malformed input yields a partial/None decode.

use browser_forensic_storage::indexeddb::fuzz_decode_v8;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_decode_v8(data);
});
