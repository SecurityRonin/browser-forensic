#![no_main]
//! Fuzz the panic-free IndexedDB key decoder (the (db,store,index) prefix and
//! the encoded IDBKey). Invariant: arbitrary bytes must never panic or read out
//! of bounds — array nesting is depth-capped and every length is bounds-checked.

use browser_forensic_storage::indexeddb::fuzz_decode_idb_key;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_decode_idb_key(data);
});
