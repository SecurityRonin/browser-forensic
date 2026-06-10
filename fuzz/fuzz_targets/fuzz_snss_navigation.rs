#![no_main]
//! Fuzz the SNSS navigation-command Pickle decoder: 4-byte aligned, length-prefixed
//! fields read from an arbitrary payload. Must never panic, read OOB, or over-allocate.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = snss::decode_navigation(data);
});
