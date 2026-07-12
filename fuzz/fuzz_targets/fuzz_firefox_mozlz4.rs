#![no_main]
//! Fuzz the bounds-checked mozLz4 (`.jsonlz4`) decompressor over arbitrary
//! bytes. The decoder validates the `mozLz40\0` magic, caps the declared
//! uncompressed size against a decompression bomb before allocating, and treats
//! a malformed LZ4 block as an error. Invariant: it never panics, never
//! out-of-memory on a lying size field, and never indexes out of bounds on a
//! short/truncated/adversarial file — it returns `Err` instead.
use browser_forensic_firefox::mozlz4::decompress_mozlz4;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decompress_mozlz4(data);
});
