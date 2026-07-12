#![no_main]
//! Fuzz the bounds-checked SQLite header parser over arbitrary bytes. The parser
//! reads the fixed 100-byte header layout with checked slicing; the invariant is
//! that it never panics and never indexes out of bounds on a short, truncated, or
//! adversarial file — it returns None instead.
use browser_forensic_integrity::sqlite_header::parse_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_header(data);
});
