#![no_main]
//! Fuzz the SQLite free-page carver: parses the SQLite header (page size, freelist
//! trunk) and walks raw pages from arbitrary bytes. Page size and page counts are
//! attacker-controlled — this target must never panic, divide by zero, or read OOB.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    let _ = browser_forensic_carve::carve_sqlite_free_pages(tmp.path());
});
