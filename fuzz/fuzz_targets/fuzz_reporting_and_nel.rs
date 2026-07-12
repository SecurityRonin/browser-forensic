#![no_main]
//! Fuzz the Chromium `Reporting and NEL` parser: SQLite-magic detection then
//! either the SQLite store or the legacy JSON walk. Invariant: never panic.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    let _ = browser_forensic_chrome::parse_reporting_and_nel(tmp.path());
});
