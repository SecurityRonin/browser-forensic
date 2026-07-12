#![no_main]
//! Fuzz the Firefox `SiteSecurityServiceState.txt` line parser: arbitrary bytes
//! -> lossy UTF-8 -> tab/comma field splitting. Invariant: never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = browser_forensic_firefox::site_security::parse_lines(&text, "fuzz");
});
