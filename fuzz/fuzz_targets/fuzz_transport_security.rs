#![no_main]
//! Fuzz the Chromium `TransportSecurity` JSON parser (hashed HSTS): arbitrary
//! bytes -> serde_json -> sts array / legacy-map walk. Invariant: never panic.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    let _ = browser_forensic_chrome::parse_transport_security(tmp.path());
});
