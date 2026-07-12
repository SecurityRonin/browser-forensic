#![no_main]
//! Fuzz the Chromium `Network Persistent State` JSON parser: arbitrary bytes ->
//! serde_json -> server-property walk + URL host extraction. Invariant: never panic.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    let _ = browser_forensic_chrome::parse_network_persistent_state(tmp.path());
});
