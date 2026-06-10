#![no_main]
//! Fuzz the integrity auditors (database/WAL state, history monotonicity checks)
//! over an arbitrary on-disk file. The first byte selects which auditor; the rest is
//! written to a file and audited. Must never panic on a corrupt/partial database.
use libfuzzer_sys::fuzz_target;
use browser_core::BrowserFamily;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(body).is_err() {
        return;
    }
    let path = tmp.path();
    match selector % 4 {
        0 => {
            let _ = browser_integrity::check_database_integrity(path);
        }
        1 => {
            let _ = browser_integrity::check_wal_state(path);
        }
        2 => {
            let _ = browser_integrity::check_history_integrity(path, BrowserFamily::Chromium);
        }
        _ => {
            let _ = browser_integrity::check_cookie_integrity(path, BrowserFamily::Chromium);
        }
    }
});
