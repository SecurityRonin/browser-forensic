#![no_main]
//! Fuzz the Chrome/Firefox/Safari history parsers over an arbitrary on-disk file.
//! The first byte selects the dialect; the rest is written to a `.sqlite` file and
//! parsed. Exercises our row-extraction/timestamp-decode logic on whatever the
//! SQLite engine surfaces. Must never panic.
use libfuzzer_sys::fuzz_target;
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
    match selector % 3 {
        0 => {
            let _ = browser_chrome::parse_history(path);
        }
        1 => {
            let _ = browser_firefox::parse_history(path);
        }
        _ => {
            let _ = browser_safari::parse_history(path);
        }
    }
});
