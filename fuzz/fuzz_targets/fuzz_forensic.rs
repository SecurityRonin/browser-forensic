#![no_main]
//! Full-pipeline fuzz: drive `triage_profile` over a synthetic profile directory
//! whose artifact files are arbitrary bytes. Exercises the end-to-end
//! parse -> carve -> integrity -> TriageReport assembly. Must never panic.
use libfuzzer_sys::fuzz_target;
use browser_core::BrowserFamily;
use std::fs;

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let p = dir.path();
    // Seed every artifact name the three dialects look for with the same fuzz
    // bytes, so a single input reaches whichever parser the dialect selects.
    for name in [
        "History",
        "Cookies",
        "Bookmarks",
        "places.sqlite",
        "cookies.sqlite",
        "History.db",
    ] {
        let _ = fs::write(p.join(name), data);
    }
    let browser = match data.first().copied().unwrap_or(0) % 3 {
        0 => BrowserFamily::Chromium,
        1 => BrowserFamily::Firefox,
        _ => BrowserFamily::Safari,
    };
    let _ = browser_rt::triage_profile(p, browser);
});
