//! Structured, process-attributed memory carve — public behavior tests.
//!
//! These exercise the fail-loud vs. degrade-to-byte-scan contract and the
//! browser-process classification. End-to-end extraction against a real image
//! is covered by the env-gated `real_image_*` tests (skip cleanly when absent).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::Path;

use browser_forensic_core::BrowserFamily;
use browser_forensic_memory::{
    browser_family_for_process, carve_memory_image, carve_memory_image_with_symbols,
};

#[test]
fn nonexistent_image_fails_loud_not_degradable() {
    let err = carve_memory_image(Path::new("/no/such/memory.image"))
        .expect_err("a missing image must error, never a silent empty");
    assert!(
        !err.is_degradable(),
        "a missing/unreadable image is a hard bootstrap failure, not a byte-scan fallback: {err}"
    );
}

#[test]
fn unstructured_buffer_is_degradable_to_byte_scan() {
    // A readable file with no recognizable OS/process structure opens as a raw
    // buffer; the structured carve cannot attribute it and signals the CLI to
    // fall back to a raw byte-scan (loud, never a silent empty).
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[0u8; 4096]).unwrap();
    let err = carve_memory_image(f.path())
        .expect_err("no OS/process structure → structured carve errors");
    assert!(
        err.is_degradable(),
        "an unstructured buffer must be degradable to a byte-scan: {err}"
    );
}

#[test]
fn with_symbols_none_matches_default_entry_point() {
    let a = carve_memory_image(Path::new("/no/such.image")).is_err();
    let b = carve_memory_image_with_symbols(Path::new("/no/such.image"), None).is_err();
    assert_eq!(a, b, "carve_memory_image is with_symbols(_, None)");
}

#[test]
fn browser_family_classification() {
    assert_eq!(
        browser_family_for_process("chrome.exe"),
        Some(BrowserFamily::Chromium)
    );
    assert_eq!(
        browser_family_for_process("MSEDGE.EXE"),
        Some(BrowserFamily::Chromium),
        "classification is case-insensitive"
    );
    assert_eq!(
        browser_family_for_process("brave.exe"),
        Some(BrowserFamily::Chromium)
    );
    assert_eq!(
        browser_family_for_process("opera.exe"),
        Some(BrowserFamily::Chromium)
    );
    assert_eq!(
        browser_family_for_process("firefox.exe"),
        Some(BrowserFamily::Firefox)
    );
    assert_eq!(
        browser_family_for_process("notepad.exe"),
        None,
        "non-browser processes are not classified"
    );
}
