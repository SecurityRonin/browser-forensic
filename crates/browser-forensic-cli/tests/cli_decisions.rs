#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Humble-Object decision helpers in `browser_forensic_cli::cli`: carve-stat merging, the
//! triage text summary, and filename-based browser inference. The CLI shells only
//! `println!` what these return, so they carry the testable behavior.

use std::path::Path;

use browser_forensic_carve::CarveStats;
use browser_forensic_cli::cli::{
    infer_browser_from_filename, merge_carve_stats, triage_summary_lines,
};

#[test]
fn merge_carve_stats_sums_every_field() {
    let a = CarveStats {
        bytes_scanned: 10,
        pages_scanned: 1,
        free_pages_found: 2,
        records_recovered: 3,
        records_partial: 4,
    };
    let b = CarveStats {
        bytes_scanned: 100,
        pages_scanned: 5,
        free_pages_found: 6,
        records_recovered: 7,
        records_partial: 8,
    };
    let m = merge_carve_stats(&a, &b);
    assert_eq!(m.bytes_scanned, 110);
    assert_eq!(m.pages_scanned, 6);
    assert_eq!(m.free_pages_found, 8);
    assert_eq!(m.records_recovered, 10);
    assert_eq!(m.records_partial, 12);
}

#[test]
fn triage_summary_lines_reports_the_counts() {
    let report = browser_forensic_triage::TriageReport {
        events: Vec::new(),
        carved: Vec::new(),
        integrity: Vec::new(),
        profiles: Vec::new(),
        generated_at_ns: 42,
    };
    let lines = triage_summary_lines(&report);
    assert_eq!(lines[0], "Browser Forensic Triage Report");
    assert_eq!(lines[1], "==============================");
    assert!(lines.iter().any(|l| l == "Generated: 42"));
    assert!(lines.iter().any(|l| l == "Profiles found: 0"));
    assert!(lines.iter().any(|l| l == "Events parsed: 0"));
    assert!(lines.iter().any(|l| l == "Integrity indicators: 0"));
    assert!(lines.iter().any(|l| l == "Carved records: 0"));
}

#[test]
fn infer_browser_safari_history_db() {
    assert_eq!(
        infer_browser_from_filename(Path::new("/x/history.db")),
        Some(browser_forensic_core::BrowserFamily::Safari)
    );
}

#[test]
fn infer_browser_firefox_artifacts() {
    for name in [
        "places.sqlite",
        "formhistory.sqlite",
        "cookies.sqlite",
        "extensions.json",
        "logins.json",
        "sessionstore.jsonlz4",
    ] {
        assert_eq!(
            infer_browser_from_filename(Path::new(name)),
            Some(browser_forensic_core::BrowserFamily::Firefox),
            "{name} should infer Firefox"
        );
    }
}

#[test]
fn infer_browser_unknown_is_none() {
    assert_eq!(infer_browser_from_filename(Path::new("History")), None);
    assert_eq!(infer_browser_from_filename(Path::new("/")), None);
}
