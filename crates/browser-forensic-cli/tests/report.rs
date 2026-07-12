//! DFIR-interop serializer tests: TSK bodyfile (mactime 3.x), plaso `l2t_csv`,
//! and the HTML report. Machine formats are checked for exact field order and
//! delimiter faithfulness; the HTML report for escaping and structure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_cli::report::to_bodyfile;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

// 2023-11-14T22:13:20Z
const TS_NS: i64 = 1_700_000_000_000_000_000;
const TS_SECS: i64 = 1_700_000_000;

fn history_event() -> BrowserEvent {
    BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p/History",
        "visit",
    )
    .with_attr("url", json!("https://example.com/page"))
    .with_attr("title", json!("Example"))
}

fn download_event() -> BrowserEvent {
    BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::Downloads,
        "/p/History",
        "file.zip (10 bytes)",
    )
    .with_attr("url", json!("https://example.com/file.zip"))
}

#[test]
fn bodyfile_has_eleven_pipe_fields() {
    let out = to_bodyfile(&[history_event()]);
    let line = out.lines().next().unwrap();
    let fields: Vec<&str> = line.split('|').collect();
    // MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    assert_eq!(
        fields.len(),
        11,
        "TSK bodyfile 3.x has 11 pipe-delimited fields, got: {line}"
    );
}

#[test]
fn bodyfile_history_visit_in_atime_slot() {
    let out = to_bodyfile(&[history_event()]);
    let f: Vec<&str> = out.lines().next().unwrap().split('|').collect();
    assert_eq!(f[0], "0", "MD5");
    assert_eq!(f[2], "0", "inode");
    assert_eq!(f[3], "0", "mode");
    assert_eq!(f[6], "0", "size");
    assert_eq!(f[7], TS_SECS.to_string(), "atime = visit time");
    assert_eq!(f[8], "0", "mtime");
    assert_eq!(f[9], "0", "ctime");
    assert_eq!(f[10], "0", "crtime");
}

#[test]
fn bodyfile_name_is_descriptive() {
    let out = to_bodyfile(&[history_event()]);
    let f: Vec<&str> = out.lines().next().unwrap().split('|').collect();
    assert!(f[1].contains("[chromium history]"), "name: {}", f[1]);
    assert!(f[1].contains("https://example.com/page"), "name: {}", f[1]);
    assert!(f[1].contains("Last Visited Time"), "name: {}", f[1]);
}

#[test]
fn bodyfile_download_in_crtime_slot() {
    let out = to_bodyfile(&[download_event()]);
    let f: Vec<&str> = out.lines().next().unwrap().split('|').collect();
    assert_eq!(f[7], "0", "atime empty for a download creation time");
    assert_eq!(f[10], TS_SECS.to_string(), "crtime = download time");
}

#[test]
fn bodyfile_empty_events_is_empty_string() {
    assert_eq!(to_bodyfile(&[]), "");
}

#[test]
fn bodyfile_name_sanitizes_pipe_to_preserve_field_count() {
    let e = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Firefox,
        ArtifactKind::History,
        "/p",
        "x",
    )
    .with_attr("url", json!("https://e.com/a|b"));
    let out = to_bodyfile(&[e]);
    let f: Vec<&str> = out.lines().next().unwrap().split('|').collect();
    assert_eq!(
        f.len(),
        11,
        "a pipe inside a value must not add a bodyfile field"
    );
}
