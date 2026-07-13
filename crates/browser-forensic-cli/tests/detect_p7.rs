#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for `br4n6` RFC 0001 Phase P7 — layered PATH
//! auto-detection with confidence + basis, logged to the manifest (D8).
//!
//! `investigate` runs the layered detector over its input, prints
//! `Detected:/Confidence:/Basis:` (to stderr, so stdout stays byte-clean for
//! JSONL), and — with `--manifest <PATH>` — records a `DetectionRecord` per
//! detected input for court defensibility. A `--type <KIND>` override always
//! exists for carved / stomped data the detector will guess wrong.

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chrome profile whose `History` carries the real `urls`/`visits` schema.
fn chrome_profile() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let history = profile.join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1,'https://example.com','Example',1,13327626000000000);
         INSERT INTO visits VALUES (1,1,13327626000000000,0,0);",
    )
    .unwrap();
    drop(conn);
    (dir, profile)
}

/// A Firefox profile whose `places.sqlite` carries `moz_places`.
fn firefox_profile() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("mozilla").join("abcd.default-release");
    std::fs::create_dir_all(&profile).unwrap();
    let places = profile.join("places.sqlite");
    let conn = Connection::open(&places).unwrap();
    conn.execute_batch(
        "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
         CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
         INSERT INTO moz_places VALUES (1,'https://example.org','Example',1,1700000000000000);
         INSERT INTO moz_historyvisits VALUES (1,1,1700000000000000,1);",
    )
    .unwrap();
    drop(conn);
    (dir, profile)
}

fn stderr_of(args: &[&str]) -> String {
    let out = br4n6().args(args).assert().success();
    String::from_utf8(out.get_output().stderr.clone()).unwrap()
}

#[test]
fn chrome_history_detected_high_confidence_with_schema_basis() {
    let (_dir, profile) = chrome_profile();
    let err = stderr_of(&["investigate", profile.to_str().unwrap(), "--format", "text"]);
    assert!(
        err.contains("Detected: Chromium History (SQLite)"),
        "detection line names the artifact: {err}"
    );
    assert!(
        err.contains("Confidence: high") || err.contains("Confidence: High"),
        "high confidence for a real schema match: {err}"
    );
    assert!(
        err.to_lowercase().contains("urls/visits"),
        "basis cites the schema probe that distinguishes History from Cookies: {err}"
    );
}

#[test]
fn firefox_places_detected() {
    let (_dir, profile) = firefox_profile();
    let err = stderr_of(&["investigate", profile.to_str().unwrap(), "--format", "text"]);
    assert!(
        err.contains("Firefox places (SQLite)"),
        "Firefox places recognized by its moz_places schema: {err}"
    );
    assert!(
        err.to_lowercase().contains("moz_places"),
        "basis cites moz_places: {err}"
    );
}

#[test]
fn detection_record_lands_in_the_manifest() {
    let (dir, profile) = chrome_profile();
    let manifest = dir.path().join("manifest.json");
    br4n6()
        .args([
            "investigate",
            profile.to_str().unwrap(),
            "--format",
            "text",
            "--manifest",
            manifest.to_str().unwrap(),
        ])
        .assert()
        .success();
    let text = std::fs::read_to_string(&manifest).unwrap();
    assert!(
        text.contains("detection_basis"),
        "manifest carries the detection basis array (D8): {text}"
    );
    assert!(
        text.contains("Chromium History (SQLite)"),
        "the detected kind is recorded for court defensibility: {text}"
    );
    assert!(
        text.to_lowercase().contains("urls/visits"),
        "the human basis string is recorded verbatim: {text}"
    );
}

#[test]
fn type_override_forces_the_kind_even_when_detection_would_differ() {
    // Point the override at a Chrome History but FORCE Firefox places — the
    // examiner's word wins on carved / stomped data (Gemini's objection).
    let (dir, profile) = chrome_profile();
    let manifest = dir.path().join("manifest.json");
    let out = br4n6()
        .args([
            "investigate",
            profile.to_str().unwrap(),
            "--type",
            "firefox-places",
            "--format",
            "text",
            "--manifest",
            manifest.to_str().unwrap(),
        ])
        .assert()
        .success();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        err.contains("Firefox places (SQLite)"),
        "the forced --type is what is reported, not the auto-detection: {err}"
    );
    let text = std::fs::read_to_string(&manifest).unwrap();
    assert!(
        text.contains("Firefox places (SQLite)"),
        "the forced kind is the one recorded in the manifest: {text}"
    );
    assert!(
        text.contains("--type"),
        "the manifest notes the detection was overridden by --type: {text}"
    );
}
