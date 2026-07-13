#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for `br4n6 investigate` (RFC 0001 Phase P3a): the ranked,
//! court-safe summary with tiering and the always-present skipped-work footer,
//! exercised against the `br4n6` binary over a Chrome profile fixture.

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chrome profile whose `History` carries a visit and an executable download
/// (`evil.exe`) — enough to produce at least one ranked finding. Returns
/// `(TempDir, profile_dir)`; point `investigate` at the profile dir.
fn chrome_profile_with_exe_download() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let history = profile.join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1,'https://example.com','Example',1,13327626000000000);
         INSERT INTO visits VALUES (1,1,13327626000000000,0,0);
         CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT NOT NULL DEFAULT '', start_time INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0, state INTEGER NOT NULL DEFAULT 0, danger_type INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE downloads_url_chains (id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url TEXT NOT NULL);
         INSERT INTO downloads (id,target_path,start_time,total_bytes,state,danger_type) VALUES (1,'/Users/x/Downloads/evil.exe',13327626000000000,1024,1,0);
         INSERT INTO downloads_url_chains (id,chain_index,url) VALUES (1,0,'https://evil.example/evil.exe');",
    )
    .unwrap();
    drop(conn);
    (dir, profile)
}

fn stdout_of(args: &[&str]) -> String {
    let out = br4n6().args(args).assert().success();
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

#[test]
fn investigate_help_exits_zero() {
    br4n6().args(["investigate", "--help"]).assert().success();
}

#[test]
fn default_tier_is_standard() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let out = stdout_of(&["investigate", profile.to_str().unwrap(), "--format", "text"]);
    // The standard footer points at --deep for the expensive work …
    assert!(
        out.contains("investigate --deep"),
        "default (standard) footer points at --deep: {out}"
    );
    // … and does NOT name bounded freelist/WAL recovery as skipped (standard runs it).
    assert!(
        !out.to_lowercase().contains("freelist"),
        "standard does not skip bounded recovery: {out}"
    );
}

#[test]
fn quick_skips_more_than_standard() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let p = profile.to_str().unwrap();
    let quick = stdout_of(&["investigate", p, "--quick", "--format", "text"]);
    let standard = stdout_of(&["investigate", p, "--standard", "--format", "text"]);
    assert!(
        quick.to_lowercase().contains("freelist"),
        "quick footer names skipped bounded freelist/WAL recovery: {quick}"
    );
    assert!(
        !standard.to_lowercase().contains("freelist"),
        "standard footer does not (it runs that recovery): {standard}"
    );
}

#[test]
fn deep_is_marked_todo() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let out = stdout_of(&[
        "investigate",
        profile.to_str().unwrap(),
        "--deep",
        "--format",
        "text",
    ]);
    let lower = out.to_lowercase();
    assert!(
        lower.contains("not yet") || lower.contains("todo"),
        "deep is honestly marked unimplemented: {out}"
    );
    assert!(
        lower.contains("p3b") || lower.contains("p5"),
        "cites deferring phase: {out}"
    );
}

#[test]
fn text_render_shows_three_axes_and_next() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let out = stdout_of(&["investigate", profile.to_str().unwrap(), "--format", "text"]);
    for label in ["Priority:", "Confidence:", "Interpretation:", "Next:"] {
        assert!(
            out.contains(label),
            "render shows the `{label}` axis/pointer: {out}"
        );
    }
    // The finding's next: pointer is a concrete drill-down command.
    assert!(
        out.contains("br4n6 artifact"),
        "next: points at an artifact command: {out}"
    );
}

#[test]
fn text_render_shows_detection_header() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let out = stdout_of(&["investigate", profile.to_str().unwrap(), "--format", "text"]);
    assert!(
        out.contains("Detected:"),
        "first line names what was detected: {out}"
    );
}

#[test]
fn footer_always_present_even_with_no_profiles() {
    let empty = TempDir::new().unwrap();
    let out = stdout_of(&[
        "investigate",
        empty.path().to_str().unwrap(),
        "--format",
        "text",
    ]);
    assert!(
        out.contains("Deep recovery"),
        "the skipped-work footer is present even with nothing found: {out}"
    );
}

#[test]
fn piped_output_is_jsonl_with_stderr_notice() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    // No --format on a (piped) stdout → JSONL findings + a loud stderr notice.
    let out = br4n6()
        .args(["investigate", profile.to_str().unwrap()])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("piped output") && stderr.contains("JSONL"),
        "the auto-switch to JSONL is announced on stderr: {stderr}"
    );
    let first = stdout
        .lines()
        .next()
        .expect("at least one JSONL finding line");
    let value: serde_json::Value = serde_json::from_str(first)
        .unwrap_or_else(|e| panic!("piped output line is JSON: {e}: {first}"));
    assert!(
        value.get("priority").is_some(),
        "each JSONL line is a serialized Finding (has priority): {first}"
    );
}

#[test]
fn nonexistent_path_fails_loudly() {
    br4n6()
        .args(["investigate", "/no/such/evidence/path", "--format", "text"])
        .assert()
        .failure();
}
