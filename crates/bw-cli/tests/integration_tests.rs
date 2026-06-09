//! Integration tests for `bw` CLI — end-to-end coverage.

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

/// Create a minimal Chrome History SQLite file with one URL.
/// Returns the TempDir (to keep it alive) and the path to the History file.
fn create_chrome_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    // Create a path that looks like a Chrome profile
    let profile_dir = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let history_path = profile_dir.join("History");
    let conn = Connection::open(&history_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL
        );
        INSERT INTO urls (url, title, visit_count, last_visit_time)
        VALUES ('https://example.com', 'Example', 1, 13327626000000000);",
    )
    .unwrap();
    (dir, history_path)
}

/// Create a minimal Firefox places.sqlite file with one URL.
fn create_firefox_places() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile_dir = dir.path().join("mozilla").join("firefox").join("default");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let places_path = profile_dir.join("places.sqlite");
    let conn = Connection::open(&places_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit_date INTEGER
        );
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            place_id INTEGER NOT NULL,
            visit_date INTEGER NOT NULL
        );
        INSERT INTO moz_places (url, title, visit_count, last_visit_date)
        VALUES ('https://firefox-example.com', 'Firefox Example', 1, 1648000000000000);
        INSERT INTO moz_historyvisits (place_id, visit_date) VALUES (1, 1648000000000000);",
    )
    .unwrap();
    (dir, places_path)
}

#[test]
fn bw_timeline_chrome_history_csv_has_header() {
    let (_dir, path) = create_chrome_history();
    let output = Command::cargo_bin("bw")
        .unwrap()
        .args(["timeline", "--format", "csv", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bw timeline failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.contains("timestamp")
            && first_line.contains("browser")
            && first_line.contains("artifact"),
        "CSV header not found in: {first_line}"
    );
}

#[test]
fn bw_timeline_chrome_history_jsonl_valid_json() {
    let (_dir, path) = create_chrome_history();
    let output = Command::cargo_bin("bw")
        .unwrap()
        .args(["timeline", "--format", "jsonl", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.is_empty() {
            let _: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("line is not valid JSON: {e}\nline: {line}"));
        }
    }
}

#[test]
fn bw_cookies_nonexistent_path_exits_nonzero() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["cookies", "/nonexistent/Cookies"])
        .assert()
        .failure();
}

#[test]
fn bw_timeline_firefox_history_text() {
    let (_dir, path) = create_firefox_places();
    let output = Command::cargo_bin("bw")
        .unwrap()
        .args(["timeline", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bw timeline failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Text format includes '[' before timestamp
    assert!(
        stdout.contains('['),
        "Expected '[' in text output: {stdout}"
    );
}

#[test]
fn bw_history_chrome_text_output() {
    let (_dir, path) = create_chrome_history();
    let output = Command::cargo_bin("bw")
        .unwrap()
        .args(["history", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bw history failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('['),
        "Expected '[' in text output: {stdout}"
    );
}
