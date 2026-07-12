#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for the forensic CLI subcommands that `br4n6` absorbed
//! from the former `bw` binary (history/cookies/downloads/bookmarks/extensions/
//! login-data/autofill/session/cache/profiles/analyze/integrity/carve/triage and
//! the `timeline` alias). Each subcommand is exercised against the `br4n6`
//! binary; the parallel `bw` alias is covered in `bw_alias.rs`.

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::{NamedTempFile, TempDir};

/// Minimal Chrome `History` SQLite file with one URL, under a Chrome-looking dir.
fn create_chrome_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
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

/// Minimal Firefox `places.sqlite` with one URL.
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

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

// ---- help-exits for every absorbed subcommand ----

#[test]
fn every_subcommand_help_exits_0() {
    for sub in [
        "timeline",
        "history",
        "cookies",
        "downloads",
        "bookmarks",
        "extensions",
        "login-data",
        "autofill",
        "session",
        "cache",
        "cachestorage",
        "profiles",
        "analyze",
        "integrity",
        "carve",
        "triage",
        "browsers",
        "sessions",
    ] {
        br4n6().args([sub, "--help"]).assert().success();
    }
}

// ---- timeline (the artifact pipeline) ----

#[test]
fn timeline_chrome_history_csv_has_header() {
    let (_dir, path) = create_chrome_history();
    let output = br4n6()
        .args(["timeline", "--format", "csv", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "timeline failed: {:?}",
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
fn timeline_chrome_history_jsonl_valid_json() {
    let (_dir, path) = create_chrome_history();
    let output = br4n6()
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
fn timeline_firefox_history_text() {
    let (_dir, path) = create_firefox_places();
    let output = br4n6()
        .args(["timeline", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "timeline failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('['),
        "Expected '[' in text output: {stdout}"
    );
}

#[test]
fn cookies_nonexistent_path_exits_nonzero() {
    br4n6()
        .args(["cookies", "/nonexistent/Cookies"])
        .assert()
        .failure();
}

// ---- profiles (the bw-style discovery output) ----

#[test]
fn profiles_exits_0() {
    br4n6().args(["profiles"]).assert().success();
}

// ---- integrity ----

#[test]
fn integrity_on_valid_chrome_history_succeeds() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
         INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
    ).expect("setup");
    drop(conn);

    br4n6().arg("integrity").arg(f.path()).assert().success();
}

#[test]
fn integrity_on_cleared_history_reports_indicators() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
         UPDATE sqlite_sequence SET seq = 500 WHERE name = 'urls';
         DELETE FROM urls;"
    ).expect("setup");
    drop(conn);

    let output = br4n6()
        .arg("integrity")
        .arg(f.path())
        .arg("--format")
        .arg("jsonl")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HistoryCleared")
            || stdout.contains("integrity")
            || stdout.contains("AutoIncrementGap"),
        "should report integrity findings for cleared history, got: {stdout}"
    );
}

// ---- carve ----

#[test]
fn carve_on_valid_db_succeeds() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
         INSERT INTO urls VALUES (1, 'https://example.com');",
    )
    .expect("setup");
    drop(conn);

    br4n6().arg("carve").arg(f.path()).assert().success();
}

#[test]
fn carve_jsonl_output_is_valid_json() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);")
        .expect("setup");
    drop(conn);

    let output = br4n6()
        .arg("carve")
        .arg(f.path())
        .arg("--format")
        .arg("jsonl")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.is_empty() {
            let _: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("Invalid JSON line: {line:?}, error: {e}"));
        }
    }
}

// ---- triage ----

#[test]
fn triage_on_empty_home_succeeds() {
    let home = TempDir::new().expect("tempdir");
    br4n6()
        .arg("triage")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success();
}

#[test]
fn triage_with_chrome_profile_finds_events() {
    let home = TempDir::new().expect("tempdir");
    let chrome_default = home
        .path()
        .join("Library/Application Support/Google/Chrome/Default");
    std::fs::create_dir_all(&chrome_default).expect("mkdir");

    let conn = rusqlite::Connection::open(chrome_default.join("History")).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
         INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
    ).expect("setup");
    drop(conn);

    let output = br4n6()
        .arg("triage")
        .arg("--home")
        .arg(home.path())
        .arg("--format")
        .arg("jsonl")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "triage should produce output");
}

// ---- analyze ----

#[test]
fn analyze_chrome_history_succeeds() {
    let (_dir, path) = create_chrome_history();
    br4n6()
        .args(["analyze", path.to_str().unwrap()])
        .assert()
        .success();
}

// ---- preferences ----

#[test]
fn preferences_chrome_json_parses() {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let prefs = profile.join("Preferences");
    std::fs::write(
        &prefs,
        r#"{"homepage":"https://start.example.com/","download":{"default_directory":"/tmp/dl"}}"#,
    )
    .unwrap();
    let output = br4n6()
        .args(["preferences", prefs.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("start.example.com"), "got: {stdout}");
}

#[test]
fn preferences_firefox_prefs_js_parses() {
    let dir = TempDir::new().unwrap();
    let prefs = dir.path().join("prefs.js");
    std::fs::write(
        &prefs,
        "user_pref(\"browser.startup.homepage\", \"https://ff.example.com\");\n",
    )
    .unwrap();
    let output = br4n6()
        .args(["preferences", prefs.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ff.example.com"), "got: {stdout}");
}

// ---- export ----

#[test]
fn export_jsonl_stream_from_chrome_home() {
    let (_dir, path) = create_chrome_history();
    let profile = path.parent().unwrap();
    let output = br4n6()
        .args(["export", profile.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("example.com"), "got: {stdout}");
}

#[test]
fn export_sqlite_writes_timeline_table() {
    let (dir, path) = create_chrome_history();
    let profile = path.parent().unwrap();
    let out = dir.path().join("timeline.sqlite");
    br4n6()
        .args([
            "export",
            profile.to_str().unwrap(),
            "--format",
            "sqlite",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let conn = Connection::open(&out).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM timeline", [], |r| r.get(0))
        .unwrap();
    assert!(count >= 1, "timeline should have at least one event");
}

#[test]
fn export_rejects_unknown_timezone() {
    let (dir, _path) = create_chrome_history();
    br4n6()
        .args([
            "export",
            dir.path().to_str().unwrap(),
            "--timezone",
            "Bogus/Zone",
            "--format",
            "jsonl",
        ])
        .assert()
        .failure();
}

#[test]
fn export_sqlite_requires_output() {
    let (dir, _path) = create_chrome_history();
    br4n6()
        .args(["export", dir.path().to_str().unwrap(), "--format", "sqlite"])
        .assert()
        .failure();
}
