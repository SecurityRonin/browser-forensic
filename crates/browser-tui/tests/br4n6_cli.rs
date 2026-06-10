//! Integration tests for the `br4n6` dual-mode CLI/TUI front-end (Chromium MVP).
//!
//! These drive the real binary end-to-end: build a synthetic Chromium `History`
//! SQLite with a redirect chain and an SNSS `Sessions/` directory, then assert
//! `br4n6` surfaces history visits redirect-collapsed and session-state tabs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use assert_cmd::Command;
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;

const SERVER_REDIRECT: i64 = 0x8000_0000;
const CHAIN_END: i64 = 0x2000_0000;

/// Build a Chromium `History` DB containing a redirect chain:
/// `start (typed)` → `hop (redirect, mid-chain)` → `landing (redirect, chain-end)`,
/// plus a standalone `other (typed)` visit. Returns the profile dir + History path.
fn create_chrome_history_with_redirect() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile_dir = dir.path().join("Google").join("Chrome").join("Default");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let history = profile_dir.join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (
            id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
         CREATE TABLE visits (
            id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
            from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
         INSERT INTO urls (id,url,title,visit_count,last_visit_time) VALUES
            (1,'https://start.example','Start',1,13327626000000000),
            (2,'https://hop.example','Hop',1,13327626000000000),
            (3,'https://landing.example','Landing',1,13327626000000000),
            (4,'https://other.example','Other',1,13327626000000000);",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (1,13327626000000000,0,1)",
        [],
    )
    .unwrap(); // typed → kept
    conn.execute(
        "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (2,13327626100000000,0,?1)",
        [SERVER_REDIRECT],
    )
    .unwrap(); // mid-chain redirect → dropped when collapsed
    conn.execute(
        "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (3,13327626200000000,0,?1)",
        [SERVER_REDIRECT | CHAIN_END],
    )
    .unwrap(); // redirect landing → kept
    conn.execute(
        "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (4,13327627000000000,0,1)",
        [],
    )
    .unwrap(); // standalone typed → kept
    (dir, history)
}

// ── SNSS session fixture builders (mirror browser-chrome/src/session.rs) ──────

fn pad4(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}

fn nav_payload(tab_id: i32, index: i32, url: &str, title: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&tab_id.to_le_bytes());
    body.extend_from_slice(&index.to_le_bytes());
    body.extend_from_slice(&(url.len() as i32).to_le_bytes());
    body.extend_from_slice(url.as_bytes());
    pad4(&mut body);
    let units: Vec<u16> = title.encode_utf16().collect();
    body.extend_from_slice(&(units.len() as i32).to_le_bytes());
    for u in &units {
        body.extend_from_slice(&u.to_le_bytes());
    }
    pad4(&mut body);
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn snss_bytes(records: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = b"SNSS".to_vec();
    out.extend_from_slice(&3i32.to_le_bytes());
    for (id, payload) in records {
        let size = (payload.len() + 1) as u16;
        out.extend_from_slice(&size.to_le_bytes());
        out.push(*id);
        out.extend_from_slice(payload);
    }
    out
}

/// Create a `Sessions/` directory with a current-session file holding two tabs.
fn create_sessions_dir() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("Sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let bytes = snss_bytes(&[
        (6, nav_payload(10, 0, "https://alpha.example", "Alpha")),
        (6, nav_payload(11, 0, "https://beta.example", "Beta")),
    ]);
    std::fs::write(sessions.join("Session_100"), bytes).unwrap();
    (dir, sessions)
}

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

fn jsonl_lines(stdout: &[u8]) -> Vec<Value> {
    String::from_utf8(stdout.to_vec())
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("each line is JSON"))
        .collect()
}

fn urls_of(lines: &[Value]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|v| v["url"].as_str().map(str::to_string))
        .collect()
}

// ── History ──────────────────────────────────────────────────────────────────

#[test]
fn br4n6_history_collapses_redirect_chain_by_default() {
    let (_d, history) = create_chrome_history_with_redirect();
    let out = br4n6()
        .args(["history", "--format", "jsonl", history.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let urls = urls_of(&jsonl_lines(&out.stdout));
    assert_eq!(
        urls,
        vec![
            "https://start.example",
            "https://landing.example",
            "https://other.example",
        ],
        "mid-chain redirect hop is collapsed away by default"
    );
}

#[test]
fn br4n6_history_no_collapse_keeps_every_visit() {
    let (_d, history) = create_chrome_history_with_redirect();
    let out = br4n6()
        .args([
            "history",
            "--no-collapse",
            "--format",
            "jsonl",
            history.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let urls = urls_of(&jsonl_lines(&out.stdout));
    assert_eq!(urls.len(), 4, "--no-collapse surfaces all four raw visits");
    assert!(urls.contains(&"https://hop.example".to_string()));
}

#[test]
fn br4n6_history_search_filters_to_substring() {
    let (_d, history) = create_chrome_history_with_redirect();
    let out = br4n6()
        .args([
            "history",
            "--search",
            "landing",
            "--format",
            "jsonl",
            history.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let urls = urls_of(&jsonl_lines(&out.stdout));
    assert_eq!(urls, vec!["https://landing.example"]);
}

#[test]
fn br4n6_history_accepts_profile_directory() {
    let (_d, history) = create_chrome_history_with_redirect();
    let profile = history.parent().unwrap();
    let out = br4n6()
        .args(["history", "--format", "jsonl", profile.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a profile dir should resolve to its History file; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let urls = urls_of(&jsonl_lines(&out.stdout));
    assert!(urls.contains(&"https://start.example".to_string()));
}

// ── Sessions ─────────────────────────────────────────────────────────────────

#[test]
fn br4n6_sessions_surfaces_open_tabs() {
    let (_d, sessions) = create_sessions_dir();
    let out = br4n6()
        .args(["sessions", "--format", "jsonl", sessions.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let lines = jsonl_lines(&out.stdout);
    let urls = urls_of(&lines);
    assert!(urls.contains(&"https://alpha.example".to_string()));
    assert!(urls.contains(&"https://beta.example".to_string()));
}

#[test]
fn br4n6_sessions_search_filters() {
    let (_d, sessions) = create_sessions_dir();
    let out = br4n6()
        .args([
            "sessions",
            "--search",
            "beta",
            "--format",
            "jsonl",
            sessions.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let urls = urls_of(&jsonl_lines(&out.stdout));
    assert_eq!(urls, vec!["https://beta.example"]);
}

// ── Discovery ────────────────────────────────────────────────────────────────

#[test]
fn br4n6_browsers_discovers_chromium_profile() {
    let (dir, _history) = create_chrome_history_with_redirect();
    // Lay out a discoverable macOS Chrome profile under a fake HOME.
    let home = TempDir::new().unwrap();
    let chrome_default = home
        .path()
        .join("Library/Application Support/Google/Chrome/Default");
    std::fs::create_dir_all(&chrome_default).unwrap();
    std::fs::copy(dir.path().join("Google/Chrome/Default/History"), chrome_default.join("History"))
        .unwrap();

    let out = br4n6()
        .args(["browsers", "--home", home.path().to_str().unwrap(), "--format", "jsonl"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let lines = jsonl_lines(&out.stdout);
    assert!(
        lines.iter().any(|v| v["browser"] == "Chromium" && v["name"] == "Default"),
        "expected a Chromium/Default profile, got: {lines:?}"
    );
}
