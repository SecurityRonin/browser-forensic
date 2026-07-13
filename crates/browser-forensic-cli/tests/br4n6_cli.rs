//! Integration tests for the `br4n6` dual-mode CLI/TUI front-end (cross-browser).
//!
//! These drive the real binary end-to-end: build synthetic Chromium `History`
//! (redirect chain) + SNSS `Sessions/`, Firefox `places.sqlite` +
//! `sessionstore.jsonlz4`, and Safari `History.db` fixtures, then assert `br4n6`
//! auto-detects the browser family and surfaces visits/tabs through the unified
//! `BrowserEvent` output.

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
        .args([
            "artifact",
            "history",
            "--format",
            "jsonl",
            history.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
            "artifact",
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
            "artifact",
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
        .args([
            "artifact",
            "history",
            "--format",
            "jsonl",
            profile.to_str().unwrap(),
        ])
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
        .args([
            "artifact",
            "sessions",
            "--format",
            "jsonl",
            sessions.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
            "artifact",
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
    std::fs::copy(
        dir.path().join("Google/Chrome/Default/History"),
        chrome_default.join("History"),
    )
    .unwrap();

    let out = br4n6()
        .args([
            "browsers",
            "--home",
            home.path().to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = jsonl_lines(&out.stdout);
    assert!(
        lines
            .iter()
            .any(|v| v["browser"] == "Chromium" && v["name"] == "Default"),
        "expected a Chromium/Default profile, got: {lines:?}"
    );
}

// ── Firefox fixtures ─────────────────────────────────────────────────────────

/// Build a Firefox `places.sqlite` with `moz_places` + `moz_historyvisits`.
/// `last_visit_date` is `PRTime` (microseconds since the Unix epoch). Returns the
/// profile dir + `places.sqlite` path.
fn create_firefox_places() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile_dir = dir
        .path()
        .join("Firefox")
        .join("Profiles")
        .join("abc.default-release");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let places = profile_dir.join("places.sqlite");
    let conn = Connection::open(&places).unwrap();
    conn.execute_batch(
        "CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT,
            visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
         CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL,
            visit_date INTEGER NOT NULL, visit_type INTEGER NOT NULL);
         INSERT INTO moz_places (id,url,title,visit_count,last_visit_date) VALUES
            (1,'https://ff-one.example','FF One',3,1648000000000000),
            (2,'https://ff-two.example','FF Two',1,1648000100000000);
         INSERT INTO moz_historyvisits (id,place_id,visit_date,visit_type) VALUES
            (1,1,1648000000000000,1),
            (2,2,1648000100000000,1);",
    )
    .unwrap();
    (dir, places)
}

/// Build a Firefox `sessionstore.jsonlz4` (mozLz4: magic + u32 LE size + LZ4
/// block) with one window holding two open tabs. Returns the profile dir + path.
fn create_firefox_sessionstore() -> (TempDir, PathBuf) {
    const MOZLZ4_MAGIC: &[u8] = b"mozLz40\0";
    let dir = TempDir::new().unwrap();
    let profile_dir = dir
        .path()
        .join("Firefox")
        .join("Profiles")
        .join("abc.default-release");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let session = serde_json::json!({
        "windows": [{
            "tabs": [
                { "lastAccessed": 1_648_000_000_000_i64,
                  "entries": [{ "url": "https://ff-tab-a.example", "title": "FF Tab A" }] },
                { "lastAccessed": 1_648_000_001_000_i64,
                  "entries": [{ "url": "https://ff-tab-b.example", "title": "FF Tab B" }] }
            ]
        }]
    });
    let json_bytes = session.to_string().into_bytes();
    let compressed = lz4_flex::block::compress(&json_bytes);
    let mut bytes = MOZLZ4_MAGIC.to_vec();
    bytes.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&compressed);
    let path = profile_dir.join("sessionstore.jsonlz4");
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

#[test]
fn br4n6_history_reads_firefox_places() {
    let (_d, places) = create_firefox_places();
    let out = br4n6()
        .args([
            "artifact",
            "history",
            "--format",
            "jsonl",
            places.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = jsonl_lines(&out.stdout);
    let urls = urls_of(&lines);
    assert!(urls.contains(&"https://ff-one.example".to_string()));
    assert!(urls.contains(&"https://ff-two.example".to_string()));
    assert!(
        lines.iter().all(|v| v["browser"] == "Firefox"),
        "family auto-detected as Firefox, got: {lines:?}"
    );
}

#[test]
fn br4n6_history_accepts_firefox_profile_directory() {
    let (_d, places) = create_firefox_places();
    let profile = places.parent().unwrap();
    let out = br4n6()
        .args([
            "artifact",
            "history",
            "--format",
            "jsonl",
            profile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a Firefox profile dir should resolve to places.sqlite; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let urls = urls_of(&jsonl_lines(&out.stdout));
    assert!(urls.contains(&"https://ff-one.example".to_string()));
}

#[test]
fn br4n6_sessions_reads_firefox_sessionstore() {
    let (_d, session) = create_firefox_sessionstore();
    let out = br4n6()
        .args([
            "artifact",
            "sessions",
            "--format",
            "jsonl",
            session.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = jsonl_lines(&out.stdout);
    let urls = urls_of(&lines);
    assert!(urls.contains(&"https://ff-tab-a.example".to_string()));
    assert!(urls.contains(&"https://ff-tab-b.example".to_string()));
    assert!(
        lines.iter().all(|v| v["browser"] == "Firefox"),
        "family auto-detected as Firefox, got: {lines:?}"
    );
}

#[test]
fn br4n6_sessions_accepts_firefox_profile_directory() {
    let (_d, session) = create_firefox_sessionstore();
    let profile = session.parent().unwrap();
    let out = br4n6()
        .args([
            "artifact",
            "sessions",
            "--format",
            "jsonl",
            profile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a Firefox profile dir should resolve to sessionstore.jsonlz4; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let urls = urls_of(&jsonl_lines(&out.stdout));
    assert!(urls.contains(&"https://ff-tab-a.example".to_string()));
}

// ── Safari fixtures ──────────────────────────────────────────────────────────

/// Build a Safari `History.db` with `history_items` + `history_visits`.
/// `visit_time` is Core Data seconds (since 2001-01-01). Returns the Safari
/// dir + `History.db` path.
fn create_safari_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let safari_dir = dir.path().join("Library").join("Safari");
    std::fs::create_dir_all(&safari_dir).unwrap();
    let history = safari_dir.join("History.db");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE history_items (
            id INTEGER PRIMARY KEY, url TEXT NOT NULL, visit_count INTEGER DEFAULT 0);
         CREATE TABLE history_visits (
            id INTEGER PRIMARY KEY, history_item INTEGER NOT NULL, visit_time REAL NOT NULL);
         INSERT INTO history_items (id,url,visit_count) VALUES
            (1,'https://sf-one.example',2),
            (2,'https://sf-two.example',1);
         INSERT INTO history_visits (id,history_item,visit_time) VALUES
            (1,1,700000000.0),
            (2,2,700000100.0);",
    )
    .unwrap();
    (dir, history)
}

#[test]
fn br4n6_history_reads_safari_history_db() {
    let (_d, history) = create_safari_history();
    let out = br4n6()
        .args([
            "artifact",
            "history",
            "--format",
            "jsonl",
            history.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = jsonl_lines(&out.stdout);
    let urls = urls_of(&lines);
    assert!(urls.contains(&"https://sf-one.example".to_string()));
    assert!(urls.contains(&"https://sf-two.example".to_string()));
    assert!(
        lines.iter().all(|v| v["browser"] == "Safari"),
        "family auto-detected as Safari, got: {lines:?}"
    );
}

#[test]
fn br4n6_history_accepts_safari_profile_directory() {
    let (_d, history) = create_safari_history();
    let safari_dir = history.parent().unwrap();
    let out = br4n6()
        .args([
            "artifact",
            "history",
            "--format",
            "jsonl",
            safari_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a Safari dir should resolve to History.db; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let urls = urls_of(&jsonl_lines(&out.stdout));
    assert!(urls.contains(&"https://sf-one.example".to_string()));
}

// ── Tamper-check ─────────────────────────────────────────────────────────────

/// A Chromium `History` with a visit-id gap (rows 1 then 50) — residue
/// consistent with deleted visits — for the tamper-check fires/silent oracle.
fn create_tampered_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let history = dir.path().join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT,
            visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1,'https://a.example','A',1,13300000000000000);
         INSERT INTO visits VALUES (1,1,13300000000000000,0,0);
         INSERT INTO visits VALUES (50,1,13300000001000000,0,0);",
    )
    .unwrap();
    conn.close().ok();
    (dir, history)
}

fn create_pristine_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let history = dir.path().join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT,
            visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1,'https://a.example','A',1,13300000000000000);
         INSERT INTO visits VALUES (1,1,13300000000000000,0,0);",
    )
    .unwrap();
    conn.close().ok();
    (dir, history)
}

#[test]
fn br4n6_tamper_check_fires_on_tampered_db() {
    let (_d, history) = create_tampered_history();
    let out = br4n6()
        .args(["tamper-check", history.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "tamper-check should succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("indicator"),
        "tampered DB should report indicators, got: {stdout}"
    );
    // Every finding must carry an innocent alternative (the framing rule).
    assert!(
        stdout.to_lowercase().contains("innocent alternative"),
        "each finding must show an innocent alternative, got: {stdout}"
    );
}

#[test]
fn br4n6_tamper_check_clean_on_pristine_db() {
    let (_d, history) = create_pristine_history();
    let out = br4n6()
        .args(["tamper-check", history.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("no tampering"),
        "pristine DB should report no indicators, got: {stdout}"
    );
}
