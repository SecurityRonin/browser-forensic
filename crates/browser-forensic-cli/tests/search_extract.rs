//! RFC 0001 P5a clean break — the former `search` / `extract-iocs` /
//! `match-domains` commands are removed; `find` (P4) is the front door. These
//! tests exercise the surviving capabilities via `find`:
//!   * term / regex / time-range search (was `search`) — here;
//!   * blocklist matching (was `match-domains`) — `find --terms-file`, in
//!     `find_supersedes.rs`.
//!
//! Retired: the pattern-free IOC *enumeration* of `extract-iocs` (list every
//! email/IP/card/search-term with no query) is NOT a `find` capability — `find`
//! is term/regex/@file-driven. Its former tests are dropped rather than forced
//! into a shape `find` does not have. The `extract_iocs` library API remains and
//! is still surfaced by `export --interpret`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

/// A Chrome `History` seeded with URLs/titles carrying an IPv4, a Google search
/// term, and a blocklisted host. Returns `(TempDir, profile_dir)`.
fn ioc_history() -> (TempDir, PathBuf) {
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
        INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES
          ('https://www.google.com/search?q=how+to+launder+money', 'Google Search', 1, 13327626000000000),
          ('http://8.8.8.8/malware', 'contact evil@phish.example', 1, 13327627000000000),
          ('https://tracker.evil.com/beacon', 'Tracker', 1, 13327628000000000),
          ('https://good.example.org/news', 'Good News', 1, 13327629000000000);",
    )
    .unwrap();
    (dir, profile_dir)
}

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

// ---- help ----

#[test]
fn find_help_exits_zero() {
    br4n6().args(["find", "--help"]).assert().success();
}

// ---- find --regex (was `search --regex`) ----

#[test]
fn find_regex_filters_events() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            home.to_str().unwrap(),
            "--regex",
            r"8\.8\.8\.8",
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("8.8.8.8"),
        "expected the 8.8.8.8 hit, got: {text}"
    );
    assert!(
        !text.contains("good.example.org"),
        "unrelated event leaked: {text}"
    );
}

// ---- find <TERM> against a title (was `search --substring`) ----

#[test]
fn find_literal_term_matches_title() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            "Tracker",
            home.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("tracker.evil.com"), "got: {text}");
}

// ---- find --from/--to (was `search --from/--to`) ----

#[test]
fn find_time_range_excludes_future() {
    let (_dir, home) = ioc_history();
    // All fixture visits are in 2023; a 2100 lower bound excludes everything.
    let out = br4n6()
        .args([
            "find",
            home.to_str().unwrap(),
            "--regex",
            r"8\.8\.8\.8",
            "--from",
            "2100-01-01",
            "--format",
            "text",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.trim().is_empty(), "expected no hits, got: {text}");
}

#[test]
fn find_time_range_includes_past() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            home.to_str().unwrap(),
            "--regex",
            r"8\.8\.8\.8",
            "--from",
            "2000-01-01",
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("8.8.8.8"),
        "past events should be included: {text}"
    );
}

// ---- find --terms-file missing (was `match-domains --list` missing) ----

#[test]
fn find_terms_file_missing_errors() {
    let (_dir, home) = ioc_history();
    br4n6()
        .args([
            "find",
            home.to_str().unwrap(),
            "--terms-file",
            "/no/such/list.txt",
        ])
        .assert()
        .failure();
}
