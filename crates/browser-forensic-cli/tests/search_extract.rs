//! End-to-end coverage for the Milestone-6 analysis subcommands: `search`,
//! `extract-iocs`, and `match-domains`, exercised against the `br4n6` binary
//! over an IOC-rich Chrome `History` fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

/// A Chrome `History` seeded with URLs/titles carrying an email, an IPv4, a
/// Google search term, and a blocklisted host. Returns `(TempDir, profile_dir)`;
/// the profile dir is what the analysis subcommands point at.
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
fn help_exits_zero_for_new_subcommands() {
    for sub in ["search", "extract-iocs", "match-domains"] {
        br4n6().args([sub, "--help"]).assert().success();
    }
}

// ---- search ----

#[test]
fn search_regex_filters_events() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "search",
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
        "expected the 8.8.8.8 event, got: {text}"
    );
    assert!(
        !text.contains("good.example.org"),
        "unrelated event leaked: {text}"
    );
}

#[test]
fn search_substring_matches_title() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "search",
            home.to_str().unwrap(),
            "--substring",
            "Tracker",
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

#[test]
fn search_time_range_excludes_future() {
    let (_dir, home) = ioc_history();
    // All fixture visits are in 2023; a 2100 lower bound excludes everything.
    let out = br4n6()
        .args([
            "search",
            home.to_str().unwrap(),
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
    assert!(text.trim().is_empty(), "expected no events, got: {text}");
}

#[test]
fn search_time_range_includes_past() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "search",
            home.to_str().unwrap(),
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

// ---- extract-iocs ----

#[test]
fn extract_iocs_finds_email_ip_and_search_term() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args(["extract-iocs", home.to_str().unwrap(), "--format", "jsonl"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("evil@phish.example"), "email missing: {text}");
    assert!(text.contains("8.8.8.8"), "ipv4 missing: {text}");
    assert!(
        text.contains("how to launder money"),
        "search term missing: {text}"
    );
}

#[test]
fn extract_iocs_jsonl_is_valid_json() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args(["extract-iocs", home.to_str().unwrap(), "--format", "jsonl"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    let mut lines = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid json line");
        assert!(v.get("kind").is_some(), "line missing kind: {line}");
        assert!(v.get("value").is_some(), "line missing value: {line}");
        lines += 1;
    }
    assert!(lines >= 3, "expected several IOC rows, got {lines}");
}

#[test]
fn extract_iocs_missing_path_errors() {
    br4n6()
        .args(["extract-iocs", "/no/such/path/xyz"])
        .assert()
        .failure();
}

// ---- match-domains ----

#[test]
fn match_domains_flags_blocklisted_host() {
    let (_dir, home) = ioc_history();
    let list = home.join("blocklist.txt");
    std::fs::write(&list, "# bad domains\nevil.com\n").unwrap();
    let out = br4n6()
        .args([
            "match-domains",
            home.to_str().unwrap(),
            "--list",
            list.to_str().unwrap(),
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
        text.contains("tracker.evil.com"),
        "blocklisted host not flagged: {text}"
    );
    assert!(text.contains("evil.com"), "blocklist entry missing: {text}");
    assert!(
        !text.contains("good.example.org"),
        "clean host leaked: {text}"
    );
}

#[test]
fn match_domains_missing_list_errors() {
    let (_dir, home) = ioc_history();
    br4n6()
        .args([
            "match-domains",
            home.to_str().unwrap(),
            "--list",
            "/no/such/list.txt",
        ])
        .assert()
        .failure();
}

#[test]
fn match_domains_empty_list_errors_loudly() {
    let (_dir, home) = ioc_history();
    let list = home.join("empty.txt");
    std::fs::write(&list, "# only comments\n\n").unwrap();
    br4n6()
        .args([
            "match-domains",
            home.to_str().unwrap(),
            "--list",
            list.to_str().unwrap(),
        ])
        .assert()
        .failure();
}
