//! RFC 0001 P5c — `find --iocs <PATH>` restores pattern-free IOC *enumeration*.
//!
//! P5a removed the top-level `extract-iocs` command but kept the `extract_iocs`
//! library API. `find` (P4) is term/regex/@file-driven and had NO way to list
//! every candidate entity with no query. `--iocs` is that mode: it collects the
//! profile/home events (the same collect path `find` already uses) and
//! enumerates every IOC via the existing `browser_forensic_search::extract_iocs`
//! — reusing extraction, not reimplementing it. Each IOC renders with the P2
//! provenance-aware output (TTY table / JSONL objects) carrying its kind, value,
//! and source event; the honest `user_action_claim` is `observed-string` because
//! an IOC-shaped string appearing in an artifact is not a claim the user
//! visited/searched anything.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

/// A Chrome `History` seeded with an email (in a title), an IPv4 (in a URL), and
/// a Google search term. Returns `(TempDir, home_dir)`. All visits are in 2023.
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
    // Return the home directory (parent of google-chrome) so collection walks it.
    let home = dir.path().to_path_buf();
    (dir, home)
}

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// `find --iocs <PATH>` with NO term enumerates candidate entities: a known
/// email and IPv4 from the fixture appear.
#[test]
fn find_iocs_enumerates_known_entities() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            "--iocs",
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
    assert!(
        text.contains("evil@phish.example"),
        "expected the enumerated email, got: {text}"
    );
    assert!(
        text.contains("8.8.8.8"),
        "expected the enumerated IPv4, got: {text}"
    );
}

/// The JSONL objects carry kind + value + source: the email IOC line parses to
/// an object whose `term` is the IOC kind label, `match` is the value, and whose
/// provenance names the source evidence class.
#[test]
fn find_iocs_jsonl_carries_kind_value_source() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            "--iocs",
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
    let line = text
        .lines()
        .find(|l| l.contains("evil@phish.example"))
        .unwrap_or_else(|| panic!("no email IOC line in: {text}"));
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["term"], "email", "kind is carried in `term`: {line}");
    assert_eq!(
        v["match"], "evil@phish.example",
        "value is carried in `match`: {line}"
    );
    assert!(
        v["provenance"]["source"].is_string(),
        "provenance names the source event class: {line}"
    );
    // Enumerations are observed strings, never a claimed visit/search (honest).
    assert_eq!(
        v["provenance"]["user_action_claim"], "observed-string",
        "an enumerated IOC is an observed string: {line}"
    );
}

/// `--iocs` composes with `--from`/`--to`: a lower bound past every fixture
/// timestamp scopes the enumeration to empty.
#[test]
fn find_iocs_scopes_by_time_range() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            "--iocs",
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
    assert!(
        text.trim().is_empty(),
        "a future lower bound excludes every IOC, got: {text}"
    );
}

/// `--iocs` enumerates ALL IOCs and takes no query: passing a positional TERM
/// alongside is a clear error, not a silently-ignored argument.
#[test]
fn find_iocs_with_term_errors() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args(["find", "--iocs", "Tracker", home.to_str().unwrap()])
        .assert()
        .failure();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.to_lowercase().contains("iocs") && stderr.to_lowercase().contains("term"),
        "error must explain --iocs takes no TERM, got: {stderr}"
    );
}

/// The old `extract-iocs` top-level command stays removed (P5a): invoking it is
/// an unknown-subcommand error.
#[test]
fn extract_iocs_command_stays_removed() {
    let out = br4n6()
        .args(["extract-iocs", "/tmp/whatever"])
        .assert()
        .failure();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.to_lowercase().contains("unrecognized")
            || stderr.to_lowercase().contains("unexpected"),
        "extract-iocs must be gone as a subcommand, got: {stderr}"
    );
}
