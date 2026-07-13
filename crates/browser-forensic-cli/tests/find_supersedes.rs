#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RFC 0001 Phase P5a clean break (D11): the `find` verb (P4) supersedes the
//! former `search`, `extract-iocs`, and `match-domains` top-level commands, which
//! are removed. This proves the removal and that the surviving capabilities —
//! term/regex/time-range search and blocklist matching — are reachable via `find`.

use std::path::PathBuf;

use assert_cmd::Command;
use rusqlite::Connection;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chrome `History` with a blocklistable host and a distinct clean host.
fn ioc_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile_dir = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let history_path = profile_dir.join("History");
    let conn = Connection::open(&history_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
             visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
         INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES
           ('http://8.8.8.8/malware', 'contact evil@phish.example', 1, 13327627000000000),
           ('https://tracker.evil.com/beacon', 'Tracker', 1, 13327628000000000),
           ('https://good.example.org/news', 'Good News', 1, 13327629000000000);",
    )
    .unwrap();
    (dir, profile_dir)
}

#[test]
fn removed_search_verbs_are_unknown_subcommands() {
    for name in ["search", "extract-iocs", "match-domains"] {
        let out = br4n6().args([name, "--help"]).output().unwrap();
        assert!(
            !out.status.success(),
            "removed `{name}` still resolves; clean break not applied"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("unrecognized subcommand") || stderr.contains("unexpected argument"),
            "`{name}` did not error as an unknown subcommand: {stderr}"
        );
    }
}

#[test]
fn find_regex_supersedes_search() {
    let (_d, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            home.to_str().unwrap(),
            "--regex",
            r"8\.8\.8\.8",
            "--format",
            "jsonl",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("8.8.8.8"), "regex hit missing: {text}");
    assert!(
        !text.contains("good.example.org"),
        "unrelated event leaked: {text}"
    );
}

#[test]
fn find_terms_file_supersedes_match_domains() {
    let (_d, home) = ioc_history();
    let list = home.join("blocklist.txt");
    std::fs::write(&list, "# bad domains\nevil.com\n").unwrap();
    let out = br4n6()
        .args([
            "find",
            home.to_str().unwrap(),
            "--terms-file",
            list.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("tracker.evil.com"),
        "blocklisted host not found via find: {text}"
    );
    assert!(
        !text.contains("good.example.org"),
        "clean host leaked: {text}"
    );
}
