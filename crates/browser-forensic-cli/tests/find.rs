//! End-to-end coverage for the RFC 0001 P4 `find` verb, exercised against the
//! `br4n6` binary over a fixture profile that carries the same term in DISTINCT
//! evidence classes: a live history visit AND a domain recovered from a
//! network-state artifact. The verb must keep those classes as separate,
//! provenance-tagged rows (D4) — never collapse them into a bare "found X".
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use rusqlite::Connection;
use serde_json::Value;
use std::path::PathBuf;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chrome profile with a live `History` (a `tracker.evil.com` visit, a Google
/// search, an IP) AND a `Network Persistent State` recording contact with
/// `evil.com` — so `find evil.com` has both a live and a recovered hit.
fn profile_with_live_and_recovered() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let conn = Connection::open(profile.join("History")).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL
        );
        INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES
          ('https://tracker.evil.com/beacon', 'Tracker', 1, 13327628000000000),
          ('https://www.google.com/search?q=how+to+launder+money', 'Google Search', 1, 13327626000000000),
          ('https://good.example.org/news', 'Good News', 1, 13327629000000000);",
    )
    .unwrap();
    drop(conn);
    // Network Persistent State — an HTTP server the browser contacted; the host
    // survives a history wipe and is recovered independently of the visit.
    std::fs::write(
        profile.join("Network Persistent State"),
        br#"{"net":{"http_server_properties":{"servers":[{"server":"https://evil.com"}]}}}"#,
    )
    .unwrap();
    (dir, profile)
}

/// A Chrome profile whose `History` had a `carved-only.example` row DELETED, so
/// the term survives only as a carvable free-cell record — never live.
fn profile_with_deleted_row() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let conn = Connection::open(profile.join("History")).unwrap();
    conn.execute_batch(
        "PRAGMA page_size=4096; PRAGMA secure_delete=OFF;
         CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL
         );
         INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES
           ('https://alive-one.example/', 'One', 3, 13327620000000000),
           ('https://carved-only.example/secret', 'Secret', 9, 13327621000000000),
           ('https://alive-two.example/', 'Two', 1, 13327622000000000);
         DELETE FROM urls WHERE url = 'https://carved-only.example/secret';",
    )
    .unwrap();
    conn.close().ok();
    (dir, profile)
}

/// Parse stdout into the JSONL hit objects (skipping any blank lines).
fn hits(stdout: &[u8]) -> Vec<Value> {
    String::from_utf8(stdout.to_vec())
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("valid json line"))
        .collect()
}

fn prov<'a>(hit: &'a Value, axis: &str) -> &'a str {
    hit.get("provenance")
        .and_then(|p| p.get(axis))
        .and_then(Value::as_str)
        .unwrap_or("")
}

#[test]
fn help_exits_zero() {
    br4n6().args(["find", "--help"]).assert().success();
}

#[test]
fn classifies_domain_and_announces_on_stderr() {
    let (_d, profile) = profile_with_live_and_recovered();
    let out = br4n6()
        .args([
            "find",
            "evil.com",
            profile.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("domain") && stderr.contains("evil.com"),
        "classifier should announce the domain on stderr, got: {stderr}"
    );
}

#[test]
fn live_and_recovered_are_distinct_rows_not_merged() {
    let (_d, profile) = profile_with_live_and_recovered();
    let out = br4n6()
        .args([
            "find",
            "evil.com",
            profile.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let all = hits(&out);
    let evil: Vec<&Value> = all
        .iter()
        .filter(|h| h.get("term").and_then(Value::as_str) == Some("evil.com"))
        .collect();
    // A live history visit and a recovered domain are BOTH present and DISTINCT.
    let has_live_history = evil
        .iter()
        .any(|h| prov(h, "source") == "History" && prov(h, "state") == "Live");
    let has_recovered = evil
        .iter()
        .any(|h| prov(h, "source") == "Recovered" && prov(h, "state") == "Inferred");
    assert!(has_live_history, "missing the live history row: {evil:?}");
    assert!(has_recovered, "missing the recovered-domain row: {evil:?}");
    // Not homogenized: the two classes have different source/state.
    assert!(
        evil.len() >= 2,
        "live and recovered must be separate rows, got {evil:?}"
    );
}

#[test]
fn recovered_hit_is_never_labelled_visited_or_live() {
    let (_d, profile) = profile_with_live_and_recovered();
    let out = br4n6()
        .args([
            "find",
            "evil.com",
            profile.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    for h in hits(&out) {
        if prov(&h, "source") == "Recovered" {
            assert_ne!(prov(&h, "state"), "Live", "recovered hit mislabelled live");
            assert_ne!(
                prov(&h, "user_action_claim"),
                "Visited",
                "recovered hit mislabelled as a confirmed visit"
            );
        }
    }
}

#[test]
fn jsonl_carries_every_axis() {
    let (_d, profile) = profile_with_live_and_recovered();
    let out = br4n6()
        .args([
            "find",
            "evil.com",
            profile.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let all = hits(&out);
    assert!(!all.is_empty(), "expected hits");
    for h in &all {
        assert!(h.get("term").is_some(), "term axis");
        assert!(h.get("confidence").is_some(), "confidence axis");
        assert!(h.get("rule_id").is_some(), "rule axis");
        assert!(h.get("match").is_some(), "concrete match value");
        for axis in ["source", "state", "timestamp_basis", "user_action_claim"] {
            assert!(
                !prov(h, axis).is_empty(),
                "provenance carries {axis}: {h:?}"
            );
        }
    }
}

#[test]
fn text_output_is_markdown_table_without_box_drawing() {
    let (_d, profile) = profile_with_live_and_recovered();
    let out = br4n6()
        .args([
            "find",
            "evil.com",
            profile.to_str().unwrap(),
            "--format",
            "text",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("| TERM |"), "markdown header row: {text}");
    assert!(
        text.contains("SOURCE") && text.contains("STATE"),
        "provenance columns"
    );
    // Full values, never ellipsized; no box-drawing characters (paste-safe).
    for boxc in ['┌', '┐', '└', '┘', '│', '─', '┼'] {
        assert!(!text.contains(boxc), "box-drawing char {boxc} leaked");
    }
    assert!(!text.contains('…'), "values must never be ellipsized");
}

#[test]
fn at_file_reads_a_term_list() {
    let (_d, profile) = profile_with_live_and_recovered();
    let list = profile.join("terms.txt");
    std::fs::write(&list, "# iocs\nevil.com\n").unwrap();
    let at = format!("@{}", list.to_str().unwrap());
    let out = br4n6()
        .args(["find", &at, profile.to_str().unwrap(), "--format", "jsonl"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("evil.com"),
        "@file term list should match: {text}"
    );
}

#[test]
fn regex_flag_matches() {
    let (_d, profile) = profile_with_live_and_recovered();
    let out = br4n6()
        .args([
            "find",
            profile.to_str().unwrap(),
            "--regex",
            r"tracker\.evil\.com",
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
        "regex hit missing: {text}"
    );
}

#[test]
fn no_hits_prints_where_it_looked_and_what_it_skipped() {
    let (_d, profile) = profile_with_live_and_recovered();
    let out = br4n6()
        .args([
            "find",
            "no-such-domain-anywhere.example",
            profile.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(out.stdout.is_empty(), "no hits → empty stdout");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("no hits in"),
        "negative-result line: {stderr}"
    );
    assert!(
        stderr.contains("skipped"),
        "must name skipped sources: {stderr}"
    );
}

#[test]
fn dash_leading_term_via_double_dash() {
    let (_d, profile) = profile_with_live_and_recovered();
    // A term beginning with `-` is accepted after `--` (D3): must not error.
    br4n6()
        .args([
            "find",
            "--format",
            "jsonl",
            "--",
            "-evil.com",
            profile.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn dash_leading_term_via_term_flag() {
    let (_d, profile) = profile_with_live_and_recovered();
    br4n6()
        .args([
            "find",
            profile.to_str().unwrap(),
            "--term",
            "-evil.com",
            "--format",
            "jsonl",
        ])
        .assert()
        .success();
}

#[test]
fn carved_deleted_row_surfaces_and_is_never_live_or_visited() {
    let (_d, profile) = profile_with_deleted_row();
    let out = br4n6()
        .args([
            "find",
            "carved-only.example",
            profile.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let all = hits(&out);
    let carved: Vec<&Value> = all
        .iter()
        .filter(|h| prov(h, "source") == "Carved")
        .collect();
    assert!(
        !carved.is_empty(),
        "the deleted row should surface as a carved hit, got: {all:?}"
    );
    for h in &carved {
        assert_ne!(prov(h, "state"), "Live", "carved hit mislabelled live");
        assert_ne!(
            prov(h, "user_action_claim"),
            "Visited",
            "carved hit mislabelled as a confirmed visit"
        );
    }
}
