#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for `br4n6` RFC 0001 Phase P7 / D9 — multi-user /
//! multi-profile selectors. `--user` / `--profile` / `--browser` SCOPE a run;
//! every emitted finding is stamped with its origin (user/profile/browser); a
//! selector that matches nothing errors LOUDLY, naming what WAS found (never a
//! silent empty result).

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A home under `Users/alice` carrying a Chrome `Default` (with an executable
/// download → a finding) and a Firefox `default-release` profile.
fn two_profile_home() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("Users").join("alice");

    let chrome = home.join("AppData/Local/Google/Chrome/User Data/Default");
    std::fs::create_dir_all(&chrome).unwrap();
    let conn = Connection::open(chrome.join("History")).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1,'https://example.com','Example',1,13327626000000000);
         INSERT INTO visits VALUES (1,1,13327626000000000,0,0);
         CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT NOT NULL DEFAULT '', start_time INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0, state INTEGER NOT NULL DEFAULT 0, danger_type INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE downloads_url_chains (id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url TEXT NOT NULL);
         INSERT INTO downloads (id,target_path,start_time,total_bytes,state,danger_type) VALUES (1,'/Users/alice/Downloads/evil.exe',13327626000000000,1024,1,0);
         INSERT INTO downloads_url_chains (id,chain_index,url) VALUES (1,0,'https://evil.example/evil.exe');",
    )
    .unwrap();
    drop(conn);

    let ff = home.join("AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release");
    std::fs::create_dir_all(&ff).unwrap();
    let conn = Connection::open(ff.join("places.sqlite")).unwrap();
    conn.execute_batch(
        "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
         CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
         INSERT INTO moz_places VALUES (1,'https://example.org','Example',1,1700000000000000);",
    )
    .unwrap();
    drop(conn);

    (dir, home)
}

fn jsonl_lines(args: &[&str]) -> Vec<String> {
    let out = br4n6().args(args).assert().success();
    String::from_utf8(out.get_output().stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_string)
        .filter(|l| l.starts_with('{'))
        .collect()
}

#[test]
fn profile_selector_scopes_and_stamps_origin() {
    let (_dir, home) = two_profile_home();
    let lines = jsonl_lines(&[
        "investigate",
        home.to_str().unwrap(),
        "--profile",
        "Chrome/Default",
        "--format",
        "jsonl",
    ]);
    assert!(!lines.is_empty(), "the Chrome profile produced a finding");
    for l in &lines {
        assert!(
            l.contains("\"profile\":\"Chrome/Default\""),
            "every finding is stamped with the scoped profile: {l}"
        );
        assert!(
            !l.contains("Firefox"),
            "the Firefox profile is scoped OUT: {l}"
        );
    }
}

#[test]
fn nonmatching_profile_errors_naming_what_is_present() {
    let (_dir, home) = two_profile_home();
    let assert = br4n6()
        .args([
            "investigate",
            home.to_str().unwrap(),
            "--profile",
            "Chrome/DoesNotExist",
        ])
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(err.contains("not found"), "loud non-match error: {err}");
    assert!(
        err.contains("Chrome/Default") && err.contains("default-release"),
        "names the profiles that WERE present: {err}"
    );
}

#[test]
fn nonmatching_browser_errors_naming_present_browsers() {
    let (_dir, home) = two_profile_home();
    let assert = br4n6()
        .args(["investigate", home.to_str().unwrap(), "--browser", "safari"])
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(err.contains("not found"), "loud non-match error: {err}");
    assert!(
        err.to_lowercase().contains("chromium") && err.to_lowercase().contains("firefox"),
        "names the browsers that WERE present: {err}"
    );
}

#[test]
fn user_selector_matches_and_rejects() {
    let (_dir, home) = two_profile_home();
    // A matching user scopes and succeeds.
    br4n6()
        .args([
            "investigate",
            home.to_str().unwrap(),
            "--user",
            "alice",
            "--format",
            "jsonl",
        ])
        .assert()
        .success();
    // A non-matching user errors, naming the user that was present.
    let assert = br4n6()
        .args(["investigate", home.to_str().unwrap(), "--user", "bob"])
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        err.contains("not found") && err.contains("alice"),
        "non-matching user names the present user: {err}"
    );
}

#[test]
fn findings_carry_full_origin_without_a_selector() {
    let (_dir, home) = two_profile_home();
    let lines = jsonl_lines(&["investigate", home.to_str().unwrap(), "--format", "jsonl"]);
    let chrome_finding = lines
        .iter()
        .find(|l| l.contains("Chrome/Default"))
        .expect("a Chrome finding is present");
    assert!(
        chrome_finding.contains("\"user\":\"alice\""),
        "{chrome_finding}"
    );
    assert!(
        chrome_finding.contains("\"browser\":\"Chromium\""),
        "{chrome_finding}"
    );
}

#[test]
fn find_honors_selector_nonmatch() {
    let (_dir, home) = two_profile_home();
    let assert = br4n6()
        .args([
            "find",
            "example",
            home.to_str().unwrap(),
            "--browser",
            "safari",
        ])
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        err.contains("not found"),
        "find scopes by selector and errors loudly on a non-match: {err}"
    );
}
