#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for `br4n6` RFC 0001 Phase P7 / D3 — the guarded bare-path
//! convenience. `br4n6 <PATH>` (no subcommand) runs `investigate <PATH>`, but
//! ONLY when the single token is an existing on-disk path AND is not an exact
//! command name. A token that is both a command and a path fails with a specific
//! ambiguity diagnostic; a token that is neither gets clap's unknown-subcommand
//! error. `--` forces path interpretation for awkward names.

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::Path;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chrome profile dir (so bare-path `investigate` has something to chew on).
fn chrome_profile(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    let conn = Connection::open(root.join("History")).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER NOT NULL DEFAULT 0);
         INSERT INTO urls VALUES (1,'https://example.com',1,13327626000000000);",
    )
    .unwrap();
    drop(conn);
}

/// Every real verb: a path named after one of these that exists is ambiguous.
const VERB_COMMANDS: &[&str] = &[
    "investigate",
    "find",
    "timeline",
    "reconstruct",
    "recover",
    "report",
    "artifact",
    "tui",
    "schema",
];

#[test]
fn bare_existing_path_runs_investigate() {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("Default");
    chrome_profile(&profile);
    let out = br4n6().arg(profile.to_str().unwrap()).assert().success();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.get_output().stdout),
        String::from_utf8_lossy(&out.get_output().stderr)
    );
    // The standard-tier skipped-work footer is investigate's fingerprint.
    assert!(
        combined.contains("investigate --deep"),
        "bare path ran investigate (standard tier footer present): {combined}"
    );
}

#[test]
fn token_that_is_both_command_and_path_is_ambiguous() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("find"), b"x").unwrap();
    let assert = br4n6()
        .current_dir(dir.path())
        .arg("find")
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        err.contains("Ambiguous:") && err.contains("both a br4n6 command and a path"),
        "specific ambiguity diagnostic: {err}"
    );
    assert!(
        err.contains("investigate ./find"),
        "diagnostic shows the disambiguated investigate form: {err}"
    );
}

#[test]
fn every_verb_named_path_is_ambiguous() {
    for verb in VERB_COMMANDS {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(verb), b"x").unwrap();
        let assert = br4n6().current_dir(dir.path()).arg(verb).assert().failure();
        let err = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
        assert!(
            err.contains("Ambiguous:"),
            "path named after verb `{verb}` is ambiguous: {err}"
        );
    }
}

#[test]
fn ls_named_path_is_not_a_command_so_runs_investigate() {
    // `ls` is not a br4n6 command, so a path named `ls` is unambiguous → investigate.
    let dir = TempDir::new().unwrap();
    let ls = dir.path().join("ls");
    std::fs::create_dir_all(&ls).unwrap();
    br4n6().current_dir(dir.path()).arg("ls").assert().success();
}

#[test]
fn nonexistent_token_is_a_normal_unknown_subcommand_error() {
    let assert = br4n6()
        .arg("definitely_not_a_path_or_cmd_zzz")
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        err.contains("unrecognized subcommand") || err.contains("unexpected argument"),
        "clap's normal unknown-subcommand error: {err}"
    );
    assert!(
        !err.contains("Ambiguous:"),
        "a nonexistent token is not ambiguous: {err}"
    );
}

#[test]
fn dashdash_forces_path_interpretation_for_a_dash_leading_name() {
    let dir = TempDir::new().unwrap();
    let weird = dir.path().join("-weird-named-path");
    std::fs::create_dir_all(&weird).unwrap();
    // Without `--`, `-weird-named-path` looks like a flag; `--` forces path.
    br4n6()
        .current_dir(dir.path())
        .args(["--", "-weird-named-path"])
        .assert()
        .success();
}

#[test]
fn known_argless_subcommand_still_works() {
    // `schema` is a command and (normally) not an existing path → clap runs it.
    br4n6().arg("schema").assert().success();
}
