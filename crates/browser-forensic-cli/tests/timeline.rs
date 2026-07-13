#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RFC 0001 Phase P5a — the `timeline` verb absorbs the former standalone
//! `correlate` (unified cross-artifact chronology), `chains` (referrer/redirect/
//! session reconstruction, via `--chains`), and `graph` (entity graph, via
//! `--graph <json|dot>`) commands, plus a `--around`/`--window` pivot. The three
//! old top-level commands are removed (clean break, D11). Driven end-to-end
//! through the real `br4n6` binary.

use std::path::PathBuf;

use assert_cmd::Command;
use rusqlite::Connection;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chromium profile dir with a two-visit `History` (`urls` + `visits`), one
/// visit in 2023 (`alpha.example`) and one far earlier in 2016 (`beta.example`),
/// so `--around` can be shown to narrow the chronology. Returns the profile dir.
fn two_visit_profile() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let history = profile.join("History");
    let conn = Connection::open(&history).unwrap();
    // 13327626000000000 (Chrome epoch µs) => 2023-05-03T22:20:00Z.
    // 13100000000000000                    => 2016-02-15 (far earlier).
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
             visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
             from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
         INSERT INTO urls VALUES
            (1,'https://alpha.example/','Alpha',1,13327626000000000),
            (2,'https://beta.example/','Beta',1,13100000000000000);
         INSERT INTO visits (url,visit_time,from_visit,transition) VALUES
            (1,13327626000000000,0,1),
            (2,13100000000000000,0,1);",
    )
    .unwrap();
    (dir, profile)
}

// ---- default: the unified cross-artifact chronology (was `correlate`) ----

#[test]
fn timeline_default_is_unified_chronology() {
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args(["timeline", profile.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "timeline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("alpha.example") && stdout.contains("beta.example"),
        "unified chronology must list both hosts:\n{stdout}"
    );
}

// ---- --around narrows to a pivot moment ----

#[test]
fn timeline_around_narrows_to_the_pivot_window() {
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args([
            "timeline",
            profile.to_str().unwrap(),
            "--around",
            "2023-05-03",
            "--window",
            "2d",
            "--format",
            "text",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "timeline --around failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("alpha.example"),
        "the 2023 event must be inside the window:\n{stdout}"
    );
    assert!(
        !stdout.contains("beta.example"),
        "the 2016 event must be outside the window:\n{stdout}"
    );
}

// ---- --chains reaches the referrer/redirect/session reconstruction ----

#[test]
fn timeline_chains_reconstruction_reachable() {
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args([
            "timeline",
            profile.to_str().unwrap(),
            "--chains",
            "--format",
            "jsonl",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "timeline --chains failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("session_id"),
        "chains reconstruction must carry the inferred session_id:\n{stdout}"
    );
}

// ---- --graph reaches the entity graph (json + dot) ----

#[test]
fn timeline_graph_json_reachable() {
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args(["timeline", profile.to_str().unwrap(), "--graph", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("graph json");
    assert!(
        v["nodes"].is_array() && v["edges"].is_array(),
        "graph shape"
    );
    assert!(
        stdout.contains("alpha.example"),
        "host node present:\n{stdout}"
    );
}

#[test]
fn timeline_graph_dot_reachable() {
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args(["timeline", profile.to_str().unwrap(), "--graph", "dot"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("digraph browser_entity_graph {"),
        "DOT digraph header:\n{stdout}"
    );
}

// ---- clean break: the old standalone commands are gone ----

#[test]
fn removed_chronology_commands_are_unknown_subcommands() {
    for name in ["chains", "correlate", "graph"] {
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
