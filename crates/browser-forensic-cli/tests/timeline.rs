#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RFC 0001 Phase P5a — the `timeline` verb. Navigation-chain reconstruction
//! (referrer → page → redirect hops + inferred sessions) is the DEFAULT view:
//! the navigation story IS the point of a timeline ("don't make them think").
//! `--flat` opts OUT to the plain chronological stream (the unified
//! cross-artifact chronology, formerly the default). `--graph <json|dot>` stays
//! an explicit opt-in alternate artifact. When a `--user`/`--profile`/`--browser`
//! selector is active, the run scopes to the selection and DROPS the path-wide
//! per-visit enrichment (D9) — chains-by-default must not reintroduce
//! cross-profile visits. Evidence with no per-visit referrer data (Safari, a
//! visits-less history) degrades to the flat chronology rather than erroring.
//! Driven end-to-end through the real `br4n6` binary.

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

/// A Chromium profile dir whose second visit links back to the first
/// (`from_visit = 1`), so referrer-chain reconstruction resolves a KNOWN
/// referrer edge: `landing.example` was reached FROM `origin.example`.
fn referrer_edge_profile() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let history = profile.join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
             visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
             from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
         INSERT INTO urls VALUES
            (1,'https://origin.example/','Origin',1,13327626000000000),
            (2,'https://landing.example/','Landing',1,13327626000000001);
         INSERT INTO visits (id,url,visit_time,from_visit,transition) VALUES
            (1,1,13327626000000000,0,1),
            (2,2,13327626000000001,1,1);",
    )
    .unwrap();
    (dir, profile)
}

/// A Safari `History.db` (no per-visit `from_visit` table). `timeline` cannot
/// reconstruct chains here; it must degrade to the flat chronology, never error.
/// Returns the temp dir + the `History.db` file path.
fn safari_history_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let safari = dir.path().join("Library").join("Safari");
    std::fs::create_dir_all(&safari).unwrap();
    let history = safari.join("History.db");
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

/// A Chromium `History` file with `urls` rows but an EMPTY `visits` table:
/// there is nothing to reconstruct, so the chain-enriched default must degrade
/// to the flat urls chronology rather than emit an empty chains view or error.
/// Returns the temp dir + the `History` file path.
fn visitsless_history_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let history = dir.path().join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
             visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
             from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
         INSERT INTO urls VALUES
            (1,'https://onlyurls.example/','OnlyUrls',1,13327626000000000);",
    )
    .unwrap();
    (dir, history)
}

/// A home with two Chromium profiles — `Chrome/Default` (`scoped.example`) and
/// `Chrome/Profile 1` (`other.example`) — so a `--profile Chrome/Default`
/// selector can be shown to scope to one profile and NOT pull the other's data.
fn two_profile_home() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("Users").join("alice");
    let base = home.join("AppData/Local/Google/Chrome/User Data");

    for (sub, host) in [
        ("Default", "scoped.example"),
        ("Profile 1", "other.example"),
    ] {
        let profile = base.join(sub);
        std::fs::create_dir_all(&profile).unwrap();
        let conn = Connection::open(profile.join("History")).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
                 visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
                 from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
             INSERT INTO urls VALUES (1,'https://{host}/','H',1,13327626000000000);
             INSERT INTO visits (id,url,visit_time,from_visit,transition) VALUES (1,1,13327626000000000,0,1);"
        ))
        .unwrap();
    }
    (dir, home)
}

// ---- DEFAULT: navigation-chain reconstruction (no flag) ----

#[test]
fn timeline_default_reconstructs_chains() {
    // The default view (no `--chains`, which is gone) is the referrer/redirect/
    // session-enriched reconstruction: a known referrer edge and the inferred
    // session_id must be present without asking for them.
    let (_d, profile) = referrer_edge_profile();
    let out = br4n6()
        .args(["timeline", profile.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "default timeline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("session_id"),
        "chains-by-default must carry the inferred session_id:\n{stdout}"
    );
    assert!(
        stdout.contains("referrer_url") && stdout.contains("https://origin.example/"),
        "chains-by-default must resolve the known referrer edge (landing FROM origin):\n{stdout}"
    );
}

// ---- --chains is GONE (clean break) ----

#[test]
fn timeline_chains_flag_is_removed() {
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args(["timeline", profile.to_str().unwrap(), "--chains"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "`--chains` must no longer be accepted (it is now the default)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("--chains"),
        "`--chains` did not error as an unknown flag: {stderr}"
    );
}

// ---- --flat opts OUT to the plain chronological stream ----

#[test]
fn timeline_flat_has_no_chain_edges() {
    let (_d, profile) = referrer_edge_profile();
    let out = br4n6()
        .args([
            "timeline",
            profile.to_str().unwrap(),
            "--flat",
            "--format",
            "jsonl",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "timeline --flat failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The flat stream still lists the events...
    assert!(
        stdout.contains("origin.example") && stdout.contains("landing.example"),
        "flat chronology must still list the hosts:\n{stdout}"
    );
    // ...but carries NONE of the chain-reconstruction enrichment.
    assert!(
        !stdout.contains("session_id")
            && !stdout.contains("referrer_url")
            && !stdout.contains("redirect_chain_id"),
        "--flat must NOT carry chain edges (session/referrer/redirect):\n{stdout}"
    );
}

// ---- --around narrows to a pivot moment (unchanged) ----

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

// ---- selector scoping: no cross-profile chain data (P5a / D9) ----

#[test]
fn timeline_selector_scopes_and_drops_cross_profile_chains() {
    let (_d, home) = two_profile_home();
    let out = br4n6()
        .args([
            "timeline",
            home.to_str().unwrap(),
            "--profile",
            "Chrome/Default",
            "--format",
            "jsonl",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scoped timeline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("scoped.example"),
        "the selected profile's host must be present:\n{stdout}"
    );
    assert!(
        !stdout.contains("other.example"),
        "the other profile must be scoped OUT (no cross-profile data):\n{stdout}"
    );
    assert!(
        !stdout.contains("session_id"),
        "a selector DROPS the path-wide per-visit enrichment (no chains):\n{stdout}"
    );
}

// ---- degrade gracefully on evidence with no referrer data ----

#[test]
fn timeline_safari_only_degrades_to_flat() {
    let (_d, history) = safari_history_file();
    let out = br4n6()
        .args(["timeline", history.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "Safari-only timeline must SUCCEED (degrade to flat), got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("sf-one.example") || stdout.contains("sf-two.example"),
        "the flat Safari chronology must list its hosts:\n{stdout}"
    );
    assert!(
        !stdout.contains("session_id"),
        "Safari has no per-visit data — nothing to reconstruct:\n{stdout}"
    );
}

#[test]
fn timeline_visitsless_history_degrades_to_flat() {
    let (_d, history) = visitsless_history_file();
    let out = br4n6()
        .args(["timeline", history.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a visits-less history must SUCCEED (degrade to flat), got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("onlyurls.example"),
        "the flat urls chronology must list the host:\n{stdout}"
    );
    assert!(
        !stdout.contains("session_id"),
        "no visits means nothing to reconstruct:\n{stdout}"
    );
}

// ---- --graph reaches the entity graph (json + dot) — UNCHANGED ----

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
