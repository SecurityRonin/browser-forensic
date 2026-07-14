#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RFC 0001 Phase P5a — the `timeline` verb. The DEFAULT view is the FULL
//! cross-artifact chronology (history, cookies, downloads, cache, web-storage, …)
//! WITH each history event enriched in place by navigation-chain reconstruction
//! (referrer → page → redirect hops + inferred sessions) — so a download sits
//! next to the visit that led to it, and that visit carries its chain. `--flat`
//! shows the SAME breadth WITHOUT the chain enrichment (plain view + per-host
//! rollup, formerly the default `correlate`). `--graph <json|dot>` stays an
//! explicit opt-in alternate artifact. A multi-profile home reconstructs EACH
//! profile's chains independently (profile-local `from_visit` edges) and merges
//! them into the one time-sorted, origin-stamped stream (D9). Because each
//! profile's chains are self-contained, a `--user`/`--profile`/`--browser`
//! selector yields SCOPED chains for the selected profiles — never cross-profile
//! visits. Evidence with no per-visit referrer data (Safari, a visits-less
//! history) contributes its artifacts with no chain attrs rather than erroring.
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

/// A home with TWO Chromium profiles that each carry a DISTINCT referrer chain
/// (`*-origin.example` → `*-landing.example`, `from_visit = 1`). `from_visit`
/// edges are profile-local, so `timeline <home>` must reconstruct BOTH profiles'
/// chains, merge them time-sorted, and stamp each event with its own profile
/// origin — never mixing one profile's edge into the other.
fn two_profile_chain_home() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("Users").join("alice");
    let base = home.join("AppData/Local/Google/Chrome/User Data");

    for (sub, origin, landing) in [
        ("Default", "a-origin.example", "a-landing.example"),
        ("Profile 1", "b-origin.example", "b-landing.example"),
    ] {
        let profile = base.join(sub);
        std::fs::create_dir_all(&profile).unwrap();
        let conn = Connection::open(profile.join("History")).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
                 visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
                 from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
             INSERT INTO urls VALUES
                (1,'https://{origin}/','O',1,13327626000000000),
                (2,'https://{landing}/','L',1,13327626000000001);
             INSERT INTO visits (id,url,visit_time,from_visit,transition) VALUES
                (1,1,13327626000000000,0,1),
                (2,2,13327626000000001,1,1);"
        ))
        .unwrap();
    }
    (dir, home)
}

/// A MIXED home: a Chromium profile with a reconstructable referrer chain
/// (`cx-origin.example` → `cx-landing.example`) alongside a Safari `History.db`
/// (no per-visit `from_visit` table). The merged timeline must carry the
/// Chromium chain edges AND the Safari flat visits, origin-stamped, never
/// dropping the referrer-less profile.
fn chrome_chain_and_safari_flat_home() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("Users").join("bob");

    let chrome = home.join("Library/Application Support/Google/Chrome/Default");
    std::fs::create_dir_all(&chrome).unwrap();
    let conn = Connection::open(chrome.join("History")).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
             visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
             from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
         INSERT INTO urls VALUES
            (1,'https://cx-origin.example/','O',1,13327626000000000),
            (2,'https://cx-landing.example/','L',1,13327626000000001);
         INSERT INTO visits (id,url,visit_time,from_visit,transition) VALUES
            (1,1,13327626000000000,0,1),
            (2,2,13327626000000001,1,1);",
    )
    .unwrap();

    let safari = home.join("Library/Safari");
    std::fs::create_dir_all(&safari).unwrap();
    let sconn = Connection::open(safari.join("History.db")).unwrap();
    sconn
        .execute_batch(
            "CREATE TABLE history_items (
                id INTEGER PRIMARY KEY, url TEXT NOT NULL, visit_count INTEGER DEFAULT 0);
             CREATE TABLE history_visits (
                id INTEGER PRIMARY KEY, history_item INTEGER NOT NULL, visit_time REAL NOT NULL);
             INSERT INTO history_items (id,url,visit_count) VALUES
                (1,'https://sf-flat.example',1);
             INSERT INTO history_visits (id,history_item,visit_time) VALUES
                (1,1,700000000.0);",
        )
        .unwrap();

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

// ---- MULTI-PROFILE: each profile's chains reconstructed + merged (D9) ----

#[test]
fn timeline_multiprofile_home_reconstructs_each_profiles_chains() {
    // The closed gap: a multi-profile home reconstructs EACH profile's chains
    // (profile-local `from_visit` edges), merges them time-sorted, and stamps
    // every event with its profile origin — instead of degrading to a flat view.
    let (_d, home) = two_profile_chain_home();
    let out = br4n6()
        .args(["timeline", home.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "multi-profile timeline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // BOTH profiles' referrer edges are reconstructed (not just one).
    assert!(
        stdout.contains("referrer_url") && stdout.contains("https://a-origin.example/"),
        "profile Default's referrer edge must be reconstructed:\n{stdout}"
    );
    assert!(
        stdout.contains("https://b-origin.example/"),
        "profile 'Profile 1's referrer edge must be reconstructed:\n{stdout}"
    );
    // Each event is origin-stamped with its own profile (D9).
    assert!(
        stdout.contains("Chrome/Default") && stdout.contains("Chrome/Profile 1"),
        "each event must carry its profile origin (D9):\n{stdout}"
    );
    // The two landing events carry DIFFERENT profile origins — no cross-profile
    // mix. The chains JSONL hoists attrs to the top level (`url`/`profile`/…).
    let landing_profile = |host: &str| -> String {
        stdout
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|v| v["url"].as_str().is_some_and(|u| u.contains(host)))
            .and_then(|v| v["profile"].as_str().map(str::to_string))
            .unwrap_or_default()
    };
    let a = landing_profile("a-landing.example");
    let b = landing_profile("b-landing.example");
    assert_eq!(
        a, "Chrome/Default",
        "Default's landing must be stamped Default"
    );
    assert_eq!(
        b, "Chrome/Profile 1",
        "Profile 1's landing must be stamped Profile 1"
    );
    assert_ne!(a, b, "landing events must carry distinct profile origins");
}

#[test]
fn timeline_mixed_home_merges_chrome_chains_and_safari_flat() {
    // A Chrome-with-chains + Safari-flat home: the merged timeline carries the
    // Chromium chain edge AND the Safari flat visit, no error, no dropped profile.
    let (_d, home) = chrome_chain_and_safari_flat_home();
    let out = br4n6()
        .args(["timeline", home.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mixed home timeline must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Chromium chain edge present...
    assert!(
        stdout.contains("referrer_url") && stdout.contains("https://cx-origin.example/"),
        "the Chromium profile's chain edge must be reconstructed:\n{stdout}"
    );
    // ...and the referrer-less Safari profile's flat visit is merged in, not dropped.
    assert!(
        stdout.contains("sf-flat.example"),
        "the Safari flat visit must be merged in (never dropped):\n{stdout}"
    );
}

#[test]
fn timeline_flat_home_merges_without_chain_edges() {
    // `--flat` forces the merged plain chronology across all profiles: both
    // profiles' hosts appear, but NONE of the chain-reconstruction enrichment.
    let (_d, home) = two_profile_chain_home();
    let out = br4n6()
        .args([
            "timeline",
            home.to_str().unwrap(),
            "--flat",
            "--format",
            "jsonl",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "flat multi-profile timeline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("a-origin.example") && stdout.contains("b-origin.example"),
        "the flat chronology must list both profiles' hosts:\n{stdout}"
    );
    assert!(
        !stdout.contains("session_id")
            && !stdout.contains("referrer_url")
            && !stdout.contains("redirect_chain_id"),
        "--flat must NOT carry chain edges across the merged home:\n{stdout}"
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

// ---- selector scoping: SCOPED chains for the selected profile (P5a / D9) ----

#[test]
fn timeline_selector_gets_scoped_chains() {
    // Behavior change from P10: chains are profile-local, so a selector now
    // reconstructs SCOPED chains for the selected profile (not the flat fallback)
    // — the selected profile's data only, still origin-stamped, with the other
    // profile scoped OUT (no cross-profile contamination, D9).
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
    // Scoped CHAINS now: the selected profile's per-visit enrichment is present.
    assert!(
        stdout.contains("session_id"),
        "a selector now yields SCOPED chains (profile-local, D9):\n{stdout}"
    );
    // ...stamped with the selected profile's origin.
    assert!(
        stdout.contains("Chrome/Default"),
        "scoped chains must carry the profile origin (D9):\n{stdout}"
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

// ---- P12: the DEFAULT is the FULL cross-artifact breadth WITH chain-enriched
// history — not history-only. `--flat` is the SAME breadth, minus the chains. ----

/// A base Chromium `History` schema carrying `urls`/`visits` (referrer chain)
/// AND a `downloads` table, so one file exercises both history reconstruction
/// and the downloads artifact.
const HISTORY_WITH_DOWNLOADS_SCHEMA: &str =
    "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
         visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
     CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
         from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
     CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT NOT NULL DEFAULT '',
         start_time INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0,
         state INTEGER NOT NULL DEFAULT 0, danger_type INTEGER NOT NULL DEFAULT 0);
     CREATE TABLE downloads_url_chains (id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url TEXT NOT NULL);";

/// The Chromium `Cookies` jar schema (pre-CHIPS), matching what `parse_cookies`
/// reads.
const COOKIES_SCHEMA: &str = "CREATE TABLE cookies (
        creation_utc    INTEGER NOT NULL, host_key TEXT NOT NULL, name TEXT NOT NULL,
        value           TEXT DEFAULT '', path TEXT NOT NULL, expires_utc INTEGER DEFAULT 0,
        is_secure       INTEGER DEFAULT 0, is_httponly INTEGER DEFAULT 0,
        samesite        INTEGER DEFAULT -1, encrypted_value BLOB DEFAULT '');";

/// Write a Chromium `History` with a referrer chain (`<host_prefix>-origin` ->
/// `<host_prefix>-landing`, `from_visit = 1`) plus one download
/// (`<host_prefix>-dl.example`), and a sibling `Cookies` jar
/// (`<host_prefix>-cookie.example`), into `profile`.
fn write_chrome_profile_artifacts(profile: &std::path::Path, host_prefix: &str) {
    std::fs::create_dir_all(profile).unwrap();
    let conn = Connection::open(profile.join("History")).unwrap();
    conn.execute_batch(&format!(
        "{HISTORY_WITH_DOWNLOADS_SCHEMA}
         INSERT INTO urls VALUES
            (1,'https://{host_prefix}-origin.example/','Origin',1,13327626000000000),
            (2,'https://{host_prefix}-landing.example/','Landing',1,13327626000000001);
         INSERT INTO visits (id,url,visit_time,from_visit,transition) VALUES
            (1,1,13327626000000000,0,1),
            (2,2,13327626000000001,1,1);
         INSERT INTO downloads (id,target_path,start_time,total_bytes,state,danger_type) VALUES
            (1,'/home/u/Downloads/tool.exe',13327626000000002,1024,1,0);
         INSERT INTO downloads_url_chains (id,chain_index,url) VALUES
            (1,0,'https://{host_prefix}-dl.example/tool.exe');"
    ))
    .unwrap();
    let cconn = Connection::open(profile.join("Cookies")).unwrap();
    cconn
        .execute_batch(&format!(
            "{COOKIES_SCHEMA}
             INSERT INTO cookies (creation_utc,host_key,name,path,is_secure,is_httponly,samesite)
                VALUES (13327626000000000,'{host_prefix}-cookie.example','sid','/',1,1,0);"
        ))
        .unwrap();
}

/// A single Chromium profile dir carrying THREE artifact kinds: a `History` with
/// a referrer chain AND a downloads row, plus a sibling `Cookies` jar.
fn history_cookies_downloads_profile() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    write_chrome_profile_artifacts(&profile, "solo");
    (dir, profile)
}

/// A home with two Chromium profiles, each carrying a distinct referrer chain,
/// download, and cookie — so the merged default must show BOTH profiles' full
/// cross-artifact breadth, per-profile chain-enriched and origin-stamped.
fn two_profile_full_breadth_home() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("Users").join("alice");
    let base = home.join("AppData/Local/Google/Chrome/User Data");
    write_chrome_profile_artifacts(&base.join("Default"), "a");
    write_chrome_profile_artifacts(&base.join("Profile 1"), "b");
    (dir, home)
}

/// A Chromium profile whose `History` has `urls` but an EMPTY `visits` table
/// (nothing to reconstruct → chains degrade to `None`), yet still carries a
/// `Cookies` jar — proving the non-history breadth survives the degrade path.
fn visitsless_with_cookies_profile() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let conn = Connection::open(profile.join("History")).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
             visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
             from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
         INSERT INTO urls VALUES (1,'https://onlyurls.example/','OnlyUrls',1,13327626000000000);",
    )
    .unwrap();
    let cconn = Connection::open(profile.join("Cookies")).unwrap();
    cconn
        .execute_batch(
            "CREATE TABLE cookies (
                creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, name TEXT NOT NULL,
                value TEXT DEFAULT '', path TEXT NOT NULL, expires_utc INTEGER DEFAULT 0,
                is_secure INTEGER DEFAULT 0, is_httponly INTEGER DEFAULT 0,
                samesite INTEGER DEFAULT -1, encrypted_value BLOB DEFAULT '');
             INSERT INTO cookies (creation_utc,host_key,name,path,is_secure,is_httponly,samesite)
                VALUES (13327626000000000,'degraded-cookie.example','sid','/',1,1,0);",
        )
        .unwrap();
    (dir, profile)
}

#[test]
fn timeline_default_includes_cookies_downloads_and_chains() {
    // The regression: P10/P11 made the default history-only, silently dropping
    // cookies/downloads. The default must be the FULL cross-artifact breadth
    // (cookie + download events present) WITH the history chain enrichment.
    let (_d, profile) = history_cookies_downloads_profile();
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
    // Non-history artifacts are present in the DEFAULT (fails today: history-only).
    assert!(
        stdout.contains("\"Cookies\"") && stdout.contains("solo-cookie.example"),
        "default must carry the cookie event (full breadth):\n{stdout}"
    );
    assert!(
        stdout.contains("\"Downloads\"") && stdout.contains("solo-dl.example"),
        "default must carry the download event (full breadth):\n{stdout}"
    );
    // ...AND the history events carry the reconstructed chain edge in the SAME output.
    assert!(
        stdout.contains("referrer_url") && stdout.contains("https://solo-origin.example/"),
        "default must ALSO chain-enrich the history events:\n{stdout}"
    );
    assert!(
        stdout.contains("session_id"),
        "default history events must carry the inferred session_id:\n{stdout}"
    );
}

#[test]
fn timeline_flat_includes_cookies_and_downloads_no_chains() {
    // `--flat` is the SAME full breadth as the default, minus the chain edges:
    // the cookie + download events are still present, but no referrer/session/
    // redirect enrichment.
    let (_d, profile) = history_cookies_downloads_profile();
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
        "flat timeline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("solo-cookie.example"),
        "--flat must still carry the cookie event:\n{stdout}"
    );
    assert!(
        stdout.contains("solo-dl.example"),
        "--flat must still carry the download event:\n{stdout}"
    );
    assert!(
        !stdout.contains("session_id")
            && !stdout.contains("referrer_url")
            && !stdout.contains("redirect_chain_id"),
        "--flat must NOT carry chain edges:\n{stdout}"
    );
}

#[test]
fn timeline_multiprofile_includes_each_profiles_full_breadth() {
    // A multi-profile home: the default merges BOTH profiles' full cross-artifact
    // breadth (cookies + downloads + history), per-profile chain-enriched and
    // origin-stamped (P11 preserved).
    let (_d, home) = two_profile_full_breadth_home();
    let out = br4n6()
        .args(["timeline", home.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "multi-profile timeline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Both profiles' non-history artifacts are present.
    assert!(
        stdout.contains("a-cookie.example") && stdout.contains("b-cookie.example"),
        "both profiles' cookies must be present:\n{stdout}"
    );
    assert!(
        stdout.contains("a-dl.example") && stdout.contains("b-dl.example"),
        "both profiles' downloads must be present:\n{stdout}"
    );
    // Both profiles' chains are reconstructed and origin-stamped (P11).
    assert!(
        stdout.contains("https://a-origin.example/")
            && stdout.contains("https://b-origin.example/"),
        "both profiles' referrer edges must be reconstructed:\n{stdout}"
    );
    assert!(
        stdout.contains("Chrome/Default") && stdout.contains("Chrome/Profile 1"),
        "each event must carry its profile origin (D9):\n{stdout}"
    );
}

#[test]
fn timeline_degraded_home_still_shows_nonhistory_artifacts() {
    // A profile with no reconstructable chains (empty `visits`) still contributes
    // its full flat breadth: the cookie event must appear, with no chain attrs.
    let (_d, profile) = visitsless_with_cookies_profile();
    let out = br4n6()
        .args(["timeline", profile.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "degraded timeline must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("degraded-cookie.example"),
        "the cookie must survive the degrade-to-flat path:\n{stdout}"
    );
    assert!(
        stdout.contains("onlyurls.example"),
        "the flat history must still be present:\n{stdout}"
    );
    assert!(
        !stdout.contains("session_id"),
        "no visits means nothing to reconstruct:\n{stdout}"
    );
}

// ---- `--tz` must shift the DEFAULT view's human timestamps, exactly as it
// already does under `--flat`. The default renders through `emit_events`, which
// predated `--tz` wiring, so `timeline --tz <IANA>` silently showed UTC on the
// default view — a flag that did nothing. Fixture visit `alpha.example` is at
// Chrome µs 13327626000000000 == 2023-05-03T22:20:00Z (Unix ns
// 1683152400000000000); in America/New_York (EDT, UTC-4) that is
// 2023-05-03T18:20:00-04:00. ----

#[test]
fn timeline_default_tz_shifts_human_timestamp() {
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args([
            "timeline",
            profile.to_str().unwrap(),
            "--tz",
            "America/New_York",
            "--format",
            "text",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "default timeline --tz failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("2023-05-03T18:20:00-04:00"),
        "default view must render the visit in the requested zone (18:20 EDT), \
         not UTC:\n{stdout}"
    );
    assert!(
        !stdout.contains("2023-05-03T22:20:00+00:00"),
        "default view with --tz must NOT still show the UTC hour:\n{stdout}"
    );
}

#[test]
fn timeline_flat_tz_still_shifts_human_timestamp() {
    // Characterization: the `--flat` path already honored `--tz`; the fix must
    // not regress it — same zone => same rendered string as the default view.
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args([
            "timeline",
            profile.to_str().unwrap(),
            "--flat",
            "--tz",
            "America/New_York",
            "--format",
            "text",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "flat timeline --tz failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("2023-05-03T18:20:00-04:00"),
        "--flat must render the visit in the requested zone (18:20 EDT):\n{stdout}"
    );
}

#[test]
fn timeline_default_no_tz_stays_utc() {
    // Characterization: with no `--tz`, the default view keeps its current UTC
    // rendering unchanged.
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args(["timeline", profile.to_str().unwrap(), "--format", "text"])
        .output()
        .unwrap();
    assert!(out.status.success(), "default timeline failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("2023-05-03T22:20:00+00:00"),
        "no --tz must keep the UTC rendering:\n{stdout}"
    );
    assert!(
        !stdout.contains("-04:00"),
        "no --tz must not shift the zone:\n{stdout}"
    );
}

#[test]
fn timeline_default_tz_jsonl_keeps_numeric_ns_utc() {
    // Machine-faithful: `--tz` is DISPLAY-only. The numeric `timestamp_ns` stays
    // UTC (a consumer re-zones itself); only the human `timestamp` string shifts.
    let (_d, profile) = two_visit_profile();
    let out = br4n6()
        .args([
            "timeline",
            profile.to_str().unwrap(),
            "--tz",
            "America/New_York",
            "--format",
            "jsonl",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "default timeline --tz jsonl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"timestamp_ns\":1683152400000000000"),
        "numeric timestamp_ns must stay UTC-faithful regardless of --tz:\n{stdout}"
    );
    assert!(
        stdout.contains("2023-05-03T18:20:00-04:00"),
        "the human timestamp string must honor --tz:\n{stdout}"
    );
}
