#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RFC 0001 Phase P1 — the `artifact <NAME> <PATH>` namespace and the clean
//! break that removes the old flat per-artifact command names.
//!
//! These drive the real `br4n6` binary end-to-end. The regression anchors
//! (`*_matches_legacy_*`) compare `artifact <name>` output against golden output
//! captured from the OLD flat command *before* it was removed, so the cut-over is
//! provably behavior-preserving. Routing-equivalence anchors (cookies / webcache
//! / cache) prove the new path reaches the same handler (identical error) as the
//! old flat command did.

use std::path::PathBuf;

use assert_cmd::Command;
use rusqlite::Connection;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// The 26 per-artifact primitives moved under `artifact` in P1.
const MOVED_PRIMITIVES: &[&str] = &[
    "history",
    "sessions",
    "cookies",
    "downloads",
    "bookmarks",
    "extensions",
    "logins",
    "autofill",
    "session",
    "cache",
    "cachestorage",
    "preferences",
    "permissions",
    "credentials",
    "storage",
    "webcache",
    "indexeddb",
    "favicons",
    "top-sites",
    "shortcuts",
    "network-action-predictor",
    "media-history",
    "extension-cookies",
    "typed-input",
    "annotations",
    "deleted-bookmarks",
];

/// Build a deterministic single-visit Chromium `History` DB and return its path.
fn create_chrome_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("Google").join("Chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let history = profile.join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
             visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
             from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
         INSERT INTO urls VALUES (1,'https://example.com/','Example',1,13327626000000000);
         INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (1,13327626000000000,0,1);",
    )
    .unwrap();
    (dir, history)
}

// ---- regression anchor: positive-parse equivalence (history) ----

/// Golden captured from the OLD `br4n6 history <fix>` (text) before removal.
const HISTORY_TEXT_GOLDEN: &str =
    "[2023-05-03T22:20:00+00:00] Chromium/History: Example  <https://example.com/>";

#[test]
fn artifact_history_matches_legacy_text_output() {
    let (_dir, history) = create_chrome_history();
    let out = br4n6()
        .args(["artifact", "history", history.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "artifact history failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim_end(), HISTORY_TEXT_GOLDEN);
}

// ---- routing-equivalence anchors (cookies / webcache / cache) ----

/// Replace the concrete fixture path with a stable placeholder so the golden is
/// machine-independent.
fn normalize(stderr: &[u8], path: &str) -> String {
    String::from_utf8_lossy(stderr).replace(path, "<PATH>")
}

#[test]
fn artifact_cookies_routes_like_legacy() {
    let path = "/nonexistent/Cookies";
    let out = br4n6()
        .args(["artifact", "cookies", path])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        normalize(&out.stderr, path).trim_end(),
        "br4n6: cannot determine browser from path: <PATH>"
    );
}

#[test]
fn artifact_cache_routes_like_legacy() {
    let path = "/nonexistent/Cache";
    let out = br4n6().args(["artifact", "cache", path]).output().unwrap();
    assert!(!out.status.success());
    assert_eq!(
        normalize(&out.stderr, path).trim_end(),
        "br4n6: cannot determine browser from path: <PATH>"
    );
}

#[test]
fn artifact_webcache_routes_like_legacy() {
    let path = "/nonexistent/WebCacheV01.dat";
    let out = br4n6()
        .args(["artifact", "webcache", path])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        normalize(&out.stderr, path).trim_end(),
        "br4n6: parsing WebCache from <PATH>: opening ESE WebCache database <PATH>: \
         io: No such file or directory (os error 2): No such file or directory (os error 2)"
    );
}

// ---- clean break: old flat names are gone ----

#[test]
fn legacy_flat_names_are_unknown_subcommands() {
    for name in [
        "history",
        "cookies",
        "login-data", // renamed to `logins`, removed as a flat name
        "predictor",  // renamed to `network-action-predictor`, removed as a flat name
        "top-sites",
        "webcache",
        "cachestorage",
        "typed-input",
    ] {
        let out = br4n6().args([name, "--help"]).output().unwrap();
        assert!(
            !out.status.success(),
            "flat `{name}` still resolves; clean break not applied"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("unrecognized subcommand") || stderr.contains("unexpected argument"),
            "flat `{name}` did not error as an unknown subcommand: {stderr}"
        );
    }
}

// ---- artifact --list ----

#[test]
fn artifact_list_names_all_moved_primitives() {
    let out = br4n6().args(["artifact", "--list"]).output().unwrap();
    assert!(
        out.status.success(),
        "artifact --list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in MOVED_PRIMITIVES {
        assert!(
            stdout.contains(name),
            "artifact --list missing `{name}`:\n{stdout}"
        );
    }
}

// ---- help surface ----

#[test]
fn top_level_help_hides_moved_primitives_and_shows_artifact() {
    let out = br4n6().arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Names unique to the moved set (not present in the about tagline) must be gone.
    for gone in [
        "cachestorage",
        "typed-input",
        "media-history",
        "predictor",
        "deleted-bookmarks",
    ] {
        assert!(
            !stdout.contains(gone),
            "top-level --help still lists moved primitive `{gone}`"
        );
    }
    assert!(
        stdout.contains("artifact"),
        "top-level --help lacks `artifact`"
    );
    // Kept verbs stay visible (`carve` was absorbed into `recover` in P5b).
    for kept in ["timeline", "triage", "recover", "reconstruct"] {
        assert!(stdout.contains(kept), "top-level --help lost verb `{kept}`");
    }
}

#[test]
fn artifact_help_shows_moved_primitives() {
    let out = br4n6().args(["artifact", "--help"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in ["history", "cachestorage", "typed-input", "logins"] {
        assert!(
            stdout.contains(name),
            "artifact --help missing subcommand `{name}`:\n{stdout}"
        );
    }
}

// ---- flag preservation + renames ----

#[test]
fn artifact_cookies_exposes_unified_keys_flag_and_drops_the_soup() {
    // RFC 0001 P6/D7 clean break: the per-platform decrypt flag soup is collapsed
    // into one `--keys <PATH>` (+ `--password-stdin`); the old flags are gone.
    let out = br4n6()
        .args(["artifact", "cookies", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in ["--keys", "--password-stdin"] {
        assert!(stdout.contains(flag), "artifact cookies missing `{flag}`");
    }
    for gone in [
        "--decrypt-win",
        "--decrypt-macos",
        "--local-state",
        "--dpapi-masterkey",
    ] {
        assert!(
            !stdout.contains(gone),
            "artifact cookies still exposes removed `{gone}`"
        );
    }
}

#[test]
fn artifact_logins_rename_resolves() {
    br4n6()
        .args(["artifact", "logins", "--help"])
        .assert()
        .success();
}

#[test]
fn artifact_network_action_predictor_rename_resolves() {
    br4n6()
        .args(["artifact", "network-action-predictor", "--help"])
        .assert()
        .success();
}
