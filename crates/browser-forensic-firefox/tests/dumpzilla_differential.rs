#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Differential oracle: browser-forensic's Firefox parsers vs the independent
//! third-party tool **dumpzilla** (<https://github.com/Busindre/dumpzilla>), on
//! a REAL Firefox profile, reconciling history / download / cookie counts.
//!
//! This is the consolidated Milestone-10 differential harness. dumpzilla is an
//! unrelated Python forensic tool that reads the same `places.sqlite` /
//! `cookies.sqlite`; agreement between two independently-authored parsers on the
//! same real artifacts is tier-1 validation. The two tools apply slightly
//! different WHERE-clauses (a documented *interpretation* difference, not a bug),
//! so each count reconciles against dumpzilla's total minus a precisely-defined
//! bridge quantity computed by the neutral `sqlite3` CLI:
//!
//! | Count | browser-forensic query | dumpzilla query | bridge (never in bf) |
//! |---|---|---|---|
//! | history | `moz_places WHERE last_visit_date IS NOT NULL` | all `moz_places` | places with `last_visit_date IS NULL` (never-visited: bookmark/redirect/download source URLs) |
//! | downloads | `moz_annos` where attr = `downloads/destinationFileURI` | `moz_annos` where `content LIKE 'file%'` | file-content annotations that are not `destinationFileURI` |
//! | cookies | `moz_cookies WHERE creationTime > 0` | all `moz_cookies` | cookies with `creationTime <= 0` |
//!
//! browser-forensic emits an event only for the forensically-meaningful subset;
//! `bf + bridge == dumpzilla_total` proves the two parsers partition the exact
//! same universe. Cookies additionally reconcile by exact equality on any
//! profile whose cookies all carry a positive creation time (the common case).
//!
//! Env-gated; skips cleanly unless a real profile, dumpzilla, and `sqlite3` are
//! all present. The originals are never touched: the profile's databases are
//! copied to a temp dir and both tools run against the copy (dumpzilla opens
//! SQLite read-write, so it must never see the evidence).
//!
//! ```sh
//! python3 -m venv /tmp/dz-venv && /tmp/dz-venv/bin/pip install lz4
//! git clone https://github.com/Busindre/dumpzilla /tmp/dumpzilla
//! BR4N6_FIREFOX_PROFILE="$HOME/Library/Application Support/Firefox/Profiles/<p>" \
//! BR4N6_DUMPZILLA=/tmp/dumpzilla/dumpzilla.py \
//! BR4N6_DUMPZILLA_PYTHON=/tmp/dz-venv/bin/python \
//!   cargo test -p browser-forensic-firefox --test dumpzilla_differential -- --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

fn have_tool(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Copy a database plus any WAL/SHM sidecars into `dst_dir` so both tools see an
/// identical, committed state and the original evidence is never touched.
fn copy_db(profile: &Path, dst_dir: &Path, name: &str) -> bool {
    let src = profile.join(name);
    if !src.is_file() {
        return false;
    }
    for suffix in ["", "-wal", "-shm"] {
        let s = profile.join(format!("{name}{suffix}"));
        if s.is_file() {
            std::fs::copy(&s, dst_dir.join(format!("{name}{suffix}"))).expect("copy db sidecar");
        }
    }
    true
}

/// Run dumpzilla for one section against `profile_dir` and return the integer on
/// the `Total <label>: N` summary line. `None` if dumpzilla cannot run (e.g. its
/// `lz4` dependency is missing) or the label is absent.
fn dumpzilla_total(
    python: &Path,
    script: &Path,
    profile_dir: &Path,
    flag: &str,
    label: &str,
) -> Option<u64> {
    let out = Command::new(python)
        .arg(script)
        .arg(profile_dir)
        .arg(flag)
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "dumpzilla {flag} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .last()
                .unwrap_or("")
        );
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The summary line is `Total <padded label>: N`. Match the label prefix and
    // take the integer after the final colon.
    let needle = format!("Total {label}");
    for line in stdout.lines() {
        let t = line.trim_start();
        if t.starts_with(&needle) {
            if let Some((_, n)) = t.rsplit_once(':') {
                if let Ok(v) = n.trim().parse::<u64>() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Independent bridge count via the neutral `sqlite3` CLI over a read-only,
/// immutable handle (never a rusqlite handle — keep the bridge off browser-
/// forensic's own engine).
fn sqlite3_count(db: &Path, sql: &str) -> u64 {
    let uri = format!("file:{}?immutable=1", db.display());
    let out = Command::new("sqlite3")
        .arg(&uri)
        .arg(sql)
        .output()
        .expect("sqlite3 oracle");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("sqlite3 count")
}

#[test]
fn firefox_counts_reconcile_with_dumpzilla() {
    let Some(profile) = env_path("BR4N6_FIREFOX_PROFILE") else {
        eprintln!("skipping: BR4N6_FIREFOX_PROFILE not set");
        return;
    };
    let Some(script) = env_path("BR4N6_DUMPZILLA") else {
        eprintln!("skipping: BR4N6_DUMPZILLA (path to dumpzilla.py) not set");
        return;
    };
    if !script.is_file() {
        eprintln!("skipping: dumpzilla.py not found at {}", script.display());
        return;
    }
    if !have_tool("sqlite3") {
        eprintln!("skipping: sqlite3 CLI not available (needed for the bridge counts)");
        return;
    }
    let python = env_path("BR4N6_DUMPZILLA_PYTHON").unwrap_or_else(|| PathBuf::from("python3"));

    // Work on a copy: dumpzilla opens SQLite read-write, so the evidence must
    // never be the file it touches.
    let work = tempfile::tempdir().expect("tempdir");
    let have_places = copy_db(&profile, work.path(), "places.sqlite");
    let have_cookies = copy_db(&profile, work.path(), "cookies.sqlite");
    if !have_places {
        eprintln!("skipping: no places.sqlite in {}", profile.display());
        return;
    }
    let places = work.path().join("places.sqlite");
    let cookies = work.path().join("cookies.sqlite");

    // Probe dumpzilla runnability once (its top-level `import lz4.block` fails on
    // a bare interpreter); a broken toolchain is a skip, not a test failure.
    let Some(dz_history) = dumpzilla_total(&python, &script, work.path(), "--History", "History")
    else {
        eprintln!("skipping: dumpzilla could not run (missing lz4? wrong interpreter?)");
        return;
    };

    // --- History -----------------------------------------------------------
    let bf_history = browser_forensic_firefox::parse_history(&places)
        .expect("parse_history on real places.sqlite")
        .len() as u64;
    let history_bridge = sqlite3_count(
        &places,
        "SELECT count(*) FROM moz_places WHERE last_visit_date IS NULL",
    );
    eprintln!("history:   browser-forensic={bf_history}  dumpzilla={dz_history}  never-visited-bridge={history_bridge}");
    assert!(
        bf_history <= dz_history,
        "browser-forensic history ({bf_history}) must be a subset of dumpzilla's all-places count ({dz_history})"
    );
    assert_eq!(
        bf_history + history_bridge,
        dz_history,
        "history must reconcile: visited places + never-visited bridge == dumpzilla total"
    );

    // --- Downloads ---------------------------------------------------------
    let dz_downloads = dumpzilla_total(
        &python,
        &script,
        work.path(),
        "--Downloads",
        "Downloads history",
    )
    .expect("dumpzilla --Downloads must report a 'Downloads history' total");
    let bf_downloads = browser_forensic_firefox::parse_downloads(&places)
        .expect("parse_downloads on real places.sqlite")
        .len() as u64;
    let downloads_bridge = sqlite3_count(
        &places,
        "SELECT count(*) FROM moz_annos a \
         JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id \
         WHERE a.content LIKE 'file%' AND attr.name != 'downloads/destinationFileURI'",
    );
    eprintln!("downloads: browser-forensic={bf_downloads}  dumpzilla={dz_downloads}  non-destination-file-bridge={downloads_bridge}");
    assert!(
        bf_downloads <= dz_downloads,
        "browser-forensic downloads ({bf_downloads}) must be a subset of dumpzilla's file-content annotations ({dz_downloads})"
    );
    assert_eq!(
        bf_downloads + downloads_bridge,
        dz_downloads,
        "downloads must reconcile: destinationFileURI annotations + non-destination file-content bridge == dumpzilla total"
    );

    // --- Cookies -----------------------------------------------------------
    if have_cookies {
        let dz_cookies = dumpzilla_total(&python, &script, work.path(), "--Cookies", "Cookies")
            .expect("dumpzilla --Cookies must report a total");
        let bf_cookies = browser_forensic_firefox::parse_cookies(&cookies)
            .expect("parse_cookies on real cookies.sqlite")
            .len() as u64;
        let cookies_bridge = sqlite3_count(
            &cookies,
            "SELECT count(*) FROM moz_cookies WHERE creationTime <= 0",
        );
        eprintln!("cookies:   browser-forensic={bf_cookies}  dumpzilla={dz_cookies}  nonpositive-ctime-bridge={cookies_bridge}");
        assert!(
            bf_cookies <= dz_cookies,
            "browser-forensic cookies ({bf_cookies}) must be a subset of dumpzilla's all-cookies count ({dz_cookies})"
        );
        assert_eq!(
            bf_cookies + cookies_bridge,
            dz_cookies,
            "cookies must reconcile: positive-ctime cookies + nonpositive-ctime bridge == dumpzilla total"
        );
    } else {
        eprintln!("cookies:   no cookies.sqlite in profile — skipping the cookie reconciliation");
    }
}
