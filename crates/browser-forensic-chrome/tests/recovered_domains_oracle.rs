//! Tier-1 oracle validation for the recovered-domain parsers against a **real**
//! Chromium/Brave/Edge profile, using independent third-party tools (`sqlite3`,
//! `jq`) as the answer key.
//!
//! Env-gated and skips cleanly when the profile or a tool is absent (CI has
//! neither). Point it at a real profile directory:
//!
//! ```sh
//! BR4N6_REAL_PROFILE="$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default" \
//!   cargo test -p browser-forensic-chrome --test recovered_domains_oracle -- --nocapture
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve an artifact that may sit at the profile root or under `Network/`.
fn locate(profile: &Path, name: &str) -> Option<PathBuf> {
    for base in [profile.to_path_buf(), profile.join("Network")] {
        let p = base.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn have_tool(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Independent oracle: count rows via the `sqlite3` CLI. Copies the DB plus its
/// `-wal`/`-shm` sidecars to a temp dir and queries the copy so the WAL is
/// honored (matching the parser's WAL-safe open) and the evidence is untouched.
fn sqlite_count(db: &Path, sql: &str) -> Option<i64> {
    let dir = tempfile::tempdir().ok()?;
    let name = db.file_name()?;
    let copy = dir.path().join(name);
    std::fs::copy(db, &copy).ok()?;
    for suffix in ["-wal", "-shm"] {
        let mut side = db.as_os_str().to_os_string();
        side.push(suffix);
        let side = PathBuf::from(side);
        if side.exists() {
            let mut dst = copy.as_os_str().to_os_string();
            dst.push(suffix);
            std::fs::copy(&side, PathBuf::from(dst)).ok()?;
        }
    }
    let out = Command::new("sqlite3").arg(&copy).arg(sql).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Independent oracle: evaluate a `jq` numeric expression over a JSON file.
fn jq_number(file: &Path, expr: &str) -> Option<i64> {
    let out = Command::new("jq")
        .arg("-r")
        .arg(expr)
        .arg(file)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

fn profile() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var("BR4N6_REAL_PROFILE").ok()?);
    p.is_dir().then_some(p)
}

#[test]
fn dips_count_matches_sqlite3_oracle() {
    let Some(profile) = profile() else {
        eprintln!("skip: BR4N6_REAL_PROFILE unset");
        return;
    };
    if !have_tool("sqlite3") {
        eprintln!("skip: sqlite3 not available");
        return;
    }
    let Some(dips) = locate(&profile, "DIPS") else {
        eprintln!("skip: no DIPS in profile");
        return;
    };
    let parsed = browser_forensic_chrome::parse_dips(&dips).expect("parse DIPS");
    let oracle = sqlite_count(&dips, "SELECT count(*) FROM bounces WHERE site <> ''")
        .expect("sqlite3 oracle");
    assert_eq!(
        parsed.len() as i64,
        oracle,
        "DIPS bounces count: parser {} vs sqlite3 {oracle}",
        parsed.len()
    );
    eprintln!("DIPS oracle matched: {oracle} sites");
}

#[test]
fn nel_count_matches_sqlite3_oracle() {
    let Some(profile) = profile() else {
        eprintln!("skip: BR4N6_REAL_PROFILE unset");
        return;
    };
    if !have_tool("sqlite3") {
        eprintln!("skip: sqlite3 not available");
        return;
    }
    let Some(nel) = locate(&profile, "Reporting and NEL") else {
        eprintln!("skip: no Reporting and NEL in profile");
        return;
    };
    // The modern store is SQLite; skip the legacy-JSON case here.
    if sqlite_count(&nel, "SELECT 1").is_none() {
        eprintln!("skip: Reporting and NEL is not a SQLite store");
        return;
    }
    let parsed = browser_forensic_chrome::parse_reporting_and_nel(&nel).expect("parse NEL");
    let policies = sqlite_count(
        &nel,
        "SELECT count(*) FROM nel_policies WHERE origin_host <> ''",
    )
    .expect("policies oracle");
    let endpoints = sqlite_count(
        &nel,
        "SELECT count(*) FROM reporting_endpoints WHERE origin_host <> ''",
    )
    .expect("endpoints oracle");
    assert_eq!(
        parsed.len() as i64,
        policies + endpoints,
        "NEL count: parser {} vs sqlite3 {}",
        parsed.len(),
        policies + endpoints
    );
    eprintln!("NEL oracle matched: {policies} policies + {endpoints} endpoints");
}

#[test]
fn network_persistent_state_count_matches_jq_oracle() {
    let Some(profile) = profile() else {
        eprintln!("skip: BR4N6_REAL_PROFILE unset");
        return;
    };
    if !have_tool("jq") {
        eprintln!("skip: jq not available");
        return;
    }
    let Some(nps) = locate(&profile, "Network Persistent State") else {
        eprintln!("skip: no Network Persistent State in profile");
        return;
    };
    let parsed = browser_forensic_chrome::parse_network_persistent_state(&nps).expect("parse NPS");
    let oracle = jq_number(
        &nps,
        "([.net.http_server_properties.servers[]?|select(.server)]|length) + \
         ([.net.http_server_properties.broken_alternative_services[]?|select(.host)]|length)",
    )
    .expect("jq oracle");
    assert_eq!(
        parsed.len() as i64,
        oracle,
        "Network Persistent State count: parser {} vs jq {oracle}",
        parsed.len()
    );
    eprintln!("Network Persistent State oracle matched: {oracle} entries");
}

#[test]
fn transport_security_count_matches_jq_oracle() {
    let Some(profile) = profile() else {
        eprintln!("skip: BR4N6_REAL_PROFILE unset");
        return;
    };
    if !have_tool("jq") {
        eprintln!("skip: jq not available");
        return;
    }
    let Some(ts) = locate(&profile, "TransportSecurity") else {
        eprintln!("skip: no TransportSecurity in profile");
        return;
    };
    let parsed = browser_forensic_chrome::parse_transport_security(&ts).expect("parse TS");
    // Modern layout: count the `sts` array (hashed, non-enumerable).
    let oracle = jq_number(&ts, "(.sts // []) | length").expect("jq oracle");
    assert_eq!(
        parsed.len() as i64,
        oracle,
        "TransportSecurity count: parser {} vs jq {oracle}",
        parsed.len()
    );
    // Every recovered HSTS entry must be marked non-enumerable (never a domain).
    assert!(parsed
        .iter()
        .all(|e| e.attrs.get("enumerable") == Some(&serde_json::json!(false))));
    eprintln!("TransportSecurity oracle matched: {oracle} hashed entries");
}
