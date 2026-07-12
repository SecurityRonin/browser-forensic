//! Tier-1 oracle validation for the Milestone-4 Chromium coverage parsers
//! (Favicons, Top Sites, Shortcuts, Network Action Predictor, Media History,
//! Extension Cookies) against a **real** Chromium/Brave/Edge profile, using the
//! independent `sqlite3` CLI as the answer key.
//!
//! Env-gated and skips cleanly when the profile or `sqlite3` is absent (CI has
//! neither). Point it at a real profile directory:
//!
//! ```sh
//! BR4N6_REAL_PROFILE="$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default" \
//!   cargo test -p browser-forensic-chrome --test coverage_oracle -- --nocapture
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn have_tool(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Independent oracle: count rows via the `sqlite3` CLI over a WAL-honoring copy.
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

fn profile() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var("BR4N6_REAL_PROFILE").ok()?);
    p.is_dir().then_some(p)
}

/// Guard shared by every oracle test: `(profile, artifact_path)` or `None` to skip.
fn setup(artifact: &str) -> Option<(PathBuf, PathBuf)> {
    let profile = profile().or_else(|| {
        eprintln!("skip: BR4N6_REAL_PROFILE unset");
        None
    })?;
    if !have_tool("sqlite3") {
        eprintln!("skip: sqlite3 not available");
        return None;
    }
    let p = profile.join(artifact);
    if !p.is_file() {
        eprintln!("skip: no {artifact} in profile");
        return None;
    }
    Some((profile, p))
}

#[test]
fn favicons_count_matches_sqlite3_oracle() {
    let Some((_profile, favicons)) = setup("Favicons") else {
        return;
    };
    let parsed = browser_forensic_chrome::parse_favicons(&favicons).expect("parse Favicons");
    let oracle = sqlite_count(
        &favicons,
        "SELECT count(*) FROM icon_mapping im \
         JOIN favicons f ON im.icon_id = f.id \
         JOIN favicon_bitmaps fb ON fb.icon_id = f.id \
         WHERE im.page_url <> ''",
    )
    .expect("sqlite3 oracle");
    assert_eq!(
        parsed.len() as i64,
        oracle,
        "Favicons join count: parser {} vs sqlite3 {oracle}",
        parsed.len()
    );
    eprintln!("Favicons oracle matched: {oracle} bitmap mappings");
}

#[test]
fn top_sites_count_matches_sqlite3_oracle() {
    let Some((_profile, top_sites)) = setup("Top Sites") else {
        return;
    };
    let parsed = browser_forensic_chrome::parse_top_sites(&top_sites).expect("parse Top Sites");
    let oracle =
        sqlite_count(&top_sites, "SELECT count(*) FROM top_sites WHERE url <> ''").expect("oracle");
    assert_eq!(
        parsed.len() as i64,
        oracle,
        "Top Sites count: parser {} vs sqlite3 {oracle}",
        parsed.len()
    );
    eprintln!("Top Sites oracle matched: {oracle} sites");
}

#[test]
fn shortcuts_count_matches_sqlite3_oracle() {
    let Some((_profile, shortcuts)) = setup("Shortcuts") else {
        return;
    };
    let parsed = browser_forensic_chrome::parse_shortcuts(&shortcuts).expect("parse Shortcuts");
    let oracle = sqlite_count(
        &shortcuts,
        "SELECT count(*) FROM omni_box_shortcuts WHERE text <> ''",
    )
    .expect("oracle");
    assert_eq!(
        parsed.len() as i64,
        oracle,
        "Shortcuts count: parser {} vs sqlite3 {oracle}",
        parsed.len()
    );
    eprintln!("Shortcuts oracle matched: {oracle} typed shortcuts");
}
