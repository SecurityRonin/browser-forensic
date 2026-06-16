#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! `RapidTriage` orchestration for browser forensics.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use browser_forensic_carve::CarvedRecord;
use browser_forensic_core::{BrowserEvent, BrowserFamily};
use browser_forensic_discovery::DiscoveredProfile;
use browser_forensic_integrity::IntegrityIndicator;

/// Consolidated triage report combining all forensic data sources.
#[derive(Debug, Serialize)]
pub struct TriageReport {
    /// Browser events from history, cookies, downloads, etc.
    pub events: Vec<BrowserEvent>,
    /// Records recovered from carving (free pages, WAL, etc.).
    pub carved: Vec<CarvedRecord>,
    /// Integrity anomalies (clearing, tampering, corruption).
    pub integrity: Vec<IntegrityIndicator>,
    /// Discovered browser profiles.
    pub profiles: Vec<DiscoveredProfile>,
    /// Timestamp when this report was generated (Unix nanos).
    pub generated_at_ns: i64,
}

/// Triage a single browser profile directory.
pub fn triage_profile(profile_path: &Path, browser: BrowserFamily) -> Result<TriageReport> {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);

    let mut events = Vec::new();
    let mut integrity = Vec::new();
    let mut carved = Vec::new();

    match browser {
        BrowserFamily::Chromium => {
            triage_chromium_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
        BrowserFamily::Firefox => {
            triage_firefox_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
        BrowserFamily::Safari => {
            triage_safari_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
    }

    events.sort_by_key(|e| e.timestamp_ns);

    Ok(TriageReport {
        events,
        carved,
        integrity,
        profiles: Vec::new(),
        generated_at_ns: now_ns,
    })
}

/// Triage all discovered profiles under a home directory.
pub fn triage(home_dir: &Path) -> Result<TriageReport> {
    let profiles = browser_forensic_discovery::discover_profiles(home_dir);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);

    let mut all_events = Vec::new();
    let mut all_integrity = Vec::new();
    let mut all_carved = Vec::new();

    for profile in &profiles {
        let mut events = Vec::new();
        let mut integrity_vec = Vec::new();
        let mut carved_vec = Vec::new();

        match profile.browser {
            BrowserFamily::Chromium => {
                triage_chromium_profile(
                    &profile.path,
                    &mut events,
                    &mut integrity_vec,
                    &mut carved_vec,
                );
            }
            BrowserFamily::Firefox => {
                triage_firefox_profile(
                    &profile.path,
                    &mut events,
                    &mut integrity_vec,
                    &mut carved_vec,
                );
            }
            BrowserFamily::Safari => {
                triage_safari_profile(
                    &profile.path,
                    &mut events,
                    &mut integrity_vec,
                    &mut carved_vec,
                );
            }
        }

        all_events.extend(events);
        all_integrity.extend(integrity_vec);
        all_carved.extend(carved_vec);
    }

    all_events.sort_by_key(|e| e.timestamp_ns);

    Ok(TriageReport {
        events: all_events,
        carved: all_carved,
        integrity: all_integrity,
        profiles,
        generated_at_ns: now_ns,
    })
}

fn triage_chromium_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let history_path = path.join("History");
    if history_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_history(&history_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_history_integrity(
            &history_path,
            BrowserFamily::Chromium,
        ) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_database_integrity(&history_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_forensic_carve::carve_sqlite_free_pages(&history_path) {
            carved.extend(result.records);
        }
    }

    let cookies_path = path.join("Cookies");
    if cookies_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_cookies(&cookies_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_cookie_integrity(
            &cookies_path,
            BrowserFamily::Chromium,
        ) {
            integrity.append(&mut ind);
        }
    }

    let bookmarks_path = path.join("Bookmarks");
    if bookmarks_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_bookmarks(&bookmarks_path) {
            events.append(&mut evts);
        }
    }
}

fn triage_firefox_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let places_path = path.join("places.sqlite");
    if places_path.is_file() {
        if let Ok(mut evts) = browser_forensic_firefox::parse_history(&places_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_history_integrity(
            &places_path,
            BrowserFamily::Firefox,
        ) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_database_integrity(&places_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_forensic_carve::carve_sqlite_free_pages(&places_path) {
            carved.extend(result.records);
        }
    }

    let cookies_path = path.join("cookies.sqlite");
    if cookies_path.is_file() {
        if let Ok(mut evts) = browser_forensic_firefox::parse_cookies(&cookies_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_cookie_integrity(
            &cookies_path,
            BrowserFamily::Firefox,
        ) {
            integrity.append(&mut ind);
        }
    }
}

fn triage_safari_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let history_path = path.join("History.db");
    if history_path.is_file() {
        if let Ok(mut evts) = browser_forensic_safari::parse_history(&history_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_history_integrity(
            &history_path,
            BrowserFamily::Safari,
        ) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_database_integrity(&history_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_forensic_carve::carve_sqlite_free_pages(&history_path) {
            carved.extend(result.records);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::BrowserFamily;
    use tempfile::TempDir;

    #[test]
    fn triage_report_serializes() {
        let report = TriageReport {
            events: Vec::new(),
            carved: Vec::new(),
            integrity: Vec::new(),
            profiles: Vec::new(),
            generated_at_ns: 1_700_000_000_000_000_000,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("generated_at_ns"));
        assert!(json.contains("1700000000000000000"));
    }

    #[test]
    fn triage_profile_chrome_returns_report() {
        let dir = TempDir::new().expect("tempdir");
        let history = dir.path().join("History");

        let conn = rusqlite::Connection::open(&history).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
        ).expect("setup");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(
            !report.events.is_empty(),
            "should have parsed history events"
        );
        assert!(report.generated_at_ns > 0);
    }

    #[test]
    fn triage_profile_nonexistent_path_returns_empty_report() {
        let dir = TempDir::new().expect("tempdir");
        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(report.events.is_empty());
    }

    #[test]
    fn triage_report_has_all_fields() {
        let report = TriageReport {
            events: vec![],
            carved: vec![],
            integrity: vec![],
            profiles: vec![],
            generated_at_ns: 0,
        };
        let _ = report.events.len();
        let _ = report.carved.len();
        let _ = report.integrity.len();
        let _ = report.profiles.len();
        let _ = report.generated_at_ns;
    }
}
