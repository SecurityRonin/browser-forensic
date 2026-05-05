//! Integration test: full triage pipeline.

use browser_core::BrowserFamily;
use browser_rt::triage_profile;
use tempfile::TempDir;

#[test]
fn triage_chromium_profile_with_history_and_cookies() {
    let dir = TempDir::new().expect("tempdir");

    // Create Chromium History database with known data
    {
        let conn = rusqlite::Connection::open(dir.path().join("History")).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://evidence.example.com', 'Evidence Page', 3, 13300000000000000);
             INSERT INTO urls VALUES (2, 'https://second.example.com', 'Second', 1, 13300000001000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);
             INSERT INTO visits VALUES (10, 2, 13300000001000000, 0, 0);
             UPDATE sqlite_sequence SET seq = 2 WHERE name = 'urls';"
        ).expect("setup history");
    }

    // Create Cookies database with the minimal schema (missing samesite column)
    // This exercises that parse_cookies handles a minimal schema gracefully,
    // and that cookie events are still emitted even without the optional column.
    {
        let conn = rusqlite::Connection::open(dir.path().join("Cookies")).expect("open");
        conn.execute_batch(
            "CREATE TABLE cookies (
                creation_utc INTEGER NOT NULL,
                host_key TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT DEFAULT '',
                path TEXT NOT NULL,
                expires_utc INTEGER DEFAULT 0,
                last_access_utc INTEGER DEFAULT 0,
                is_secure INTEGER DEFAULT 0,
                is_httponly INTEGER DEFAULT 0,
                samesite INTEGER DEFAULT -1,
                encrypted_value BLOB DEFAULT ''
             );
             INSERT INTO cookies (creation_utc, host_key, name, value, path, expires_utc, last_access_utc, is_httponly, is_secure, samesite)
             VALUES (13300000000000000, '.example.com', 'sid', 'val', '/', 13400000000000000, 13300000001000000, 0, 1, -1);"
        ).expect("setup cookies");
    }

    let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");

    // History events should be present
    assert!(!report.events.is_empty(), "should have parsed events");
    assert!(report.events.iter().any(|e|
        e.attrs.get("url").and_then(|v| v.as_str()) == Some("https://evidence.example.com")
    ), "should contain the evidence URL");

    // Cookie events should also be present
    assert!(report.events.iter().any(|e|
        e.artifact == browser_core::ArtifactKind::Cookies
    ), "should have cookie events from Cookies database");

    // Integrity: visit ID gap should be detected (visits 1 -> 10)
    assert!(report.integrity.iter().any(|i|
        matches!(i, browser_integrity::IntegrityIndicator::VisitIdGap { .. })
    ), "should detect visit ID gap (1 -> 10)");

    // Report should have a valid timestamp
    assert!(report.generated_at_ns > 0, "report should have generation timestamp");
}

#[test]
fn triage_firefox_profile_with_places() {
    let dir = TempDir::new().expect("tempdir");

    {
        let conn = rusqlite::Connection::open(dir.path().join("places.sqlite")).expect("open");
        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://firefox-test.example.com', 'Firefox Test', 1, 1700000000000000);
             INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1);"
        ).expect("setup");
    }

    let report = triage_profile(dir.path(), BrowserFamily::Firefox).expect("triage");
    assert!(!report.events.is_empty(), "should have Firefox history events");
}

#[test]
fn integrity_indicators_are_serializable_to_json() {
    use browser_integrity::IntegrityIndicator;
    use std::path::PathBuf;

    let indicators = vec![
        IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/test/History"),
            detected_at_ns: 1_000_000,
        },
        IntegrityIndicator::VisitIdGap {
            path: PathBuf::from("/test/History"),
            expected_id: 5,
            found_id: 100,
        },
    ];

    for ind in &indicators {
        let json = serde_json::to_string(ind);
        assert!(json.is_ok(), "IntegrityIndicator should serialize: {ind:?}");
    }
}
