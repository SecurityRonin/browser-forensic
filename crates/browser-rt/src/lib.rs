#![deny(clippy::unwrap_used)]
//! RapidTriage orchestration for browser forensics.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::BrowserFamily;
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
        assert!(!report.events.is_empty(), "should have parsed history events");
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
