//! History integrity checks across browser families.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::BrowserFamily;
    use browser_core::test_utils::sqlite::TestDb;
    use crate::IntegrityIndicator;

    fn chrome_history_schema() -> &'static str {
        "CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit_time INTEGER DEFAULT 0
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER DEFAULT 0,
            transition INTEGER DEFAULT 0
        );
        CREATE TABLE sqlite_sequence (name TEXT, seq INTEGER);"
    }

    #[test]
    fn chromium_history_clean_returns_empty() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO urls VALUES (2, 'https://b.com', 'B', 1, 13000000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (2, 2, 13000000001000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO sqlite_sequence VALUES ('urls', 2)", rusqlite::params![]);
        db.insert("INSERT INTO sqlite_sequence VALUES ('visits', 2)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        let clearing: Vec<_> = result.iter().filter(|i| matches!(i, IntegrityIndicator::HistoryCleared { .. })).collect();
        assert!(clearing.is_empty(), "clean db should have no clearing indicators");
    }

    #[test]
    fn chromium_history_clearing_detected_by_autoinc_gap() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO sqlite_sequence VALUES ('urls', 500)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::AutoIncrementGap { .. })),
            "should detect auto-increment gap indicating mass deletion");
    }

    #[test]
    fn chromium_visit_id_gap_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls VALUES (1, 'https://a.com', 'A', 2, 13000000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (50, 1, 13000000001000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })),
            "should detect visit ID gap from 1 to 50");
    }

    #[test]
    fn chromium_timestamp_non_monotonic_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO urls VALUES (2, 'https://b.com', 'B', 1, 12000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (1, 1, 13000000001000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (2, 2, 13000000000000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::TimestampNonMonotonic { .. })),
            "should detect non-monotonic timestamps in visits");
    }

    #[test]
    fn empty_history_with_nonzero_autoinc_is_clearing() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO sqlite_sequence VALUES ('urls', 100)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::HistoryCleared { .. })),
            "empty db with high auto-increment should indicate clearing");
    }
}
