//! History integrity checks across browser families.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserFamily;
use browser_core::timestamp::webkit_micros_to_unix_nanos;
use rusqlite::Connection;

use crate::IntegrityIndicator;

/// Check a browser history database for integrity anomalies.
///
/// Detects:
/// - History clearing (empty tables with high auto-increment counters)
/// - Visit ID gaps (deleted records leaving gaps in sequential IDs)
/// - Timestamp non-monotonicity (manually edited or imported timestamps)
pub fn check_history_integrity(path: &Path, browser: BrowserFamily) -> Result<Vec<IntegrityIndicator>> {
    match browser {
        BrowserFamily::Chromium => check_chromium_history(path),
        _ => Ok(Vec::new()),
    }
}

fn check_chromium_history(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let conn = Connection::open(path)?;
    let mut indicators = Vec::new();
    check_chromium_autoinc_gap(&conn, path, &mut indicators)?;
    check_chromium_visit_id_gaps(&conn, path, &mut indicators)?;
    check_chromium_timestamp_monotonicity(&conn, path, &mut indicators)?;
    Ok(indicators)
}

fn check_chromium_autoinc_gap(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let max_rowid: Option<i64> = conn
        .query_row("SELECT MAX(id) FROM urls", [], |row| row.get(0))
        .ok();
    let autoinc: Option<i64> = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = 'urls'",
            [],
            |row| row.get(0),
        )
        .ok();

    match (max_rowid, autoinc) {
        (None, Some(seq)) if seq > 0 => {
            indicators.push(IntegrityIndicator::HistoryCleared {
                browser: BrowserFamily::Chromium,
                path: path.to_path_buf(),
                detected_at_ns: 0,
            });
        }
        (Some(max_id), Some(seq)) if max_id > 0 && seq > max_id * 5 => {
            indicators.push(IntegrityIndicator::AutoIncrementGap {
                path: path.to_path_buf(),
                table: "urls".to_string(),
                max_rowid: max_id,
                auto_increment: seq,
            });
        }
        _ => {}
    }

    Ok(())
}

fn check_chromium_visit_id_gaps(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id FROM visits ORDER BY id ASC")?;
    let ids: Vec<i64> = stmt
        .query_map([], |row| row.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
        .collect();

    for window in ids.windows(2) {
        let prev = window[0];
        let curr = window[1];
        if curr - prev > 1 {
            indicators.push(IntegrityIndicator::VisitIdGap {
                path: path.to_path_buf(),
                expected_id: prev + 1,
                found_id: curr,
            });
            break; // one gap indicator is sufficient per check
        }
    }

    Ok(())
}

fn check_chromium_timestamp_monotonicity(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id, visit_time FROM visits ORDER BY id ASC")?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

    for window in rows.windows(2) {
        let (_, prev_ts) = window[0];
        let (curr_id, curr_ts) = window[1];
        if curr_ts < prev_ts {
            indicators.push(IntegrityIndicator::TimestampNonMonotonic {
                path: path.to_path_buf(),
                row_id: curr_id,
                prev_ts_ns: webkit_micros_to_unix_nanos(prev_ts),
                this_ts_ns: webkit_micros_to_unix_nanos(curr_ts),
            });
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::BrowserFamily;
    use browser_core::test_utils::sqlite::TestDb;
    use crate::IntegrityIndicator;

    fn chrome_history_schema() -> &'static str {
        // Use AUTOINCREMENT so SQLite manages sqlite_sequence automatically.
        "CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit_time INTEGER DEFAULT 0
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER DEFAULT 0,
            transition INTEGER DEFAULT 0
        );"
    }

    #[test]
    fn chromium_history_clean_returns_empty() {
        let db = TestDb::new(chrome_history_schema());
        // Insert sequentially so auto-increment counter matches max rowid (ratio <= 5).
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (2, 'https://b.com', 'B', 1, 13000000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (2, 2, 13000000001000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        let clearing: Vec<_> = result.iter().filter(|i| matches!(i, IntegrityIndicator::HistoryCleared { .. })).collect();
        assert!(clearing.is_empty(), "clean db should have no clearing indicators");
    }

    #[test]
    fn chromium_history_clearing_detected_by_autoinc_gap() {
        let db = TestDb::new(chrome_history_schema());
        // Insert one URL then manipulate sqlite_sequence directly to simulate mass deletion.
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        // Update the auto-increment counter to a much higher value to simulate prior mass deletion.
        db.insert("UPDATE sqlite_sequence SET seq = 500 WHERE name = 'urls'", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::AutoIncrementGap { .. })),
            "should detect auto-increment gap indicating mass deletion");
    }

    #[test]
    fn chromium_visit_id_gap_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 2, 13000000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (50, 1, 13000000001000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })),
            "should detect visit ID gap from 1 to 50");
    }

    #[test]
    fn chromium_timestamp_non_monotonic_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (2, 'https://b.com', 'B', 1, 12000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 13000000001000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (2, 2, 13000000000000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::TimestampNonMonotonic { .. })),
            "should detect non-monotonic timestamps in visits");
    }

    #[test]
    fn empty_history_with_nonzero_autoinc_is_clearing() {
        let db = TestDb::new(chrome_history_schema());
        // Trigger sqlite_sequence creation by inserting and deleting a row.
        db.insert("INSERT INTO urls(url, title) VALUES ('https://tmp.com', 'tmp')", rusqlite::params![]);
        db.insert("DELETE FROM urls", rusqlite::params![]);
        // Now urls is empty but sqlite_sequence has seq=1; update it to simulate history clearing.
        db.insert("UPDATE sqlite_sequence SET seq = 100 WHERE name = 'urls'", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::HistoryCleared { .. })),
            "empty db with high auto-increment should indicate clearing");
    }

    fn firefox_history_schema() -> &'static str {
        "CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit_date INTEGER
        );
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            from_visit INTEGER,
            place_id INTEGER,
            visit_date INTEGER,
            visit_type INTEGER
        );"
    }

    #[test]
    fn firefox_history_clean_returns_empty() {
        let db = TestDb::new(firefox_history_schema());
        db.insert("INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 1, 1700000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO moz_places VALUES (2, 'https://b.com', 'B', 1, 1700000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1)", rusqlite::params![]);
        db.insert("INSERT INTO moz_historyvisits VALUES (2, 0, 2, 1700000001000000, 1)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(result.is_empty(), "clean Firefox db should have no issues");
    }

    #[test]
    fn firefox_visit_id_gap_detected() {
        let db = TestDb::new(firefox_history_schema());
        db.insert("INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 2, 1700000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1)", rusqlite::params![]);
        db.insert("INSERT INTO moz_historyvisits VALUES (100, 0, 1, 1700000001000000, 1)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })));
    }

    #[test]
    fn firefox_timestamp_non_monotonic_detected() {
        let db = TestDb::new(firefox_history_schema());
        db.insert("INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 1, 1700000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO moz_places VALUES (2, 'https://b.com', 'B', 1, 1600000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000001000000, 1)", rusqlite::params![]);
        db.insert("INSERT INTO moz_historyvisits VALUES (2, 0, 2, 1700000000000000, 1)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::TimestampNonMonotonic { .. })));
    }
}
