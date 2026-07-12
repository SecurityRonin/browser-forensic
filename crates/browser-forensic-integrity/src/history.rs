//! History integrity checks across browser families.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::{unix_micros_to_nanos, webkit_micros_to_unix_nanos};
use browser_forensic_core::BrowserFamily;
use rusqlite::Connection;

use crate::IntegrityIndicator;

/// The reference instant a recorded event cannot legitimately post-date: the
/// artifact's own last-modified time (a lower bound on acquisition). A visit
/// stamped after the file was last written is impossible, so this is an
/// oracle-free "future" reference. Falls back to the current wall clock if the
/// file's mtime is unreadable, so a genuine future timestamp is still caught.
fn acquisition_reference_ns(path: &Path) -> i64 {
    let from_mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_nanos()).ok());
    from_mtime.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_nanos()).ok())
            .unwrap_or(i64::MAX)
    })
}

/// Check a browser history database for integrity anomalies.
///
/// Detects:
/// - History clearing (empty tables with high auto-increment counters)
/// - Visit ID gaps (deleted records leaving gaps in sequential IDs)
/// - Timestamp non-monotonicity (manually edited or imported timestamps)
pub fn check_history_integrity(
    path: &Path,
    browser: BrowserFamily,
) -> Result<Vec<IntegrityIndicator>> {
    match browser {
        BrowserFamily::Chromium => check_chromium_history(path),
        BrowserFamily::Firefox => check_firefox_history(path),
        BrowserFamily::Safari => check_safari_history(path),
    }
}

fn check_safari_history(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut indicators = Vec::new();
    check_safari_tombstones(conn, path, &mut indicators)?;
    check_safari_visit_id_gaps(conn, path, &mut indicators)?;
    Ok(indicators)
}

fn check_safari_tombstones(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let table_exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='history_tombstones'",
        [],
        |row| row.get(0),
    )?;

    if !table_exists {
        return Ok(());
    }

    let mut stmt = conn.prepare("SELECT url FROM history_tombstones")?;
    let urls: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(std::result::Result::ok)
        .collect();

    for url in urls {
        indicators.push(IntegrityIndicator::HistoryTombstoneFound {
            path: path.to_path_buf(),
            url,
            deleted_at_ns: 0,
        });
    }
    Ok(())
}

fn check_safari_visit_id_gaps(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id FROM history_visits ORDER BY id ASC")?;
    let ids: Vec<i64> = stmt
        .query_map([], |row| row.get::<_, i64>(0))?
        .filter_map(std::result::Result::ok)
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
            break;
        }
    }
    Ok(())
}

fn check_firefox_history(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut indicators = Vec::new();
    check_firefox_visit_id_gaps(conn, path, &mut indicators)?;
    check_firefox_timestamp_monotonicity(conn, path, &mut indicators)?;
    check_firefox_future_timestamps(conn, path, &mut indicators)?;
    Ok(indicators)
}

/// Flag `moz_historyvisits` rows whose visit date is after the reference time.
fn check_firefox_future_timestamps(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let reference_ns = acquisition_reference_ns(path);
    let mut stmt =
        conn.prepare("SELECT id, visit_date FROM moz_historyvisits WHERE visit_date > 0")?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .filter_map(std::result::Result::ok)
        .collect();
    for (row_id, visit_date) in rows {
        let ts_ns = unix_micros_to_nanos(visit_date);
        if ts_ns > reference_ns {
            indicators.push(IntegrityIndicator::TimestampInFuture {
                path: path.to_path_buf(),
                table: "moz_historyvisits".to_string(),
                row_id,
                ts_ns,
                reference_ns,
            });
        }
    }
    Ok(())
}

fn check_firefox_visit_id_gaps(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id FROM moz_historyvisits ORDER BY id ASC")?;
    let ids: Vec<i64> = stmt
        .query_map([], |row| row.get::<_, i64>(0))?
        .filter_map(std::result::Result::ok)
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
            break;
        }
    }
    Ok(())
}

fn check_firefox_timestamp_monotonicity(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id, visit_date FROM moz_historyvisits ORDER BY id ASC")?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .filter_map(std::result::Result::ok)
        .collect();

    for window in rows.windows(2) {
        let (_, prev_ts) = window[0];
        let (curr_id, curr_ts) = window[1];
        if curr_ts < prev_ts {
            // Firefox visit_date is in microseconds since Unix epoch
            indicators.push(IntegrityIndicator::TimestampNonMonotonic {
                path: path.to_path_buf(),
                row_id: curr_id,
                prev_ts_ns: prev_ts * 1000,
                this_ts_ns: curr_ts * 1000,
            });
            break;
        }
    }
    Ok(())
}

fn check_chromium_history(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut indicators = Vec::new();
    check_chromium_autoinc_gap(conn, path, &mut indicators)?;
    check_chromium_visit_id_gaps(conn, path, &mut indicators)?;
    check_chromium_timestamp_monotonicity(conn, path, &mut indicators)?;
    check_chromium_visit_count_consistency(conn, path, &mut indicators)?;
    check_chromium_future_timestamps(conn, path, &mut indicators)?;
    check_chromium_last_visit_consistency(conn, path, &mut indicators)?;
    Ok(indicators)
}

/// Flag `visits` rows whose visit time is after the artifact reference time.
fn check_chromium_future_timestamps(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let reference_ns = acquisition_reference_ns(path);
    let mut stmt = conn.prepare("SELECT id, visit_time FROM visits WHERE visit_time > 0")?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .filter_map(std::result::Result::ok)
        .collect();
    for (row_id, visit_time) in rows {
        let ts_ns = webkit_micros_to_unix_nanos(visit_time);
        if ts_ns > reference_ns {
            indicators.push(IntegrityIndicator::TimestampInFuture {
                path: path.to_path_buf(),
                table: "visits".to_string(),
                row_id,
                ts_ns,
                reference_ns,
            });
        }
    }
    Ok(())
}

/// Flag `urls` rows whose recorded `last_visit_time` differs from the maximum
/// `visits.visit_time` referencing them.
fn check_chromium_last_visit_consistency(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT u.id, u.last_visit_time, MAX(v.visit_time) \
         FROM urls u JOIN visits v ON v.url = u.id \
         WHERE u.last_visit_time > 0 \
         GROUP BY u.id, u.last_visit_time \
         HAVING u.last_visit_time <> MAX(v.visit_time)",
    )?;
    let rows: Vec<(i64, i64, i64)> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .collect();
    for (url_id, last_visit, max_visit) in rows {
        indicators.push(IntegrityIndicator::LastVisitMismatch {
            path: path.to_path_buf(),
            url_id,
            recorded_last_visit_ns: webkit_micros_to_unix_nanos(last_visit),
            max_visit_ns: webkit_micros_to_unix_nanos(max_visit),
        });
    }
    Ok(())
}

/// Flag `urls` rows whose recorded `visit_count` exceeds the number of surviving
/// `visits` rows referencing them — consistent with individual visits deleted
/// while the summary row was kept. Only `recorded > actual` fires; the reverse is
/// normal because Chromium omits redirect/synthesized visits from `visit_count`.
fn check_chromium_visit_count_consistency(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT u.id, u.visit_count, COUNT(v.id) \
         FROM urls u LEFT JOIN visits v ON v.url = u.id \
         GROUP BY u.id, u.visit_count \
         HAVING u.visit_count > COUNT(v.id)",
    )?;
    let rows: Vec<(i64, i64, i64)> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .collect();

    for (url_id, recorded, actual) in rows {
        indicators.push(IntegrityIndicator::VisitCountMismatch {
            path: path.to_path_buf(),
            url_id,
            recorded_visit_count: recorded,
            actual_visit_rows: actual,
        });
    }
    Ok(())
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
        .filter_map(std::result::Result::ok)
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
        .filter_map(std::result::Result::ok)
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
    use crate::IntegrityIndicator;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use browser_forensic_core::BrowserFamily;

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
        let clearing: Vec<_> = result
            .iter()
            .filter(|i| matches!(i, IntegrityIndicator::HistoryCleared { .. }))
            .collect();
        assert!(
            clearing.is_empty(),
            "clean db should have no clearing indicators"
        );
    }

    #[test]
    fn chromium_history_clearing_detected_by_autoinc_gap() {
        let db = TestDb::new(chrome_history_schema());
        // Insert one URL then manipulate sqlite_sequence directly to simulate mass deletion.
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        // Update the auto-increment counter to a much higher value to simulate prior mass deletion.
        db.insert(
            "UPDATE sqlite_sequence SET seq = 500 WHERE name = 'urls'",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::AutoIncrementGap { .. })),
            "should detect auto-increment gap indicating mass deletion"
        );
    }

    #[test]
    fn chromium_visit_id_gap_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 2, 13000000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (50, 1, 13000000001000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })),
            "should detect visit ID gap from 1 to 50"
        );
    }

    #[test]
    fn chromium_timestamp_non_monotonic_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (2, 'https://b.com', 'B', 1, 12000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 13000000001000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (2, 2, 13000000000000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::TimestampNonMonotonic { .. })),
            "should detect non-monotonic timestamps in visits"
        );
    }

    #[test]
    fn empty_history_with_nonzero_autoinc_is_clearing() {
        let db = TestDb::new(chrome_history_schema());
        // Trigger sqlite_sequence creation by inserting and deleting a row.
        db.insert(
            "INSERT INTO urls(url, title) VALUES ('https://tmp.com', 'tmp')",
            rusqlite::params![],
        );
        db.insert("DELETE FROM urls", rusqlite::params![]);
        // Now urls is empty but sqlite_sequence has seq=1; update it to simulate history clearing.
        db.insert(
            "UPDATE sqlite_sequence SET seq = 100 WHERE name = 'urls'",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::HistoryCleared { .. })),
            "empty db with high auto-increment should indicate clearing"
        );
    }

    #[test]
    fn chromium_visit_count_exceeding_surviving_visits_detected() {
        let db = TestDb::new(chrome_history_schema());
        // url 1 claims 5 visits but only 2 visit rows survive → visits deleted
        // while the summary row was kept.
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 5, 13000000002000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (2, 1, 13000000001000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(
            result.iter().any(|i| matches!(
                i,
                IntegrityIndicator::VisitCountMismatch {
                    url_id: 1,
                    recorded_visit_count: 5,
                    actual_visit_rows: 2,
                    ..
                }
            )),
            "should detect visit_count (5) exceeding surviving visits rows (2), got {result:?}"
        );
    }

    #[test]
    fn chromium_visit_count_matching_or_below_does_not_fire() {
        let db = TestDb::new(chrome_history_schema());
        // Recorded count equals surviving rows; and a second url has MORE visit
        // rows than its count (normal: redirects/synthesized aren't counted).
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 2, 13000000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (2, 'https://b.com', 'B', 1, 13000000003000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (2, 1, 13000000001000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (3, 2, 13000000002000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (4, 2, 13000000003000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(
            !result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::VisitCountMismatch { .. })),
            "recorded<=actual must not fire, got {result:?}"
        );
    }

    #[test]
    fn chromium_future_visit_timestamp_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 1, 16000000000000000)", rusqlite::params![]);
        // Webkit micros ~1.6e16 -> ~year 2107, far past the file's mtime.
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 16000000000000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::TimestampInFuture { row_id: 1, .. })),
            "a visit dated ~2107 should be flagged as future relative to acquisition, got {result:?}"
        );
    }

    #[test]
    fn chromium_last_visit_time_mismatch_detected() {
        let db = TestDb::new(chrome_history_schema());
        // urls.last_visit_time claims a newer visit than any surviving visits row.
        db.insert("INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (1, 'https://a.com', 'A', 2, 13000000005000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES (2, 1, 13000000001000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::LastVisitMismatch { url_id: 1, .. })),
            "urls.last_visit_time != max(visits.visit_time) should fire, got {result:?}"
        );
    }

    #[test]
    fn firefox_future_visit_timestamp_detected() {
        let db = TestDb::new(firefox_history_schema());
        // Unix micros ~4.1e15 -> ~year 2100.
        db.insert(
            "INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 1, 4100000000000000)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_historyvisits VALUES (1, 0, 1, 4100000000000000, 1)",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::TimestampInFuture { .. })),
            "a Firefox visit dated ~2100 should be flagged as future, got {result:?}"
        );
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
        db.insert(
            "INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 1, 1700000000000000)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_places VALUES (2, 'https://b.com', 'B', 1, 1700000001000000)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_historyvisits VALUES (2, 0, 2, 1700000001000000, 1)",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(result.is_empty(), "clean Firefox db should have no issues");
    }

    #[test]
    fn firefox_visit_id_gap_detected() {
        let db = TestDb::new(firefox_history_schema());
        db.insert(
            "INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 2, 1700000001000000)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_historyvisits VALUES (100, 0, 1, 1700000001000000, 1)",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(result
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })));
    }

    #[test]
    fn firefox_timestamp_non_monotonic_detected() {
        let db = TestDb::new(firefox_history_schema());
        db.insert(
            "INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 1, 1700000000000000)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_places VALUES (2, 'https://b.com', 'B', 1, 1600000000000000)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000001000000, 1)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO moz_historyvisits VALUES (2, 0, 2, 1700000000000000, 1)",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(result
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::TimestampNonMonotonic { .. })));
    }

    fn safari_history_schema() -> &'static str {
        "CREATE TABLE history_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            domain_expansion TEXT,
            visit_count INTEGER NOT NULL DEFAULT 0,
            daily_visit_counts BLOB,
            weekly_visit_counts BLOB,
            autocomplete_triggers BLOB,
            should_recompute_derived_visit_counts INTEGER NOT NULL DEFAULT 1,
            visit_count_score INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE history_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_item INTEGER NOT NULL REFERENCES history_items(id) ON DELETE CASCADE,
            visit_time REAL NOT NULL,
            title TEXT,
            load_successful BOOLEAN NOT NULL DEFAULT 1,
            http_non_get INTEGER NOT NULL DEFAULT 0,
            synthesized INTEGER NOT NULL DEFAULT 0,
            redirect_source INTEGER,
            redirect_destination INTEGER,
            origin INTEGER NOT NULL DEFAULT 0,
            generation INTEGER NOT NULL DEFAULT 0,
            attributes INTEGER NOT NULL DEFAULT 0,
            score INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE history_tombstones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            generation INTEGER NOT NULL
        );"
    }

    #[test]
    fn safari_history_clean_returns_empty() {
        let db = TestDb::new(safari_history_schema());
        db.insert(
            "INSERT INTO history_items (id, url, visit_count) VALUES (1, 'https://a.com', 1)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO history_visits (id, history_item, visit_time) VALUES (1, 1, 700000000.0)",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Safari).expect("check");
        let tombstones: Vec<_> = result
            .iter()
            .filter(|i| matches!(i, IntegrityIndicator::HistoryTombstoneFound { .. }))
            .collect();
        assert!(tombstones.is_empty());
    }

    #[test]
    fn safari_tombstones_detected() {
        let db = TestDb::new(safari_history_schema());
        db.insert(
            "INSERT INTO history_tombstones (id, url, generation) VALUES (1, 'https://deleted.example.com', 5)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO history_tombstones (id, url, generation) VALUES (2, 'https://also-deleted.example.com', 5)",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Safari).expect("check");
        let tombstones: Vec<_> = result
            .iter()
            .filter(|i| matches!(i, IntegrityIndicator::HistoryTombstoneFound { .. }))
            .collect();
        assert_eq!(tombstones.len(), 2, "should detect 2 tombstoned URLs");
    }

    #[test]
    fn safari_visit_id_gap_detected() {
        let db = TestDb::new(safari_history_schema());
        db.insert(
            "INSERT INTO history_items (id, url, visit_count) VALUES (1, 'https://a.com', 2)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO history_visits (id, history_item, visit_time) VALUES (1, 1, 700000000.0)",
            rusqlite::params![],
        );
        db.insert(
            "INSERT INTO history_visits (id, history_item, visit_time) VALUES (50, 1, 700000001.0)",
            rusqlite::params![],
        );

        let result = check_history_integrity(db.path(), BrowserFamily::Safari).expect("check");
        assert!(result
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })));
    }
}
