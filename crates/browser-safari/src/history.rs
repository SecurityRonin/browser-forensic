//! Safari `History.db` parser.
//!
//! Reads the `history_visits` and `history_items` tables from Safari's
//! `History.db` SQLite database and emits [`BrowserEvent`]s with
//! [`ArtifactKind::History`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Core Data epoch offset in seconds (2001-01-01 to 1970-01-01).
pub const CORE_DATA_EPOCH_OFFSET_SECS: f64 = 978_307_200.0;

/// Convert a Core Data timestamp (seconds since 2001-01-01) to Unix nanoseconds.
#[must_use]
pub fn safari_to_unix_ns(core_data_secs: f64) -> i64 {
    todo!("not yet implemented")
}

/// Parse a Safari `History.db` SQLite file.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_history(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn create_safari_history_db(rows: &[(&str, i64, f64)]) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE history_items (
                id          INTEGER PRIMARY KEY,
                url         TEXT NOT NULL,
                visit_count INTEGER DEFAULT 0
            );
            CREATE TABLE history_visits (
                id           INTEGER PRIMARY KEY,
                history_item INTEGER NOT NULL,
                visit_time   REAL NOT NULL
            );",
        )
        .unwrap();
        for (url, visit_count, visit_time) in rows {
            conn.execute(
                "INSERT INTO history_items (url, visit_count) VALUES (?1, ?2)",
                rusqlite::params![url, visit_count],
            )
            .unwrap();
            let item_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO history_visits (history_item, visit_time) VALUES (?1, ?2)",
                rusqlite::params![item_id, visit_time],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn safari_epoch_offset_is_correct() {
        // core_data_secs=0 => Unix epoch 978_307_200 sec
        assert_eq!(safari_to_unix_ns(0.0), 978_307_200_000_000_000);
    }

    #[test]
    fn safari_epoch_known_value() {
        // 700_000_000 + 978_307_200 = 1_678_307_200 seconds
        assert_eq!(safari_to_unix_ns(700_000_000.0), 1_678_307_200_000_000_000);
    }

    #[test]
    fn parse_empty_safari_history_returns_empty() {
        let f = create_safari_history_db(&[]);
        let events = parse_history(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_safari_url() {
        let f = create_safari_history_db(&[("https://example.com", 3, 700_000_000.0)]);
        let events = parse_history(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Safari);
        assert_eq!(ev.artifact, ArtifactKind::History);
        assert_eq!(ev.attrs["url"], serde_json::json!("https://example.com"));
        assert_eq!(ev.attrs["visit_count"], serde_json::json!(3_i64));
        assert_eq!(ev.timestamp_ns, safari_to_unix_ns(700_000_000.0));
    }

    #[test]
    fn parse_multiple_visits_creates_one_event_per_visit() {
        let f = create_safari_history_db(&[
            ("https://a.com", 1, 100_000_000.0),
            ("https://b.com", 2, 200_000_000.0),
        ]);
        let events = parse_history(f.path()).unwrap();
        assert_eq!(events.len(), 2);
    }
}
