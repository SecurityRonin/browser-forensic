//! Safari `History.db` parser.
//!
//! Reads the `history_visits` and `history_items` tables from Safari's
//! `History.db` SQLite database and emits [`BrowserEvent`]s with
//! [`ArtifactKind::History`].

use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use browser_core::timestamp::core_data_secs_to_unix_nanos;
use rusqlite::Connection;
use serde_json::json;

/// Parse a Safari `History.db` SQLite file.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_history(path: &Path) -> Result<Vec<BrowserEvent>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT i.url, i.visit_count, v.visit_time \
         FROM history_visits v \
         JOIN history_items i ON v.history_item = i.id \
         WHERE v.visit_time > 0 \
         ORDER BY v.visit_time ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let visit_count: i64 = row.get(1)?;
            let visit_time: f64 = row.get(2)?;
            Ok((url, visit_count, visit_time))
        })?
        .filter_map(|r| r.ok())
        .map(|(url, visit_count, visit_time)| {
            let ts_ns = core_data_secs_to_unix_nanos(visit_time);
            let desc = format!("[{visit_count} visits] {url}");
            BrowserEvent::new(ts_ns, BrowserFamily::Safari, ArtifactKind::History, &source, desc)
                .with_attr("url", json!(url))
                .with_attr("visit_count", json!(visit_count))
        })
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use browser_core::timestamp::core_data_secs_to_unix_nanos;
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
        assert_eq!(core_data_secs_to_unix_nanos(0.0), 978_307_200_000_000_000);
    }

    #[test]
    fn safari_epoch_known_value() {
        // 700_000_000 + 978_307_200 = 1_678_307_200 seconds
        assert_eq!(core_data_secs_to_unix_nanos(700_000_000.0), 1_678_307_200_000_000_000);
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
        assert_eq!(ev.timestamp_ns, core_data_secs_to_unix_nanos(700_000_000.0));
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
