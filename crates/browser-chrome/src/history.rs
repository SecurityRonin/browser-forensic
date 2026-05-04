//! Chromium-family browser history parser.
//!
//! Reads the `urls` table from a Chromium `History` SQLite database and emits
//! [`BrowserEvent`]s with [`ArtifactKind::History`].

use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use browser_core::timestamp::webkit_micros_to_unix_nanos;
use rusqlite::Connection;
use serde_json::json;

/// Parse a Chromium `History` SQLite file.
///
/// Queries the `urls` table and emits one [`BrowserEvent`] per row.
/// Rows with a zero or negative `last_visit_time` are skipped.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_history(path: &Path) -> Result<Vec<BrowserEvent>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_time \
         FROM urls \
         ORDER BY last_visit_time ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let title: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            let visit_count: i64 = row.get(2)?;
            let webkit_time: i64 = row.get(3)?;
            Ok((url, title, visit_count, webkit_time))
        })?
        .filter_map(|r| r.ok())
        .filter(|(_, _, _, webkit_time)| *webkit_time > 0)
        .map(|(url, title, visit_count, webkit_time)| {
            let ts_ns = webkit_micros_to_unix_nanos(webkit_time);
            let desc = if title.is_empty() {
                url.clone()
            } else {
                format!("[{visit_count} visits] {title} \u{2014} {url}")
            };
            BrowserEvent::new(ts_ns, BrowserFamily::Chromium, ArtifactKind::History, &source, desc)
                .with_attr("url", json!(url))
                .with_attr("title", json!(title))
                .with_attr("visit_count", json!(visit_count))
        })
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::test_utils::sqlite::TestDb;
    use browser_core::timestamp::webkit_micros_to_unix_nanos;
    use rusqlite::params;

    const SCHEMA: &str = "CREATE TABLE urls (
        id INTEGER PRIMARY KEY,
        url TEXT NOT NULL,
        title TEXT DEFAULT '',
        visit_count INTEGER DEFAULT 0 NOT NULL,
        last_visit_time INTEGER NOT NULL
    );";

    #[test]
    fn parse_empty_history_returns_empty() {
        let db = TestDb::new(SCHEMA);
        let events = parse_history(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_url_emits_event() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?1, ?2, ?3, ?4)",
            params!["https://example.com", "Example", 3_i64, 13_327_626_000_000_000_i64],
        );
        let events = parse_history(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert!(ev.description.contains("https://example.com"));
        assert!(ev.timestamp_ns > 0);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
    }

    #[test]
    fn webkit_epoch_conversion() {
        // (13_327_626_000_000_000 - 11_644_473_600_000_000) * 1000
        // = 1_683_152_400_000_000_000
        assert_eq!(webkit_micros_to_unix_nanos(13_327_626_000_000_000), 1_683_152_400_000_000_000);
    }

    #[test]
    fn zero_timestamp_row_skipped() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?1, ?2, ?3, ?4)",
            params!["https://zero.example", "Zero", 1_i64, 0_i64],
        );
        db.insert(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?1, ?2, ?3, ?4)",
            params!["https://real.example", "Real", 2_i64, 13_327_626_000_000_000_i64],
        );
        let events = parse_history(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains("real.example"));
    }
}
