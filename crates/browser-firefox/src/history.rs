//! Firefox `places.sqlite` history parser.

use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use browser_core::timestamp::unix_micros_to_nanos;
use rusqlite::Connection;
use serde_json::json;

/// Parse a Firefox `places.sqlite` file.
///
/// Queries `moz_places` and emits one [`BrowserEvent`] per row that has a
/// non-NULL `last_visit_date`.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_history(path: &Path) -> Result<Vec<BrowserEvent>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_date \
         FROM moz_places \
         WHERE last_visit_date IS NOT NULL \
         ORDER BY last_visit_date ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let title: Option<String> = row.get(1)?;
            let visit_count: i64 = row.get::<_, Option<i64>>(2)?.unwrap_or(0);
            let last_visit_us: i64 = row.get(3)?;
            Ok((url, title, visit_count, last_visit_us))
        })?
        .filter_map(|r| r.ok())
        .map(|(url, title, visit_count, last_visit_us)| {
            let ts_ns = unix_micros_to_nanos(last_visit_us);
            let title_str = title.unwrap_or_default();
            let desc = if title_str.is_empty() {
                url.clone()
            } else {
                format!("[{visit_count} visits] {title_str} \u{2014} {url}")
            };
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Firefox,
                ArtifactKind::History,
                &source,
                desc,
            )
            .with_attr("url", json!(url))
            .with_attr("title", json!(title_str))
            .with_attr("visit_count", json!(visit_count))
        })
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn create_places_db(rows: &[(&str, Option<&str>, i64, Option<i64>)]) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT,
                visit_count INTEGER DEFAULT 0,
                last_visit_date INTEGER
            );",
        )
        .unwrap();
        for (url, title, vc, ts) in rows {
            conn.execute(
                "INSERT INTO moz_places (url, title, visit_count, last_visit_date) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![url, title, vc, ts],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_places_returns_empty() {
        let f = create_places_db(&[]);
        let events = parse_history(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_url_emits_event() {
        let f = create_places_db(&[(
            "https://example.com",
            Some("Example"),
            5,
            Some(1_648_000_000_000_000),
        )]);
        let events = parse_history(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, 1_648_000_000_000_000_000);
        assert!(events[0].description.contains("example.com"));
    }

    #[test]
    fn null_visit_date_skipped() {
        let f = create_places_db(&[
            ("https://null.example", Some("Null"), 1, None),
            (
                "https://real.example",
                Some("Real"),
                2,
                Some(1_648_000_000_000_000),
            ),
        ]);
        let events = parse_history(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains("real.example"));
    }
}
