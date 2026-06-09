//! Firefox `places.sqlite` bookmarks parser.
//!
//! Reads URL bookmarks from `moz_bookmarks` joined with `moz_places` and
//! emits [`BrowserEvent`]s with [`ArtifactKind::Bookmarks`].

use std::path::Path;

use anyhow::Result;
use browser_core::timestamp::unix_micros_to_nanos;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use rusqlite::Connection;
use serde_json::json;

/// Parse a Firefox `places.sqlite` file for bookmarks.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_bookmarks(path: &Path) -> Result<Vec<BrowserEvent>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT b.title, p.url, b.dateAdded \
         FROM moz_bookmarks b \
         JOIN moz_places p ON b.fk = p.id \
         WHERE b.type = 1 AND b.dateAdded > 0 \
         ORDER BY b.dateAdded ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let title: Option<String> = row.get(0)?;
            let url: String = row.get(1)?;
            let date_added_us: i64 = row.get(2)?;
            Ok((title, url, date_added_us))
        })?
        .filter_map(|r| r.ok())
        .map(|(title, url, date_added_us)| {
            let ts_ns = unix_micros_to_nanos(date_added_us);
            let title_str = title.clone().unwrap_or_default();
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Firefox,
                ArtifactKind::Bookmarks,
                &source,
                title_str.clone(),
            )
            .with_attr("url", json!(url))
            .with_attr("title", json!(title_str))
        })
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::test_utils::sqlite::TestDb;
    use browser_core::{ArtifactKind, BrowserFamily};
    use rusqlite::Connection;
    use serde_json::json;

    const SCHEMA: &str = "CREATE TABLE moz_places (
        id  INTEGER PRIMARY KEY,
        url TEXT NOT NULL
    );
    CREATE TABLE moz_bookmarks (
        id         INTEGER PRIMARY KEY,
        type       INTEGER NOT NULL,
        fk         INTEGER,
        title      TEXT,
        dateAdded  INTEGER NOT NULL DEFAULT 0
    );";

    fn insert_bookmark(db: &TestDb, title: &str, url: &str, date_added: i64, bm_type: i32) {
        let conn = Connection::open(db.path()).unwrap();
        let place_id = if bm_type == 1 {
            conn.execute(
                "INSERT INTO moz_places (url) VALUES (?1)",
                rusqlite::params![url],
            )
            .unwrap();
            Some(conn.last_insert_rowid())
        } else {
            None
        };
        conn.execute(
            "INSERT INTO moz_bookmarks (type, fk, title, dateAdded) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![bm_type, place_id, title, date_added],
        )
        .unwrap();
    }

    #[test]
    fn parse_empty_ff_bookmarks_returns_empty() {
        let db = TestDb::new(SCHEMA);
        let events = parse_bookmarks(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_ff_bookmark() {
        let date_added_us = 1_648_000_000_000_000_i64;
        let db = TestDb::new(SCHEMA);
        insert_bookmark(&db, "Example", "https://example.com", date_added_us, 1);
        let events = parse_bookmarks(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Bookmarks);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["url"], json!("https://example.com"));
        assert_eq!(ev.attrs["title"], json!("Example"));
        assert_eq!(ev.timestamp_ns, date_added_us * 1_000);
    }

    #[test]
    fn folder_type_excluded() {
        let db = TestDb::new(SCHEMA);
        insert_bookmark(&db, "A Folder", "", 1_648_000_000_000_000, 2);
        let events = parse_bookmarks(db.path()).unwrap();
        assert!(events.is_empty());
    }
}
