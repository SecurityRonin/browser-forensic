//! Firefox `places.sqlite` bookmarks parser.
//!
//! Reads URL bookmarks from `moz_bookmarks` joined with `moz_places` and
//! emits [`BrowserEvent`]s with [`ArtifactKind::Bookmarks`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Firefox `places.sqlite` file for bookmarks.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_bookmarks(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn create_ff_bookmarks_db(rows: &[(&str, &str, i64, i32)]) -> NamedTempFile {
        // rows: (title, url, date_added_us, type: 1=url, 2=folder)
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (
                id  INTEGER PRIMARY KEY,
                url TEXT NOT NULL
            );
            CREATE TABLE moz_bookmarks (
                id         INTEGER PRIMARY KEY,
                type       INTEGER NOT NULL,
                fk         INTEGER,
                title      TEXT,
                dateAdded  INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        for (title, url, date_added, bm_type) in rows {
            let place_id = if *bm_type == 1 {
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
        f
    }

    #[test]
    fn parse_empty_ff_bookmarks_returns_empty() {
        let f = create_ff_bookmarks_db(&[]);
        let events = parse_bookmarks(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_ff_bookmark() {
        let date_added_us = 1_648_000_000_000_000_i64;
        let f = create_ff_bookmarks_db(&[("Example", "https://example.com", date_added_us, 1)]);
        let events = parse_bookmarks(f.path()).unwrap();
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
        let f = create_ff_bookmarks_db(&[
            ("A Folder", "", 1_648_000_000_000_000, 2), // type=2, folder
        ]);
        let events = parse_bookmarks(f.path()).unwrap();
        assert!(events.is_empty());
    }
}
