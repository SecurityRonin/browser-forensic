//! Firefox `places.sqlite` downloads parser.
//!
//! Reads download records from `moz_annos` joined with `moz_places` and
//! `moz_anno_attributes`, filtering for `downloads/destinationFileURI` annotations.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Firefox `places.sqlite` file for download records.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_downloads(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn create_ff_downloads_db(rows: &[(&str, &str, i64)]) -> NamedTempFile {
        // rows: (url, dest_path, date_added_us)
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (
                id      INTEGER PRIMARY KEY,
                url     TEXT NOT NULL
            );
            CREATE TABLE moz_anno_attributes (
                id   INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            );
            CREATE TABLE moz_annos (
                id                 INTEGER PRIMARY KEY,
                place_id           INTEGER NOT NULL,
                anno_attribute_id  INTEGER NOT NULL,
                content            TEXT,
                dateAdded          INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_anno_attributes (id, name) VALUES (1, 'downloads/destinationFileURI')",
            [],
        )
        .unwrap();
        for (url, dest_path, date_added) in rows {
            conn.execute(
                "INSERT INTO moz_places (url) VALUES (?1)",
                rusqlite::params![url],
            )
            .unwrap();
            let place_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) \
                 VALUES (?1, 1, ?2, ?3)",
                rusqlite::params![place_id, dest_path, date_added],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_ff_downloads_returns_empty() {
        let f = create_ff_downloads_db(&[]);
        let events = parse_downloads(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_ff_download() {
        let date_added_us = 1_648_000_000_000_000_i64;
        let f = create_ff_downloads_db(&[(
            "https://example.com/file.zip",
            "file:///home/user/Downloads/file.zip",
            date_added_us,
        )]);
        let events = parse_downloads(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Downloads);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["url"], json!("https://example.com/file.zip"));
        assert_eq!(ev.timestamp_ns, date_added_us * 1_000);
    }
}
