//! Chromium-family browser downloads parser.
//!
//! Reads the `downloads` table (joined with `downloads_url_chains`) from a
//! Chromium `History` SQLite database and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Downloads`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

use crate::history::webkit_to_unix_ns;

/// Parse a Chromium `History` SQLite file for download records.
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

    fn create_downloads_db(rows: &[(&str, &str, i64, i64, i32, i32)]) -> NamedTempFile {
        // rows: (url, target_path, start_time, total_bytes, state, danger_type)
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE downloads (
                id          INTEGER PRIMARY KEY,
                target_path TEXT NOT NULL DEFAULT '',
                start_time  INTEGER NOT NULL DEFAULT 0,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                state       INTEGER NOT NULL DEFAULT 0,
                danger_type INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE downloads_url_chains (
                id          INTEGER NOT NULL,
                chain_index INTEGER NOT NULL,
                url         TEXT NOT NULL
            );",
        )
        .unwrap();
        for (url, target_path, start_time, total_bytes, state, danger_type) in rows {
            conn.execute(
                "INSERT INTO downloads (target_path, start_time, total_bytes, state, danger_type) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![target_path, start_time, total_bytes, state, danger_type],
            )
            .unwrap();
            let download_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (?1, 0, ?2)",
                rusqlite::params![download_id, url],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_downloads_returns_empty() {
        let f = create_downloads_db(&[]);
        let events = parse_downloads(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_download() {
        let f = create_downloads_db(&[(
            "https://example.com/file.zip",
            "/home/user/Downloads/file.zip",
            13_327_626_000_000_000,
            1024,
            1,
            0,
        )]);
        let events = parse_downloads(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Downloads);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs["url"], json!("https://example.com/file.zip"));
        assert_eq!(ev.attrs["total_bytes"], json!(1024_i64));
        assert_eq!(ev.timestamp_ns, webkit_to_unix_ns(13_327_626_000_000_000));
    }

    #[test]
    fn dangerous_download_flagged_in_attrs() {
        let f = create_downloads_db(&[(
            "https://malware.example/evil.exe",
            "/tmp/evil.exe",
            13_327_626_000_000_000,
            512,
            0,
            1,
        )]);
        let events = parse_downloads(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["danger_type"], json!(1_i32));
    }
}
