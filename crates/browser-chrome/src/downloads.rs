//! Chromium-family browser downloads parser.
//!
//! Reads the `downloads` table (joined with `downloads_url_chains`) from a
//! Chromium `History` SQLite database and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Downloads`].

use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use rusqlite::Connection;
use serde_json::json;

use crate::history::webkit_to_unix_ns;

/// Parse a Chromium `History` SQLite file for download records.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_downloads(path: &Path) -> Result<Vec<BrowserEvent>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT d.start_time, d.target_path, d.total_bytes, d.state, d.danger_type, u.url \
         FROM downloads d \
         LEFT JOIN downloads_url_chains u ON d.id = u.id AND u.chain_index = 0 \
         WHERE d.start_time > 0 \
         ORDER BY d.start_time ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let start_time: i64 = row.get(0)?;
            let target_path: String = row.get(1)?;
            let total_bytes: i64 = row.get(2)?;
            let state: i32 = row.get(3)?;
            let danger_type: i32 = row.get(4)?;
            let url: Option<String> = row.get(5)?;
            Ok((start_time, target_path, total_bytes, state, danger_type, url))
        })?
        .filter_map(|r| r.ok())
        .map(|(start_time, target_path, total_bytes, state, danger_type, url)| {
            let ts_ns = webkit_to_unix_ns(start_time);
            let filename = std::path::Path::new(&target_path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| target_path.clone());
            let desc = format!("{filename} ({total_bytes} bytes)");
            let url_val = url.unwrap_or_default();
            BrowserEvent::new(ts_ns, BrowserFamily::Chromium, ArtifactKind::Downloads, &source, desc)
                .with_attr("url", json!(url_val))
                .with_attr("target_path", json!(target_path))
                .with_attr("total_bytes", json!(total_bytes))
                .with_attr("state", json!(state))
                .with_attr("danger_type", json!(danger_type))
        })
        .collect();
    Ok(events)
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
