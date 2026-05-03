//! Firefox `cookies.sqlite` parser.
//!
//! Reads the `moz_cookies` table and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Cookies`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Firefox `cookies.sqlite` file.
///
/// Queries `moz_cookies` and emits one [`BrowserEvent`] per row with
/// `creationTime > 0`.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_cookies(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::NamedTempFile;

    // (host, name, path, creationTime_us, expiry_epoch_secs, isSecure, isHttpOnly)
    fn create_ff_cookies_db(rows: &[(&str, &str, &str, i64, i64, bool, bool)]) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_cookies (
                id          INTEGER PRIMARY KEY,
                host        TEXT NOT NULL,
                name        TEXT NOT NULL,
                value       TEXT DEFAULT '',
                path        TEXT NOT NULL,
                expiry      INTEGER DEFAULT 0,
                creationTime INTEGER NOT NULL,
                lastAccessed INTEGER DEFAULT 0,
                isSecure    INTEGER DEFAULT 0,
                isHttpOnly  INTEGER DEFAULT 0,
                sameSite    INTEGER DEFAULT 0
            );",
        )
        .unwrap();
        for (host, name, path, creation, expiry, secure, httponly) in rows {
            conn.execute(
                "INSERT INTO moz_cookies \
                 (host, name, path, creationTime, expiry, isSecure, isHttpOnly) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![host, name, path, creation, expiry, *secure as i64, *httponly as i64],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_cookies_returns_empty() {
        let f = create_ff_cookies_db(&[]);
        let events = parse_cookies(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_firefox_cookie() {
        let f = create_ff_cookies_db(&[(".example.com", "session", "/", 1_648_000_000_000_000, 0, true, false)]);
        let events = parse_cookies(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Cookies);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert!(ev.description.contains(".example.com"));
        assert!(ev.description.contains("session"));
        assert_eq!(ev.attrs["host"], json!(".example.com"));
        assert_eq!(ev.attrs["is_secure"], json!(true));
    }

    #[test]
    fn firefox_cookie_timestamp_microseconds_to_ns() {
        let creation_us = 1_648_000_000_000_000_i64;
        let f = create_ff_cookies_db(&[(".example.com", "ts_test", "/", creation_us, 0, false, false)]);
        let events = parse_cookies(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, creation_us * 1_000);
    }
}
