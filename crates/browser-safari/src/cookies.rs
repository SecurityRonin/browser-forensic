//! Safari `Cookies.db` parser.
//!
//! Reads cookies from Safari's `Cookies.db` SQLite database and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Cookies`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

use crate::history::safari_to_unix_ns;

/// Parse a Safari `Cookies.db` SQLite file.
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
    use crate::history::safari_to_unix_ns;
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn create_safari_cookies_db(rows: &[(&str, &str, &str, &str, f64, f64, bool, bool)]) -> NamedTempFile {
        // rows: (name, value, domain, path, creation, expiry, is_secure, is_httponly)
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE cookies (
                name        TEXT NOT NULL,
                value       TEXT NOT NULL DEFAULT '',
                domain      TEXT NOT NULL DEFAULT '',
                path        TEXT NOT NULL DEFAULT '/',
                creation    REAL NOT NULL DEFAULT 0,
                expiry      REAL NOT NULL DEFAULT 0,
                is_secure   INTEGER NOT NULL DEFAULT 0,
                is_httponly INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        for (name, value, domain, path, creation, expiry, is_secure, is_httponly) in rows {
            conn.execute(
                "INSERT INTO cookies (name, value, domain, path, creation, expiry, is_secure, is_httponly) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![name, value, domain, path, creation, expiry, *is_secure as i64, *is_httponly as i64],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_safari_cookies_returns_empty() {
        let f = create_safari_cookies_db(&[]);
        let events = parse_cookies(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_safari_cookie() {
        let f = create_safari_cookies_db(&[("session_id", "abc123", ".example.com", "/", 700_000_000.0, 0.0, true, false)]);
        let events = parse_cookies(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Safari);
        assert_eq!(ev.artifact, ArtifactKind::Cookies);
        assert_eq!(ev.attrs["domain"], json!(".example.com"));
        assert_eq!(ev.attrs["name"], json!("session_id"));
    }

    #[test]
    fn safari_cookie_timestamp_uses_core_data_epoch() {
        let creation = 700_000_000.0_f64;
        let f = create_safari_cookies_db(&[("ts_test", "v", ".example.com", "/", creation, 0.0, false, false)]);
        let events = parse_cookies(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, safari_to_unix_ns(creation));
    }
}
