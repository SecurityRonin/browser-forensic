//! Chromium-family browser cookies parser.
//!
//! Reads the `cookies` table from a Chromium `Cookies` SQLite database and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Cookies`].
//!
//! **Security note**: The `encrypted_value` BLOB is never exposed; attrs always
//! contain `"ENCRYPTED"` for that field.

use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use rusqlite::Connection;
use serde_json::json;

use crate::history::webkit_to_unix_ns;

/// Parse a Chromium `Cookies` SQLite file.
///
/// Queries the `cookies` table and emits one [`BrowserEvent`] per row.
/// Rows with `creation_utc = 0` are skipped.
/// The `encrypted_value` BLOB is never surfaced; attrs report `"ENCRYPTED"`.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_cookies(path: &Path) -> Result<Vec<BrowserEvent>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT creation_utc, host_key, name, path, expires_utc, \
                is_secure, is_httponly, samesite \
         FROM cookies \
         WHERE creation_utc > 0 \
         ORDER BY creation_utc ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let creation_utc: i64 = row.get(0)?;
            let host_key: String = row.get(1)?;
            let name: String = row.get(2)?;
            let cookie_path: String = row.get(3)?;
            let expires_utc: i64 = row.get(4)?;
            let is_secure: bool = row.get::<_, i64>(5)? != 0;
            let is_httponly: bool = row.get::<_, i64>(6)? != 0;
            let samesite: i32 = row.get(7)?;
            Ok((creation_utc, host_key, name, cookie_path, expires_utc, is_secure, is_httponly, samesite))
        })?
        .filter_map(|r| r.ok())
        .map(|(creation_utc, host_key, name, cookie_path, expires_utc, is_secure, is_httponly, samesite)| {
            let ts_ns = webkit_to_unix_ns(creation_utc);
            let desc = format!("{host_key} \u{2014} {name} (path={cookie_path})");
            BrowserEvent::new(ts_ns, BrowserFamily::Chromium, ArtifactKind::Cookies, &source, desc)
                .with_attr("host", json!(host_key))
                .with_attr("name", json!(name))
                .with_attr("path", json!(cookie_path))
                .with_attr("is_secure", json!(is_secure))
                .with_attr("is_httponly", json!(is_httponly))
                .with_attr("samesite", json!(samesite))
                .with_attr("expires_utc", json!(expires_utc))
                .with_attr("encrypted_value", json!("ENCRYPTED"))
        })
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use crate::history::webkit_to_unix_ns;
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::NamedTempFile;

    // (host, name, path, creation_utc, expires_utc, is_secure, is_httponly)
    fn create_cookies_db(rows: &[(&str, &str, &str, i64, i64, bool, bool)]) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE cookies (
                creation_utc    INTEGER NOT NULL,
                host_key        TEXT NOT NULL,
                name            TEXT NOT NULL,
                value           TEXT DEFAULT '',
                path            TEXT NOT NULL,
                expires_utc     INTEGER DEFAULT 0,
                is_secure       INTEGER DEFAULT 0,
                is_httponly     INTEGER DEFAULT 0,
                samesite        INTEGER DEFAULT -1,
                encrypted_value BLOB DEFAULT ''
            );",
        )
        .unwrap();
        for (host, name, path, creation, expires, secure, httponly) in rows {
            conn.execute(
                "INSERT INTO cookies \
                 (creation_utc, host_key, name, path, expires_utc, is_secure, is_httponly) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![creation, host, name, path, expires, *secure as i64, *httponly as i64],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_cookies_returns_empty() {
        let f = create_cookies_db(&[]);
        let events = parse_cookies(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_cookie_emits_event() {
        let f = create_cookies_db(&[(".example.com", "session", "/", 13_327_626_000_000_000, 0, true, false)]);
        let events = parse_cookies(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Cookies);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert!(ev.description.contains(".example.com"));
        assert!(ev.description.contains("session"));
        assert_eq!(ev.attrs["host"], json!(".example.com"));
        assert_eq!(ev.attrs["is_secure"], json!(true));
        assert_eq!(ev.attrs["encrypted_value"], json!("ENCRYPTED"));
    }

    #[test]
    fn cookie_timestamp_uses_webkit_epoch() {
        let creation_utc = 13_327_626_000_000_000_i64;
        let f = create_cookies_db(&[(".example.com", "ts_test", "/", creation_utc, 0, false, false)]);
        let events = parse_cookies(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, webkit_to_unix_ns(creation_utc));
    }

    #[test]
    fn zero_creation_utc_is_skipped() {
        let f = create_cookies_db(&[
            (".skip.example", "zero", "/", 0, 0, false, false),
            (".keep.example", "real", "/", 13_327_626_000_000_000, 0, false, false),
        ]);
        let events = parse_cookies(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains(".keep.example"));
    }
}
