//! Firefox `cookies.sqlite` parser.
//!
//! Reads the `moz_cookies` table and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Cookies`].

use std::path::Path;

use anyhow::Result;
use browser_core::sqlite::open_evidence_db;
use browser_core::timestamp::unix_micros_to_nanos;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Firefox `cookies.sqlite` file.
///
/// Queries `moz_cookies` and emits one [`BrowserEvent`] per row with
/// `creationTime > 0`.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_cookies(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut stmt = conn.prepare(
        "SELECT host, name, path, creationTime, expiry, isSecure, isHttpOnly, sameSite \
         FROM moz_cookies \
         WHERE creationTime > 0 \
         ORDER BY creationTime ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let host: String = row.get(0)?;
            let name: String = row.get(1)?;
            let cookie_path: String = row.get(2)?;
            let creation_us: i64 = row.get(3)?;
            let expiry: i64 = row.get(4)?;
            let is_secure: bool = row.get::<_, i64>(5)? != 0;
            let is_httponly: bool = row.get::<_, i64>(6)? != 0;
            let samesite: i32 = row.get(7)?;
            Ok((
                host,
                name,
                cookie_path,
                creation_us,
                expiry,
                is_secure,
                is_httponly,
                samesite,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .map(
            |(host, name, cookie_path, creation_us, expiry, is_secure, is_httponly, samesite)| {
                let ts_ns = unix_micros_to_nanos(creation_us);
                let desc = format!("{host} \u{2014} {name} (path={cookie_path})");
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Firefox,
                    ArtifactKind::Cookies,
                    &source,
                    desc,
                )
                .with_attr("host", json!(host))
                .with_attr("name", json!(name))
                .with_attr("path", json!(cookie_path))
                .with_attr("expiry", json!(expiry))
                .with_attr("is_secure", json!(is_secure))
                .with_attr("is_httponly", json!(is_httponly))
                .with_attr("samesite", json!(samesite))
            },
        )
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::test_utils::sqlite::TestDb;
    use browser_core::{ArtifactKind, BrowserFamily};
    use rusqlite::params;
    use serde_json::json;

    const SCHEMA: &str = "CREATE TABLE moz_cookies (
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
    );";

    #[test]
    fn parse_empty_cookies_returns_empty() {
        let db = TestDb::new(SCHEMA);
        let events = parse_cookies(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_firefox_cookie() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO moz_cookies (host, name, path, creationTime, expiry, isSecure, isHttpOnly) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![".example.com", "session", "/", 1_648_000_000_000_000_i64, 0_i64, 1_i64, 0_i64],
        );
        let events = parse_cookies(db.path()).unwrap();
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
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO moz_cookies (host, name, path, creationTime, expiry, isSecure, isHttpOnly) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![".example.com", "ts_test", "/", creation_us, 0_i64, 0_i64, 0_i64],
        );
        let events = parse_cookies(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, creation_us * 1_000);
    }
}
