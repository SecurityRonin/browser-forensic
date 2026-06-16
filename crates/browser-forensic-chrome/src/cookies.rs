//! Chromium-family browser cookies parser.
//!
//! Reads the `cookies` table from a Chromium `Cookies` SQLite database and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Cookies`].
//!
//! **Security note**: The `encrypted_value` BLOB is never exposed; attrs always
//! contain `"ENCRYPTED"` for that field.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;

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
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
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
            Ok((
                creation_utc,
                host_key,
                name,
                cookie_path,
                expires_utc,
                is_secure,
                is_httponly,
                samesite,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .map(
            |(
                creation_utc,
                host_key,
                name,
                cookie_path,
                expires_utc,
                is_secure,
                is_httponly,
                samesite,
            )| {
                let ts_ns = webkit_micros_to_unix_nanos(creation_utc);
                let desc = format!("{host_key} \u{2014} {name} (path={cookie_path})");
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Chromium,
                    ArtifactKind::Cookies,
                    &source,
                    desc,
                )
                .with_attr("host", json!(host_key))
                .with_attr("name", json!(name))
                .with_attr("path", json!(cookie_path))
                .with_attr("is_secure", json!(is_secure))
                .with_attr("is_httponly", json!(is_httponly))
                .with_attr("samesite", json!(samesite))
                .with_attr("expires_utc", json!(expires_utc))
                .with_attr("encrypted_value", json!("ENCRYPTED"))
            },
        )
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use rusqlite::params;
    use serde_json::json;

    const SCHEMA: &str = "CREATE TABLE cookies (
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
    );";

    #[test]
    fn parse_empty_cookies_returns_empty() {
        let db = TestDb::new(SCHEMA);
        let events = parse_cookies(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_cookie_emits_event() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO cookies (creation_utc, host_key, name, path, expires_utc, is_secure, is_httponly) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![13_327_626_000_000_000_i64, ".example.com", "session", "/", 0_i64, 1_i64, 0_i64],
        );
        let events = parse_cookies(db.path()).unwrap();
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
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO cookies (creation_utc, host_key, name, path, expires_utc, is_secure, is_httponly) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![creation_utc, ".example.com", "ts_test", "/", 0_i64, 0_i64, 0_i64],
        );
        let events = parse_cookies(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].timestamp_ns,
            webkit_micros_to_unix_nanos(creation_utc)
        );
    }

    #[test]
    fn zero_creation_utc_is_skipped() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO cookies (creation_utc, host_key, name, path, expires_utc, is_secure, is_httponly) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![0_i64, ".skip.example", "zero", "/", 0_i64, 0_i64, 0_i64],
        );
        db.insert(
            "INSERT INTO cookies (creation_utc, host_key, name, path, expires_utc, is_secure, is_httponly) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![13_327_626_000_000_000_i64, ".keep.example", "real", "/", 0_i64, 0_i64, 0_i64],
        );
        let events = parse_cookies(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains(".keep.example"));
    }
}
