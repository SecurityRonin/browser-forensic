//! Safari `Cookies.db` parser.
//!
//! Reads cookies from Safari's `Cookies.db` SQLite database and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Cookies`].

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

use browser_forensic_core::timestamp::core_data_secs_to_unix_nanos;

/// Parse a Safari `Cookies.db` SQLite file.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_cookies(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut stmt = conn.prepare(
        "SELECT name, value, domain, path, creation, expiry, is_secure, is_httponly \
         FROM cookies \
         WHERE creation > 0 \
         ORDER BY creation ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let _value: String = row.get(1)?;
            let domain: String = row.get(2)?;
            let cookie_path: String = row.get(3)?;
            let creation: f64 = row.get(4)?;
            let expiry: f64 = row.get(5)?;
            let is_secure: bool = row.get::<_, i64>(6)? != 0;
            let is_httponly: bool = row.get::<_, i64>(7)? != 0;
            Ok((
                name,
                domain,
                cookie_path,
                creation,
                expiry,
                is_secure,
                is_httponly,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .map(
            |(name, domain, cookie_path, creation, expiry, is_secure, is_httponly)| {
                let ts_ns = core_data_secs_to_unix_nanos(creation);
                let desc = format!("{domain} \u{2014} {name}");
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Safari,
                    ArtifactKind::Cookies,
                    &source,
                    desc,
                )
                .with_attr("name", json!(name))
                .with_attr("domain", json!(domain))
                .with_attr("path", json!(cookie_path))
                .with_attr("expiry", json!(expiry))
                .with_attr("is_secure", json!(is_secure))
                .with_attr("is_httponly", json!(is_httponly))
            },
        )
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use browser_forensic_core::timestamp::core_data_secs_to_unix_nanos;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use rusqlite::params;
    use serde_json::json;

    const SCHEMA: &str = "CREATE TABLE cookies (
        name        TEXT NOT NULL,
        value       TEXT NOT NULL DEFAULT '',
        domain      TEXT NOT NULL DEFAULT '',
        path        TEXT NOT NULL DEFAULT '/',
        creation    REAL NOT NULL DEFAULT 0,
        expiry      REAL NOT NULL DEFAULT 0,
        is_secure   INTEGER NOT NULL DEFAULT 0,
        is_httponly INTEGER NOT NULL DEFAULT 0
    );";

    #[test]
    fn parse_empty_safari_cookies_returns_empty() {
        let db = TestDb::new(SCHEMA);
        let events = parse_cookies(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_safari_cookie() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO cookies (name, value, domain, path, creation, expiry, is_secure, is_httponly) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params!["session_id", "abc123", ".example.com", "/", 700_000_000.0_f64, 0.0_f64, 1_i64, 0_i64],
        );
        let events = parse_cookies(db.path()).unwrap();
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
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO cookies (name, value, domain, path, creation, expiry, is_secure, is_httponly) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params!["ts_test", "v", ".example.com", "/", creation, 0.0_f64, 0_i64, 0_i64],
        );
        let events = parse_cookies(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].timestamp_ns,
            core_data_secs_to_unix_nanos(creation)
        );
    }
}
