//! Chromium-family browser login data parser.
//!
//! Reads the `logins` table from a Chromium `Login Data` SQLite database and
//! emits [`BrowserEvent`]s with [`ArtifactKind::LoginData`].
//!
//! **Security note**: `password_value` is NEVER selected or exposed.
//! attrs always contain `"ENCRYPTED"` for the password field.

use std::path::Path;

use anyhow::Result;
use browser_core::sqlite::open_evidence_db;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

use browser_core::timestamp::webkit_micros_to_unix_nanos;

/// Parse a Chromium `Login Data` SQLite file.
///
/// CRITICAL: `password_value` is never selected or returned.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_login_data(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    // CRITICAL: password_value is NEVER in this query
    let mut stmt = conn.prepare(
        "SELECT origin_url, action_url, username_value, date_created, date_last_used \
         FROM logins \
         WHERE date_created > 0 \
         ORDER BY date_created ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let origin_url: String = row.get(0)?;
            let action_url: String = row.get(1)?;
            let username: String = row.get(2)?;
            let date_created: i64 = row.get(3)?;
            let date_last_used: i64 = row.get(4)?;
            Ok((
                origin_url,
                action_url,
                username,
                date_created,
                date_last_used,
            ))
        })?
        .filter_map(|r| r.ok())
        .map(
            |(origin_url, action_url, username, date_created, date_last_used)| {
                let ts_ns = webkit_micros_to_unix_nanos(date_created);
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Chromium,
                    ArtifactKind::LoginData,
                    &source,
                    origin_url.clone(),
                )
                .with_attr("origin_url", json!(origin_url))
                .with_attr("action_url", json!(action_url))
                .with_attr("username", json!(username))
                .with_attr("date_last_used", json!(date_last_used))
                .with_attr("password", json!("ENCRYPTED"))
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

    const SCHEMA: &str = "CREATE TABLE logins (
        id              INTEGER PRIMARY KEY,
        origin_url      TEXT NOT NULL DEFAULT '',
        action_url      TEXT NOT NULL DEFAULT '',
        username_value  TEXT NOT NULL DEFAULT '',
        password_value  BLOB DEFAULT '',
        date_created    INTEGER NOT NULL DEFAULT 0,
        date_last_used  INTEGER NOT NULL DEFAULT 0
    );";

    #[test]
    fn parse_empty_login_data_returns_empty() {
        let db = TestDb::new(SCHEMA);
        let events = parse_login_data(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn login_data_password_never_exposed() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO logins (origin_url, action_url, username_value, date_created, date_last_used) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["https://example.com", "https://example.com/login", "user@example.com", 13_327_626_000_000_000_i64, 13_327_626_000_000_000_i64],
        );
        let events = parse_login_data(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["password"], json!("ENCRYPTED"));
        // Ensure no raw password value exists anywhere in attrs
        for val in events[0].attrs.values() {
            assert_ne!(val, &json!("real_password_value"));
        }
    }

    #[test]
    fn login_data_emits_url_and_username() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO logins (origin_url, action_url, username_value, date_created, date_last_used) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["https://example.com", "https://example.com/login", "testuser", 13_327_626_000_000_000_i64, 0_i64],
        );
        let events = parse_login_data(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::LoginData);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs["origin_url"], json!("https://example.com"));
        assert_eq!(ev.attrs["username"], json!("testuser"));
    }
}
