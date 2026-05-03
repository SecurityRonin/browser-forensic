//! Chromium-family browser login data parser.
//!
//! Reads the `logins` table from a Chromium `Login Data` SQLite database and
//! emits [`BrowserEvent`]s with [`ArtifactKind::LoginData`].
//!
//! **Security note**: `password_value` is NEVER selected or exposed.
//! attrs always contain `"ENCRYPTED"` for the password field.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

use crate::history::webkit_to_unix_ns;

/// Parse a Chromium `Login Data` SQLite file.
///
/// CRITICAL: `password_value` is never selected or returned.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_login_data(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn create_login_data_db(rows: &[(&str, &str, &str, i64, i64)]) -> NamedTempFile {
        // rows: (origin_url, action_url, username_value, date_created, date_last_used)
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE logins (
                id              INTEGER PRIMARY KEY,
                origin_url      TEXT NOT NULL DEFAULT '',
                action_url      TEXT NOT NULL DEFAULT '',
                username_value  TEXT NOT NULL DEFAULT '',
                password_value  BLOB DEFAULT '',
                date_created    INTEGER NOT NULL DEFAULT 0,
                date_last_used  INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        for (origin, action, username, created, last_used) in rows {
            conn.execute(
                "INSERT INTO logins (origin_url, action_url, username_value, date_created, date_last_used) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![origin, action, username, created, last_used],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_login_data_returns_empty() {
        let f = create_login_data_db(&[]);
        let events = parse_login_data(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn login_data_password_never_exposed() {
        let f = create_login_data_db(&[(
            "https://example.com",
            "https://example.com/login",
            "user@example.com",
            13_327_626_000_000_000,
            13_327_626_000_000_000,
        )]);
        let events = parse_login_data(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["password"], json!("ENCRYPTED"));
        // Ensure no raw password value exists anywhere in attrs
        for (_key, val) in &events[0].attrs {
            assert_ne!(val, &json!("real_password_value"));
        }
    }

    #[test]
    fn login_data_emits_url_and_username() {
        let f = create_login_data_db(&[(
            "https://example.com",
            "https://example.com/login",
            "testuser",
            13_327_626_000_000_000,
            0,
        )]);
        let events = parse_login_data(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::LoginData);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs["origin_url"], json!("https://example.com"));
        assert_eq!(ev.attrs["username"], json!("testuser"));
    }
}
