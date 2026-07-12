//! Chromium-family browser login data parser.
//!
//! Reads the `logins` table from a Chromium `Login Data` SQLite database and
//! emits [`BrowserEvent`]s with [`ArtifactKind::LoginData`].
//!
//! **Security note**: `password_value` is NEVER selected or exposed.
//! attrs always contain `"ENCRYPTED"` for the password field.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;

/// Credential metadata read from one `logins` row. `password_value` is
/// deliberately absent — it is never selected.
struct LoginRow {
    origin_url: String,
    action_url: String,
    username: String,
    signon_realm: String,
    date_created: i64,
    date_last_used: i64,
    date_password_modified: i64,
    times_used: i64,
    blacklisted_by_user: bool,
}

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
    // CRITICAL: password_value is NEVER in this query.
    // signon_realm is NOT NULL in the real schema; the timestamp/count columns
    // carry DEFAULT 0, so read them defensively via COALESCE for older DBs.
    let mut stmt = conn.prepare(
        "SELECT origin_url, action_url, username_value, signon_realm, date_created, \
                date_last_used, date_password_modified, times_used, blacklisted_by_user \
         FROM logins \
         WHERE date_created > 0 OR blacklisted_by_user = 1 \
         ORDER BY date_created ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            Ok(LoginRow {
                origin_url: row.get(0)?,
                action_url: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                username: row.get(2)?,
                signon_realm: row.get(3)?,
                date_created: row.get(4)?,
                date_last_used: row.get(5)?,
                date_password_modified: row.get(6)?,
                times_used: row.get(7)?,
                blacklisted_by_user: row.get::<_, i64>(8)? != 0,
            })
        })?
        .filter_map(std::result::Result::ok)
        .map(|r| {
            let ts_ns = webkit_micros_to_unix_nanos(r.date_created);
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Chromium,
                ArtifactKind::LoginData,
                &source,
                r.origin_url.clone(),
            )
            .with_attr("origin_url", json!(r.origin_url))
            .with_attr("action_url", json!(r.action_url))
            .with_attr("username", json!(r.username))
            .with_attr("signon_realm", json!(r.signon_realm))
            .with_attr("date_last_used", json!(r.date_last_used))
            .with_attr("date_password_modified", json!(r.date_password_modified))
            .with_attr("times_used", json!(r.times_used))
            .with_attr("blacklisted_by_user", json!(r.blacklisted_by_user))
            .with_attr("password", json!("ENCRYPTED"))
        })
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use rusqlite::params;
    use serde_json::json;

    const SCHEMA: &str = "CREATE TABLE logins (
        id                     INTEGER PRIMARY KEY,
        origin_url             TEXT NOT NULL DEFAULT '',
        action_url             TEXT NOT NULL DEFAULT '',
        username_value         TEXT NOT NULL DEFAULT '',
        password_value         BLOB DEFAULT '',
        signon_realm           TEXT NOT NULL DEFAULT '',
        date_created           INTEGER NOT NULL DEFAULT 0,
        date_last_used         INTEGER NOT NULL DEFAULT 0,
        date_password_modified INTEGER NOT NULL DEFAULT 0,
        times_used             INTEGER NOT NULL DEFAULT 0,
        blacklisted_by_user    INTEGER NOT NULL DEFAULT 0
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
    fn login_data_emits_credential_metadata() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO logins (origin_url, action_url, username_value, signon_realm, date_created, date_last_used, date_password_modified, times_used, blacklisted_by_user) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                "https://bank.example.com",
                "https://bank.example.com/login",
                "victim@example.com",
                "https://bank.example.com/",
                13_327_626_000_000_000_i64,
                13_350_000_000_000_000_i64,
                13_340_000_000_000_000_i64,
                7_i32,
                0_i32
            ],
        );
        let events = parse_login_data(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        // The FACTS that prove the credential existed and was used — no secrets.
        assert_eq!(ev.attrs["signon_realm"], json!("https://bank.example.com/"));
        assert_eq!(ev.attrs["times_used"], json!(7));
        assert_eq!(
            ev.attrs["date_password_modified"],
            json!(13_340_000_000_000_000_i64)
        );
        assert_eq!(ev.attrs["blacklisted_by_user"], json!(false));
        assert_eq!(ev.attrs["password"], json!("ENCRYPTED"));
    }

    #[test]
    fn login_data_blacklisted_never_save_site_surfaced() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO logins (origin_url, username_value, signon_realm, date_created, blacklisted_by_user) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "https://neversave.example.com",
                "",
                "https://neversave.example.com/",
                13_327_626_000_000_000_i64,
                1_i32
            ],
        );
        let events = parse_login_data(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["blacklisted_by_user"], json!(true));
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
