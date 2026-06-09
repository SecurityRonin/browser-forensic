//! Firefox `formhistory.sqlite` autofill parser.
//!
//! Reads form history entries from `moz_formhistory` table and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Autofill`].

use std::path::Path;

use anyhow::Result;
use browser_core::timestamp::unix_micros_to_nanos;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use rusqlite::Connection;
use serde_json::json;

/// Parse a Firefox `formhistory.sqlite` file.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_autofill(path: &Path) -> Result<Vec<BrowserEvent>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT fieldname, value, timesUsed, firstUsed, lastUsed \
         FROM moz_formhistory \
         WHERE firstUsed > 0 \
         ORDER BY firstUsed ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let fieldname: String = row.get(0)?;
            let value: String = row.get(1)?;
            let times_used: i64 = row.get(2)?;
            let first_used_us: i64 = row.get(3)?;
            let last_used_us: i64 = row.get(4)?;
            Ok((fieldname, value, times_used, first_used_us, last_used_us))
        })?
        .filter_map(|r| r.ok())
        .map(
            |(fieldname, value, times_used, first_used_us, _last_used_us)| {
                let ts_ns = unix_micros_to_nanos(first_used_us);
                let desc = format!("{fieldname}: {value}");
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Firefox,
                    ArtifactKind::Autofill,
                    &source,
                    desc,
                )
                .with_attr("fieldname", json!(fieldname))
                .with_attr("value", json!(value))
                .with_attr("times_used", json!(times_used))
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

    const SCHEMA: &str = "CREATE TABLE moz_formhistory (
        id        INTEGER PRIMARY KEY,
        fieldname TEXT NOT NULL,
        value     TEXT NOT NULL,
        timesUsed INTEGER NOT NULL DEFAULT 0,
        firstUsed INTEGER NOT NULL DEFAULT 0,
        lastUsed  INTEGER NOT NULL DEFAULT 0
    );";

    #[test]
    fn parse_empty_formhistory_returns_empty() {
        let db = TestDb::new(SCHEMA);
        let events = parse_autofill(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_formhistory_entry() {
        let first_used_us = 1_648_000_000_000_000_i64;
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO moz_formhistory (fieldname, value, timesUsed, firstUsed, lastUsed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["email", "user@example.com", 5_i64, first_used_us, 0_i64],
        );
        let events = parse_autofill(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Autofill);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["fieldname"], json!("email"));
        assert_eq!(ev.attrs["value"], json!("user@example.com"));
        assert_eq!(ev.timestamp_ns, first_used_us * 1_000);
    }
}
