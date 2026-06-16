//! Chromium-family browser autofill parser.
//!
//! Reads the `autofill` table from a Chromium `Web Data` SQLite database and
//! emits [`BrowserEvent`]s with [`ArtifactKind::Autofill`].
//!
//! **IMPORTANT**: `date_created` in the autofill table is Unix epoch SECONDS,
//! NOT WebKit microseconds. Convert with `ts_ns = date_created * 1_000_000_000`.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::unix_secs_to_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Chromium `Web Data` SQLite file for autofill entries.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_autofill(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut stmt = conn.prepare(
        "SELECT name, value, count, date_created, date_last_used \
         FROM autofill \
         WHERE date_created > 0 \
         ORDER BY date_created ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let value: String = row.get(1)?;
            let count: i32 = row.get(2)?;
            let date_created: i64 = row.get(3)?;
            let date_last_used: i64 = row.get(4)?;
            Ok((name, value, count, date_created, date_last_used))
        })?
        .filter_map(std::result::Result::ok)
        .map(|(name, value, count, date_created, date_last_used)| {
            // NOTE: date_created is Unix epoch SECONDS, not WebKit microseconds
            let ts_ns = unix_secs_to_nanos(date_created);
            let desc = format!("{name}: {value}");
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Chromium,
                ArtifactKind::Autofill,
                &source,
                desc,
            )
            .with_attr("name", json!(name))
            .with_attr("value", json!(value))
            .with_attr("count", json!(count))
            .with_attr("date_last_used", json!(date_last_used))
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

    const SCHEMA: &str = "CREATE TABLE autofill (
        name           TEXT NOT NULL,
        value          TEXT NOT NULL,
        count          INTEGER NOT NULL DEFAULT 0,
        date_created   INTEGER NOT NULL DEFAULT 0,
        date_last_used INTEGER NOT NULL DEFAULT 0
    );";

    #[test]
    fn parse_empty_autofill_returns_empty() {
        let db = TestDb::new(SCHEMA);
        let events = parse_autofill(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_autofill_entry() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO autofill (name, value, count, date_created, date_last_used) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["email", "user@example.com", 5_i32, 1_648_000_000_i64, 1_650_000_000_i64],
        );
        let events = parse_autofill(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Autofill);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs["name"], json!("email"));
        assert_eq!(ev.attrs["value"], json!("user@example.com"));
    }

    #[test]
    fn autofill_uses_unix_seconds_not_webkit() {
        let date_created_secs = 1_648_000_000_i64;
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO autofill (name, value, count, date_created, date_last_used) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["name_field", "John", 1_i32, date_created_secs, 0_i64],
        );
        let events = parse_autofill(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        // Must use Unix epoch seconds * 1_000_000_000, NOT webkit_to_unix_ns
        assert_eq!(events[0].timestamp_ns, date_created_secs * 1_000_000_000);
    }
}
