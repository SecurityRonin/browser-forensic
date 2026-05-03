//! Chromium-family browser autofill parser.
//!
//! Reads the `autofill` table from a Chromium `Web Data` SQLite database and
//! emits [`BrowserEvent`]s with [`ArtifactKind::Autofill`].
//!
//! **IMPORTANT**: `date_created` in the autofill table is Unix epoch SECONDS,
//! NOT WebKit microseconds. Convert with `ts_ns = date_created * 1_000_000_000`.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Chromium `Web Data` SQLite file for autofill entries.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_autofill(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn create_autofill_db(rows: &[(&str, &str, i32, i64, i64)]) -> NamedTempFile {
        // rows: (name, value, count, date_created_secs, date_last_used_secs)
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE autofill (
                name           TEXT NOT NULL,
                value          TEXT NOT NULL,
                count          INTEGER NOT NULL DEFAULT 0,
                date_created   INTEGER NOT NULL DEFAULT 0,
                date_last_used INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        for (name, value, count, date_created, date_last_used) in rows {
            conn.execute(
                "INSERT INTO autofill (name, value, count, date_created, date_last_used) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![name, value, count, date_created, date_last_used],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_autofill_returns_empty() {
        let f = create_autofill_db(&[]);
        let events = parse_autofill(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_autofill_entry() {
        let f = create_autofill_db(&[("email", "user@example.com", 5, 1_648_000_000, 1_650_000_000)]);
        let events = parse_autofill(f.path()).unwrap();
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
        let f = create_autofill_db(&[("name_field", "John", 1, date_created_secs, 0)]);
        let events = parse_autofill(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        // Must use Unix epoch seconds * 1_000_000_000, NOT webkit_to_unix_ns
        assert_eq!(events[0].timestamp_ns, date_created_secs * 1_000_000_000);
    }
}
