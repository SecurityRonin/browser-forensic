//! Firefox `formhistory.sqlite` autofill parser.
//!
//! Reads form history entries from `moz_formhistory` table and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Autofill`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Firefox `formhistory.sqlite` file.
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

    fn create_formhistory_db(rows: &[(&str, &str, i64, i64, i64)]) -> NamedTempFile {
        // rows: (fieldname, value, times_used, first_used_us, last_used_us)
        let f = NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_formhistory (
                id        INTEGER PRIMARY KEY,
                fieldname TEXT NOT NULL,
                value     TEXT NOT NULL,
                timesUsed INTEGER NOT NULL DEFAULT 0,
                firstUsed INTEGER NOT NULL DEFAULT 0,
                lastUsed  INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        for (fieldname, value, times_used, first_used, last_used) in rows {
            conn.execute(
                "INSERT INTO moz_formhistory (fieldname, value, timesUsed, firstUsed, lastUsed) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![fieldname, value, times_used, first_used, last_used],
            )
            .unwrap();
        }
        f
    }

    #[test]
    fn parse_empty_formhistory_returns_empty() {
        let f = create_formhistory_db(&[]);
        let events = parse_autofill(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_formhistory_entry() {
        let first_used_us = 1_648_000_000_000_000_i64;
        let f = create_formhistory_db(&[("email", "user@example.com", 5, first_used_us, 0)]);
        let events = parse_autofill(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Autofill);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["fieldname"], json!("email"));
        assert_eq!(ev.attrs["value"], json!("user@example.com"));
        assert_eq!(ev.timestamp_ns, first_used_us * 1_000);
    }
}
