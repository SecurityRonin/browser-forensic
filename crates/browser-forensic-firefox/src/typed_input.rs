//! Firefox `places.sqlite` typed-input parser (`moz_inputhistory`).
//!
//! `moz_inputhistory` records the string the user typed into the address bar
//! (`input`), the page it resolved to (`place_id` -> `moz_places`), and a
//! decayed `use_count`. It is direct evidence that the user *typed* the address,
//! distinct from a passive visit. Mozilla ref:
//! `toolkit/components/places/nsPlacesTables.h` (`CREATE_MOZ_INPUTHISTORY`).
//!
//! The table carries no per-keystroke timestamp, so events are emitted with a
//! zero timestamp; `use_count` is stored as a decayed floating-point value in
//! real profiles despite the column's `INTEGER` affinity.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Firefox `places.sqlite` file for typed address-bar input.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_typed_input(_path: &Path) -> Result<Vec<BrowserEvent>> {
    // RED stub: real implementation lands in the GREEN commit.
    let _ = (
        open_evidence_db,
        json!(0),
        ArtifactKind::TypedInput,
        BrowserFamily::Firefox,
    );
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    // Schema mirrors a real places.sqlite (verified on-disk):
    //   moz_inputhistory(place_id, input LONGVARCHAR, use_count) PK(place_id,input)
    const SCHEMA: &str = "CREATE TABLE moz_places (
        id  INTEGER PRIMARY KEY,
        url TEXT NOT NULL
    );
    CREATE TABLE moz_inputhistory (
        place_id  INTEGER NOT NULL,
        input     LONGVARCHAR NOT NULL,
        use_count INTEGER,
        PRIMARY KEY (place_id, input)
    );";

    fn seed_place(db: &TestDb, url: &str) -> i64 {
        db.insert("INSERT INTO moz_places (url) VALUES (?1)", params![url]);
        // TestDb rows are inserted sequentially from id 1.
        let conn = rusqlite::Connection::open(db.path()).unwrap();
        conn.query_row(
            "SELECT id FROM moz_places WHERE url=?1",
            params![url],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn empty_inputhistory_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_typed_input(db.path()).unwrap().is_empty());
    }

    #[test]
    fn single_typed_input_emits_event() {
        let db = TestDb::new(SCHEMA);
        let pid = seed_place(&db, "https://www.mozilla.org/");
        db.insert(
            "INSERT INTO moz_inputhistory (place_id, input, use_count) VALUES (?1, ?2, ?3)",
            params![pid, "moz", 0.5_f64],
        );
        let events = parse_typed_input(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::TypedInput);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["input"], json!("moz"));
        assert_eq!(ev.attrs["url"], json!("https://www.mozilla.org/"));
        assert!(ev.description.contains("moz"));
    }

    #[test]
    fn decayed_float_use_count_is_preserved() {
        // Real profiles store use_count as a decayed REAL despite INTEGER
        // affinity; the parser must read it as a float, not error.
        let db = TestDb::new(SCHEMA);
        let pid = seed_place(&db, "https://example.com/");
        db.insert(
            "INSERT INTO moz_inputhistory (place_id, input, use_count) VALUES (?1, ?2, ?3)",
            params![pid, "exa", 0.185_002_789_614_035_f64],
        );
        let events = parse_typed_input(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let uc = events[0].attrs["use_count"].as_f64().unwrap();
        assert!((uc - 0.185_002_789_614_035).abs() < 1e-9, "got {uc}");
    }

    #[test]
    fn input_without_matching_place_is_excluded() {
        // An inputhistory row whose place_id has no moz_places row must not
        // produce an event (inner join).
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO moz_inputhistory (place_id, input, use_count) VALUES (?1, ?2, ?3)",
            params![999_i64, "orphan", 1.0_f64],
        );
        assert!(parse_typed_input(db.path()).unwrap().is_empty());
    }
}
