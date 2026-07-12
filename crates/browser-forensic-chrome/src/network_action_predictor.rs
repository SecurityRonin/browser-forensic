//! Chromium-family `Network Action Predictor` parser.
//!
//! Chromium logs every omnibox prefix the user typed and the URL it learned to
//! predict in `network_action_predictor(user_text, url, number_of_hits,
//! number_of_misses)`. Unlike `Shortcuts` (only selected shortcuts), this table
//! keeps **partial** typed strings — often the incremental prefixes of a single
//! query (`s`, `se`, `sec`, `secu`, …) — so the `user_text` is a direct record
//! of what the user typed, stated as fact. There is no per-row timestamp.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

const NAP_NOTE: &str = "the user typed this (often partial) string into the omnibox; the browser \
     associated it with this predicted URL — user_text is what was typed (fact)";

/// Parse a Chromium `Network Action Predictor` database into typed-prefix events.
///
/// # Errors
///
/// Returns an error only if the SQLite file cannot be opened.
pub fn parse_network_action_predictor(_path: &Path) -> Result<Vec<BrowserEvent>> {
    // RED stub — replaced by the real query in GREEN.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    const SCHEMA: &str = "CREATE TABLE network_action_predictor (id TEXT PRIMARY KEY, user_text TEXT, url TEXT, number_of_hits INTEGER, number_of_misses INTEGER);";

    #[test]
    fn parse_empty_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_network_action_predictor(db.path())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn parse_single_row_surfaces_user_text() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO network_action_predictor VALUES ('n1', ?1, ?2, ?3, ?4)",
            params![
                "sec",
                "https://github.com/SecurityRonin/issen",
                0_i64,
                10_i64
            ],
        );
        let events = parse_network_action_predictor(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::NetworkPrediction);
        assert_eq!(ev.attrs["user_text"], json!("sec"));
        assert_eq!(
            ev.attrs["url"],
            json!("https://github.com/SecurityRonin/issen")
        );
        assert_eq!(ev.attrs["number_of_hits"], json!(0));
        assert_eq!(ev.attrs["number_of_misses"], json!(10));
        assert_eq!(ev.timestamp_ns, 0);
    }

    #[test]
    fn empty_user_text_is_skipped() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO network_action_predictor VALUES ('n2', '', 'https://x.example/', 1, 0)",
            params![],
        );
        assert!(parse_network_action_predictor(db.path())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn missing_table_degrades_to_empty() {
        let db = TestDb::new("CREATE TABLE meta(key TEXT, value TEXT);");
        assert!(parse_network_action_predictor(db.path())
            .unwrap()
            .is_empty());
    }
}
