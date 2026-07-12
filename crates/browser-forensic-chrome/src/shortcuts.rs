//! Chromium-family `Shortcuts` parser.
//!
//! The `Shortcuts` SQLite database backs the omnibox (address-bar) shortcut
//! provider: `omni_box_shortcuts(text, fill_into_edit, url, contents,
//! last_access_time, number_of_hits, …)`. The `text` column is **the exact
//! string the user typed into the omnibox** that led them to select `url` — a
//! direct record of user intent, stated as fact. `last_access_time` is WebKit
//! microseconds; `number_of_hits` counts how often the shortcut was reinforced.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

const SHORTCUT_NOTE: &str =
    "the user typed this exact string into the omnibox (address bar) and selected \
     the resulting URL; the browser saved it as a shortcut";

/// Parse a Chromium `Shortcuts` database into omnibox typed-text events.
///
/// # Errors
///
/// Returns an error only if the SQLite file cannot be opened.
pub fn parse_shortcuts(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let source = path.to_string_lossy().into_owned();

    let sql = "SELECT text, fill_into_edit, url, contents, last_access_time, number_of_hits \
               FROM omni_box_shortcuts \
               WHERE text <> '' \
               ORDER BY last_access_time ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Ok(Vec::new());
    };
    let Ok(rows) = stmt.query_map([], |row| {
        let text: String = row.get(0)?;
        let fill_into_edit: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        let url: String = row.get::<_, Option<String>>(2)?.unwrap_or_default();
        let contents: String = row.get::<_, Option<String>>(3)?.unwrap_or_default();
        let last_access_time: i64 = row.get::<_, Option<i64>>(4)?.unwrap_or_default();
        let number_of_hits: i64 = row.get::<_, Option<i64>>(5)?.unwrap_or_default();
        Ok((
            text,
            fill_into_edit,
            url,
            contents,
            last_access_time,
            number_of_hits,
        ))
    }) else {
        return Ok(Vec::new());
    };

    let events = rows
        .filter_map(std::result::Result::ok)
        .map(
            |(text, fill_into_edit, url, contents, last_access_time, number_of_hits)| {
                let ts_ns = if last_access_time > 0 {
                    webkit_micros_to_unix_nanos(last_access_time)
                } else {
                    0
                };
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Chromium,
                    ArtifactKind::Shortcut,
                    &source,
                    format!("typed \u{201c}{text}\u{201d} \u{2192} {url}"),
                )
                .with_attr("typed_text", json!(text))
                .with_attr("fill_into_edit", json!(fill_into_edit))
                .with_attr("url", json!(url))
                .with_attr("contents", json!(contents))
                .with_attr("last_access_time", json!(last_access_time))
                .with_attr("number_of_hits", json!(number_of_hits))
                .with_attr("note", json!(SHORTCUT_NOTE))
            },
        )
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    const SCHEMA: &str = "CREATE TABLE omni_box_shortcuts (id VARCHAR PRIMARY KEY, text VARCHAR, fill_into_edit VARCHAR, url VARCHAR, document_type INTEGER, contents VARCHAR, contents_class VARCHAR, description VARCHAR, description_class VARCHAR, transition INTEGER, type INTEGER, keyword VARCHAR, last_access_time INTEGER, number_of_hits INTEGER);";

    fn webkit_for_unix(unix_secs: i64) -> i64 {
        (unix_secs + 11_644_473_600) * 1_000_000
    }

    #[test]
    fn parse_empty_shortcuts_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_shortcuts(db.path()).unwrap().is_empty());
    }

    #[test]
    fn parse_single_shortcut_surfaces_typed_text() {
        let db = TestDb::new(SCHEMA);
        let lat = webkit_for_unix(1_700_000_000);
        db.insert(
            "INSERT INTO omni_box_shortcuts (id, text, fill_into_edit, url, contents, last_access_time, number_of_hits) VALUES ('g1', ?1, ?2, ?3, ?4, ?5, ?6)",
            params!["github", "github.com", "https://github.com/", "GitHub", lat, 131_i64],
        );
        let events = parse_shortcuts(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Shortcut);
        assert_eq!(ev.attrs["typed_text"], json!("github"));
        assert_eq!(ev.attrs["url"], json!("https://github.com/"));
        assert_eq!(ev.attrs["number_of_hits"], json!(131));
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn empty_text_row_is_skipped() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO omni_box_shortcuts (id, text, url, last_access_time, number_of_hits) VALUES ('g2', '', 'https://x.example/', 0, 0)",
            params![],
        );
        assert!(parse_shortcuts(db.path()).unwrap().is_empty());
    }

    #[test]
    fn missing_table_degrades_to_empty() {
        let db = TestDb::new("CREATE TABLE meta(key TEXT, value TEXT);");
        assert!(parse_shortcuts(db.path()).unwrap().is_empty());
    }
}
