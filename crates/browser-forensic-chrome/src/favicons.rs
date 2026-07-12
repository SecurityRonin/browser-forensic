//! Chromium-family `Favicons` parser.
//!
//! The `Favicons` SQLite database maps every page the browser rendered to the
//! favicon it fetched: `icon_mapping(page_url → icon_id)` ⋈ `favicons(id, url)`
//! ⋈ `favicon_bitmaps(icon_id, last_updated, width)`. The `page_url` values are
//! cleartext and make the database an independent source of visited URLs — a
//! favicon is stored whenever a page is rendered (also for bookmarks and some
//! suggestions), so a `page_url` here is **consistent with** the page having
//! been visited, not proof of a deliberate navigation.
//!
//! `last_updated` is `ToDeltaSinceWindowsEpoch().InMicroseconds()` (WebKit
//! microseconds), converted with the shared timestamp helper.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

const FAVICON_NOTE: &str =
    "favicon stored for this page — consistent with the page having been visited \
     (favicons are also fetched for bookmarks and some suggestions)";

/// Parse a Chromium `Favicons` database into per-page favicon events.
///
/// Joins `icon_mapping` → `favicons` → `favicon_bitmaps` and emits one
/// [`BrowserEvent`] per stored bitmap, surfacing `page_url`, `icon_url`,
/// `last_updated`, and the bitmap `width`. Missing tables (schema drift across
/// Chromium versions) degrade cleanly to an empty result.
///
/// # Errors
///
/// Returns an error only if the SQLite file cannot be opened.
pub fn parse_favicons(_path: &Path) -> Result<Vec<BrowserEvent>> {
    // RED stub — replaced by the real join in GREEN.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    const SCHEMA: &str = "CREATE TABLE icon_mapping(id INTEGER PRIMARY KEY, page_url LONGVARCHAR NOT NULL, icon_id INTEGER, page_url_type INTEGER DEFAULT 0);
        CREATE TABLE favicons(id INTEGER PRIMARY KEY, url LONGVARCHAR NOT NULL, icon_type INTEGER DEFAULT 1);
        CREATE TABLE favicon_bitmaps(id INTEGER PRIMARY KEY, icon_id INTEGER NOT NULL, last_updated INTEGER DEFAULT 0, image_data BLOB, width INTEGER DEFAULT 0, height INTEGER DEFAULT 0, last_requested INTEGER DEFAULT 0);";

    fn webkit_for_unix(unix_secs: i64) -> i64 {
        (unix_secs + 11_644_473_600) * 1_000_000
    }

    fn seed(db: &TestDb, page: &str, icon: &str, last_updated: i64, width: i64) {
        db.insert(
            "INSERT INTO favicons (id, url) VALUES (1, ?1)",
            params![icon],
        );
        db.insert(
            "INSERT INTO icon_mapping (page_url, icon_id) VALUES (?1, 1)",
            params![page],
        );
        db.insert(
            "INSERT INTO favicon_bitmaps (icon_id, last_updated, width) VALUES (1, ?1, ?2)",
            params![last_updated, width],
        );
    }

    #[test]
    fn parse_empty_favicons_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_favicons(db.path()).unwrap().is_empty());
    }

    #[test]
    fn parse_single_page_emits_event() {
        let db = TestDb::new(SCHEMA);
        let lu = webkit_for_unix(1_700_000_000);
        seed(
            &db,
            "https://example.com/page",
            "https://example.com/favicon.ico",
            lu,
            16,
        );
        let events = parse_favicons(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Favicon);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs["page_url"], json!("https://example.com/page"));
        assert_eq!(ev.attrs["url"], json!("https://example.com/page"));
        assert_eq!(
            ev.attrs["icon_url"],
            json!("https://example.com/favicon.ico")
        );
        assert_eq!(ev.attrs["width"], json!(16));
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn missing_tables_degrade_to_empty() {
        let db = TestDb::new("CREATE TABLE meta(key TEXT, value TEXT);");
        assert!(parse_favicons(db.path()).unwrap().is_empty());
    }

    #[test]
    fn zero_last_updated_yields_zero_timestamp() {
        let db = TestDb::new(SCHEMA);
        seed(
            &db,
            "https://z.example/",
            "https://z.example/fav.ico",
            0,
            32,
        );
        let events = parse_favicons(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, 0);
    }
}
