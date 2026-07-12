//! Chromium-family `Top Sites` parser.
//!
//! The `Top Sites` SQLite database caches the profile's most-visited pages for
//! the new-tab page: `top_sites(url, url_rank, title)`. The ranking is derived
//! from Chromium's frecency (frequency × recency) scoring, so a `url` here is
//! **consistent with** the page being among the profile's most-visited — not a
//! per-visit record and carrying no timestamp.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

const TOP_SITES_NOTE: &str =
    "among this profile's most-visited / top sites (frecency-ranked) — consistent \
     with the page being frequently and recently visited, not a per-visit record";

/// Parse a Chromium `Top Sites` database into most-visited events.
///
/// # Errors
///
/// Returns an error only if the SQLite file cannot be opened.
pub fn parse_top_sites(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let source = path.to_string_lossy().into_owned();

    let sql = "SELECT url, url_rank, title FROM top_sites WHERE url <> '' ORDER BY url_rank ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Ok(Vec::new());
    };
    let Ok(rows) = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let url_rank: i64 = row.get::<_, Option<i64>>(1)?.unwrap_or_default();
        let title: String = row.get::<_, Option<String>>(2)?.unwrap_or_default();
        Ok((url, url_rank, title))
    }) else {
        return Ok(Vec::new());
    };

    let events = rows
        .filter_map(std::result::Result::ok)
        .map(|(url, url_rank, title)| {
            let label = if title.is_empty() {
                url.clone()
            } else {
                title.clone()
            };
            BrowserEvent::new(
                0,
                BrowserFamily::Chromium,
                ArtifactKind::TopSite,
                &source,
                format!("{label} (top-site rank {url_rank})"),
            )
            .with_attr("url", json!(url))
            .with_attr("title", json!(title))
            .with_attr("url_rank", json!(url_rank))
            .with_attr("note", json!(TOP_SITES_NOTE))
        })
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    const SCHEMA: &str =
        "CREATE TABLE top_sites(url TEXT NOT NULL PRIMARY KEY, url_rank INTEGER NOT NULL, title TEXT NOT NULL);";

    #[test]
    fn parse_empty_top_sites_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_top_sites(db.path()).unwrap().is_empty());
    }

    #[test]
    fn parse_single_top_site_emits_event() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO top_sites (url, url_rank, title) VALUES (?1, ?2, ?3)",
            params!["https://news.example/", 0_i64, "News"],
        );
        let events = parse_top_sites(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::TopSite);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs["url"], json!("https://news.example/"));
        assert_eq!(ev.attrs["title"], json!("News"));
        assert_eq!(ev.attrs["url_rank"], json!(0));
    }

    #[test]
    fn missing_table_degrades_to_empty() {
        let db = TestDb::new("CREATE TABLE meta(key TEXT, value TEXT);");
        assert!(parse_top_sites(db.path()).unwrap().is_empty());
    }
}
