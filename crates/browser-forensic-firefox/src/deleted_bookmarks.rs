//! Deleted-bookmark recovery from Firefox `bookmarkbackups/*.jsonlz4`.
//!
//! Firefox periodically writes a mozLz4-compressed JSON snapshot of the whole
//! bookmark tree to `<profile>/bookmarkbackups/bookmarks-YYYY-MM-DD_*.jsonlz4`
//! (Mozilla `toolkit/components/places/BookmarkJSONUtils.sys.mjs`). Each node
//! carries `type`/`typeCode` (1 = `text/x-moz-place` bookmark, 2 =
//! `text/x-moz-place-container` folder, 3 = separator), and bookmarks carry a
//! `uri`, `title`, and `dateAdded` (PRTime microseconds).
//!
//! Diffing a backup's bookmark URLs against the *current* `moz_bookmarks`
//! surfaces bookmarks that existed at backup time but are gone now — consistent
//! with deletion after that backup. The backup date bounds *when* the deletion
//! could have happened; it does not establish who deleted it or why.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::unix_micros_to_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

use crate::mozlz4::decompress_mozlz4;

/// A bookmark recovered from a backup, absent from the current profile.
struct RecoveredBookmark {
    url: String,
    title: String,
    date_added_us: i64,
    source_backup: String,
    backup_date: Option<String>,
}

/// Recover bookmarks present in a `bookmarkbackups/*.jsonlz4` backup but absent
/// from the profile's current `moz_bookmarks`.
///
/// `profile_dir` is a Firefox profile directory containing `places.sqlite` and
/// (optionally) a `bookmarkbackups/` directory.
///
/// # Errors
///
/// Errors loudly if `places.sqlite` is missing or unreadable — the current
/// bookmark set is the prerequisite for the diff (bootstrap failure). An absent
/// `bookmarkbackups/` directory is not an error (there is simply nothing to
/// recover); an individual malformed backup file is skipped, not fatal.
pub fn recover_deleted_bookmarks(_profile_dir: &Path) -> Result<Vec<BrowserEvent>> {
    // RED stub: real implementation lands in the GREEN commit.
    let _ = (
        current_bookmark_urls as fn(&Path) -> Result<std::collections::HashSet<String>>,
        collect_backup_bookmarks as fn(&Path) -> Result<Vec<(String, String, i64)>>,
        backup_date_from_name as fn(&str) -> Option<String>,
        unix_micros_to_nanos as fn(i64) -> i64,
        decompress_mozlz4 as fn(&[u8]) -> Result<Vec<u8>>,
        json!(0),
        ArtifactKind::RecoveredBookmark,
        BrowserFamily::Firefox,
        RecoveredBookmark {
            url: String::new(),
            title: String::new(),
            date_added_us: 0,
            source_backup: String::new(),
            backup_date: None,
        },
    );
    Ok(Vec::new())
}

/// Read the set of current bookmark URLs (`moz_bookmarks` type=1 -> `moz_places`).
fn current_bookmark_urls(places: &Path) -> Result<std::collections::HashSet<String>> {
    let db = open_evidence_db(places)
        .with_context(|| format!("opening current bookmarks from {}", places.display()))?;
    let mut stmt = db.conn.prepare(
        "SELECT p.url FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.type = 1",
    )?;
    let urls = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(std::result::Result::ok)
        .collect();
    Ok(urls)
}

/// Decompress + walk one backup, returning its (url, title, `date_added_us`)
/// bookmark tuples. Walk is iterative to bound stack use on hostile nesting.
fn collect_backup_bookmarks(_file: &Path) -> Result<Vec<(String, String, i64)>> {
    Err(anyhow!("stub"))
}

/// Extract the `YYYY-MM-DD` date from a `bookmarks-YYYY-MM-DD_*.jsonlz4` name.
fn backup_date_from_name(_name: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_places(dir: &Path, current: &[&str]) {
        let conn = Connection::open(dir.join("places.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT NOT NULL);
             CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER,
                 title TEXT, dateAdded INTEGER);",
        )
        .unwrap();
        for url in current {
            conn.execute("INSERT INTO moz_places (url) VALUES (?1)", [url])
                .unwrap();
            let pid = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO moz_bookmarks (type, fk, title, dateAdded) VALUES (1, ?1, ?2, 0)",
                rusqlite::params![pid, url],
            )
            .unwrap();
        }
    }

    /// Mint a `bookmarkbackups/<name>` mozLz4 file holding a bookmark tree.
    fn mint_backup(dir: &Path, name: &str, bookmarks: &[(&str, &str, i64)]) {
        let backups = dir.join("bookmarkbackups");
        std::fs::create_dir_all(&backups).unwrap();
        let children: Vec<_> = bookmarks
            .iter()
            .map(|(title, uri, added)| {
                json!({
                    "guid": "aaaaaaaaaaaa",
                    "title": title,
                    "typeCode": 1,
                    "type": "text/x-moz-place",
                    "uri": uri,
                    "dateAdded": added,
                })
            })
            .collect();
        let tree = json!({
            "guid": "root________",
            "title": "",
            "typeCode": 2,
            "type": "text/x-moz-place-container",
            "root": "placesRoot",
            "children": children,
        });
        let payload = serde_json::to_vec(&tree).unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(forensicnomicon::sqlite::MOZLZ4_MAGIC);
        framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(&lz4_flex::block::compress(&payload));
        std::fs::write(backups.join(name), framed).unwrap();
    }

    #[test]
    fn no_backups_returns_empty() {
        let dir = TempDir::new().unwrap();
        make_places(dir.path(), &["https://a.example/"]);
        assert!(recover_deleted_bookmarks(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn bookmark_in_backup_absent_from_current_is_recovered() {
        let dir = TempDir::new().unwrap();
        make_places(dir.path(), &["https://a.example/"]);
        mint_backup(
            dir.path(),
            "bookmarks-2024-06-01_2_hash.jsonlz4",
            &[
                ("Kept", "https://a.example/", 100),
                ("Deleted", "https://b.example/", 200),
            ],
        );
        let events = recover_deleted_bookmarks(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::RecoveredBookmark);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["url"], json!("https://b.example/"));
        assert_eq!(ev.attrs["title"], json!("Deleted"));
        assert_eq!(
            ev.attrs["source_backup"],
            json!("bookmarks-2024-06-01_2_hash.jsonlz4")
        );
        assert_eq!(ev.attrs["backup_date"], json!("2024-06-01"));
        assert_eq!(ev.timestamp_ns, 200 * 1_000);
    }

    #[test]
    fn bookmark_present_in_both_is_not_recovered() {
        let dir = TempDir::new().unwrap();
        make_places(dir.path(), &["https://a.example/"]);
        mint_backup(
            dir.path(),
            "bookmarks-2024-06-01_1_hash.jsonlz4",
            &[("Kept", "https://a.example/", 100)],
        );
        assert!(recover_deleted_bookmarks(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn recovered_dedup_attributes_newest_backup() {
        let dir = TempDir::new().unwrap();
        make_places(dir.path(), &["https://a.example/"]);
        // Same deleted URL in two backups; the newest should be attributed.
        mint_backup(
            dir.path(),
            "bookmarks-2024-01-01_2_old.jsonlz4",
            &[("Deleted", "https://b.example/", 200)],
        );
        mint_backup(
            dir.path(),
            "bookmarks-2024-06-01_2_new.jsonlz4",
            &[("Deleted", "https://b.example/", 200)],
        );
        let events = recover_deleted_bookmarks(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].attrs["source_backup"],
            json!("bookmarks-2024-06-01_2_new.jsonlz4")
        );
    }

    #[test]
    fn malformed_backup_is_skipped_not_fatal() {
        let dir = TempDir::new().unwrap();
        make_places(dir.path(), &["https://a.example/"]);
        mint_backup(
            dir.path(),
            "bookmarks-2024-06-01_2_good.jsonlz4",
            &[("Deleted", "https://b.example/", 200)],
        );
        // A garbage file alongside the good one must not abort the whole run.
        let mut f = std::fs::File::create(
            dir.path()
                .join("bookmarkbackups/bookmarks-2024-07-01_x.jsonlz4"),
        )
        .unwrap();
        f.write_all(b"not a mozLz4 file at all").unwrap();
        let events = recover_deleted_bookmarks(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["url"], json!("https://b.example/"));
    }

    #[test]
    fn missing_places_sqlite_errors_loudly() {
        let dir = TempDir::new().unwrap();
        // Backups but no places.sqlite -> the diff has no baseline (bootstrap).
        mint_backup(
            dir.path(),
            "bookmarks-2024-06-01_2_x.jsonlz4",
            &[("Any", "https://b.example/", 1)],
        );
        assert!(recover_deleted_bookmarks(dir.path()).is_err());
    }

    #[test]
    fn backup_date_from_name_parses_iso_date() {
        assert_eq!(
            backup_date_from_name("bookmarks-2026-05-15_10_hash=.jsonlz4"),
            Some("2026-05-15".to_string())
        );
        assert_eq!(backup_date_from_name("not-a-backup.jsonlz4"), None);
    }
}
