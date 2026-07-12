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
pub fn recover_deleted_bookmarks(profile_dir: &Path) -> Result<Vec<BrowserEvent>> {
    let places = profile_dir.join("places.sqlite");
    if !places.is_file() {
        return Err(anyhow!(
            "no places.sqlite in {} — the current bookmark set is the baseline required to diff \
             backups (bookmark recovery cannot proceed)",
            profile_dir.display()
        ));
    }
    let current = current_bookmark_urls(&places)?;

    let backups_dir = profile_dir.join("bookmarkbackups");
    if !backups_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(&backups_dir)?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonlz4"))
        .collect();
    entries.sort();

    // For each deleted URL, keep the newest backup (by date, then name) that
    // still contained it — the tightest "deleted after" bound.
    let mut recovered: BTreeMap<String, RecoveredBookmark> = BTreeMap::new();
    for file in entries {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let backup_date = backup_date_from_name(&name);
        // A malformed individual backup is skipped, not fatal (partial recovery).
        let Ok(bookmarks) = collect_backup_bookmarks(&file) else {
            continue;
        };
        for (url, title, date_added_us) in bookmarks {
            if current.contains(&url) {
                continue;
            }
            let cand_key = (backup_date.clone(), name.clone());
            let keep_existing = recovered
                .get(&url)
                .is_some_and(|ex| (ex.backup_date.clone(), ex.source_backup.clone()) >= cand_key);
            if keep_existing {
                continue;
            }
            recovered.insert(
                url.clone(),
                RecoveredBookmark {
                    url,
                    title,
                    date_added_us,
                    source_backup: name.clone(),
                    backup_date: backup_date.clone(),
                },
            );
        }
    }

    let mut events: Vec<BrowserEvent> = recovered
        .into_values()
        .map(|r| {
            let ts_ns = unix_micros_to_nanos(r.date_added_us);
            let source = backups_dir
                .join(&r.source_backup)
                .to_string_lossy()
                .into_owned();
            let date_str = r
                .backup_date
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let desc = format!(
                "recovered bookmark \u{201c}{}\u{201d} {} \u{2014} present in backup {} ({}), \
                 absent from current bookmarks (consistent with deletion after that backup)",
                r.title, r.url, r.source_backup, date_str
            );
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Firefox,
                ArtifactKind::RecoveredBookmark,
                source,
                desc,
            )
            .with_attr("url", json!(r.url))
            .with_attr("title", json!(r.title))
            .with_attr("date_added_us", json!(r.date_added_us))
            .with_attr("source_backup", json!(r.source_backup))
            .with_attr(
                "backup_date",
                r.backup_date.map_or(serde_json::Value::Null, |d| json!(d)),
            )
            .with_attr("status", json!("absent from current bookmarks"))
        })
        .collect();
    events.sort_by_key(|e| e.timestamp_ns);
    Ok(events)
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
fn collect_backup_bookmarks(file: &Path) -> Result<Vec<(String, String, i64)>> {
    use serde_json::Value;
    let data = std::fs::read(file)?;
    let json_bytes = decompress_mozlz4(&data)?;
    let root: Value = serde_json::from_slice(&json_bytes)
        .with_context(|| format!("parsing bookmark backup JSON from {}", file.display()))?;

    let mut out = Vec::new();
    // Iterative DFS over borrowed nodes: bounds stack use on hostile nesting.
    let mut stack: Vec<&Value> = vec![&root];
    while let Some(node) = stack.pop() {
        let is_place = node.get("typeCode").and_then(Value::as_i64) == Some(1)
            || node.get("type").and_then(Value::as_str) == Some("text/x-moz-place");
        if is_place {
            if let Some(uri) = node.get("uri").and_then(Value::as_str) {
                let title = node
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let added = node
                    .get("dateAdded")
                    .and_then(Value::as_i64)
                    .unwrap_or_default();
                out.push((uri.to_string(), title, added));
            }
        }
        if let Some(children) = node.get("children").and_then(Value::as_array) {
            for c in children {
                stack.push(c);
            }
        }
    }
    Ok(out)
}

/// Extract the `YYYY-MM-DD` date from a `bookmarks-YYYY-MM-DD_*.jsonlz4` name.
fn backup_date_from_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("bookmarks-")?;
    let date = rest.get(..10)?;
    let b = date.as_bytes();
    let well_formed = b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit);
    well_formed.then(|| date.to_string())
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
