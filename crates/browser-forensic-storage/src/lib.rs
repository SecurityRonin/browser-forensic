#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Web-storage artifact parsers for browser forensics.
//!
//! Covers the three web-storage backends the browsers use:
//!
//! * **Chromium Local / Session Storage** — LevelDB, decoded via the published
//!   [`leveldb_forensic`] crate ([`parse_local_storage`],
//!   [`parse_session_storage`]).
//! * **Chromium IndexedDB** — LevelDB; values are Blink/v8-serialized and
//!   surfaced as opaque raw records rather than a fabricated decode
//!   ([`parse_indexeddb`]).
//! * **Firefox web storage** — plain SQLite: `webappsstore.sqlite`
//!   ([`parse_firefox_local_storage`]) and `storage/default/*/idb/*.sqlite`
//!   ([`parse_firefox_indexeddb`]).
//!
//! Every parser emits [`BrowserEvent`]s with [`ArtifactKind::LocalStorage`],
//! distinguished by a `storage_type` attr (`local_storage`, `session_storage`,
//! `indexeddb`). [`parse_path`] auto-detects the backend from a file or
//! directory; [`collect_chromium_web_storage`] / [`collect_firefox_web_storage`]
//! aggregate every web-storage source found under a profile directory.

pub mod chromium;
pub mod firefox;

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::BrowserEvent;

pub use chromium::{parse_indexeddb, parse_local_storage, parse_session_storage};
pub use firefox::{parse_firefox_indexeddb, parse_firefox_local_storage};

/// `storage_type` attr value for Local Storage events.
pub const STORAGE_TYPE_LOCAL: &str = "local_storage";
/// `storage_type` attr value for Session Storage events.
pub const STORAGE_TYPE_SESSION: &str = "session_storage";
/// `storage_type` attr value for IndexedDB events.
pub const STORAGE_TYPE_INDEXEDDB: &str = "indexeddb";

/// Lowercase-hex encode raw bytes (used to surface raw keys/values verbatim).
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let _ = bytes;
    String::new()
}

/// True if `dir` looks like a LevelDB directory (has a `CURRENT` file or any
/// `.ldb`/`.sst`/`.log` file).
pub(crate) fn is_leveldb_dir(dir: &Path) -> bool {
    let _ = dir;
    false
}

/// Auto-detect the web-storage backend at `path` and parse it.
///
/// * A `webappsstore.sqlite` file → Firefox Local Storage; any other `.sqlite`
///   → Firefox IndexedDB.
/// * A LevelDB directory → Chromium Local / Session Storage / IndexedDB,
///   classified by the enclosing path.
/// * Any other directory is treated as a profile directory: every Chromium and
///   Firefox web-storage source found beneath it is aggregated.
///
/// # Errors
///
/// Returns an error if `path` does not exist, is an unrecognized file, or is a
/// directory holding no recognized web storage.
pub fn parse_path(path: &Path) -> Result<Vec<BrowserEvent>> {
    let _ = path;
    Ok(Vec::new())
}

/// Aggregate every Chromium web-storage source found under a profile directory:
/// `Local Storage/leveldb`, `Session Storage`, and each `IndexedDB/*.leveldb`.
/// A single unreadable source is skipped; the rest are still returned.
#[must_use]
pub fn collect_chromium_web_storage(profile_dir: &Path) -> Vec<BrowserEvent> {
    let _ = profile_dir;
    Vec::new()
}

/// Aggregate every Firefox web-storage source found under a profile directory:
/// `webappsstore.sqlite` and each `storage/default/*/idb/*.sqlite`.
/// A single unreadable source is skipped; the rest are still returned.
#[must_use]
pub fn collect_firefox_web_storage(profile_dir: &Path) -> Vec<BrowserEvent> {
    let _ = profile_dir;
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn to_hex_encodes_lowercase() {
        assert_eq!(to_hex(&[0x01, 0xab, 0xff]), "01abff");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn is_leveldb_dir_detects_current_file() {
        let dir = TempDir::new().unwrap();
        assert!(!is_leveldb_dir(dir.path()));
        fs::write(dir.path().join("CURRENT"), b"MANIFEST-000001\n").unwrap();
        assert!(is_leveldb_dir(dir.path()));
    }

    #[test]
    fn is_leveldb_dir_detects_ldb_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("000005.ldb"), b"x").unwrap();
        assert!(is_leveldb_dir(dir.path()));
    }

    #[test]
    fn parse_path_nonexistent_errors() {
        assert!(parse_path(Path::new("/nonexistent/web-storage")).is_err());
    }

    #[test]
    fn parse_path_unrecognized_file_errors() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("notes.txt");
        fs::write(&f, b"hello").unwrap();
        assert!(parse_path(&f).is_err());
    }

    #[test]
    fn parse_path_routes_webappsstore() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("webappsstore.sqlite");
        let conn = rusqlite::Connection::open(&f).unwrap();
        conn.execute_batch(
            "CREATE TABLE webappsstore2 (scope TEXT, key TEXT, value TEXT);
             INSERT INTO webappsstore2 VALUES ('moc.elpmaxe.:http:80', 'k', 'v');",
        )
        .unwrap();
        drop(conn);
        let events = parse_path(&f).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["storage_type"], json_local());
    }

    #[test]
    fn parse_path_empty_profile_dir_errors() {
        let dir = TempDir::new().unwrap();
        assert!(parse_path(dir.path()).is_err());
    }

    #[test]
    fn collect_chromium_aggregates_local_storage() {
        let profile = TempDir::new().unwrap();
        let ls = profile.path().join("Local Storage").join("leveldb");
        build_real_leveldb(&ls, &[(b"_http://example.com\x00\x01theme", b"\x01dark")]);
        let events = collect_chromium_web_storage(profile.path());
        assert!(!events.is_empty(), "local storage should be picked up");
    }

    #[test]
    fn collect_firefox_aggregates_local_and_idb() {
        let profile = TempDir::new().unwrap();
        // webappsstore.sqlite
        let ls = profile.path().join("webappsstore.sqlite");
        let conn = rusqlite::Connection::open(&ls).unwrap();
        conn.execute_batch(
            "CREATE TABLE webappsstore2 (scope TEXT, key TEXT, value TEXT);
             INSERT INTO webappsstore2 VALUES ('moc.elpmaxe.:http:80', 'k', 'v');",
        )
        .unwrap();
        drop(conn);
        // storage/default/<origin>/idb/<db>.sqlite
        let idb = profile
            .path()
            .join("storage")
            .join("default")
            .join("https+++example.com")
            .join("idb");
        fs::create_dir_all(&idb).unwrap();
        let idb_file = idb.join("1234.sqlite");
        let conn = rusqlite::Connection::open(&idb_file).unwrap();
        conn.execute_batch(
            "CREATE TABLE object_data (object_store_id INTEGER, key BLOB, data BLOB);
             INSERT INTO object_data VALUES (1, x'0102', x'deadbeef');",
        )
        .unwrap();
        drop(conn);

        let events = collect_firefox_web_storage(profile.path());
        assert!(events
            .iter()
            .any(|e| e.attrs["storage_type"] == json_local()));
        assert!(events
            .iter()
            .any(|e| e.attrs["storage_type"] == json_indexeddb()));
    }

    fn json_local() -> serde_json::Value {
        serde_json::json!(STORAGE_TYPE_LOCAL)
    }
    fn json_indexeddb() -> serde_json::Value {
        serde_json::json!(STORAGE_TYPE_INDEXEDDB)
    }

    /// Build a real on-disk LevelDB directory at `path`.
    fn build_real_leveldb(path: &Path, entries: &[(&[u8], &[u8])]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut opt = rusty_leveldb::Options::default();
        opt.create_if_missing = true;
        let mut db = rusty_leveldb::DB::open(path, opt).unwrap();
        for (k, v) in entries {
            db.put(k, v).unwrap();
        }
        db.flush().unwrap();
        db.close().unwrap();
    }
}
