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
pub mod indexeddb;

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
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// True if `dir` looks like a LevelDB directory (has a `CURRENT` file or any
/// `.ldb`/`.sst`/`.log` file).
pub(crate) fn is_leveldb_dir(dir: &Path) -> bool {
    if dir.join("CURRENT").is_file() {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.path()
            .extension()
            .is_some_and(|ext| ext == "ldb" || ext == "sst" || ext == "log")
    })
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
    if !path.exists() {
        anyhow::bail!("web-storage path does not exist: {}", path.display());
    }
    if path.is_file() {
        return parse_file(path);
    }
    if is_leveldb_dir(path) {
        return parse_leveldb_dir(path);
    }
    // Treat any other directory as a profile directory and aggregate.
    let mut events = collect_chromium_web_storage(path);
    events.extend(collect_firefox_web_storage(path));
    if events.is_empty() {
        anyhow::bail!(
            "{} is not a LevelDB directory and contains no recognized web storage \
             (Local Storage/leveldb, Session Storage, IndexedDB/*.leveldb, \
             webappsstore.sqlite, storage/default/*/idb/*.sqlite)",
            path.display()
        );
    }
    Ok(events)
}

/// Route a single web-storage *file* to the matching Firefox parser.
fn parse_file(path: &Path) -> Result<Vec<BrowserEvent>> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name == "webappsstore.sqlite" {
        return parse_firefox_local_storage(path);
    }
    if name.ends_with(".sqlite") {
        // Firefox IndexedDB lives at storage/default/*/idb/*.sqlite; any other
        // .sqlite is attempted as IndexedDB and fails loud if it lacks the table.
        return parse_firefox_indexeddb(path);
    }
    anyhow::bail!(
        "unrecognized web-storage file {} (name {name:?}); expected \
         webappsstore.sqlite or an IndexedDB *.sqlite",
        path.display()
    );
}

/// Classify a LevelDB directory by its enclosing path and parse it.
fn parse_leveldb_dir(dir: &Path) -> Result<Vec<BrowserEvent>> {
    let lower = dir.to_string_lossy().to_lowercase();
    if lower.contains("session storage") {
        parse_session_storage(dir)
    } else if lower.contains("indexeddb") {
        parse_indexeddb(dir)
    } else {
        parse_local_storage(dir)
    }
}

/// Aggregate every Chromium web-storage source found under a profile directory:
/// `Local Storage/leveldb`, `Session Storage`, and each `IndexedDB/*.leveldb`.
/// A single unreadable source is skipped; the rest are still returned.
#[must_use]
pub fn collect_chromium_web_storage(profile_dir: &Path) -> Vec<BrowserEvent> {
    let mut events = Vec::new();

    let local = profile_dir.join("Local Storage").join("leveldb");
    if is_leveldb_dir(&local) {
        if let Ok(mut e) = parse_local_storage(&local) {
            events.append(&mut e);
        }
    }

    let session = profile_dir.join("Session Storage");
    if is_leveldb_dir(&session) {
        if let Ok(mut e) = parse_session_storage(&session) {
            events.append(&mut e);
        }
    }

    let idb_root = profile_dir.join("IndexedDB");
    if let Ok(entries) = std::fs::read_dir(&idb_root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() && is_leveldb_dir(&p) {
                if let Ok(mut e) = parse_indexeddb(&p) {
                    events.append(&mut e);
                }
            }
        }
    }

    events
}

/// Aggregate every Firefox web-storage source found under a profile directory:
/// `webappsstore.sqlite` and each `storage/default/*/idb/*.sqlite`.
/// A single unreadable source is skipped; the rest are still returned.
#[must_use]
pub fn collect_firefox_web_storage(profile_dir: &Path) -> Vec<BrowserEvent> {
    let mut events = Vec::new();

    let local = profile_dir.join("webappsstore.sqlite");
    if local.is_file() {
        if let Ok(mut e) = parse_firefox_local_storage(&local) {
            events.append(&mut e);
        }
    }

    // storage/default/<origin>/idb/<db>.sqlite
    let default_root = profile_dir.join("storage").join("default");
    if let Ok(origins) = std::fs::read_dir(&default_root) {
        for origin in origins.flatten() {
            let idb = origin.path().join("idb");
            let Ok(files) = std::fs::read_dir(&idb) else {
                continue;
            };
            for f in files.flatten() {
                let p = f.path();
                if p.extension().is_some_and(|x| x == "sqlite") {
                    if let Ok(mut e) = parse_firefox_indexeddb(&p) {
                        events.append(&mut e);
                    }
                }
            }
        }
    }

    events
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

    #[test]
    fn parse_path_classifies_session_storage_dir() {
        let profile = TempDir::new().unwrap();
        let ss = profile.path().join("Session Storage");
        build_real_leveldb(&ss, &[(b"map-1-tab", b"\x01open")]);
        let events = parse_path(&ss).unwrap();
        assert!(!events.is_empty());
        assert!(events
            .iter()
            .all(|e| e.attrs["storage_type"] == json_session()));
    }

    #[test]
    fn parse_path_classifies_indexeddb_dir() {
        let profile = TempDir::new().unwrap();
        let idb = profile
            .path()
            .join("IndexedDB")
            .join("https_example.com_0.indexeddb.leveldb");
        let (k, v) = idb_data_entry();
        build_real_leveldb(&idb, &[(&k, &v)]);
        let events = parse_path(&idb).unwrap();
        assert!(!events.is_empty());
        assert!(events
            .iter()
            .all(|e| e.attrs["storage_type"] == json_indexeddb()));
    }

    #[test]
    fn parse_path_routes_stray_sqlite_as_indexeddb() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("1234.sqlite");
        let conn = rusqlite::Connection::open(&f).unwrap();
        conn.execute_batch(
            "CREATE TABLE object_data (object_store_id INTEGER, key BLOB, data BLOB);
             INSERT INTO object_data VALUES (1, x'01', x'02');",
        )
        .unwrap();
        drop(conn);
        let events = parse_path(&f).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["storage_type"], json_indexeddb());
    }

    #[test]
    fn collect_chromium_aggregates_indexeddb() {
        let profile = TempDir::new().unwrap();
        let idb = profile
            .path()
            .join("IndexedDB")
            .join("https_example.com_0.indexeddb.leveldb");
        let (k, v) = idb_data_entry();
        build_real_leveldb(&idb, &[(&k, &v)]);
        let events = collect_chromium_web_storage(profile.path());
        assert!(events
            .iter()
            .any(|e| e.attrs["storage_type"] == json_indexeddb()));
    }

    #[test]
    fn is_leveldb_dir_nonexistent_is_false() {
        assert!(!is_leveldb_dir(Path::new("/nonexistent/leveldb-dir")));
    }

    fn json_local() -> serde_json::Value {
        serde_json::json!(STORAGE_TYPE_LOCAL)
    }
    fn json_session() -> serde_json::Value {
        serde_json::json!(STORAGE_TYPE_SESSION)
    }
    fn json_indexeddb() -> serde_json::Value {
        serde_json::json!(STORAGE_TYPE_INDEXEDDB)
    }

    /// A minimal decodable IndexedDB object-store data record: key `String "k1"`
    /// under prefix (db 1, store 1, index 1), value the real captured Reddit blob
    /// decoding to the string "false". Returns `(key, value)`.
    fn idb_data_entry() -> (Vec<u8>, Vec<u8>) {
        let mut key = vec![0x00, 0x01, 0x01, 0x01]; // KeyPrefix(1,1,1)
        key.extend_from_slice(&[0x01, 0x02]); // IDBKey String, 2 UTF-16 units
        key.extend_from_slice(
            &"k1"
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<u8>>(),
        );
        let value: Vec<u8> = (0.."03ff15fe000000000000000000000000ff0f220566616c7365".len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(
                    &"03ff15fe000000000000000000000000ff0f220566616c7365"[i..i + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        (key, value)
    }

    /// Build a real on-disk LevelDB directory at `path`.
    fn build_real_leveldb(path: &Path, entries: &[(&[u8], &[u8])]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let opt = rusty_leveldb::Options {
            create_if_missing: true,
            ..Default::default()
        };
        let mut db = rusty_leveldb::DB::open(path, opt).unwrap();
        for (k, v) in entries {
            db.put(k, v).unwrap();
        }
        db.flush().unwrap();
        db.close().unwrap();
    }
}
