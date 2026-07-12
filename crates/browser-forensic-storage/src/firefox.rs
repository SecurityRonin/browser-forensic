//! Firefox/Gecko web storage: Local Storage (`webappsstore.sqlite`) and
//! IndexedDB (`storage/default/<origin>/idb/*.sqlite`).
//!
//! Both are plain SQLite, opened read-only and WAL-safe through
//! [`browser_forensic_core::sqlite::open_evidence_db`]. Local Storage rows carry
//! the scope/key/value directly; IndexedDB values are structured-clone blobs
//! that this crate does not decode, so its rows are surfaced as opaque records.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use rusqlite::OptionalExtension;
use serde_json::json;

use crate::{to_hex, STORAGE_TYPE_INDEXEDDB, STORAGE_TYPE_LOCAL};

/// Parse a Firefox `webappsstore.sqlite` file into [`BrowserEvent`]s.
///
/// Reads the `webappsstore2` table (`scope`, `key`, `value`). The `scope` is a
/// reversed-host origin string (e.g. `moc.elpmaxe.:http:80`); a best-effort
/// readable host is attached alongside the verbatim scope. `webappsstore2`
/// carries no per-row timestamp, so events have a zero event time.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or the `webappsstore2`
/// table cannot be queried.
pub fn parse_firefox_local_storage(path: &Path) -> Result<Vec<BrowserEvent>> {
    let _ = path;
    Ok(Vec::new())
}

/// Parse a Firefox IndexedDB `*.sqlite` file into opaque [`BrowserEvent`]s.
///
/// Enumerates the `object_data` table. The `data` column is a
/// (snappy-compressed) structured-clone blob this crate does not decode; each
/// row is surfaced honestly with its object-store id, raw key (hex), value
/// length, and an `opaque` flag. The database name (from the `database` table)
/// is attached when present.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or lacks an
/// `object_data` table.
pub fn parse_firefox_indexeddb(path: &Path) -> Result<Vec<BrowserEvent>> {
    let _ = path;
    Ok(Vec::new())
}

/// Recover a readable host from a Firefox `webappsstore2` scope string.
///
/// The scope is `reversedHost:scheme:port` with a character-reversed host
/// (`moc.elpmaxe.` → `example.com`). The reversed host is reversed back and a
/// single leading dot is trimmed; a scope without a `:` is treated as a bare
/// reversed host.
pub(crate) fn descope_host(scope: &str) -> String {
    let _ = scope;
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;

    #[test]
    fn descope_reverses_host_and_trims_leading_dot() {
        assert_eq!(descope_host("moc.elpmaxe.:http:80"), "example.com");
        assert_eq!(descope_host("gro.elpmaxe:https:443"), "example.org");
    }

    #[test]
    fn descope_handles_missing_colon_and_empty() {
        assert_eq!(descope_host(""), "");
        // No scheme/port separator: treat the whole string as a reversed host.
        assert_eq!(descope_host("tsohlacol"), "localhost");
    }

    #[test]
    fn parse_webappsstore_reads_rows() {
        let db = TestDb::new("CREATE TABLE webappsstore2 (scope TEXT, key TEXT, value TEXT);");
        db.insert(
            "INSERT INTO webappsstore2 (scope, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params!["moc.elpmaxe.:http:80", "theme", "dark"],
        );
        let events = parse_firefox_local_storage(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::LocalStorage);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["storage_type"], json!(STORAGE_TYPE_LOCAL));
        assert_eq!(ev.attrs["host"], json!("example.com"));
        assert_eq!(ev.attrs["scope"], json!("moc.elpmaxe.:http:80"));
        assert_eq!(ev.attrs["key"], json!("theme"));
        assert_eq!(ev.attrs["value"], json!("dark"));
    }

    #[test]
    fn parse_webappsstore_empty_returns_empty() {
        let db = TestDb::new("CREATE TABLE webappsstore2 (scope TEXT, key TEXT, value TEXT);");
        let events = parse_firefox_local_storage(db.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_webappsstore_missing_table_errors() {
        let db = TestDb::new("CREATE TABLE unrelated (x INTEGER);");
        assert!(parse_firefox_local_storage(db.path()).is_err());
    }

    #[test]
    fn parse_firefox_indexeddb_surfaces_opaque_rows() {
        let db = TestDb::new(
            "CREATE TABLE database (name TEXT, origin TEXT);
             CREATE TABLE object_data (object_store_id INTEGER, key BLOB, data BLOB);",
        );
        db.insert(
            "INSERT INTO database (name, origin) VALUES (?1, ?2)",
            rusqlite::params!["mydb", "http://example.com"],
        );
        db.insert(
            "INSERT INTO object_data (object_store_id, key, data) VALUES (?1, ?2, ?3)",
            rusqlite::params![1_i64, vec![0x01_u8, 0x02], vec![0xde_u8, 0xad, 0xbe, 0xef]],
        );
        let events = parse_firefox_indexeddb(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.attrs["storage_type"], json!(STORAGE_TYPE_INDEXEDDB));
        assert_eq!(ev.attrs["value_opaque"], json!(true));
        assert_eq!(ev.attrs["key_hex"], json!("0102"));
        assert_eq!(ev.attrs["value_len"], json!(4));
        assert_eq!(ev.attrs["object_store_id"], json!(1));
        assert_eq!(ev.attrs["database"], json!("mydb"));
    }

    #[test]
    fn parse_firefox_indexeddb_missing_table_errors() {
        let db = TestDb::new("CREATE TABLE unrelated (x INTEGER);");
        assert!(parse_firefox_indexeddb(db.path()).is_err());
    }
}
