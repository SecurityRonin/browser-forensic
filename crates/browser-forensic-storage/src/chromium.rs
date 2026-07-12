//! Chromium-family web storage: Local Storage, Session Storage, and IndexedDB.
//!
//! Local Storage (`<profile>/Local Storage/leveldb/`) and Session Storage
//! (`<profile>/Session Storage/`) are decoded by the published
//! [`leveldb_forensic`] crate — itself panic-free and oracle-tested against
//! `rusty-leveldb` — and mapped to [`BrowserEvent`]s here. IndexedDB
//! (`<profile>/IndexedDB/*.leveldb/`) values are Blink/v8-serialized; rather
//! than fabricate a decode we cannot validate, its records are enumerated with
//! [`leveldb_core`] and surfaced as opaque raw key/value records.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use leveldb_forensic::{LocalStorageRecord, SessionStorageRecord, StorageValue};
use serde_json::json;

use crate::{to_hex, STORAGE_TYPE_INDEXEDDB, STORAGE_TYPE_LOCAL, STORAGE_TYPE_SESSION};

/// Parse a Chromium `Local Storage/leveldb` directory into [`BrowserEvent`]s.
///
/// Delegates the LevelDB decode to [`leveldb_forensic::decode_local_storage`],
/// then maps each decoded record to an event carrying the origin, script-visible
/// key, decoded value, the origin's last-modified time (WebKit microseconds,
/// from the `META:` record), the LevelDB sequence number, and the deleted
/// (tombstone) flag.
///
/// # Errors
///
/// Returns an error if the directory cannot be opened or read as LevelDB.
pub fn parse_local_storage(dir: &Path) -> Result<Vec<BrowserEvent>> {
    let records = leveldb_forensic::decode_local_storage(dir)
        .map_err(|e| anyhow::anyhow!("reading Local Storage LevelDB at {}: {e}", dir.display()))?;
    Ok(local_records_to_events(&records, &dir.to_string_lossy()))
}

/// Parse a Chromium `Session Storage` LevelDB directory into [`BrowserEvent`]s.
///
/// # Errors
///
/// Returns an error if the directory cannot be opened or read as LevelDB.
pub fn parse_session_storage(dir: &Path) -> Result<Vec<BrowserEvent>> {
    let records = leveldb_forensic::decode_session_storage(dir).map_err(|e| {
        anyhow::anyhow!("reading Session Storage LevelDB at {}: {e}", dir.display())
    })?;
    Ok(session_records_to_events(&records, &dir.to_string_lossy()))
}

/// Parse a Chromium IndexedDB LevelDB directory into opaque [`BrowserEvent`]s.
///
/// IndexedDB stores Blink/v8-serialized values that this crate does not decode.
/// Each raw LevelDB record is surfaced honestly: the raw key (hex), the value
/// length, and an `opaque` flag — never a fabricated value decode.
///
/// # Errors
///
/// Returns an error if the directory cannot be opened or read as LevelDB.
pub fn parse_indexeddb(dir: &Path) -> Result<Vec<BrowserEvent>> {
    let records = leveldb_core::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("reading IndexedDB LevelDB at {}: {e}", dir.display()))?;
    let source = dir.to_string_lossy();
    Ok(records
        .iter()
        .map(|r| indexeddb_event(&source, r, BrowserFamily::Chromium))
        .collect())
}

/// Build an opaque IndexedDB event from a raw LevelDB record. The value is
/// Blink/v8-serialized and is *not* decoded; its length and the raw key (hex)
/// are surfaced so an examiner has the evidence without a fabricated decode.
fn indexeddb_event(
    source: &str,
    rec: &leveldb_core::Record,
    browser: BrowserFamily,
) -> BrowserEvent {
    BrowserEvent::new(
        0,
        browser,
        ArtifactKind::LocalStorage,
        source,
        format!(
            "IndexedDB record: key {} bytes, value {} bytes (opaque, v8-serialized)",
            rec.key.len(),
            rec.value.len()
        ),
    )
    .with_attr("storage_type", json!(STORAGE_TYPE_INDEXEDDB))
    .with_attr("key_hex", json!(to_hex(&rec.key)))
    .with_attr("value_len", json!(rec.value.len()))
    .with_attr("value_opaque", json!(true))
    .with_attr("seq", json!(rec.seq))
    .with_attr("deleted", json!(rec.deleted))
}

/// Map decoded Local Storage records to events, correlating each `Data` record
/// with its origin's `META:` last-modified timestamp.
pub(crate) fn local_records_to_events(
    records: &[LocalStorageRecord],
    source: &str,
) -> Vec<BrowserEvent> {
    // First pass: latest live META timestamp (WebKit micros) per origin.
    let mut meta_micros: HashMap<&str, (u64, u64)> = HashMap::new();
    for r in records {
        if let LocalStorageRecord::Meta {
            origin,
            timestamp_webkit_micros,
            seq,
            deleted,
            ..
        } = r
        {
            if *deleted {
                continue;
            }
            let slot = meta_micros.entry(origin.as_str()).or_insert((0, 0));
            if *seq >= slot.0 {
                *slot = (*seq, *timestamp_webkit_micros);
            }
        }
    }

    let mut events = Vec::new();
    for r in records {
        match r {
            LocalStorageRecord::Data {
                origin,
                script_key,
                value,
                seq,
                deleted,
            } => {
                let ts_ns = meta_micros.get(origin.as_str()).map_or(0, |(_, micros)| {
                    webkit_micros_to_unix_nanos(clamp_micros(*micros))
                });
                let ev = BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Chromium,
                    ArtifactKind::LocalStorage,
                    source,
                    format!("{origin} \u{2014} {} = {}", script_key.text, value.text),
                )
                .with_attr("storage_type", json!(STORAGE_TYPE_LOCAL))
                .with_attr("record", json!("data"))
                .with_attr("origin", json!(origin))
                .with_attr("key", json!(script_key.text))
                .with_attr("seq", json!(seq))
                .with_attr("deleted", json!(deleted));
                events.push(attach_value(ev, value));
            }
            LocalStorageRecord::Other { key, seq, deleted } => {
                events.push(other_event(
                    source,
                    STORAGE_TYPE_LOCAL,
                    key,
                    *seq,
                    *deleted,
                    BrowserFamily::Chromium,
                ));
            }
            // META records feed the timestamp map above; they are not events.
            LocalStorageRecord::Meta { .. } => {}
        }
    }
    events
}

/// Clamp a WebKit-microsecond `u64` into the `i64` the timestamp helpers use;
/// realistic dates are far below `i64::MAX`, so an out-of-range value (corrupt
/// input) saturates rather than wrapping.
fn clamp_micros(micros: u64) -> i64 {
    i64::try_from(micros).unwrap_or(i64::MAX)
}

/// Map decoded Session Storage records to events.
pub(crate) fn session_records_to_events(
    records: &[SessionStorageRecord],
    source: &str,
) -> Vec<BrowserEvent> {
    let mut events = Vec::new();
    for r in records {
        match r {
            SessionStorageRecord::Map {
                map_id,
                host,
                script_key,
                value,
                seq,
                deleted,
            } => {
                let host_str = host.as_deref().unwrap_or("<unknown host>");
                let ev = BrowserEvent::new(
                    0,
                    BrowserFamily::Chromium,
                    ArtifactKind::LocalStorage,
                    source,
                    format!("{host_str} \u{2014} {script_key} = {}", value.text),
                )
                .with_attr("storage_type", json!(STORAGE_TYPE_SESSION))
                .with_attr("record", json!("map"))
                .with_attr("map_id", json!(map_id))
                .with_attr("host", json!(host))
                .with_attr("key", json!(script_key))
                .with_attr("seq", json!(seq))
                .with_attr("deleted", json!(deleted));
                events.push(attach_value(ev, value));
            }
            SessionStorageRecord::Other { key, seq, deleted } => {
                events.push(other_event(
                    source,
                    STORAGE_TYPE_SESSION,
                    key,
                    *seq,
                    *deleted,
                    BrowserFamily::Chromium,
                ));
            }
            // Namespace records map host -> map_id; that correlation is already
            // folded into each Map record's `host`, so they are not events.
            SessionStorageRecord::Namespace { .. } => {}
        }
    }
    events
}

/// Attach a decoded [`StorageValue`]'s text, encoding, and — when the decode was
/// lossy — its raw bytes (hex) to an event, so a lossy decode is never mistaken
/// for a clean one.
fn attach_value(ev: BrowserEvent, value: &StorageValue) -> BrowserEvent {
    let ev = ev
        .with_attr("value", json!(value.text))
        .with_attr("value_encoding", json!(format!("{:?}", value.encoding)));
    if value.lossy {
        ev.with_attr("value_lossy", json!(true))
            .with_attr("value_hex", json!(to_hex(&value.raw)))
    } else {
        ev
    }
}

/// Build an event for a record whose key matched no known web-storage shape.
/// The raw key bytes are surfaced verbatim (hex) so an examiner can identify it.
fn other_event(
    source: &str,
    storage_type: &str,
    key: &[u8],
    seq: u64,
    deleted: bool,
    browser: BrowserFamily,
) -> BrowserEvent {
    BrowserEvent::new(
        0,
        browser,
        ArtifactKind::LocalStorage,
        source,
        format!(
            "unrecognized {storage_type} record (key {} bytes)",
            key.len()
        ),
    )
    .with_attr("storage_type", json!(storage_type))
    .with_attr("record", json!("other"))
    .with_attr("key_hex", json!(to_hex(key)))
    .with_attr("seq", json!(seq))
    .with_attr("deleted", json!(deleted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::timestamp::WEBKIT_EPOCH_OFFSET_US;
    use leveldb_forensic::Encoding;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn sv(text: &str) -> StorageValue {
        StorageValue {
            text: text.to_string(),
            raw: text.as_bytes().to_vec(),
            encoding: Encoding::Latin1,
            lossy: false,
        }
    }

    /// Build a real on-disk LevelDB directory from raw key/value pairs using
    /// `rusty-leveldb` (the same writer `leveldb-forensic` uses for its own
    /// fixtures). Returns the leveldb directory path (kept alive by the TempDir).
    fn build_leveldb(entries: &[(&[u8], &[u8])]) -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("leveldb");
        let opt = rusty_leveldb::Options {
            create_if_missing: true,
            ..Default::default()
        };
        let mut db = rusty_leveldb::DB::open(&db_path, opt).unwrap();
        for (k, v) in entries {
            db.put(k, v).unwrap();
        }
        db.flush().unwrap();
        db.close().unwrap();
        (dir, db_path)
    }

    #[test]
    fn data_record_carries_meta_timestamp_and_attrs() {
        // META webkit micros for 1s after the Unix epoch.
        let webkit = u64::try_from(WEBKIT_EPOCH_OFFSET_US).unwrap() + 1_000_000;
        let records = vec![
            LocalStorageRecord::Meta {
                origin: "http://example.com".to_string(),
                timestamp_webkit_micros: webkit,
                size: Some(4),
                seq: 5,
                deleted: false,
            },
            LocalStorageRecord::Data {
                origin: "http://example.com".to_string(),
                script_key: sv("theme"),
                value: sv("dark"),
                seq: 6,
                deleted: false,
            },
        ];
        let events = local_records_to_events(&records, "src");
        assert_eq!(events.len(), 1, "one Data event; Meta feeds the timestamp");
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::LocalStorage);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.timestamp_ns, 1_000_000_000);
        assert_eq!(ev.attrs["storage_type"], json!(STORAGE_TYPE_LOCAL));
        assert_eq!(ev.attrs["origin"], json!("http://example.com"));
        assert_eq!(ev.attrs["key"], json!("theme"));
        assert_eq!(ev.attrs["value"], json!("dark"));
        assert_eq!(ev.attrs["deleted"], json!(false));
    }

    #[test]
    fn data_record_without_meta_has_zero_timestamp() {
        let records = vec![LocalStorageRecord::Data {
            origin: "http://nometa.example".to_string(),
            script_key: sv("k"),
            value: sv("v"),
            seq: 1,
            deleted: false,
        }];
        let events = local_records_to_events(&records, "src");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, 0);
    }

    #[test]
    fn lossy_value_surfaces_raw_hex() {
        let lossy = StorageValue {
            text: "\u{fffd}".to_string(),
            raw: vec![0x00, 0xd8, 0x00],
            encoding: Encoding::Utf16Le,
            lossy: true,
        };
        let records = vec![LocalStorageRecord::Data {
            origin: "http://x".to_string(),
            script_key: sv("k"),
            value: lossy,
            seq: 1,
            deleted: false,
        }];
        let events = local_records_to_events(&records, "src");
        assert_eq!(events[0].attrs["value_lossy"], json!(true));
        assert_eq!(events[0].attrs["value_hex"], json!("00d800"));
    }

    #[test]
    fn deleted_meta_is_ignored_for_timestamp() {
        let webkit = u64::try_from(WEBKIT_EPOCH_OFFSET_US).unwrap() + 5_000_000;
        let records = vec![
            LocalStorageRecord::Meta {
                origin: "http://x".to_string(),
                timestamp_webkit_micros: webkit,
                size: None,
                seq: 9,
                deleted: true,
            },
            LocalStorageRecord::Data {
                origin: "http://x".to_string(),
                script_key: sv("k"),
                value: sv("v"),
                seq: 10,
                deleted: false,
            },
        ];
        let events = local_records_to_events(&records, "src");
        assert_eq!(events[0].timestamp_ns, 0, "tombstone META not used as ts");
    }

    #[test]
    fn other_local_record_surfaces_key_hex() {
        let records = vec![LocalStorageRecord::Other {
            key: vec![0xde, 0xad],
            seq: 2,
            deleted: true,
        }];
        let events = local_records_to_events(&records, "src");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["key_hex"], json!("dead"));
        assert_eq!(events[0].attrs["deleted"], json!(true));
    }

    #[test]
    fn session_map_and_other_surface_namespace_skipped() {
        let records = vec![
            SessionStorageRecord::Namespace {
                guid: "GUID".to_string(),
                host: "http://example.com".to_string(),
                map_id: "1".to_string(),
                seq: 1,
                deleted: false,
            },
            SessionStorageRecord::Map {
                map_id: "1".to_string(),
                host: Some("http://example.com".to_string()),
                script_key: "tab".to_string(),
                value: sv("open"),
                seq: 2,
                deleted: false,
            },
            SessionStorageRecord::Other {
                key: vec![0x01],
                seq: 3,
                deleted: false,
            },
        ];
        let events = session_records_to_events(&records, "src");
        assert_eq!(events.len(), 2, "Map + Other; Namespace is structural");
        let map_ev = events
            .iter()
            .find(|e| e.attrs.get("key") == Some(&json!("tab")))
            .unwrap();
        assert_eq!(map_ev.attrs["storage_type"], json!(STORAGE_TYPE_SESSION));
        assert_eq!(map_ev.attrs["host"], json!("http://example.com"));
        assert_eq!(map_ev.attrs["value"], json!("open"));
    }

    #[test]
    fn parse_local_storage_reads_real_leveldb() {
        // Chrome Local Storage data-record layout: `_<origin>\x00<type><key>`,
        // value `<type><bytes>` (0x01 = Latin-1).
        let key = b"_http://example.com\x00\x01theme";
        let val = b"\x01dark";
        let (_dir, db_path) = build_leveldb(&[(key, val)]);

        let oracle = leveldb_forensic::decode_local_storage(&db_path).unwrap();
        let events = parse_local_storage(&db_path).unwrap();

        let expected_non_meta = oracle
            .iter()
            .filter(|r| !matches!(r, LocalStorageRecord::Meta { .. }))
            .count();
        assert_eq!(events.len(), expected_non_meta);
        assert!(!events.is_empty(), "at least one record decoded");
        // Where the oracle decoded a Data value, our event carries it faithfully.
        for r in &oracle {
            if let LocalStorageRecord::Data { value, .. } = r {
                assert!(events
                    .iter()
                    .any(|e| e.attrs.get("value") == Some(&json!(value.text))));
            }
        }
    }

    #[test]
    fn parse_session_storage_reads_real_leveldb() {
        let entries: &[(&[u8], &[u8])] = &[
            (b"namespace-GUID-http://example.com", b"1"),
            (b"map-1-theme", b"\x01dark"),
        ];
        let (_dir, db_path) = build_leveldb(entries);
        let oracle = leveldb_forensic::decode_session_storage(&db_path).unwrap();
        let events = parse_session_storage(&db_path).unwrap();
        let expected = oracle
            .iter()
            .filter(|r| !matches!(r, SessionStorageRecord::Namespace { .. }))
            .count();
        assert_eq!(events.len(), expected);
    }

    #[test]
    fn parse_indexeddb_surfaces_opaque_records() {
        let entries: &[(&[u8], &[u8])] = &[(b"\x00\x01key", b"v8-serialized-blob")];
        let (_dir, db_path) = build_leveldb(entries);
        let events = parse_indexeddb(&db_path).unwrap();
        assert!(!events.is_empty());
        let ev = &events[0];
        assert_eq!(ev.attrs["storage_type"], json!(STORAGE_TYPE_INDEXEDDB));
        assert_eq!(ev.attrs["value_opaque"], json!(true));
        assert!(ev.attrs.contains_key("key_hex"));
        assert!(ev.attrs.contains_key("value_len"));
    }

    #[test]
    fn parse_local_storage_missing_dir_errors() {
        assert!(parse_local_storage(Path::new("/nonexistent/leveldb")).is_err());
    }

    #[test]
    fn parse_indexeddb_missing_dir_errors() {
        assert!(parse_indexeddb(Path::new("/nonexistent/idb.leveldb")).is_err());
    }
}
