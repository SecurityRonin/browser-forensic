//! End-to-end IndexedDB record decoding: read the LevelDB directory, resolve the
//! database/object-store names from the metadata records, then decode each
//! object-store *data* record's key and value.
//!
//! Metadata layout (`indexed_db_leveldb_coding.cc`):
//!
//! * **Database name** records key on `00 00 00 00 C9`, then the origin and
//!   database name (each a varint UTF-16 unit count + UTF-16-BE bytes); the value
//!   is the database id (truncated int).
//! * **Object-store name** records key on `KeyPrefix(db, 0, 0)` + `0x32` +
//!   varint(store id) + a metadata-type byte (`0x00` = store name); the value is
//!   the store name (UTF-16-BE).
//!
//! Data records key on `KeyPrefix(db, store, 1)` + an encoded IDBKey; the value
//! is a Blink-wrapped V8 stream.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use serde_json::Value;

use super::envelope::{strip_blink_wrapper, Wrapper};
use super::key::{
    decode_idb_key, decode_utf16_be, read_key_prefix, IdbKey, OBJECT_STORE_DATA_INDEX_ID,
};
use super::v8::decode_v8;
use super::varint::{decode_truncated_int, read_le_varint};

/// Key prefix of a global database-name metadata record.
const DATABASE_NAME_PREFIX: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0xc9];
/// Marker byte after `KeyPrefix(db,0,0)` for an object-store metadata record.
const OBJECT_STORE_META_MARKER: u8 = 0x32;
/// Object-store metadata type for the store's name.
const STORE_NAME_META_TYPE: u8 = 0x00;

/// Origin + name for one IndexedDB database, from its metadata record.
#[derive(Debug, Clone, Default)]
pub(crate) struct DbInfo {
    pub origin: String,
    pub name: String,
}

/// The decoded value of an object-store record.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DecodedValue {
    /// A V8 value rendered to JSON. `complete` is false and `unsupported` lists
    /// `(tag, offset)` pairs when a tag could not be honestly decoded.
    Json {
        value: Value,
        complete: bool,
        unsupported: Vec<(u8, usize)>,
    },
    /// The value was stored in an external blob file (not decoded here).
    ExternalBlob { size: u64, index: u64 },
    /// A tombstone or empty value.
    Empty,
    /// The Blink/V8 wrapper could not be parsed; raw bytes are surfaced by the
    /// caller.
    Malformed,
}

/// One decoded IndexedDB object-store record.
#[derive(Debug, Clone)]
pub(crate) struct IndexedDbRecord {
    pub db_id: u64,
    pub db_name: String,
    pub origin: String,
    pub object_store_id: u64,
    pub store_name: String,
    pub key: IdbKey,
    pub value: DecodedValue,
    pub seq: u64,
    pub deleted: bool,
}

/// Decode every object-store data record in an IndexedDB LevelDB directory.
///
/// # Errors
/// Returns an error only if the directory cannot be opened/read as LevelDB (the
/// bootstrap step). Individual undecodable records degrade to a surfaced note.
pub(crate) fn decode_indexeddb(dir: &Path) -> Result<Vec<IndexedDbRecord>> {
    let records = leveldb_core::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("reading IndexedDB LevelDB at {}: {e}", dir.display()))?;

    let (db_by_id, store_names) = build_metadata(&records);

    let mut out = Vec::new();
    for rec in &records {
        let Some((prefix, plen)) = read_key_prefix(&rec.key) else {
            continue;
        };
        if prefix.index_id != OBJECT_STORE_DATA_INDEX_ID || prefix.object_store_id == 0 {
            continue;
        }
        let Some(key_bytes) = rec.key.get(plen..) else {
            continue;
        };
        let Some((key, _)) = decode_idb_key(key_bytes) else {
            continue;
        };
        let value = decode_value(&rec.value, rec.deleted);
        let db = db_by_id.get(&prefix.db_id);
        out.push(IndexedDbRecord {
            db_id: prefix.db_id,
            db_name: db.map(|d| d.name.clone()).unwrap_or_default(),
            origin: db.map(|d| d.origin.clone()).unwrap_or_default(),
            object_store_id: prefix.object_store_id,
            store_name: store_names
                .get(&(prefix.db_id, prefix.object_store_id))
                .cloned()
                .unwrap_or_default(),
            key,
            value,
            seq: rec.seq,
            deleted: rec.deleted,
        });
    }
    Ok(out)
}

/// First pass: resolve database names/origins and object-store names. Live
/// records win over tombstones; the highest sequence number wins a duplicate.
fn build_metadata(
    records: &[leveldb_core::Record],
) -> (HashMap<u64, DbInfo>, HashMap<(u64, u64), String>) {
    let mut db_by_id: HashMap<u64, DbInfo> = HashMap::new();
    let mut db_seq: HashMap<u64, u64> = HashMap::new();
    let mut store_names: HashMap<(u64, u64), String> = HashMap::new();
    let mut store_seq: HashMap<(u64, u64), u64> = HashMap::new();

    for rec in records {
        if rec.deleted {
            continue;
        }
        // Database-name record.
        if rec.key.starts_with(&DATABASE_NAME_PREFIX) {
            if let Some(info) = parse_db_name_record(&rec.key[DATABASE_NAME_PREFIX.len()..]) {
                let db_id = decode_truncated_int(&rec.value);
                if rec.seq >= db_seq.get(&db_id).copied().unwrap_or(0) {
                    db_seq.insert(db_id, rec.seq);
                    db_by_id.insert(db_id, info);
                }
            }
            continue;
        }
        // Object-store-name record: KeyPrefix(db,0,0) + 0x32 + varint(store) + type.
        let Some((prefix, plen)) = read_key_prefix(&rec.key) else {
            continue;
        };
        if prefix.object_store_id != 0 || prefix.index_id != 0 {
            continue;
        }
        let Some(tail) = rec.key.get(plen..) else {
            continue;
        };
        if tail.first() != Some(&OBJECT_STORE_META_MARKER) {
            continue;
        }
        let Some((store_id, vlen)) = read_le_varint(&tail[1..]) else {
            continue;
        };
        if tail.get(1 + vlen).copied() != Some(STORE_NAME_META_TYPE) {
            continue;
        }
        let slot = (prefix.db_id, store_id);
        if rec.seq >= store_seq.get(&slot).copied().unwrap_or(0) {
            store_seq.insert(slot, rec.seq);
            store_names.insert(slot, decode_utf16_be(&rec.value));
        }
    }
    (db_by_id, store_names)
}

/// Parse the origin + database name from a database-name record key (after the
/// 5-byte `00 00 00 00 C9` prefix).
fn parse_db_name_record(data: &[u8]) -> Option<DbInfo> {
    let (origin_units, l1) = read_le_varint(data)?;
    let origin_len = usize::try_from(origin_units).ok()?.checked_mul(2)?;
    let origin_bytes = data.get(l1..l1.checked_add(origin_len)?)?;
    let origin = decode_utf16_be(origin_bytes);

    let after = l1 + origin_len;
    let (name_units, l2) = read_le_varint(data.get(after..)?)?;
    let name_len = usize::try_from(name_units).ok()?.checked_mul(2)?;
    let start = after.checked_add(l2)?;
    let name_bytes = data.get(start..start.checked_add(name_len)?)?;
    let name = decode_utf16_be(name_bytes);

    Some(DbInfo { origin, name })
}

/// Decode a record value through the Blink wrapper and V8 stream.
fn decode_value(raw: &[u8], deleted: bool) -> DecodedValue {
    if deleted || raw.is_empty() {
        return DecodedValue::Empty;
    }
    match strip_blink_wrapper(raw) {
        Wrapper::V8 { v8, .. } => match decode_v8(v8) {
            Some(d) => DecodedValue::Json {
                value: d.value,
                complete: d.complete,
                unsupported: d.unsupported.iter().map(|u| (u.tag, u.offset)).collect(),
            },
            None => DecodedValue::Malformed,
        },
        Wrapper::ExternalBlob { size, index, .. } => DecodedValue::ExternalBlob { size, index },
        Wrapper::Malformed => DecodedValue::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// UTF-16-BE encode a string as (varint unit count, bytes).
    fn utf16be_lenprefixed(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut out = vec![u8::try_from(units.len()).unwrap()]; // small varint
        for u in units {
            out.extend_from_slice(&u.to_be_bytes());
        }
        out
    }

    fn utf16be(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    /// Build a real IndexedDB LevelDB fixture: one database "testdb", one object
    /// store "records", and one data record whose value is the *real captured*
    /// LinkedIn object blob `{sequenceNumber:29, PageViewEvent:3}`.
    fn build_idb_fixture() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("idb.leveldb");

        // Database-name record: 00 00 00 00 C9 <origin> <name> => value db_id=1
        let mut db_name_key = vec![0x00, 0x00, 0x00, 0x00, 0xc9];
        db_name_key.extend_from_slice(&utf16be_lenprefixed("https_example.com_0@1"));
        db_name_key.extend_from_slice(&utf16be_lenprefixed("testdb"));

        // Object-store-name record: prefix(1,0,0)=00 01 00 00, 0x32, store 1, type 0
        let store_key = hx("00010000320100");
        let store_val = utf16be("records");

        // Data record: prefix(1,1,1)=00 01 01 01 + IDBKey String "k1"
        // (type 1, varint len 2, UTF-16-BE "k1").
        let mut data_key = hx("00010101");
        data_key.push(0x01); // IdbKeyType::String
        data_key.push(0x02); // 2 UTF-16 units
        data_key.extend_from_slice(&utf16be("k1"));
        // Value: real LinkedIn blink+v8 blob.
        let data_val = hx("07ff15fe000000000000000000000000ff0f6f220e73657175656e63654e756d626572493a220d50616765566965774576656e7449067b02");

        let opt = rusty_leveldb::Options {
            create_if_missing: true,
            ..Default::default()
        };
        let mut db = rusty_leveldb::DB::open(&db_path, opt).unwrap();
        db.put(&db_name_key, &[0x01]).unwrap();
        db.put(&store_key, &store_val).unwrap();
        db.put(&data_key, &data_val).unwrap();
        db.flush().unwrap();
        db.close().unwrap();
        (dir, db_path)
    }

    #[test]
    fn decodes_full_record_with_names_and_value() {
        let (_dir, path) = build_idb_fixture();
        let recs = decode_indexeddb(&path).unwrap();
        assert_eq!(recs.len(), 1, "one object-store data record");
        let r = &recs[0];
        assert_eq!(r.db_id, 1);
        assert_eq!(r.db_name, "testdb");
        assert_eq!(r.origin, "https_example.com_0@1");
        assert_eq!(r.object_store_id, 1);
        assert_eq!(r.store_name, "records");
        assert_eq!(r.key, IdbKey::String("k1".to_string()));
        assert_eq!(
            r.value,
            DecodedValue::Json {
                value: json!({"sequenceNumber": 29, "PageViewEvent": 3}),
                complete: true,
                unsupported: vec![],
            }
        );
    }

    #[test]
    fn missing_dir_errors() {
        assert!(decode_indexeddb(Path::new("/nonexistent/idb.leveldb")).is_err());
    }

    #[test]
    fn parse_db_name_record_roundtrip() {
        let mut key = Vec::new();
        key.extend_from_slice(&utf16be_lenprefixed("https_a.com_0@1"));
        key.extend_from_slice(&utf16be_lenprefixed("mydb"));
        let info = parse_db_name_record(&key).unwrap();
        assert_eq!(info.origin, "https_a.com_0@1");
        assert_eq!(info.name, "mydb");
    }

    #[test]
    fn deleted_value_is_empty() {
        assert_eq!(decode_value(b"", true), DecodedValue::Empty);
        assert_eq!(decode_value(&hx("07ff15"), true), DecodedValue::Empty);
    }
}
