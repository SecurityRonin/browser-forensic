//! IndexedDB LevelDB **key** decoding: the `(database, object-store, index)`
//! prefix and the encoded IDBKey that follows it.
//!
//! Mirrors `content/browser/indexed_db/indexed_db_leveldb_coding.cc`. Every
//! record key starts with a [`KeyPrefix`]: a leading byte packs the little-endian
//! widths of three ids, which then follow as truncated LE ints. Object-store
//! *data* records carry [`OBJECT_STORE_DATA_INDEX_ID`]; the bytes past the prefix
//! are an [`IdbKey`].

use serde_json::{json, Value};

use super::varint::read_le_varint;

/// `index_id` of an object-store *data* record (the primary key → value rows).
pub(crate) const OBJECT_STORE_DATA_INDEX_ID: u64 = 1;

/// Cap on IDBKey array nesting, so a crafted key of nested arrays cannot recurse
/// without bound. Real keys are flat or shallowly nested.
const MAX_KEY_DEPTH: usize = 32;

/// The `(database id, object-store id, index id)` prefix every record key opens
/// with.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub(crate) struct KeyPrefix {
    pub db_id: u64,
    pub object_store_id: u64,
    pub index_id: u64,
}

/// A decoded IndexedDB key. Mirrors `IDBKey`'s value types.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum IdbKey {
    Null,
    Number(f64),
    /// Milliseconds since the Unix epoch (IDB dates are stored as an f64 ms).
    Date(f64),
    String(String),
    Binary(Vec<u8>),
    Array(Vec<IdbKey>),
    /// The synthetic "minimum" key; carries no value.
    MinKey,
}

/// Decode the leading [`KeyPrefix`]. Returns `(prefix, bytes_consumed)`, or
/// `None` if the buffer is too short. Never panics.
#[must_use]
pub(crate) fn read_key_prefix(data: &[u8]) -> Option<(KeyPrefix, usize)> {
    let lengths = *data.first()?;
    let db_id_size = usize::from((lengths >> 5) & 0x07) + 1;
    let os_size = usize::from((lengths >> 2) & 0x07) + 1;
    let index_size = usize::from(lengths & 0x03) + 1;

    let mut off = 1usize;
    let db_id = read_fixed_le(data, off, db_id_size)?;
    off += db_id_size;
    let object_store_id = read_fixed_le(data, off, os_size)?;
    off += os_size;
    let index_id = read_fixed_le(data, off, index_size)?;
    off += index_size;

    Some((
        KeyPrefix {
            db_id,
            object_store_id,
            index_id,
        },
        off,
    ))
}

/// Read a fixed-width (`len` bytes, `len <= 8`) little-endian integer at `off`.
fn read_fixed_le(data: &[u8], off: usize, len: usize) -> Option<u64> {
    let slice = data.get(off..off.checked_add(len)?)?;
    let mut v: u64 = 0;
    for (i, &b) in slice.iter().enumerate() {
        v |= u64::from(b) << (i * 8);
    }
    Some(v)
}

/// Decode an [`IdbKey`] from the front of `data`. Returns `(key, bytes_consumed)`
/// so a nested array element knows how far it advanced. `None` on any malformed
/// or truncated encoding — never panics, never reads out of bounds.
#[must_use]
pub(crate) fn decode_idb_key(data: &[u8]) -> Option<(IdbKey, usize)> {
    decode_key_inner(data, 0)
}

fn decode_key_inner(data: &[u8], depth: usize) -> Option<(IdbKey, usize)> {
    if depth > MAX_KEY_DEPTH {
        return None;
    }
    let type_byte = *data.first()?;
    let rest = &data[1..];
    match type_byte {
        0 => Some((IdbKey::Null, 1)),
        1 => {
            // String: varint length in UTF-16 code units, then len*2 BE bytes.
            let (units, vlen) = read_le_varint(rest)?;
            let byte_len = usize::try_from(units).ok()?.checked_mul(2)?;
            let bytes = rest.get(vlen..vlen.checked_add(byte_len)?)?;
            Some((IdbKey::String(decode_utf16_be(bytes)), 1 + vlen + byte_len))
        }
        2 | 3 => {
            let raw = rest.get(0..8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(raw);
            let f = f64::from_le_bytes(arr);
            let key = if type_byte == 2 {
                IdbKey::Date(f)
            } else {
                IdbKey::Number(f)
            };
            Some((key, 9))
        }
        4 => {
            let (count, vlen) = read_le_varint(rest)?;
            let count = usize::try_from(count).ok()?;
            let mut consumed = 1 + vlen;
            let mut items = Vec::new();
            for _ in 0..count {
                let (item, used) = decode_key_inner(data.get(consumed..)?, depth + 1)?;
                consumed = consumed.checked_add(used)?;
                items.push(item);
            }
            Some((IdbKey::Array(items), consumed))
        }
        5 => Some((IdbKey::MinKey, 1)),
        6 => {
            let (len, vlen) = read_le_varint(rest)?;
            let byte_len = usize::try_from(len).ok()?;
            let bytes = rest.get(vlen..vlen.checked_add(byte_len)?)?;
            Some((IdbKey::Binary(bytes.to_vec()), 1 + vlen + byte_len))
        }
        _ => None,
    }
}

/// Decode big-endian UTF-16 bytes, replacing malformed units with U+FFFD so a
/// corrupt key can never panic. An odd trailing byte is dropped.
fn decode_utf16_be(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]));
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{fffd}'))
        .collect()
}

impl IdbKey {
    /// A one-line human rendering for an event description.
    pub(crate) fn to_display(&self) -> String {
        match self {
            IdbKey::Null => "null".to_string(),
            IdbKey::Number(n) => n.to_string(),
            IdbKey::Date(ms) => format!("Date({ms})"),
            IdbKey::String(s) => s.clone(),
            IdbKey::Binary(b) => format!("<binary {} bytes>", b.len()),
            IdbKey::Array(items) => {
                let inner: Vec<String> = items.iter().map(IdbKey::to_display).collect();
                format!("[{}]", inner.join(", "))
            }
            IdbKey::MinKey => "<minkey>".to_string(),
        }
    }

    /// A machine-faithful JSON rendering. Dates are the raw epoch-ms number;
    /// binary keys are lowercase hex (a key value round-trips losslessly).
    pub(crate) fn to_json(&self) -> Value {
        match self {
            IdbKey::Null => Value::Null,
            IdbKey::Number(n) | IdbKey::Date(n) => json!(n),
            IdbKey::String(s) => json!(s),
            IdbKey::Binary(b) => json!(crate::to_hex(b)),
            IdbKey::Array(items) => Value::Array(items.iter().map(IdbKey::to_json).collect()),
            IdbKey::MinKey => json!("<minkey>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_db1_store1_index1() {
        // make_prefix(1, 1, 1) => lengths byte 0x00, then 1,1,1.
        let (p, len) = read_key_prefix(&[0x00, 0x01, 0x01, 0x01]).unwrap();
        assert_eq!(
            p,
            KeyPrefix {
                db_id: 1,
                object_store_id: 1,
                index_id: 1
            }
        );
        assert_eq!(len, 4);
    }

    #[test]
    fn prefix_global_metadata_zeroes() {
        // make_prefix(0,0,0) => 0x00 00 00 00.
        let (p, len) = read_key_prefix(&[0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(p.db_id, 0);
        assert_eq!(p.object_store_id, 0);
        assert_eq!(p.index_id, 0);
        assert_eq!(len, 4);
    }

    #[test]
    fn prefix_multibyte_widths() {
        // lengths 0b001_00_00 = 0x20 -> db_id 2 bytes, os 1, index 1.
        let (p, len) = read_key_prefix(&[0x20, 0x2c, 0x01, 0x05, 0x01]).unwrap();
        assert_eq!(p.db_id, 0x012c); // 300
        assert_eq!(p.object_store_id, 5);
        assert_eq!(p.index_id, 1);
        assert_eq!(len, 5);
    }

    #[test]
    fn prefix_truncated_is_none() {
        assert_eq!(read_key_prefix(&[]), None);
        assert_eq!(read_key_prefix(&[0x00, 0x01]), None); // needs 3 ids
    }

    #[test]
    fn key_string_real_reddit_bytes() {
        // Real captured Reddit key: String "disable_pns".
        let bytes = hex(b"010b00640069007300610062006c0065005f0070006e0073");
        let (k, used) = decode_idb_key(&bytes).unwrap();
        assert_eq!(k, IdbKey::String("disable_pns".to_string()));
        assert_eq!(used, bytes.len());
        assert_eq!(k.to_display(), "disable_pns");
    }

    #[test]
    fn key_number_real_linkedin_bytes() {
        // Real captured LinkedIn key: Number 1.0.
        let bytes = hex(b"03000000000000f03f");
        let (k, used) = decode_idb_key(&bytes).unwrap();
        assert_eq!(k, IdbKey::Number(1.0));
        assert_eq!(used, 9);
    }

    #[test]
    fn key_null_and_minkey() {
        assert_eq!(decode_idb_key(&[0x00]).unwrap().0, IdbKey::Null);
        assert_eq!(decode_idb_key(&[0x05]).unwrap().0, IdbKey::MinKey);
    }

    #[test]
    fn key_binary() {
        // type 6, len 3, bytes de ad be
        let (k, used) = decode_idb_key(&[0x06, 0x03, 0xde, 0xad, 0xbe]).unwrap();
        assert_eq!(k, IdbKey::Binary(vec![0xde, 0xad, 0xbe]));
        assert_eq!(used, 5);
        assert_eq!(k.to_json(), json!("deadbe"));
    }

    #[test]
    fn key_array_of_two() {
        // type 4, count 2, [Number 1.0][String "a"]
        let mut b = vec![0x04, 0x02];
        b.extend_from_slice(&[0x03]);
        b.extend_from_slice(&1.0f64.to_le_bytes());
        b.extend_from_slice(&[0x01, 0x01, 0x00, 0x61]); // string len1 "a"
        let (k, used) = decode_idb_key(&b).unwrap();
        assert_eq!(
            k,
            IdbKey::Array(vec![IdbKey::Number(1.0), IdbKey::String("a".to_string())])
        );
        assert_eq!(used, b.len());
    }

    #[test]
    fn key_truncated_string_is_none() {
        // Claims 5 units (10 bytes) but only 2 present.
        assert_eq!(decode_idb_key(&[0x01, 0x05, 0x00, 0x61]), None);
    }

    #[test]
    fn key_unknown_type_is_none() {
        assert_eq!(decode_idb_key(&[0x7f]), None);
    }

    #[test]
    fn key_deeply_nested_array_bounded() {
        // 40 nested single-element arrays exceeds MAX_KEY_DEPTH -> None, no panic.
        let mut b = Vec::new();
        for _ in 0..40 {
            b.push(0x04); // array
            b.push(0x01); // count 1
        }
        b.push(0x00); // innermost Null
        assert_eq!(decode_idb_key(&b), None);
    }

    /// Parse an ASCII-hex byte string into bytes (test helper).
    fn hex(s: &[u8]) -> Vec<u8> {
        s.chunks_exact(2)
            .map(|c| {
                let hi = (c[0] as char).to_digit(16).unwrap();
                let lo = (c[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }
}
