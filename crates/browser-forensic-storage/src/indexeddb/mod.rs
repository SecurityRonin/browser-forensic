//! Chromium IndexedDB decoding: LevelDB key structure, the Blink value wrapper,
//! and the V8 `ValueSerializer` blob inside.
//!
//! IndexedDB persists its object stores in a single LevelDB directory
//! (`<profile>/IndexedDB/<origin>.indexeddb.leveldb/`). This module decodes,
//! read-only and panic-free:
//!
//! * the LevelDB **key** layout — a `(database id, object-store id, index id)`
//!   prefix followed by an encoded IDBKey ([`varint`], [`key`]);
//! * the per-database / per-store **metadata** records that name each database
//!   and object store;
//! * the record **value** — a Blink envelope ([`envelope`]) wrapping a V8
//!   `ValueSerializer` stream ([`v8`]) decoded to a [`serde_json::Value`] for the
//!   documented tag subset, with any unsupported tag surfaced raw rather than
//!   fabricated.
//!
//! References: Chromium `content/browser/indexed_db/indexed_db_leveldb_coding.cc`,
//! `third_party/blink/renderer/modules/indexeddb/idb_value_wrapping.cc`,
//! `v8/src/objects/value-serializer.cc`, and Alex Caithness / CCL's
//! `ccl_chromium_indexeddb` reverse engineering (used as the differential oracle).

mod envelope;
mod key;
mod record;
mod v8;
mod varint;

pub(crate) use key::IdbKey;
pub(crate) use record::{decode_indexeddb, DecodedValue, IndexedDbRecord};
