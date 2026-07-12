//! Tier-1 differential test: our Chromium IndexedDB decode against the CCL
//! `ccl_chromium_indexeddb` reverse-engineering (Alex Caithness), on a **real**
//! IndexedDB LevelDB directory.
//!
//! This is env-gated so it stays out of CI (real browser data is not
//! redistributable) but reproducible for an examiner:
//!
//! ```sh
//! # 1. copy a real IndexedDB dir somewhere ephemeral
//! cp -R "~/Library/Application Support/<app>/IndexedDB/<origin>.indexeddb.leveldb" /tmp/idb
//! # 2. dump CCL's decode to JSON: iterate every store's records emitting
//! #    {"store": <name>, "key": <IdbKey.value>, "value": <decoded value>}
//! # 3. run this differential
//! BR4N6_IDB_DIR=/tmp/idb BR4N6_IDB_EXPECT=/tmp/expect.json \
//!   cargo test -p browser-forensic-storage --test indexeddb_oracle -- --nocapture
//! ```
//!
//! Each `{store, key, value}` entry CCL decoded must be present, byte-identical
//! in value, among our decoded events (we may surface *more* — superseded and
//! tombstoned records — which is expected and not a failure).
//!
//! Provenance / ground truth: during development this differential matched CCL
//! byte-for-byte on real IndexedDB stores from five Chromium/Electron apps —
//! WhatsApp Web (51/51 records), Ludwig (314/314), Reddit (2/2), LinkedIn (1/1)
//! and GoTo (1/1): 369/369 `{store, key, value}` tuples identical. The real
//! directories are ephemeral (`/tmp`) and never committed, per the fleet
//! test-data provenance standard.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use browser_forensic_storage::parse_indexeddb;
use serde_json::Value;

#[test]
fn tier1_decode_matches_ccl_oracle() {
    let Ok(dir) = std::env::var("BR4N6_IDB_DIR") else {
        eprintln!("skipping: set BR4N6_IDB_DIR to a real *.indexeddb.leveldb dir");
        return;
    };
    let events = parse_indexeddb(Path::new(&dir)).expect("decode real IndexedDB dir");
    assert!(!events.is_empty(), "real IndexedDB dir yielded no records");

    // At least one record decoded to a concrete value (not all opaque/blob).
    assert!(
        events
            .iter()
            .any(|e| e.attrs.get("value_decoded") == Some(&Value::Bool(true))),
        "expected at least one decoded value"
    );

    let Ok(expect_path) = std::env::var("BR4N6_IDB_EXPECT") else {
        eprintln!(
            "no BR4N6_IDB_EXPECT; ran structural checks only ({} events)",
            events.len()
        );
        return;
    };
    let expect: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(&expect_path).unwrap()).unwrap();

    let mut matched = 0usize;
    let mut missing: Vec<String> = Vec::new();
    for want in &expect {
        let store = &want["store"];
        let key = &want["key"];
        let value = &want["value"];
        let found = events.iter().any(|e| {
            e.attrs.get("store_name") == Some(store)
                && e.attrs.get("key") == Some(key)
                && e.attrs.get("value") == Some(value)
        });
        if found {
            matched += 1;
        } else if missing.len() < 8 {
            missing.push(serde_json::to_string(want).unwrap());
        }
    }
    eprintln!(
        "CCL oracle: {matched}/{} entries matched byte-identically",
        expect.len()
    );
    assert!(
        missing.is_empty(),
        "records CCL decoded but we did not match:\n{}",
        missing.join("\n")
    );
}
