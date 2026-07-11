//! Recovery quality that only a real SQLite carver delivers (dog-food fix):
//! `carve_sqlite_free_pages` must recover a deleted browser-history row from an
//! **in-page freeblock** — the dominant deletion pattern (deleting one history
//! entry frees a cell in-place, leaving the page allocated, so a free-*page*-only
//! byte scan finds nothing) — and attribute it to the real table, not "unknown".
//!
//! Fixture is built by the real SQLite engine via rusqlite (already a dep), so the
//! ground truth is derived from the documented construction, not a hand fixture.

use std::collections::HashMap;

use browser_forensic_carve::carve_sqlite_free_pages;
use rusqlite::Connection;
use tempfile::tempdir;

/// Build a Chrome/Firefox-style history DB with a handful of rows, then delete two
/// of them. On a single-page table the deletions become in-page freeblocks (the
/// page stays live), so only a cell-level carver recovers them.
fn build_history_with_deletions(path: &std::path::Path) {
    let conn = Connection::open(path).expect("create db");
    conn.execute_batch(
        "PRAGMA page_size=4096; PRAGMA secure_delete=OFF;
         CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
         INSERT INTO moz_places VALUES(1,'https://alive-one.example/','Alive One',3);
         INSERT INTO moz_places VALUES(2,'https://deleted-secret.example/path','Secret Page',9);
         INSERT INTO moz_places VALUES(3,'https://alive-two.example/','Alive Two',1);
         INSERT INTO moz_places VALUES(4,'https://deleted-evidence.example/x','Evidence',7);
         INSERT INTO moz_places VALUES(5,'https://alive-three.example/','Alive Three',2);
         DELETE FROM moz_places WHERE id IN (2,4);",
    )
    .expect("populate + delete");
    conn.close().ok();
}

/// Every text value across a carved record's fields, for substring assertions.
fn record_texts(fields: &HashMap<String, serde_json::Value>) -> Vec<String> {
    fields
        .values()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

#[test]
fn recovers_in_page_freeblock_deletions_with_real_table_attribution() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("History");
    build_history_with_deletions(&db);

    let result = carve_sqlite_free_pages(&db).expect("carve succeeds");

    let all_texts: Vec<String> = result
        .records
        .iter()
        .flat_map(|r| record_texts(&r.fields))
        .collect();

    // The two DELETED rows are recovered (a free-page-only URL scan misses these:
    // the deletions are in-page freeblocks, no free page exists).
    assert!(
        all_texts
            .iter()
            .any(|t| t.contains("deleted-secret.example")),
        "deleted row 2 must be recovered from its in-page freeblock; got {all_texts:?}"
    );
    assert!(
        all_texts
            .iter()
            .any(|t| t.contains("deleted-evidence.example")),
        "deleted row 4 must be recovered; got {all_texts:?}"
    );

    // Attribution: at least one recovered record names the real table, not
    // "unknown" (the crude scanner always emitted "unknown").
    assert!(
        result
            .records
            .iter()
            .any(|r| r.table.contains("moz_places")),
        "a recovered record must be attributed to moz_places; got tables {:?}",
        result.records.iter().map(|r| &r.table).collect::<Vec<_>>()
    );
}

#[test]
fn never_surfaces_a_live_row_as_deleted() {
    // The exclusion invariant sqlite-forensic guarantees and the URL scanner does
    // not: a still-live row's URL must never appear among recovered "deleted"
    // records (the scanner would match a live URL sitting in a reused free page).
    let dir = tempdir().unwrap();
    let db = dir.path().join("History");
    build_history_with_deletions(&db);

    let result = carve_sqlite_free_pages(&db).expect("carve succeeds");
    let all_texts: Vec<String> = result
        .records
        .iter()
        .flat_map(|r| record_texts(&r.fields))
        .collect();

    for live in [
        "alive-one.example",
        "alive-two.example",
        "alive-three.example",
    ] {
        assert!(
            !all_texts.iter().any(|t| t.contains(live)),
            "live row {live} must never be reported as a deleted record; got {all_texts:?}"
        );
    }
}
