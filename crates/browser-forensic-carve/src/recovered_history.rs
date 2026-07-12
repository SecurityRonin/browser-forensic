//! Recovered-deleted-history indicator.
//!
//! When the free-page / WAL carve recovers rows attributed to a history table
//! while few rows survive live, that residue is consistent with history having
//! been deleted — and equally with the browser's own per-item deletion or
//! retention expiry, which leave the same recoverable freeblocks. An indicator,
//! never proof.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_integrity::IntegrityIndicator;

use crate::carve_sqlite_free_pages;

/// Table names, across browser families, whose recovered residue is browsing
/// history proper. Attribution assigns a carved record one of these names when
/// its shape matches the live table (sqlite-forensic's exclusion invariant keeps
/// live rows out of the recovered set).
const HISTORY_TABLES: &[&str] = &[
    "urls",
    "visits",
    "moz_places",
    "moz_historyvisits",
    "history_items",
    "history_visits",
];

/// Carve free-page / in-page residue from the database at `path` and report, per
/// history table, how many deleted rows were recovered alongside the surviving
/// live-row count.
///
/// # Errors
/// Propagates a carve error (e.g. a non-SQLite file), so a bootstrap failure is
/// loud rather than a silent empty result.
pub fn detect_recovered_deleted_history(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let carved = carve_sqlite_free_pages(path)?;

    let mut recovered_per_table: BTreeMap<String, usize> = BTreeMap::new();
    for record in &carved.records {
        if HISTORY_TABLES.contains(&record.table.as_str()) {
            *recovered_per_table.entry(record.table.clone()).or_insert(0) += 1;
        }
    }
    if recovered_per_table.is_empty() {
        return Ok(Vec::new());
    }

    // Count surviving live rows so the finding states both sides. A per-table
    // query failure (table absent in this schema) degrades that count to 0
    // rather than aborting the whole check.
    let db = open_evidence_db(path)?;
    let conn = &db.conn;

    let mut indicators = Vec::new();
    for (table, recovered_rows) in recovered_per_table {
        let quoted = table.replace('"', "\"\"");
        let live_rows: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |row| {
                row.get(0)
            })
            .unwrap_or(0);
        indicators.push(IntegrityIndicator::RecoveredDeletedHistory {
            path: path.to_path_buf(),
            table,
            recovered_rows,
            live_rows,
        });
    }
    Ok(indicators)
}

#[cfg(test)]
mod tests {
    use browser_forensic_integrity::IntegrityIndicator;
    use rusqlite::Connection;
    use tempfile::tempdir;

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

    #[test]
    fn recovered_deleted_history_fires_with_residue() {
        let dir = tempdir().expect("tempdir");
        let db = dir.path().join("History");
        build_history_with_deletions(&db);

        let result =
            crate::recovered_history::detect_recovered_deleted_history(&db).expect("check");
        assert!(
            result.iter().any(|i| matches!(
                i,
                IntegrityIndicator::RecoveredDeletedHistory { table, recovered_rows, live_rows, .. }
                    if table == "moz_places" && *recovered_rows >= 1 && *live_rows == 3
            )),
            "recovered deleted moz_places rows (live=3) should fire, got {result:?}"
        );
    }

    #[test]
    fn pristine_history_does_not_fire() {
        let dir = tempdir().expect("tempdir");
        let db = dir.path().join("History");
        let conn = Connection::open(&db).expect("open");
        conn.execute_batch(
            "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             INSERT INTO moz_places VALUES(1,'https://alive.example/','Alive',3);",
        )
        .expect("populate");
        conn.close().ok();

        let result =
            crate::recovered_history::detect_recovered_deleted_history(&db).expect("check");
        assert!(
            !result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::RecoveredDeletedHistory { .. })),
            "a DB with no deletions must not fire, got {result:?}"
        );
    }
}
