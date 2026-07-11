//! WAL (Write-Ahead Log) recovery.
//!
//! Delegated to the validated [`sqlite_forensic`] carver (as [`carve_sqlite_free_pages`]
//! is for the main file): open the database WITH its `-wal` sidecar, carve, and keep
//! the records recovered from WAL-frame / commit-snapshot residue — the deleted rows
//! that live only in the uncommitted WAL, structured and attributed, under the
//! 0-false-positive exclusion invariant. On-disk residue is
//! [`carve_sqlite_free_pages`]' job, so filtering to WAL substrates avoids
//! double-counting across the two calls.

use std::path::Path;

use anyhow::{Context, Result};
use sqlite_core::Database;
use sqlite_forensic::{attribute_records, carve_all_deleted_records, RecoverySource};

use crate::{map_carved_record, CarveResult, CarveStats, RecoveryQuality};

pub fn recover_from_wal(db_path: &Path) -> Result<CarveResult> {
    let db_data = std::fs::read(db_path)
        .with_context(|| format!("database file does not exist: {}", db_path.display()))?;

    let wal_path = format!("{}-wal", db_path.display());
    // No `-wal` sidecar → nothing WAL-specific to recover.
    let Ok(wal_data) = std::fs::read(&wal_path) else {
        return Ok(empty_result(db_data.len() as u64));
    };
    let bytes_scanned = (db_data.len() + wal_data.len()) as u64;

    // A malformed database or WAL degrades to an empty result rather than erroring
    // (best-effort carve; sqlite-core never panics on bad input).
    let Ok(db) = Database::open_with_wal(db_data, &wal_data) else {
        return Ok(empty_result(bytes_scanned));
    };

    let carved = carve_all_deleted_records(&db);
    let attrs = attribute_records(&db, &carved);
    let page_size = u64::from(db.header().page_size.max(1));

    let mut records = Vec::new();
    for (rec, attr) in carved.iter().zip(attrs.iter()) {
        // Keep only WAL-frame / commit-snapshot residue — the WAL's own contribution.
        if matches!(
            rec.source,
            RecoverySource::WalFrame | RecoverySource::CommitSnapshot
        ) {
            records.push(map_carved_record(rec, attr, page_size));
        }
    }

    let records_recovered = records
        .iter()
        .filter(|r| matches!(r.quality, RecoveryQuality::Complete))
        .count();
    let records_partial = records.len() - records_recovered;

    Ok(CarveResult {
        stats: CarveStats {
            bytes_scanned,
            pages_scanned: db.file_page_count(),
            free_pages_found: 0,
            records_recovered,
            records_partial,
        },
        records,
        integrity: Vec::new(),
    })
}

/// An empty result carrying only the bytes-scanned stat (no WAL, or unparsable).
fn empty_result(bytes_scanned: u64) -> CarveResult {
    CarveResult {
        records: Vec::new(),
        integrity: Vec::new(),
        stats: CarveStats {
            bytes_scanned,
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecoveryMethod;
    use rusqlite::Connection;
    use std::path::PathBuf;
    use tempfile::{tempdir, NamedTempFile};

    /// Mint a real `<db>` + `<db>-wal` pair holding a row deleted INSIDE the WAL:
    /// the residue lives in the `-wal` frame, not the checkpointed main file. The
    /// db + `-wal` are copied to a stable snapshot path WHILE the connection is
    /// open (before SQLite's close-time checkpoint), so a valid WAL persists.
    fn mint_db_with_wal_deletion(dir: &Path) -> PathBuf {
        let live = dir.join("live.db");
        let conn = Connection::open(&live).expect("open");
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
             CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
             INSERT INTO moz_places VALUES(1,'https://kept.example/a','Kept');
             INSERT INTO moz_places VALUES(2,'https://deleted-in-wal.example/x','Gone');
             DELETE FROM moz_places WHERE id=2;",
        )
        .expect("setup");
        let snap = dir.join("snap.db");
        std::fs::copy(&live, &snap).expect("copy db");
        std::fs::copy(
            format!("{}-wal", live.display()),
            format!("{}-wal", snap.display()),
        )
        .expect("copy wal");
        drop(conn);
        snap
    }

    #[test]
    fn recover_from_wal_recovers_structured_deleted_row() {
        let dir = tempdir().expect("tempdir");
        let db = mint_db_with_wal_deletion(dir.path());
        let result = recover_from_wal(&db).expect("recover");

        let texts: Vec<String> = result
            .records
            .iter()
            .flat_map(|r| r.fields.values())
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        // The row deleted inside the WAL is recovered from the WAL-frame residue,
        // as a STRUCTURED row (its non-URL title too), not just a URL byte-match.
        assert!(
            texts.iter().any(|t| t.contains("deleted-in-wal.example")),
            "WAL-deleted URL must be recovered: {texts:?}"
        );
        assert!(
            texts.iter().any(|t| t == "Gone"),
            "the non-URL title must be recovered (structured row): {texts:?}"
        );
        // The deleted row is recovered as a MULTI-COLUMN record (id, url, title) —
        // the structural upgrade over the old URL-only byte scan. (Attribution of
        // WAL-frame residue to a live table is a separate, harder problem — the
        // residue is not on a live b-tree page — so `table` may be "unknown".)
        assert!(
            result.records.iter().any(|r| r.fields.len() >= 2),
            "a recovered WAL row must carry its full column set, not just a URL: {:?}",
            result
                .records
                .iter()
                .map(|r| r.fields.len())
                .collect::<Vec<_>>()
        );
        assert!(
            result
                .records
                .iter()
                .all(|r| matches!(r.method, RecoveryMethod::WalUncommitted)),
            "WAL recoveries carry the WalUncommitted method"
        );
    }

    #[test]
    fn recover_from_wal_no_wal_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA journal_mode = DELETE;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);",
            )
            .expect("create");
        }
        let result = recover_from_wal(f.path()).expect("recover");
        assert!(result.records.is_empty());
        assert_eq!(result.stats.records_recovered, 0);
    }

    #[test]
    fn recover_from_wal_nonexistent_returns_error() {
        let result = recover_from_wal(std::path::Path::new("/nonexistent/db"));
        assert!(result.is_err());
    }

    #[test]
    fn recover_from_wal_malformed_degrades_to_empty() {
        // A non-SQLite db + garbage WAL must not error or panic — degrade to empty.
        let dir = tempdir().expect("tempdir");
        let db = dir.path().join("x.db");
        std::fs::write(&db, b"not a sqlite database").expect("write db");
        std::fs::write(dir.path().join("x.db-wal"), b"garbage wal bytes").expect("write wal");
        let result = recover_from_wal(&db).expect("must not error on malformed input");
        assert!(result.records.is_empty());
    }
}
