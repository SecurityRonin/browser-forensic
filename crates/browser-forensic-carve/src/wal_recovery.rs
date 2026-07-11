//! WAL (Write-Ahead Log) recovery.

use std::path::Path;

use anyhow::{Context, Result};

use crate::{CarveResult, CarveStats, CarvedRecord, RecoveryMethod, RecoveryQuality};
use forensicnomicon::sqlite::{SQLITE_WAL_FRAME_HEADER_SIZE, SQLITE_WAL_HEADER_SIZE};

pub fn recover_from_wal(db_path: &Path) -> Result<CarveResult> {
    let wal_path_str = format!("{}-wal", db_path.display());
    let wal_path = Path::new(&wal_path_str);

    if !wal_path.exists() {
        // Also check that the db itself exists — return error for nonexistent db
        if !db_path.exists() {
            anyhow::bail!("database file does not exist: {}", db_path.display());
        }
        return Ok(CarveResult {
            records: Vec::new(),
            integrity: Vec::new(),
            stats: CarveStats::default(),
        });
    }

    let wal_data = std::fs::read(wal_path)
        .with_context(|| format!("failed to read WAL file: {}", wal_path.display()))?;

    if wal_data.len() < SQLITE_WAL_HEADER_SIZE {
        return Ok(CarveResult {
            records: Vec::new(),
            integrity: Vec::new(),
            stats: CarveStats {
                bytes_scanned: wal_data.len() as u64,
                ..Default::default()
            },
        });
    }

    let page_size = {
        let raw =
            u32::from_be_bytes([wal_data[8], wal_data[9], wal_data[10], wal_data[11]]) as usize;
        if raw == 0 {
            4096
        } else {
            raw
        }
    };

    let mut stats = CarveStats {
        bytes_scanned: wal_data.len() as u64,
        ..Default::default()
    };
    let mut records = Vec::new();

    let mut offset = SQLITE_WAL_HEADER_SIZE;
    while offset + SQLITE_WAL_FRAME_HEADER_SIZE + page_size <= wal_data.len() {
        stats.pages_scanned += 1;
        let page_data = &wal_data[offset + SQLITE_WAL_FRAME_HEADER_SIZE
            ..offset + SQLITE_WAL_FRAME_HEADER_SIZE + page_size];

        let recovered = scan_wal_page_for_urls(page_data, offset as u64);
        stats.records_recovered += recovered.len();
        records.extend(recovered);

        offset += SQLITE_WAL_FRAME_HEADER_SIZE + page_size;
    }

    Ok(CarveResult {
        records,
        integrity: Vec::new(),
        stats,
    })
}

fn scan_wal_page_for_urls(page_data: &[u8], frame_offset: u64) -> Vec<CarvedRecord> {
    let mut records = Vec::new();
    let needle = b"http";

    let mut i = 0;
    while i + needle.len() <= page_data.len() {
        if &page_data[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        let end = page_data[i..]
            .iter()
            .position(|&b| !(0x20..=0x7e).contains(&b))
            .map_or(page_data.len(), |pos| i + pos);

        if end > i + 10 {
            if let Ok(url) = std::str::from_utf8(&page_data[i..end]) {
                if url.starts_with("http://") || url.starts_with("https://") {
                    let mut fields = std::collections::HashMap::new();
                    fields.insert("url".to_string(), serde_json::json!(url));
                    records.push(CarvedRecord {
                        offset: frame_offset + i as u64,
                        table: "unknown".to_string(),
                        fields,
                        method: RecoveryMethod::WalUncommitted,
                        quality: RecoveryQuality::Partial,
                    });
                }
            }
        }
        i += 1;
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;
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
        // Real table attribution + WAL recovery method.
        assert!(
            result
                .records
                .iter()
                .any(|r| r.table.contains("moz_places")),
            "recovered rows attribute to the real table, not \"unknown\": {:?}",
            result.records.iter().map(|r| &r.table).collect::<Vec<_>>()
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
