//! SQLite deleted-record recovery.
//!
//! Delegated to the validated [`sqlite_forensic`] carver rather than a hand-rolled
//! free-page byte scan. `sqlite-forensic` reconstructs deleted rows from every
//! free-space substrate — freelist pages, **in-page freeblocks** (the dominant
//! browser-history deletion pattern, invisible to a free-page-only scan),
//! coalesced freeblocks, and overflow chains — under a structural
//! **0-false-positive exclusion invariant** (a still-live row is never reported as
//! deleted), and is fuzzed + tier-1 validated against the NIST/Nemetz corpora. The
//! public [`carve_sqlite_free_pages`] contract is unchanged; the recovery beneath
//! it is a strict upgrade over the previous `http`-substring page scan.

use std::path::Path;

use anyhow::{Context, Result};
use sqlite_core::Database;
use sqlite_forensic::{attribute_records, carve_all_deleted_records};

use crate::{map_carved_record, CarveResult, CarveStats, RecoveryQuality};

pub fn carve_sqlite_free_pages(path: &Path) -> Result<CarveResult> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read SQLite file: {}", path.display()))?;
    let bytes_scanned = data.len() as u64;

    // sqlite-core validates the header (magic, page-size range, structure) and
    // returns an error — never panics — on a malformed or non-SQLite file, so the
    // adversarial-header guards the old hand-rolled path carried live here too.
    let db =
        Database::open(data).map_err(|e| anyhow::anyhow!("not a valid SQLite database: {e:?}"))?;

    let carved = carve_all_deleted_records(&db);
    let attributions = attribute_records(&db, &carved);
    let page_size = u64::from(db.header().page_size.max(1));

    let mut records = Vec::with_capacity(carved.len());
    let mut records_recovered = 0usize;
    let mut records_partial = 0usize;
    for (rec, attr) in carved.iter().zip(attributions.iter()) {
        let mapped = map_carved_record(rec, attr, page_size);
        if matches!(mapped.quality, RecoveryQuality::Complete) {
            records_recovered += 1;
        } else {
            records_partial += 1;
        }
        records.push(mapped);
    }

    let stats = CarveStats {
        bytes_scanned,
        pages_scanned: db.file_page_count(),
        free_pages_found: db.freelist_count(),
        records_recovered,
        records_partial,
    };

    Ok(CarveResult {
        records,
        integrity: Vec::new(),
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::sqlite::{
        SQLITE_FREELIST_TRUNK_OFFSET, SQLITE_HEADER_SIZE, SQLITE_MAGIC, SQLITE_PAGE_SIZE_OFFSET,
    };
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn carve_empty_db_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);")
                .expect("create");
        }
        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert_eq!(result.stats.records_recovered, 0);
        assert!(result.records.is_empty());
    }

    #[test]
    fn carve_db_with_deleted_rows_finds_free_pages() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA auto_vacuum = NONE;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);",
            )
            .expect("create");

            for i in 0..200_i32 {
                conn.execute(
                    "INSERT INTO urls VALUES (?1, ?2, ?3)",
                    rusqlite::params![
                        i,
                        format!("https://example{i}.com/page/with/long/path/to/fill/space"),
                        format!("Title {i}")
                    ],
                )
                .expect("insert");
            }
            conn.execute("DELETE FROM urls", []).expect("delete");
        }

        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert!(result.stats.pages_scanned > 0, "should have scanned pages");
        assert!(
            result.stats.free_pages_found > 0,
            "should have found free pages after deletion"
        );
    }

    #[test]
    fn carve_nonexistent_file_returns_error() {
        let result = carve_sqlite_free_pages(std::path::Path::new("/nonexistent/db"));
        assert!(result.is_err());
    }

    #[test]
    fn carve_stats_populated() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, data TEXT);")
                .expect("create");
        }
        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert!(
            result.stats.bytes_scanned > 0,
            "should report bytes scanned"
        );
        assert!(
            result.stats.pages_scanned > 0,
            "should report pages scanned"
        );
    }

    #[test]
    fn carve_zero_page_size_does_not_panic() {
        // A crafted file with valid SQLite magic but a page-size field of 0x0000.
        // Real SQLite never writes this, but an attacker-controlled artifact can,
        // and `data.len() / page_size` must not divide by zero.
        use std::io::Write;
        let mut header = vec![0u8; SQLITE_HEADER_SIZE];
        header[..SQLITE_MAGIC.len()].copy_from_slice(SQLITE_MAGIC);
        header[SQLITE_PAGE_SIZE_OFFSET] = 0;
        header[SQLITE_PAGE_SIZE_OFFSET + 1] = 0;
        let f = NamedTempFile::new().expect("tempfile");
        {
            let mut fh = std::fs::File::create(f.path()).expect("create");
            fh.write_all(&header).expect("write");
        }
        // Must return cleanly (Ok or Err), never panic.
        let _ = carve_sqlite_free_pages(f.path());
    }

    #[test]
    fn carve_sub_minimum_page_size_does_not_panic() {
        // The SQLite file format (sqlite.org/fileformat2.html §1.3.2) defines the
        // page size as a power of two in 512..=65536. A crafted header can carry a
        // smaller value (here 4) that survives the divide-by-zero guard yet leaves
        // a freelist-trunk page shorter than its 8-byte (next-trunk + leaf-count)
        // prelude, so `trunk[4..8]` would read out of bounds. The carver must reject
        // the malformed page size and never panic.
        use std::io::Write;
        let mut header = vec![0u8; SQLITE_HEADER_SIZE];
        header[..SQLITE_MAGIC.len()].copy_from_slice(SQLITE_MAGIC);
        // page size = 4 (valid u16, non-zero, below the 512 minimum)
        header[SQLITE_PAGE_SIZE_OFFSET] = 0;
        header[SQLITE_PAGE_SIZE_OFFSET + 1] = 4;
        // freelist trunk = page 1, so collect_free_pages reads trunk[0..8] at offset 0
        header[SQLITE_FREELIST_TRUNK_OFFSET + 3] = 1;
        let f = NamedTempFile::new().expect("tempfile");
        {
            let mut fh = std::fs::File::create(f.path()).expect("create");
            fh.write_all(&header).expect("write");
        }
        let _ = carve_sqlite_free_pages(f.path());
    }
}
