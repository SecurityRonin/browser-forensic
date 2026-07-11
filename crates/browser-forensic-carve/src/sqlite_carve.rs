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

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use sqlite_core::{Database, Value};
use sqlite_forensic::{attribute_records, carve_all_deleted_records, Attribution};

use crate::{CarveResult, CarveStats, CarvedRecord, RecoveryMethod, RecoveryQuality};

/// Confidence at or above which a recovered record is graded [`RecoveryQuality::Complete`]
/// (a full, high-confidence row reconstruction); below it the recovery is
/// [`RecoveryQuality::Partial`] (e.g. a freeblock-reconstructed row whose clobbered
/// header was re-derived).
const COMPLETE_CONFIDENCE: f32 = 0.7;

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

/// Map a [`sqlite_forensic`] carved record plus its table attribution onto the
/// browser-forensic [`CarvedRecord`] the CLI and triage consume.
fn map_carved_record(
    rec: &sqlite_forensic::CarvedRecord,
    attr: &Attribution,
    page_size: u64,
) -> CarvedRecord {
    // Absolute byte offset of the cell: a 1-based page number → 0-based file offset.
    let offset = u64::from(rec.page.saturating_sub(1))
        .saturating_mul(page_size)
        .saturating_add(rec.offset as u64);

    let table = match attr {
        Attribution::Known(name) => name.clone(),
        Attribution::Inferred { guess, .. } => guess.clone(),
        Attribution::Unattributed => "unknown".to_string(),
    };

    // Every recovered column, keyed positionally (`col0`, `col1`, …) — the actual
    // values the deleted row held, not just a URL byte-match.
    let mut fields: HashMap<String, serde_json::Value> = HashMap::with_capacity(rec.values.len());
    for (i, value) in rec.values.iter().enumerate() {
        fields.insert(format!("col{i}"), value_to_json(value));
    }

    CarvedRecord {
        offset,
        table,
        fields,
        // `carve_sqlite_free_pages` opens the main database only (no `-wal`, no
        // `-journal`), so every recovered record comes from an on-disk free-space
        // class (freelist page / in-page freeblock / freeblock reconstruction /
        // dropped-table residue / prior version) — all reported as `FreePage`. WAL
        // and rollback-journal recovery are the separate `recover_from_wal` path.
        method: RecoveryMethod::FreePage,
        quality: if rec.confidence >= COMPLETE_CONFIDENCE {
            RecoveryQuality::Complete
        } else {
            RecoveryQuality::Partial
        },
    }
}

/// Decode a SQLite [`Value`] to JSON for the recovered-record field map. A BLOB is
/// hex-encoded so the value round-trips as a JSON string rather than being lost.
fn value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Integer(n) => serde_json::json!(n),
        Value::Real(r) => serde_json::json!(r),
        Value::Text(t) => serde_json::json!(t),
        Value::Blob(b) => serde_json::json!(hex_encode(b)),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
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
    fn value_to_json_maps_every_sqlite_type() {
        assert_eq!(value_to_json(&Value::Null), serde_json::Value::Null);
        assert_eq!(value_to_json(&Value::Integer(42)), serde_json::json!(42));
        assert_eq!(value_to_json(&Value::Real(1.5)), serde_json::json!(1.5));
        assert_eq!(
            value_to_json(&Value::Text("u".to_string())),
            serde_json::json!("u")
        );
        // A BLOB hex-encodes so it round-trips as a JSON string, never dropped.
        assert_eq!(
            value_to_json(&Value::Blob(vec![0x00, 0xab, 0xff])),
            serde_json::json!("00abff")
        );
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
