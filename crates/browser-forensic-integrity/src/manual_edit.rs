//! Manual-DB-edit indicators drawn from the SQLite header and `sqlite_sequence`.
//!
//! These observations are consistent with a database having been altered outside
//! the browser (e.g. with a hex editor or a non-standard SQLite writer). Each is
//! equally consistent with a benign cause — an older SQLite, ordinary deletion,
//! or a rolled-back insert — so they are indicators, never proof.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use browser_forensic_core::sqlite::open_evidence_db;

use crate::sqlite_header::{parse_header, HEADER_LEN};
use crate::IntegrityIndicator;

/// Inspect the SQLite header and `sqlite_sequence` at `path` for edits made
/// outside the browser's own writes.
///
/// Emits [`IntegrityIndicator::ChangeCounterMismatch`] (change counter vs
/// version-valid-for), [`IntegrityIndicator::HeaderVersionAnomaly`] (out-of-range
/// format version), and [`IntegrityIndicator::SqliteSequenceGap`] (AUTOINCREMENT
/// high-water mark ahead of the max surviving rowid).
///
/// # Errors
/// Returns an error — naming the path and the magic bytes actually found — when
/// the file is not a valid SQLite database, so a bootstrap failure is loud rather
/// than a silent empty result.
pub fn check_header_anomalies(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut head = vec![0u8; HEADER_LEN];
    let read = read_up_to(&mut file, &mut head)
        .with_context(|| format!("failed to read header of {}", path.display()))?;
    head.truncate(read);

    let header = parse_header(&head).ok_or_else(|| {
        let magic = head.get(..read.min(16)).unwrap_or(&[]);
        anyhow::anyhow!(
            "{}: not a valid SQLite database (magic bytes: {})",
            path.display(),
            hex(magic)
        )
    })?;

    let mut indicators = Vec::new();

    // version-valid-for is 0 on a file never written by a version-aware SQLite;
    // only a non-zero, differing value is a signal.
    if header.version_valid_for != 0 && header.change_counter != header.version_valid_for {
        indicators.push(IntegrityIndicator::ChangeCounterMismatch {
            path: path.to_path_buf(),
            change_counter: header.change_counter,
            version_valid_for: header.version_valid_for,
        });
    }

    for (field, value) in [
        ("write_version", header.write_version),
        ("read_version", header.read_version),
    ] {
        if value != 1 && value != 2 {
            indicators.push(IntegrityIndicator::HeaderVersionAnomaly {
                path: path.to_path_buf(),
                field: field.to_string(),
                value,
            });
        }
    }

    check_sqlite_sequence_gaps(path, &mut indicators)?;

    Ok(indicators)
}

/// Read up to `buf.len()` bytes, tolerating a file shorter than the header.
fn read_up_to(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// For every table tracked in `sqlite_sequence`, report a gap where the stored
/// high-water mark exceeds the table's current maximum rowid.
fn check_sqlite_sequence_gaps(path: &Path, indicators: &mut Vec<IntegrityIndicator>) -> Result<()> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;

    let has_seq: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'",
        [],
        |row| row.get(0),
    )?;
    if !has_seq {
        return Ok(());
    }

    let seqs: Vec<(String, i64)> = {
        let mut stmt = conn.prepare("SELECT name, seq FROM sqlite_sequence")?;
        let rows: Vec<(String, i64)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        rows
    };

    for (table, seq) in seqs {
        // The table name comes from sqlite_sequence, which SQLite populates from
        // real table names; quote it as an identifier to build the MAX query.
        let quoted = table.replace('"', "\"\"");
        let max_rowid: Option<i64> = conn
            .query_row(&format!("SELECT MAX(rowid) FROM \"{quoted}\""), [], |row| {
                row.get(0)
            })
            .ok()
            .flatten();
        let max_rowid = max_rowid.unwrap_or(0);
        if seq > max_rowid {
            indicators.push(IntegrityIndicator::SqliteSequenceGap {
                path: path.to_path_buf(),
                table,
                seq,
                max_rowid,
            });
        }
    }
    Ok(())
}

/// Lowercase hex of the offending magic bytes, so an "unknown" report shows the
/// actual value that was found rather than discarding it.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::IntegrityIndicator;
    use tempfile::tempdir;

    fn write_real_db(rows_sql: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().expect("tempdir");
        let p = dir.path().join("History");
        let conn = rusqlite::Connection::open(&p).expect("open");
        conn.execute_batch(rows_sql).expect("schema");
        drop(conn);
        (dir, p)
    }

    #[test]
    fn change_counter_mismatch_detected_after_header_edit() {
        let (_dir, p) = write_real_db(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t(v) VALUES ('a');",
        );
        // Simulate an edit by a tool that does not maintain version-valid-for:
        // overwrite offset 92..96 so it differs from the change counter (offset 24).
        let mut bytes = std::fs::read(&p).expect("read");
        let cc = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        bytes[92..96].copy_from_slice(&cc.wrapping_add(7).to_be_bytes());
        std::fs::write(&p, &bytes).expect("write");

        let result = crate::manual_edit::check_header_anomalies(&p).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::ChangeCounterMismatch { .. })),
            "header with change_counter != version_valid_for should fire, got {result:?}"
        );
    }

    #[test]
    fn pristine_header_has_no_change_counter_mismatch() {
        let (_dir, p) = write_real_db(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t(v) VALUES ('a');",
        );
        let result = crate::manual_edit::check_header_anomalies(&p).expect("check");
        assert!(
            !result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::ChangeCounterMismatch { .. })),
            "a DB written by modern SQLite keeps the fields in sync, got {result:?}"
        );
    }

    #[test]
    fn invalid_write_version_detected() {
        let (_dir, p) = write_real_db("CREATE TABLE t (id INTEGER PRIMARY KEY);");
        let mut bytes = std::fs::read(&p).expect("read");
        bytes[18] = 9; // write version must be 1 or 2
        std::fs::write(&p, &bytes).expect("write");

        let result = crate::manual_edit::check_header_anomalies(&p).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::HeaderVersionAnomaly { value: 9, .. })),
            "write_version 9 should fire HeaderVersionAnomaly, got {result:?}"
        );
    }

    #[test]
    fn sqlite_sequence_gap_detected() {
        let (_dir, p) = write_real_db(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, u TEXT);
             INSERT INTO urls(u) VALUES ('a'),('b'),('c');
             DELETE FROM urls WHERE id = 3;",
        );
        // seq is now 3 (AUTOINCREMENT high-water mark) but max rowid is 2.
        let result = crate::manual_edit::check_header_anomalies(&p).expect("check");
        assert!(
            result.iter().any(|i| matches!(
                i,
                IntegrityIndicator::SqliteSequenceGap { table, seq: 3, max_rowid: 2, .. } if table == "urls"
            )),
            "sqlite_sequence seq(3) > max rowid(2) should fire, got {result:?}"
        );
    }

    #[test]
    fn non_sqlite_file_errors() {
        let dir = tempdir().expect("tempdir");
        let p = dir.path().join("garbage");
        std::fs::write(&p, b"definitely not sqlite").expect("write");
        assert!(crate::manual_edit::check_header_anomalies(&p).is_err());
    }
}
