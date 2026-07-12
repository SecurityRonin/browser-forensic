//! Manual-DB-edit indicators drawn from the SQLite header and `sqlite_sequence`.
//!
//! These observations are consistent with a database having been altered outside
//! the browser (e.g. with a hex editor or a non-standard SQLite writer). Each is
//! equally consistent with a benign cause — an older SQLite, ordinary deletion,
//! or a rolled-back insert — so they are indicators, never proof.

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
