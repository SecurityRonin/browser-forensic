//! SQLite database-level integrity checks.

use std::path::Path;

use anyhow::Result;
use browser_core::sqlite::open_evidence_db;

use crate::IntegrityIndicator;

/// Run SQLite's `PRAGMA integrity_check` on the database at `path`.
///
/// Returns an empty vec if the database passes. Returns `SqliteIntegrityFailure` for each issue.
pub fn check_database_integrity(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut stmt = conn.prepare("PRAGMA integrity_check")?;
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();

    let mut indicators = Vec::new();
    for row in &rows {
        if row != "ok" {
            indicators.push(IntegrityIndicator::SqliteIntegrityFailure {
                path: path.to_path_buf(),
                message: row.clone(),
            });
        }
    }

    Ok(indicators)
}

/// Check whether a WAL file exists alongside the database.
///
/// A WAL file indicates uncommitted transactions or a crash before checkpointing — both forensically relevant.
pub fn check_wal_state(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let wal_path_str = format!("{}-wal", path.display());
    let wal_path = std::path::Path::new(&wal_path_str);

    let mut indicators = Vec::new();
    if wal_path.exists() && std::fs::metadata(wal_path)?.len() > 0 {
        indicators.push(IntegrityIndicator::WalPresent {
            path: wal_path.to_path_buf(),
        });
    }

    Ok(indicators)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn check_database_integrity_valid_db_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        let conn = rusqlite::Connection::open(f.path()).expect("open");
        conn.execute_batch("CREATE TABLE test (id INTEGER PRIMARY KEY, val TEXT);")
            .expect("create table");
        conn.execute("INSERT INTO test VALUES (1, 'hello')", [])
            .expect("insert");
        drop(conn);

        let result = check_database_integrity(f.path()).expect("check");
        assert!(
            result.is_empty(),
            "valid db should have no integrity issues"
        );
    }

    #[test]
    fn check_database_integrity_nonexistent_returns_error() {
        let result = check_database_integrity(Path::new("/nonexistent/path/to/db"));
        assert!(result.is_err());
    }

    #[test]
    fn check_wal_state_detects_wal_file() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&db_path).expect("open");
        conn.execute_batch("CREATE TABLE t (id INTEGER);")
            .expect("create");
        drop(conn);

        let wal_path = dir.path().join("test.db-wal");
        std::fs::write(&wal_path, b"fake wal content").expect("write wal");

        let result = check_wal_state(&db_path).expect("check");
        assert!(result
            .iter()
            .any(|i| matches!(i, crate::IntegrityIndicator::WalPresent { .. })));
    }

    #[test]
    fn check_wal_state_no_wal_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        let conn = rusqlite::Connection::open(f.path()).expect("open");
        conn.execute_batch("CREATE TABLE t (id INTEGER);")
            .expect("create");
        drop(conn);

        let result = check_wal_state(f.path()).expect("check");
        assert!(result.is_empty());
    }
}
