//! SQLite database-level integrity checks.

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
        assert!(result.is_empty(), "valid db should have no integrity issues");
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
        conn.execute_batch("CREATE TABLE t (id INTEGER);").expect("create");
        drop(conn);

        let wal_path = dir.path().join("test.db-wal");
        std::fs::write(&wal_path, b"fake wal content").expect("write wal");

        let result = check_wal_state(&db_path).expect("check");
        assert!(result.iter().any(|i| matches!(i, crate::IntegrityIndicator::WalPresent { .. })));
    }

    #[test]
    fn check_wal_state_no_wal_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        let conn = rusqlite::Connection::open(f.path()).expect("open");
        conn.execute_batch("CREATE TABLE t (id INTEGER);").expect("create");
        drop(conn);

        let result = check_wal_state(f.path()).expect("check");
        assert!(result.is_empty());
    }
}
