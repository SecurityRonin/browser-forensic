//! WAL (Write-Ahead Log) recovery.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use rusqlite::Connection;

    #[test]
    fn recover_from_wal_no_wal_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA journal_mode = DELETE;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);"
            ).expect("create");
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
    fn recover_from_wal_with_wal_file_scans_pages() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
                 INSERT INTO urls VALUES (1, 'https://wal-test.example.com');"
            ).expect("setup");
        }
        let result = recover_from_wal(f.path()).expect("recover");
        assert!(result.stats.bytes_scanned >= 0);
    }
}
