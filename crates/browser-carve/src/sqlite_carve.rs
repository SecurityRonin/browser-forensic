//! SQLite free-page carving for deleted record recovery.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use rusqlite::Connection;

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
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);"
            ).expect("create");

            for i in 0..200_i32 {
                conn.execute(
                    "INSERT INTO urls VALUES (?1, ?2, ?3)",
                    rusqlite::params![i, format!("https://example{i}.com/page/with/long/path/to/fill/space"), format!("Title {i}")],
                ).expect("insert");
            }
            conn.execute("DELETE FROM urls", []).expect("delete");
        }

        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert!(result.stats.pages_scanned > 0, "should have scanned pages");
        assert!(result.stats.free_pages_found > 0, "should have found free pages after deletion");
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
        assert!(result.stats.bytes_scanned > 0, "should report bytes scanned");
        assert!(result.stats.pages_scanned > 0, "should report pages scanned");
    }
}
