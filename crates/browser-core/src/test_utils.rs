/// SQLite helpers for use in tests across the workspace.
pub mod sqlite {
    use rusqlite::Connection;
    use std::path::Path;
    use tempfile::NamedTempFile;

    /// A temporary SQLite database for use in tests.
    pub struct TestDb {
        file: NamedTempFile,
    }

    impl TestDb {
        /// Create a new temporary database and run `schema_sql` to set it up.
        pub fn new(schema_sql: &str) -> Self {
            let file = NamedTempFile::new().unwrap();
            let conn = Connection::open(file.path()).unwrap();
            conn.execute_batch(schema_sql).unwrap();
            Self { file }
        }

        /// Return the path to the temporary database file.
        pub fn path(&self) -> &Path {
            self.file.path()
        }

        /// Execute an INSERT (or any single statement) with positional params.
        pub fn insert<P: rusqlite::Params>(&self, sql: &str, params: P) {
            let conn = Connection::open(self.file.path()).unwrap();
            conn.execute(sql, params).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sqlite::TestDb;
    use rusqlite::{Connection, params};

    #[test]
    fn test_db_creates_with_schema() {
        let db = TestDb::new("CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT);");
        // If the path is valid, we can open the DB
        let conn = Connection::open(db.path()).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM foo", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_db_insert_stores_row() {
        let db = TestDb::new("CREATE TABLE bar (val TEXT);");
        db.insert("INSERT INTO bar VALUES (?1)", params!["hello"]);
        let conn = Connection::open(db.path()).unwrap();
        let val: String = conn
            .query_row("SELECT val FROM bar", [], |r| r.get(0))
            .unwrap();
        assert_eq!(val, "hello");
    }
}
