//! Page-level SQLite indicators: freelist growth (freed pages) and header/file
//! page-count mismatch. Delegates the structural inspection to the validated
//! [`sqlite_forensic`] auditor rather than re-parsing the b-tree here.

#[cfg(test)]
mod tests {
    use crate::IntegrityIndicator;
    use tempfile::tempdir;

    /// A DB with rows deleted (no VACUUM) leaves free pages on the freelist,
    /// which the detector surfaces as a `FreelistGrowth` indicator — an
    /// observation consistent with prior deletion, never proof of clearing.
    #[test]
    fn freelist_growth_detected_after_delete() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("History");
        let conn = rusqlite::Connection::open(&db_path).expect("open");
        conn.execute_batch(
            "PRAGMA auto_vacuum=NONE;
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);",
        )
        .expect("schema");
        // Fill enough rows to span many pages, then delete them all so whole
        // pages are released to the freelist.
        for i in 0..400 {
            conn.execute(
                "INSERT INTO urls(id, url) VALUES (?1, ?2)",
                rusqlite::params![i, format!("https://example.com/{i}/{}", "x".repeat(200))],
            )
            .expect("insert");
        }
        conn.execute("DELETE FROM urls", []).expect("delete");
        drop(conn);

        let result = crate::pages::check_page_state(&db_path).expect("check");
        assert!(
            result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::FreelistGrowth { free_pages, .. } if *free_pages > 0)),
            "deleted-then-unvacuumed db should report freelist growth, got {result:?}"
        );
    }

    /// A freshly written database with no deletions has an empty freelist and
    /// must NOT fire (silent on pristine).
    #[test]
    fn pristine_db_has_no_freelist_growth() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("History");
        let conn = rusqlite::Connection::open(&db_path).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
             INSERT INTO urls(id, url) VALUES (1, 'https://a.com');",
        )
        .expect("schema+insert");
        drop(conn);

        let result = crate::pages::check_page_state(&db_path).expect("check");
        assert!(
            !result
                .iter()
                .any(|i| matches!(i, IntegrityIndicator::FreelistGrowth { .. })),
            "pristine db must not report freelist growth, got {result:?}"
        );
    }

    /// A non-SQLite / truncated file must not panic and must surface as an error
    /// (bootstrap failure), never a silent empty result.
    #[test]
    fn non_sqlite_file_errors() {
        let dir = tempdir().expect("tempdir");
        let p = dir.path().join("garbage");
        std::fs::write(&p, b"not a database").expect("write");
        assert!(crate::pages::check_page_state(&p).is_err());
    }
}
