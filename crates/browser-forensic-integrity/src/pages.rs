//! Page-level SQLite indicators: freelist growth (freed pages) and header/file
//! page-count mismatch. Delegates the structural inspection to the validated
//! [`sqlite_forensic`] auditor rather than re-parsing the b-tree here.

use std::path::Path;

use anyhow::{Context, Result};
use sqlite_core::Database;
use sqlite_forensic::AnomalyKind;

use crate::IntegrityIndicator;

/// Inspect the page-level structure of the SQLite database at `path` for
/// freed-page growth and header/file page-count disagreement.
///
/// A `-wal` sidecar, if present, is applied read-only so the freelist reflects
/// the same view the browser would see. Reuses [`sqlite_forensic::audit`] for the
/// structural read.
///
/// # Errors
/// Returns an error if the file cannot be read or is not a valid SQLite database
/// — a bootstrap failure surfaces loudly rather than as a silent empty result.
pub fn check_page_state(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read SQLite file: {}", path.display()))?;

    let wal_path_str = format!("{}-wal", path.display());
    let wal_path = Path::new(&wal_path_str);
    let db = if wal_path.exists() {
        let wal = std::fs::read(wal_path)
            .with_context(|| format!("failed to read WAL: {}", wal_path.display()))?;
        Database::open_with_wal(data, &wal)
    } else {
        Database::open(data)
    }
    .map_err(|e| anyhow::anyhow!("not a valid SQLite database: {}: {e:?}", path.display()))?;

    let total_pages = db.page_count();
    let mut indicators = Vec::new();
    for anomaly in sqlite_forensic::audit(&db) {
        match anomaly.kind {
            AnomalyKind::NonEmptyFreelist { free_pages } => {
                indicators.push(IntegrityIndicator::FreelistGrowth {
                    path: path.to_path_buf(),
                    free_pages,
                    total_pages,
                });
            }
            AnomalyKind::PageCountMismatch {
                header_pages,
                file_pages,
            } => {
                indicators.push(IntegrityIndicator::PageCountMismatch {
                    path: path.to_path_buf(),
                    header_pages,
                    file_pages,
                });
            }
            // Other audit anomalies (reserved space, WAL overlay, dropped
            // schema) are surfaced by their own dedicated checks or by the carve
            // path; page-state focuses on freelist + page-count.
            _ => {}
        }
    }

    Ok(indicators)
}

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
