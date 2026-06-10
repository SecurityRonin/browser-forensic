#![deny(clippy::unwrap_used)]
//! Browser integrity detection — detects anomalies indicating
//! tampering, clearing, or corruption in browser artifacts.

pub mod cookies;
pub mod database;
pub mod history;

pub use cookies::check_cookie_integrity;
pub use database::{check_database_integrity, check_wal_state};
pub use history::check_history_integrity;

use std::path::PathBuf;

use browser_core::BrowserFamily;
use serde::Serialize;

/// An anomaly detected in a browser artifact indicating tampering, clearing, or corruption.
///
/// Mirrors `winevt_integrity::IntegrityIndicator` from winevt-forensic.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum IntegrityIndicator {
    /// Browser history was cleared (empty tables with non-zero auto-increment counters).
    HistoryCleared {
        browser: BrowserFamily,
        path: PathBuf,
        detected_at_ns: i64,
    },
    /// Gap in visit/row IDs suggesting deleted records.
    VisitIdGap {
        path: PathBuf,
        expected_id: i64,
        found_id: i64,
    },
    /// Timestamps are not monotonically increasing within a table.
    TimestampNonMonotonic {
        path: PathBuf,
        row_id: i64,
        prev_ts_ns: i64,
        this_ts_ns: i64,
    },
    /// Cookie creation timestamp is after last_access (impossible naturally).
    CookieTimestampAnomaly {
        path: PathBuf,
        host: String,
        creation_ns: i64,
        last_access_ns: i64,
    },
    /// WAL file exists alongside database — uncommitted changes or crash recovery needed.
    WalPresent { path: PathBuf },
    /// SQLite PRAGMA integrity_check reported a problem.
    SqliteIntegrityFailure { path: PathBuf, message: String },
    /// Safari history_tombstones table contains deleted URL records.
    HistoryTombstoneFound {
        path: PathBuf,
        url: String,
        deleted_at_ns: i64,
    },
    /// Download record references a file that no longer exists on disk.
    DownloadFileMissing { path: PathBuf, target_path: String },
    /// Auto-increment counter much higher than max rowid (indicates mass deletion).
    AutoIncrementGap {
        path: PathBuf,
        table: String,
        max_rowid: i64,
        auto_increment: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::BrowserFamily;
    use std::path::PathBuf;

    #[test]
    fn integrity_indicator_history_cleared_serializes() {
        let indicator = IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/tmp/History"),
            detected_at_ns: 1_000_000_000,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("HistoryCleared"));
    }

    #[test]
    fn integrity_indicator_visit_id_gap() {
        let indicator = IntegrityIndicator::VisitIdGap {
            path: PathBuf::from("/tmp/History"),
            expected_id: 42,
            found_id: 100,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("VisitIdGap"));
        assert!(json.contains("42"));
        assert!(json.contains("100"));
    }

    #[test]
    fn integrity_indicator_timestamp_non_monotonic() {
        let indicator = IntegrityIndicator::TimestampNonMonotonic {
            path: PathBuf::from("/tmp/History"),
            row_id: 5,
            prev_ts_ns: 2_000_000_000,
            this_ts_ns: 1_000_000_000,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("TimestampNonMonotonic"));
    }

    #[test]
    fn integrity_indicator_wal_present() {
        let indicator = IntegrityIndicator::WalPresent {
            path: PathBuf::from("/tmp/History-wal"),
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("WalPresent"));
    }

    #[test]
    fn integrity_indicator_cookie_timestamp_anomaly() {
        let indicator = IntegrityIndicator::CookieTimestampAnomaly {
            path: PathBuf::from("/tmp/Cookies"),
            host: "example.com".to_string(),
            creation_ns: 2_000_000_000,
            last_access_ns: 1_000_000_000,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("CookieTimestampAnomaly"));
    }

    #[test]
    fn integrity_indicator_sqlite_integrity_failure() {
        let indicator = IntegrityIndicator::SqliteIntegrityFailure {
            path: PathBuf::from("/tmp/History"),
            message: "page 5: corrupt".to_string(),
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("SqliteIntegrityFailure"));
    }

    #[test]
    fn integrity_indicator_history_tombstone() {
        let indicator = IntegrityIndicator::HistoryTombstoneFound {
            path: PathBuf::from("/tmp/History.db"),
            url: "https://deleted.example.com".to_string(),
            deleted_at_ns: 3_000_000_000,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("HistoryTombstoneFound"));
    }

    #[test]
    fn integrity_indicator_debug_display() {
        let indicator = IntegrityIndicator::WalPresent {
            path: PathBuf::from("/tmp/test-wal"),
        };
        let debug = format!("{indicator:?}");
        assert!(debug.contains("WalPresent"));
    }

    #[test]
    fn integrity_indicator_clone() {
        let indicator = IntegrityIndicator::WalPresent {
            path: PathBuf::from("/tmp/test"),
        };
        let cloned = indicator.clone();
        assert_eq!(
            serde_json::to_string(&indicator).expect("ser1"),
            serde_json::to_string(&cloned).expect("ser2"),
        );
    }

    #[test]
    fn crate_root_reexports_check_functions() {
        use browser_core::BrowserFamily;
        use std::path::Path;
        // Verify functions are accessible at crate root (not just in submodules)
        let _: fn(&Path, BrowserFamily) -> anyhow::Result<Vec<IntegrityIndicator>> =
            check_history_integrity;
        let _: fn(&Path, BrowserFamily) -> anyhow::Result<Vec<IntegrityIndicator>> =
            check_cookie_integrity;
        let _: fn(&Path) -> anyhow::Result<Vec<IntegrityIndicator>> = check_database_integrity;
        let _: fn(&Path) -> anyhow::Result<Vec<IntegrityIndicator>> = check_wal_state;
    }
}
