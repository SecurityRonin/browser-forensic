#![deny(clippy::unwrap_used)]
//! Browser integrity detection — detects anomalies indicating
//! tampering, clearing, or corruption in browser artifacts.

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
        let debug = format!("{:?}", indicator);
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
}
