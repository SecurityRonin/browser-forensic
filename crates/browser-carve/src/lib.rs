#![deny(clippy::unwrap_used)]
//! Browser artifact carving and recovery.
//!
//! Recovers deleted browser data from SQLite free pages, WAL files,
//! and binary formats.

pub mod sqlite_carve;
pub mod wal_recovery;

pub use sqlite_carve::carve_sqlite_free_pages;
pub use wal_recovery::recover_from_wal;

use std::collections::HashMap;

use browser_integrity::IntegrityIndicator;
use serde::Serialize;

/// How a deleted record was recovered.
#[derive(Debug, Clone, Serialize)]
pub enum RecoveryMethod {
    /// Recovered from a SQLite free (deallocated) page.
    FreePage,
    /// Recovered from uncommitted WAL transactions.
    WalUncommitted,
    /// Recovered from a rollback journal.
    JournalRollback,
    /// Found via direct byte-pattern scanning.
    DirectScan,
}

/// Quality of the recovered record.
#[derive(Debug, Clone, Serialize)]
pub enum RecoveryQuality {
    /// All fields successfully recovered.
    Complete,
    /// Some fields missing or truncated.
    Partial,
    /// Record structure detected but data corrupt.
    Corrupt,
}

/// A single recovered record from carving.
#[derive(Debug, Clone, Serialize)]
pub struct CarvedRecord {
    pub offset: u64,
    pub table: String,
    pub fields: HashMap<String, serde_json::Value>,
    pub method: RecoveryMethod,
    pub quality: RecoveryQuality,
}

/// Statistics about the carving operation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CarveStats {
    pub bytes_scanned: u64,
    pub pages_scanned: u32,
    pub free_pages_found: u32,
    pub records_recovered: usize,
    pub records_partial: usize,
}

/// Result of a carving operation.
#[derive(Debug, Clone, Serialize)]
pub struct CarveResult {
    pub records: Vec<CarvedRecord>,
    pub integrity: Vec<IntegrityIndicator>,
    pub stats: CarveStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn recovery_method_serializes() {
        let method = RecoveryMethod::FreePage;
        let json = serde_json::to_string(&method).expect("serialize");
        assert!(json.contains("FreePage"));
    }

    #[test]
    fn recovery_quality_serializes() {
        let q = RecoveryQuality::Complete;
        let json = serde_json::to_string(&q).expect("serialize");
        assert!(json.contains("Complete"));
    }

    #[test]
    fn carved_record_round_trips() {
        let record = CarvedRecord {
            offset: 4096,
            table: "urls".to_string(),
            fields: {
                let mut m = HashMap::new();
                m.insert(
                    "url".to_string(),
                    serde_json::json!("https://carved.example.com"),
                );
                m.insert("title".to_string(), serde_json::json!("Carved Page"));
                m
            },
            method: RecoveryMethod::FreePage,
            quality: RecoveryQuality::Complete,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains("carved.example.com"));
        assert!(json.contains("FreePage"));
    }

    #[test]
    fn carve_stats_default_is_zero() {
        let stats = CarveStats::default();
        assert_eq!(stats.bytes_scanned, 0);
        assert_eq!(stats.pages_scanned, 0);
        assert_eq!(stats.free_pages_found, 0);
        assert_eq!(stats.records_recovered, 0);
        assert_eq!(stats.records_partial, 0);
    }

    #[test]
    fn carve_result_empty() {
        let result = CarveResult {
            records: Vec::new(),
            integrity: Vec::new(),
            stats: CarveStats::default(),
        };
        assert!(result.records.is_empty());
        assert_eq!(result.stats.records_recovered, 0);
    }

    #[test]
    fn carved_record_clone() {
        let record = CarvedRecord {
            offset: 0,
            table: "test".to_string(),
            fields: HashMap::new(),
            method: RecoveryMethod::WalUncommitted,
            quality: RecoveryQuality::Partial,
        };
        let cloned = record.clone();
        assert_eq!(cloned.table, "test");
        assert!(matches!(cloned.method, RecoveryMethod::WalUncommitted));
    }

    #[test]
    fn crate_root_reexports_carve_functions() {
        let _f1: fn(&std::path::Path) -> anyhow::Result<CarveResult> =
            crate::carve_sqlite_free_pages;
        let _f2: fn(&std::path::Path) -> anyhow::Result<CarveResult> = crate::recover_from_wal;
    }
}
