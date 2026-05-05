#![deny(clippy::unwrap_used)]
//! Browser artifact carving and recovery.
//!
//! Recovers deleted browser data from SQLite free pages, WAL files,
//! and binary formats.

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
                m.insert("url".to_string(), serde_json::json!("https://carved.example.com"));
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
}
