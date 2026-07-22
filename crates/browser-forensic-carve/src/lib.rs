#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::no_effect_underscore_binding
    )
)]
//! Browser artifact carving and recovery.
//!
//! Recovers deleted browser data from SQLite free pages, WAL files,
//! and binary formats.

pub mod recovered_history;
pub mod sqlite_carve;
pub mod wal_recovery;

pub use recovered_history::detect_recovered_deleted_history;
pub use sqlite_carve::carve_sqlite_free_pages;
pub use wal_recovery::recover_from_wal;

use std::collections::HashMap;

use browser_forensic_integrity::IntegrityIndicator;
use serde::Serialize;
use sqlite_core::Value;
use sqlite_forensic::{Attribution, RecoverySource};

/// How a deleted SQLite record was recovered — the recovery *substrate* within a
/// SQLite database (fleet ADR 0001 §3 reserves the bare `RecoveryMethod` name for
/// the fleet-level `forensic-carve` type).
#[derive(Debug, Clone, Serialize)]
pub enum SqliteRecoveryMethod {
    /// Recovered from a SQLite free (deallocated) page.
    FreePage,
    /// Recovered from uncommitted WAL transactions.
    WalUncommitted,
    /// Recovered from a rollback journal.
    JournalRollback,
    /// Found via direct byte-pattern scanning.
    DirectScan,
}

/// Deprecated alias for [`SqliteRecoveryMethod`], kept for source compatibility.
#[deprecated(
    since = "0.3.0",
    note = "renamed to SqliteRecoveryMethod (fleet ADR 0001 §3)"
)]
pub type RecoveryMethod = SqliteRecoveryMethod;

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
    pub method: SqliteRecoveryMethod,
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

/// Confidence at or above which a recovered record is graded [`RecoveryQuality::Complete`]
/// (a full, high-confidence row reconstruction); below it, [`RecoveryQuality::Partial`].
const COMPLETE_CONFIDENCE: f32 = 0.7;

/// Map a [`sqlite_forensic`] carved record plus its table attribution onto the
/// browser-forensic [`CarvedRecord`] the CLI and triage consume. Shared by the
/// free-space ([`carve_sqlite_free_pages`]) and WAL ([`recover_from_wal`]) paths;
/// the [`SqliteRecoveryMethod`] is derived from the recovery substrate.
pub(crate) fn map_carved_record(
    rec: &sqlite_forensic::CarvedRecord,
    attr: &Attribution,
    page_size: u64,
) -> CarvedRecord {
    // Absolute byte offset of the cell: a 1-based page number → 0-based file offset.
    let offset = u64::from(rec.page.saturating_sub(1))
        .saturating_mul(page_size)
        .saturating_add(rec.offset as u64);

    let table = match attr {
        Attribution::Known(name) => name.clone(),
        Attribution::Inferred { guess, .. } => guess.clone(),
        Attribution::Unattributed => "unknown".to_string(),
    };

    // Every recovered column, keyed positionally (`col0`, `col1`, …) — the actual
    // values the deleted row held, not just a URL byte-match.
    let mut fields: HashMap<String, serde_json::Value> = HashMap::with_capacity(rec.values.len());
    for (i, value) in rec.values.iter().enumerate() {
        fields.insert(format!("col{i}"), value_to_json(value));
    }

    // The recovery substrate determines the method: WAL-frame / commit-snapshot
    // residue is uncommitted WAL state; a rollback journal is JournalRollback;
    // every on-disk free-space class is a free page.
    let method = match rec.source {
        RecoverySource::WalFrame | RecoverySource::CommitSnapshot => {
            SqliteRecoveryMethod::WalUncommitted
        }
        RecoverySource::RollbackJournal(_) => SqliteRecoveryMethod::JournalRollback,
        _ => SqliteRecoveryMethod::FreePage,
    };

    CarvedRecord {
        offset,
        table,
        fields,
        method,
        quality: if rec.confidence >= COMPLETE_CONFIDENCE {
            RecoveryQuality::Complete
        } else {
            RecoveryQuality::Partial
        },
    }
}

/// Decode a SQLite [`Value`] to JSON for the recovered-record field map. A BLOB is
/// hex-encoded so the value round-trips as a JSON string rather than being lost.
pub(crate) fn value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Integer(n) => serde_json::json!(n),
        Value::Real(r) => serde_json::json!(r),
        Value::Text(t) => serde_json::json!(t),
        Value::Blob(b) => serde_json::json!(hex_encode(b)),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn recovery_method_serializes() {
        let method = SqliteRecoveryMethod::FreePage;
        let json = serde_json::to_string(&method).expect("serialize");
        assert!(json.contains("FreePage"));
    }

    #[test]
    fn value_to_json_maps_every_sqlite_type() {
        assert_eq!(value_to_json(&Value::Null), serde_json::Value::Null);
        assert_eq!(value_to_json(&Value::Integer(42)), serde_json::json!(42));
        assert_eq!(value_to_json(&Value::Real(1.5)), serde_json::json!(1.5));
        assert_eq!(
            value_to_json(&Value::Text("u".to_string())),
            serde_json::json!("u")
        );
        // A BLOB hex-encodes so it round-trips as a JSON string, never dropped.
        assert_eq!(
            value_to_json(&Value::Blob(vec![0x00, 0xab, 0xff])),
            serde_json::json!("00abff")
        );
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
            method: SqliteRecoveryMethod::FreePage,
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
            method: SqliteRecoveryMethod::WalUncommitted,
            quality: RecoveryQuality::Partial,
        };
        let cloned = record.clone();
        assert_eq!(cloned.table, "test");
        assert!(matches!(
            cloned.method,
            SqliteRecoveryMethod::WalUncommitted
        ));
    }

    #[test]
    fn crate_root_reexports_carve_functions() {
        let _f1: fn(&std::path::Path) -> anyhow::Result<CarveResult> =
            crate::carve_sqlite_free_pages;
        let _f2: fn(&std::path::Path) -> anyhow::Result<CarveResult> = crate::recover_from_wal;
    }
}
