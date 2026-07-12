#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Browser integrity detection — detects anomalies indicating
//! tampering, clearing, or corruption in browser artifacts.

pub mod cookies;
pub mod database;
pub mod history;
pub mod pages;

pub use cookies::check_cookie_integrity;
pub use database::{check_database_integrity, check_wal_state};
pub use history::check_history_integrity;
pub use pages::check_page_state;

use std::path::PathBuf;

use browser_forensic_core::BrowserFamily;
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
    /// Cookie creation timestamp is after `last_access` (impossible naturally).
    CookieTimestampAnomaly {
        path: PathBuf,
        host: String,
        creation_ns: i64,
        last_access_ns: i64,
    },
    /// WAL file exists alongside database — uncommitted changes or crash recovery needed.
    WalPresent { path: PathBuf },
    /// SQLite PRAGMA `integrity_check` reported a problem.
    SqliteIntegrityFailure { path: PathBuf, message: String },
    /// Safari `history_tombstones` table contains deleted URL records.
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
    /// The database holds free (unallocated) pages on its freelist. Consistent
    /// with prior deletions that were not followed by `VACUUM`; those pages may
    /// retain recoverable deleted records.
    FreelistGrowth {
        path: PathBuf,
        free_pages: u32,
        total_pages: u32,
    },
    /// The in-header page count disagrees with the page count implied by the file
    /// length. Consistent with truncation, carving, or an out-of-band edit of the
    /// file.
    PageCountMismatch {
        path: PathBuf,
        header_pages: u32,
        file_pages: u32,
    },
}

impl IntegrityIndicator {
    /// A plain-language statement of what was *observed* in the artifact — the
    /// raw fact, with the offending value(s), and never a conclusion. This is the
    /// layer-1 "observed fact" of the expert-witness discipline: state what the
    /// evidence shows, let the reader weigh it against [`Self::innocent_alternative`].
    #[must_use]
    pub fn observation(&self) -> String {
        match self {
            Self::HistoryCleared { path, .. } => format!(
                "{}: history tables are empty (or near-empty) while the AUTOINCREMENT \
                 counter records prior rows",
                path.display()
            ),
            Self::VisitIdGap {
                path,
                expected_id,
                found_id,
            } => format!(
                "{}: visit/row id sequence jumps from {expected_id} to {found_id} \
                 (rows once occupied the intervening ids)",
                path.display()
            ),
            Self::TimestampNonMonotonic {
                path,
                row_id,
                prev_ts_ns,
                this_ts_ns,
            } => format!(
                "{}: row {row_id} has timestamp {this_ts_ns} ns which is earlier than \
                 the preceding row's {prev_ts_ns} ns despite a later id",
                path.display()
            ),
            Self::CookieTimestampAnomaly {
                path,
                host,
                creation_ns,
                last_access_ns,
            } => format!(
                "{}: cookie for {host} has creation {creation_ns} ns after its \
                 last-access {last_access_ns} ns",
                path.display()
            ),
            Self::WalPresent { path } => format!(
                "{}: a non-empty write-ahead log sits beside the database (uncheckpointed \
                 page versions the main file does not yet reflect)",
                path.display()
            ),
            Self::SqliteIntegrityFailure { path, message } => {
                format!(
                    "{}: PRAGMA integrity_check reported: {message}",
                    path.display()
                )
            }
            Self::HistoryTombstoneFound {
                path,
                url,
                deleted_at_ns,
            } => format!(
                "{}: a deletion tombstone records the removal of {url} (at {deleted_at_ns} ns)",
                path.display()
            ),
            Self::DownloadFileMissing { path, target_path } => format!(
                "{}: a download record references {target_path}, which is not present on disk",
                path.display()
            ),
            Self::AutoIncrementGap {
                path,
                table,
                max_rowid,
                auto_increment,
            } => format!(
                "{}: sqlite_sequence for {table} is {auto_increment} but the highest \
                 surviving rowid is {max_rowid}",
                path.display()
            ),
            Self::FreelistGrowth {
                path,
                free_pages,
                total_pages,
            } => format!(
                "{}: {free_pages} of {total_pages} pages are on the freelist (freed, \
                 unallocated space)",
                path.display()
            ),
            Self::PageCountMismatch {
                path,
                header_pages,
                file_pages,
            } => format!(
                "{}: header records {header_pages} pages but the file length implies \
                 {file_pages}",
                path.display()
            ),
        }
    }

    /// At least one benign explanation that would produce the same observation.
    /// The framing rule: SQLite id gaps, freelist growth, non-monotonic
    /// timestamps and counter jumps are ALSO produced by ordinary deletion,
    /// VACUUM, crashes, imports and clock skew — so a finding is *consistent with*
    /// clearing/tampering, never proof of it (expert-witness layer 2).
    #[must_use]
    pub fn innocent_alternative(&self) -> &'static str {
        match self {
            Self::HistoryCleared { .. } => {
                "Also consistent with the user clearing browsing data through the \
                 browser's own UI, an expiry/retention policy, or a fresh profile whose \
                 rows were pruned — none of which require external manipulation."
            }
            Self::VisitIdGap { .. } => {
                "Gaps are normal after ordinary record deletion, history expiry, or a \
                 rolled-back transaction; SQLite does not renumber surviving rows."
            }
            Self::TimestampNonMonotonic { .. } => {
                "Can arise from clock changes (DST, NTP correction, timezone), history \
                 imported/synced from another device, or rows inserted out of visit order."
            }
            Self::CookieTimestampAnomaly { .. } => {
                "May result from a system clock adjustment between the two writes, or \
                 from a cookie migrated/imported with a preserved creation time."
            }
            Self::WalPresent { .. } => {
                "A WAL is present during normal operation whenever the database was \
                 captured before checkpointing, or the browser was still running."
            }
            Self::SqliteIntegrityFailure { .. } => {
                "Corruption is commonly produced by crashes, power loss, storage faults, \
                 or copying a live database, independent of any deliberate edit."
            }
            Self::HistoryTombstoneFound { .. } => {
                "Tombstones are created by the browser's normal sync/delete bookkeeping \
                 when a user removes an item, and can also be seeded by cross-device sync."
            }
            Self::DownloadFileMissing { .. } => {
                "A referenced file can be absent simply because the user moved, renamed, or \
                 deleted the download, or it lived on removable/other media."
            }
            Self::AutoIncrementGap { .. } => {
                "AUTOINCREMENT never reuses values, so this can arise from ordinary \
                 deletion of the highest-id rows, or inserts rolled back by a crash, \
                 leaving the counter ahead of the max rowid without any external editing."
            }
            Self::FreelistGrowth { .. } => {
                "Free pages are a normal by-product of ordinary DELETEs without VACUUM, \
                 of the browser's own history-expiry/eviction, and of index churn — the \
                 database reuses them for later inserts."
            }
            Self::PageCountMismatch { .. } => {
                "A page-count mismatch can be produced by an interrupted write, a copy \
                 captured mid-checkpoint, or trailing bytes appended by a backup tool, \
                 not only by deliberate truncation."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::BrowserFamily;
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
        use browser_forensic_core::BrowserFamily;
        use std::path::Path;
        // Verify functions are accessible at crate root (not just in submodules)
        let _: fn(&Path, BrowserFamily) -> anyhow::Result<Vec<IntegrityIndicator>> =
            check_history_integrity;
        let _: fn(&Path, BrowserFamily) -> anyhow::Result<Vec<IntegrityIndicator>> =
            check_cookie_integrity;
        let _: fn(&Path) -> anyhow::Result<Vec<IntegrityIndicator>> = check_database_integrity;
        let _: fn(&Path) -> anyhow::Result<Vec<IntegrityIndicator>> = check_wal_state;
    }

    /// One representative instance of every [`IntegrityIndicator`] variant, so the
    /// framing tests below exercise the full enum. Extend this when a variant is
    /// added — the framing rule (observation + innocent alternative, no
    /// conclusion language) must hold for every finding the tool can emit.
    fn sample_all_indicators() -> Vec<IntegrityIndicator> {
        vec![
            IntegrityIndicator::HistoryCleared {
                browser: BrowserFamily::Chromium,
                path: PathBuf::from("/tmp/History"),
                detected_at_ns: 1_000_000_000,
            },
            IntegrityIndicator::VisitIdGap {
                path: PathBuf::from("/tmp/History"),
                expected_id: 42,
                found_id: 100,
            },
            IntegrityIndicator::TimestampNonMonotonic {
                path: PathBuf::from("/tmp/History"),
                row_id: 5,
                prev_ts_ns: 2_000_000_000,
                this_ts_ns: 1_000_000_000,
            },
            IntegrityIndicator::CookieTimestampAnomaly {
                path: PathBuf::from("/tmp/Cookies"),
                host: "example.com".to_string(),
                creation_ns: 2_000_000_000,
                last_access_ns: 1_000_000_000,
            },
            IntegrityIndicator::WalPresent {
                path: PathBuf::from("/tmp/History-wal"),
            },
            IntegrityIndicator::SqliteIntegrityFailure {
                path: PathBuf::from("/tmp/History"),
                message: "page 5: corrupt".to_string(),
            },
            IntegrityIndicator::HistoryTombstoneFound {
                path: PathBuf::from("/tmp/History.db"),
                url: "https://deleted.example.com".to_string(),
                deleted_at_ns: 3_000_000_000,
            },
            IntegrityIndicator::DownloadFileMissing {
                path: PathBuf::from("/tmp/History"),
                target_path: "/tmp/gone.bin".to_string(),
            },
            IntegrityIndicator::AutoIncrementGap {
                path: PathBuf::from("/tmp/History"),
                table: "urls".to_string(),
                max_rowid: 10,
                auto_increment: 500,
            },
            IntegrityIndicator::FreelistGrowth {
                path: PathBuf::from("/tmp/History"),
                free_pages: 12,
                total_pages: 40,
            },
            IntegrityIndicator::PageCountMismatch {
                path: PathBuf::from("/tmp/History"),
                header_pages: 40,
                file_pages: 30,
            },
        ]
    }

    /// Words that assert a conclusion rather than an observation. The framing rule
    /// forbids them in any finding text: a finding is *consistent with* clearing or
    /// tampering, never proof of it (fleet expert-witness discipline, layer 2).
    const CONCLUSION_WORDS: &[&str] = &[
        "tamper",
        "confirmed",
        "proves",
        "proof",
        "user deleted",
        "definitely",
    ];

    #[test]
    fn every_indicator_has_observation_and_innocent_alternative() {
        for ind in sample_all_indicators() {
            let observation = ind.observation();
            let innocent = ind.innocent_alternative();
            assert!(
                !observation.trim().is_empty(),
                "{ind:?} has an empty observation"
            );
            assert!(
                !innocent.trim().is_empty(),
                "{ind:?} has no innocent alternative — the framing rule requires one"
            );
        }
    }

    #[test]
    fn no_finding_text_asserts_a_conclusion() {
        for ind in sample_all_indicators() {
            let combined = format!(
                "{} {}",
                ind.observation().to_lowercase(),
                ind.innocent_alternative().to_lowercase()
            );
            for banned in CONCLUSION_WORDS {
                assert!(
                    !combined.contains(banned),
                    "{ind:?} finding text contains conclusion word {banned:?}: {combined:?}"
                );
            }
        }
    }

    #[test]
    fn innocent_alternative_uses_hedged_language() {
        // Every innocent alternative should read as a plausible benign cause,
        // signalled by hedged phrasing rather than a verdict.
        for ind in sample_all_indicators() {
            let innocent = ind.innocent_alternative().to_lowercase();
            assert!(
                innocent.contains("consistent with")
                    || innocent.contains("may")
                    || innocent.contains("can")
                    || innocent.contains("normal")
                    || innocent.contains("produced by"),
                "{ind:?} innocent alternative is not hedged: {innocent:?}"
            );
        }
    }
}
