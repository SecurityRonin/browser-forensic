//! RFC 0001 Phase P5b — the `recover` orchestrator verb.
//!
//! `recover` is `investigate`'s recovery-focused sibling (resolved-decision #2):
//! **one verb runs ALL applicable recovery** over the evidence and presents
//! ranked, court-safe [`Finding`]s — the examiner never chooses carve-vs-memory-
//! vs-WAL. Like [`crate::investigate`], this module is UX assembly over existing
//! forensics, not new forensic logic: every finding-generator reads an existing
//! recovery engine's output (SQLite carve records, orphaned-cache resources,
//! recovered-domain / deleted-bookmark events, integrity indicators, memory
//! carve events) and re-expresses it as a [`Finding`] carrying the three D5 axes
//! and full provenance.
//!
//! Two honesty invariants hold here (RFC 0001 D2/D4/D5):
//!
//! * **Every recovered item keeps state ≠ `Live`.** A carved free-page row, an
//!   orphaned cache entry, a recovered domain, a deleted bookmark, and a RAM
//!   fragment are all *consistent-with eviction/clearing* artifacts — never
//!   asserted to be a deliberate user act (structural via the [`Finding`] model).
//! * **The skipped-work footer is mandatory and names what was NOT attempted**
//!   ([`recover_footer`]) so absence of a result is never false reassurance —
//!   e.g. over a profile it states memory and whole-image carving were not run.

use browser_forensic_core::finding::{
    Confidence, EvidenceSource, EvidenceState, Finding, Priority, Provenance, TimestampBasis,
    UserActionClaim,
};
use browser_forensic_core::BrowserEvent;
use browser_forensic_integrity::IntegrityIndicator;

pub use crate::investigate::{rank_findings, MAX_VISIBLE_FINDINGS, PRIORITY_CUE_NOTE};

/// What `recover` auto-selected to run, from the shape of the evidence `PATH`
/// (resolved-decision #2 — no submode is chosen by the examiner). Drives the
/// mandatory skipped-work footer so absence of a result is never false
/// reassurance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverScope {
    /// A profile / home directory: deleted SQLite/WAL records, orphaned cache,
    /// recovered domains, deleted bookmarks, and tamper indicators are run.
    Profile,
    /// A single SQLite database file: deleted-record carving + tamper only.
    Database,
    /// A memory image: process-attributed RAM carving only.
    MemoryImage,
    /// A raw disk / memory image carved as a whole: the unallocated-space
    /// signature carve (deleted SQLite records + Chromium SimpleCache entries)
    /// over the image's raw bytes, with no filesystem mount (RFC 0001 P15b).
    WholeImage,
}

/// Read a string attribute from an event, if present and a JSON string.
fn attr_str<'a>(event: &'a BrowserEvent, key: &str) -> Option<&'a str> {
    event.attrs.get(key).and_then(serde_json::Value::as_str)
}

/// Compact, full-value summary of a carved row's recovered columns (never
/// ellipsized — a truncated value is destroyed evidence).
fn carved_fields_summary(record: &browser_forensic_carve::CarvedRecord) -> String {
    serde_json::to_string(&record.fields).unwrap_or_else(|_| "{}".to_string())
}

/// Deleted-record findings from SQLite free-page / WAL carving. Each carved row
/// is a *recovered deleted record* — state is never `Live` — hedged as
/// consistent-with routine deletion (VACUUM, history expiry, sync), not proof of
/// a deliberate user act.
#[must_use]
pub fn carved_record_findings(records: &[browser_forensic_carve::CarvedRecord]) -> Vec<Finding> {
    use browser_forensic_carve::{RecoveryMethod, RecoveryQuality};
    records
        .iter()
        .map(|rec| {
            // Free-space / direct-scan residue is precisely "carved"; WAL /
            // rollback-journal residue is an uncommitted-then-deleted record.
            let state = match rec.method {
                RecoveryMethod::WalUncommitted | RecoveryMethod::JournalRollback => {
                    EvidenceState::Deleted
                }
                RecoveryMethod::FreePage | RecoveryMethod::DirectScan => EvidenceState::Carved,
            };
            let confidence = match rec.quality {
                RecoveryQuality::Complete => Confidence::Medium,
                RecoveryQuality::Partial | RecoveryQuality::Corrupt => Confidence::Low,
            };
            let substrate = match rec.method {
                RecoveryMethod::FreePage => "a SQLite free (deallocated) page",
                RecoveryMethod::WalUncommitted => "an uncommitted WAL frame",
                RecoveryMethod::JournalRollback => "a rollback journal",
                RecoveryMethod::DirectScan => "a raw byte-pattern scan",
            };
            let provenance = Provenance::new(
                EvidenceSource::Carved,
                state,
                TimestampBasis::None,
                UserActionClaim::Unknown,
            );
            Finding::new(
                Priority::Medium,
                confidence,
                "recover.carve.deleted_record.v1",
                format!(
                    "consistent with a record deleted from the `{table}` table and recovered \
                     from {substrate}; deletion may be routine (VACUUM, history expiry, profile \
                     sync) — not proof of a deliberate user act",
                    table = rec.table
                ),
                provenance,
                format!(
                    "{table} deleted row @offset {offset}: {fields}",
                    table = rec.table,
                    offset = rec.offset,
                    fields = carved_fields_summary(rec)
                ),
            )
            .with_next("br4n6 recover <PATH> --format jsonl")
        })
        .collect()
}

/// Orphaned/evicted cache findings from `cache-carve`. The input events are the
/// normalized [`BrowserEvent`]s the cache-carve mapper emits (artifact
/// `Cache`, `artifact_subtype = "cache_carve"`); each is a cached-then-evicted
/// artifact (state `Deleted`), never a deliberate deletion.
#[must_use]
pub fn cache_carve_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    events
        .iter()
        .map(|e| {
            let quality = attr_str(e, "recovery_quality").unwrap_or("partial");
            let confidence = if quality == "full" {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let mechanism = attr_str(e, "recovery_mechanism").unwrap_or("cache carve");
            let note = attr_str(e, "recovery_note").unwrap_or(
                "consistent with a cached response no longer referenced by the live index",
            );
            let provenance = Provenance::new(
                EvidenceSource::Cache,
                EvidenceState::Deleted,
                TimestampBasis::SurroundingPage,
                UserActionClaim::ObservedString,
            );
            Finding::new(
                Priority::Info,
                confidence,
                "recover.cache_carve.evicted.v1",
                format!(
                    "{note}; a cached-then-evicted artifact — cache eviction is routine and does \
                     not by itself establish a deliberate deletion"
                ),
                provenance,
                format!(
                    "{url} (mechanism {mechanism}, quality {quality})",
                    url = e.description
                ),
            )
            .with_browser(e.browser.clone())
            .with_next("br4n6 recover <PATH> --format jsonl")
        })
        .collect()
}

/// Recovered-domain findings (Network Persistent State / NEL / DIPS / HSTS): a
/// domain contacted even after history is cleared, recovered from a persistence
/// side effect. State is `Inferred` (contact inferred, not a recorded
/// navigation); it may be a subresource/third-party.
#[must_use]
pub fn recovered_domain_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    events
        .iter()
        .map(|e| {
            let domain = attr_str(e, "domain").unwrap_or(&e.description);
            let source_artifact =
                attr_str(e, "source_artifact").unwrap_or("a network/state artifact");
            let provenance = Provenance::new(
                EvidenceSource::Recovered,
                EvidenceState::Inferred,
                TimestampBasis::Inferred,
                UserActionClaim::Unknown,
            );
            Finding::new(
                Priority::Info,
                Confidence::Low,
                "recover.recovered_domain.v1",
                format!(
                    "consistent with contact to `{domain}` recovered from {source_artifact}, which \
                     survives a history clear; contact may be a subresource/third-party, not a \
                     deliberate navigation"
                ),
                provenance,
                format!("{domain} (recovered from {source_artifact})"),
            )
            .with_browser(e.browser.clone())
            .with_next("br4n6 recover <PATH> --format jsonl")
        })
        .collect()
}

/// Deleted-bookmark findings: a bookmark present in a Firefox backup but absent
/// from the current set (state `Deleted`), consistent with deletion after that
/// backup — routine reorganization is an innocent alternative.
#[must_use]
pub fn deleted_bookmark_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    events
        .iter()
        .map(|e| {
            let url = attr_str(e, "url").unwrap_or(&e.description);
            let provenance = Provenance::new(
                EvidenceSource::History,
                EvidenceState::Deleted,
                TimestampBasis::Explicit,
                UserActionClaim::Unknown,
            );
            Finding::new(
                Priority::Medium,
                Confidence::Medium,
                "recover.deleted_bookmark.v1",
                "consistent with a bookmark present in a Firefox backup but absent from the \
                 current set — deleted after that backup; deletion may be routine reorganization, \
                 not proof of concealment",
                provenance,
                url.to_string(),
            )
            .with_browser(e.browser.clone())
            .with_next("br4n6 artifact deleted-bookmarks <PATH>")
        })
        .collect()
}

/// Tamper / anti-forensic findings from integrity indicators. History-clearing
/// variants are the top attention cue (`High`); other anomalies are `Medium`.
/// Each keeps the integrity crate's own observation + innocent alternative.
/// The serde variant tag of an integrity indicator (e.g. `"HistoryCleared"`),
/// taken from its JSON object key so it stays in sync with the type.
fn indicator_tag(indicator: &IntegrityIndicator) -> String {
    match serde_json::to_value(indicator) {
        Ok(serde_json::Value::Object(map)) => map
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "Unknown".into()),
        Ok(serde_json::Value::String(s)) => s,
        _ => "Unknown".to_string(),
    }
}

/// Integrity variants that indicate history *clearing* or mass deletion — the
/// top attention cues (`High`), vs. lower-priority anomalies (`Medium`).
fn is_clearing_tag(tag: &str) -> bool {
    matches!(
        tag,
        "HistoryCleared" | "AutoIncrementGap" | "HistoryTombstoneFound" | "SqliteSequenceGap"
    )
}

#[must_use]
pub fn tamper_findings(indicators: &[IntegrityIndicator]) -> Vec<Finding> {
    indicators
        .iter()
        .map(|ind| {
            let tag = indicator_tag(ind);
            let clearing = is_clearing_tag(&tag);
            let priority = if clearing {
                Priority::High
            } else {
                Priority::Medium
            };
            let state = if clearing {
                EvidenceState::Deleted
            } else {
                EvidenceState::Inferred
            };
            let provenance = Provenance::new(
                EvidenceSource::History,
                state,
                TimestampBasis::None,
                UserActionClaim::Unknown,
            );
            Finding::new(
                priority,
                Confidence::Medium,
                format!("recover.tamper.{tag}.v1"),
                format!(
                    "consistent with clearing/tampering; innocent alternative: {}",
                    ind.innocent_alternative()
                ),
                provenance,
                ind.observation(),
            )
            .with_next("br4n6 integrity <PATH>")
        })
        .collect()
}

/// Memory-carve findings: browser artifacts (URLs, cookies) recovered from a RAM
/// capture. State is `Carved`; a string in RAM is not proof a human acted on it.
#[must_use]
pub fn memory_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    events
        .iter()
        .map(|e| {
            let datum = attr_str(e, "url").unwrap_or(&e.description);
            let provenance = Provenance::new(
                EvidenceSource::Memory,
                EvidenceState::Carved,
                TimestampBasis::None,
                UserActionClaim::ObservedString,
            );
            Finding::new(
                Priority::Info,
                Confidence::Low,
                "recover.memory.carved.v1",
                "consistent with a browser artifact present in process memory at capture time; a \
                 string in RAM is not proof a human acted on it",
                provenance,
                datum.to_string(),
            )
            .with_browser(e.browser.clone())
            .with_next("br4n6 recover <MEMORY-IMAGE> --format jsonl")
        })
        .collect()
}

/// Whole-image carve findings: browser artifacts recovered from the raw
/// unallocated space of a disk / memory image by the signature carve (deleted
/// SQLite records + Chromium SimpleCache entries). Each carries its absolute
/// byte-offset provenance and NO filesystem context — state is `Carved`, framed
/// as consistent with a deleted/evicted artifact, never a proven user act.
#[must_use]
pub fn whole_image_findings(
    artifacts: &[browser_forensic_imagecarve::CarvedArtifact],
) -> Vec<Finding> {
    use browser_forensic_imagecarve::CarvedArtifactKind;
    artifacts
        .iter()
        .map(|art| {
            let kind_note = match art.kind {
                CarvedArtifactKind::SqliteRecord => "a deleted SQLite record",
                CarvedArtifactKind::CacheEntry => "a Chromium SimpleCache entry",
            };
            let provenance = Provenance::new(
                EvidenceSource::Carved,
                EvidenceState::Carved,
                TimestampBasis::None,
                UserActionClaim::ObservedString,
            );
            let visit = art
                .visit_time_raw
                .map(|t| format!(" visit_time_raw={t}"))
                .unwrap_or_default();
            Finding::new(
                Priority::Info,
                Confidence::Low,
                format!("recover.imagecarve.{}.v1", art.kind.as_str()),
                format!(
                    "recovered from unallocated space — no filesystem context; consistent with a \
                     deleted/evicted artifact ({kind_note}); a byte pattern in raw slack is not \
                     proof a human acted on it"
                ),
                provenance,
                format!(
                    "{url} @image_offset {off}{visit}: {detail}",
                    url = art.url,
                    off = art.image_offset,
                    detail = art.detail,
                ),
            )
            .with_next("br4n6 recover <IMAGE> --whole-image --format jsonl")
        })
        .collect()
}

/// The always-present skipped-work footer for a scope (RFC 0001 D2). Names what
/// `recover` did NOT attempt for the auto-selected scope so absence of a result
/// is never false reassurance.
#[must_use]
pub fn recover_footer(scope: RecoverScope, path_display: &str) -> String {
    match scope {
        RecoverScope::Profile => format!(
            "Not attempted: memory was NOT scanned (no image supplied); whole-image carving is \
             N/A (not a raw image). This run covered profile recovery over {path_display}: \
             deleted SQLite/WAL records, orphaned cache, recovered domains, deleted bookmarks, \
             and tamper indicators. For RAM: br4n6 recover <memory-image>; for a whole disk \
             image: br4n6 recover <disk-image> --whole-image"
        ),
        RecoverScope::Database => format!(
            "Not attempted: memory, orphaned-cache recovery, recovered domains, and deleted \
             bookmarks were NOT scanned (single-database scope); whole-image carving is N/A (a \
             single database, not a raw image). This run carved deleted SQLite/WAL records and \
             checked tamper indicators over {path_display}. For the full set, point recover at \
             the profile directory."
        ),
        RecoverScope::MemoryImage => format!(
            "Not attempted: profile recovery (deleted SQLite/WAL records, orphaned cache, \
             recovered domains, deleted bookmarks, tamper indicators) was NOT run over a memory \
             image, and whole-image carving was NOT run. This run carved browser artifacts from \
             RAM over {path_display}. For on-disk profiles: br4n6 recover <profile-dir>"
        ),
        RecoverScope::WholeImage => format!(
            "Whole-image carving ran: an unallocated-space signature carve for deleted SQLite \
             records + Chromium SimpleCache entries over the raw bytes of {path_display}. Not \
             attempted: filesystem-aware profile recovery (deleted SQLite/WAL records, orphaned \
             cache, recovered domains, deleted bookmarks, tamper indicators) and \
             process-attributed memory carving were NOT run — this scope reads the image with no \
             filesystem mount. For a mounted profile: br4n6 recover <profile-dir>; for RAM with \
             process attribution: br4n6 recover <memory-image>"
        ),
    }
}

/// The scope header line — what `recover` auto-selected and ran (resolved-decision
/// #2: the examiner chose no submode).
#[must_use]
fn scope_header(scope: RecoverScope, path_display: &str) -> String {
    match scope {
        RecoverScope::Profile => format!(
            "Recovering (profile scope): deleted SQLite/WAL records, orphaned cache, recovered \
             domains, deleted bookmarks, tamper indicators — {path_display}"
        ),
        RecoverScope::Database => format!(
            "Recovering (single-database scope): deleted SQLite/WAL records + tamper indicators \
             — {path_display}"
        ),
        RecoverScope::MemoryImage => {
            format!(
                "Recovering (memory-image scope): process-attributed RAM carve — {path_display}"
            )
        }
        RecoverScope::WholeImage => format!(
            "Recovering (whole-image scope): unallocated-space signature carve for SQLite records \
             + Chromium SimpleCache entries — {path_display}"
        ),
    }
}

/// Colorize a rendered finding's `Priority:` value line as a TTY cue (the
/// severity word is always printed by [`Finding::render`]; color is additive).
fn colorize_priority_line(block: &str, priority: Priority) -> String {
    let ansi = match priority {
        Priority::High => crate::output::ANSI_RED,
        Priority::Medium => crate::output::ANSI_YELLOW,
        Priority::Info => crate::output::ANSI_CYAN,
    };
    block
        .lines()
        .map(|line| {
            if let Some(rest) = line.strip_prefix("Priority:") {
                format!("Priority:{}", crate::output::paint(rest, ansi, true))
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The full human (TTY) render: a scope header, the priority-cue note, the ranked
/// findings (capped), and the mandatory skipped-work footer.
#[must_use]
pub fn render_summary(
    findings: &[Finding],
    scope: RecoverScope,
    path_display: &str,
    color: bool,
) -> String {
    let mut out = String::new();
    out.push_str(&scope_header(scope, path_display));
    out.push_str("\n\n");
    out.push_str(PRIORITY_CUE_NOTE);
    out.push_str("\n\n");

    if findings.is_empty() {
        out.push_str("No recoverable items surfaced at this scope.\n\n");
    } else {
        let visible = findings.len().min(MAX_VISIBLE_FINDINGS);
        for finding in &findings[..visible] {
            let block = finding.render();
            if color {
                out.push_str(&colorize_priority_line(&block, finding.priority));
                out.push('\n');
            } else {
                out.push_str(&block);
            }
            out.push('\n');
        }
        if findings.len() > visible {
            out.push_str(&format!(
                "… {} more recovered item(s) not shown, ranked by Priority.\n\n",
                findings.len() - visible
            ));
        }
    }

    out.push_str(&recover_footer(scope, path_display));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn carved_record(table: &str) -> browser_forensic_carve::CarvedRecord {
        let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
        fields.insert("col0".into(), json!("https://deleted.example/secret"));
        browser_forensic_carve::CarvedRecord {
            offset: 4096,
            table: table.to_string(),
            fields,
            method: browser_forensic_carve::RecoveryMethod::FreePage,
            quality: browser_forensic_carve::RecoveryQuality::Complete,
        }
    }

    fn cache_carve_event(url: &str) -> BrowserEvent {
        BrowserEvent::new(
            13_300_000_000_000_000,
            BrowserFamily::Chromium,
            ArtifactKind::Cache,
            "/ev/Default/Cache/abc_0",
            url,
        )
        .with_attr("artifact_subtype", json!("cache_carve"))
        .with_attr("recovery_mechanism", json!("orphaned_simple_entry"))
        .with_attr("recovery_quality", json!("full"))
        .with_attr(
            "recovery_note",
            json!("orphaned SimpleCache entry, consistent with an evicted response"),
        )
    }

    fn recovered_domain_event(domain: &str) -> BrowserEvent {
        BrowserEvent::new(
            0,
            BrowserFamily::Chromium,
            ArtifactKind::RecoveredDomain,
            "/ev/Default/Network Persistent State",
            format!("contacted {domain}"),
        )
        .with_attr("domain", json!(domain))
        .with_attr("source_artifact", json!("Network Persistent State"))
    }

    fn deleted_bookmark_event(url: &str) -> BrowserEvent {
        BrowserEvent::new(
            13_300_000_000_000_000,
            BrowserFamily::Firefox,
            ArtifactKind::RecoveredBookmark,
            "/ev/profile/bookmarkbackups/bookmarks-2024.jsonlz4",
            format!("deleted bookmark {url}"),
        )
        .with_attr("url", json!(url))
    }

    fn memory_event(url: &str) -> BrowserEvent {
        BrowserEvent::new(
            0,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "/ev/mem.raw",
            url,
        )
        .with_attr("url", json!(url))
    }

    #[test]
    fn carved_record_is_deleted_not_live() {
        let findings = carved_record_findings(&[carved_record("urls")]);
        let f = findings.first().expect("a carved-record finding");
        assert_ne!(
            f.provenance.state,
            EvidenceState::Live,
            "a carved deleted record is never live"
        );
        assert_eq!(f.provenance.source, EvidenceSource::Carved);
        assert!(
            f.interpretation.to_lowercase().contains("consistent with"),
            "keeps the court-safe hedge: {}",
            f.interpretation
        );
        assert!(
            f.evidence.contains("urls"),
            "shows the recovered table: {}",
            f.evidence
        );
    }

    #[test]
    fn cache_carve_is_deleted_not_live() {
        let findings = cache_carve_findings(&[cache_carve_event("https://evil.example/a.js")]);
        let f = findings.first().expect("a cache-carve finding");
        assert_ne!(f.provenance.state, EvidenceState::Live);
        assert_eq!(f.provenance.source, EvidenceSource::Cache);
        assert!(
            f.evidence.contains("evil.example"),
            "shows the full recovered URL: {}",
            f.evidence
        );
    }

    #[test]
    fn recovered_domain_is_inferred_not_live() {
        let findings = recovered_domain_findings(&[recovered_domain_event("tracker.example")]);
        let f = findings.first().expect("a recovered-domain finding");
        assert_eq!(f.provenance.source, EvidenceSource::Recovered);
        assert_eq!(f.provenance.state, EvidenceState::Inferred);
        assert!(f.evidence.contains("tracker.example"));
        assert!(f.interpretation.to_lowercase().contains("consistent with"));
    }

    #[test]
    fn deleted_bookmark_is_deleted_not_live() {
        let findings = deleted_bookmark_findings(&[deleted_bookmark_event("https://gone.example")]);
        let f = findings.first().expect("a deleted-bookmark finding");
        assert_eq!(f.provenance.state, EvidenceState::Deleted);
        assert!(f.evidence.contains("gone.example"));
        assert!(f.interpretation.to_lowercase().contains("consistent with"));
        assert!(
            f.next
                .as_deref()
                .unwrap_or("")
                .contains("deleted-bookmarks"),
            "points at the artifact deleted-bookmarks drill-down: {:?}",
            f.next
        );
    }

    #[test]
    fn tamper_history_cleared_is_high_and_deleted() {
        let indicators = vec![IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/ev/Default/History"),
            detected_at_ns: 13_300_000_000_000_000,
        }];
        let f = tamper_findings(&indicators)
            .into_iter()
            .next()
            .expect("a tamper finding");
        assert_eq!(
            f.priority,
            Priority::High,
            "clearing is a top attention cue"
        );
        assert_eq!(f.provenance.state, EvidenceState::Deleted);
        assert!(
            f.interpretation
                .to_lowercase()
                .contains("innocent alternative"),
            "keeps the innocent-alternative framing: {}",
            f.interpretation
        );
    }

    #[test]
    fn tamper_generic_anomaly_is_medium() {
        let indicators = vec![IntegrityIndicator::WalPresent {
            path: PathBuf::from("/ev/Default/History-wal"),
        }];
        let f = tamper_findings(&indicators)
            .into_iter()
            .next()
            .expect("a tamper finding");
        assert_eq!(f.priority, Priority::Medium);
    }

    #[test]
    fn memory_carve_is_from_memory_not_live() {
        let findings = memory_findings(&[memory_event("https://ram.example/x")]);
        let f = findings.first().expect("a memory finding");
        assert_eq!(f.provenance.source, EvidenceSource::Memory);
        assert_ne!(f.provenance.state, EvidenceState::Live);
        assert!(f.evidence.contains("ram.example"));
    }

    #[test]
    fn every_recovery_finding_state_is_not_live() {
        // The whole point of `recover`: nothing it surfaces is a live artifact.
        let mut findings = Vec::new();
        findings.extend(carved_record_findings(&[carved_record("urls")]));
        findings.extend(cache_carve_findings(&[cache_carve_event(
            "https://a.example",
        )]));
        findings.extend(recovered_domain_findings(&[recovered_domain_event(
            "b.example",
        )]));
        findings.extend(deleted_bookmark_findings(&[deleted_bookmark_event(
            "https://c.example",
        )]));
        findings.extend(memory_findings(&[memory_event("https://d.example")]));
        assert!(!findings.is_empty());
        for f in &findings {
            assert_ne!(
                f.provenance.state,
                EvidenceState::Live,
                "recovery finding must not be live: {}",
                f.evidence
            );
        }
    }

    #[test]
    fn rank_orders_high_before_info() {
        let mut findings = memory_findings(&[memory_event("https://a.example")]); // Info-ish
        findings.extend(tamper_findings(&[IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/ev/Default/History"),
            detected_at_ns: 0,
        }])); // High
        let ranked = rank_findings(findings);
        assert_eq!(
            ranked.first().map(|f| f.priority),
            Some(Priority::High),
            "highest priority ranks first"
        );
    }

    #[test]
    fn footer_profile_names_memory_and_whole_image_not_run() {
        let f = recover_footer(RecoverScope::Profile, "/ev").to_lowercase();
        assert!(f.contains("memory"), "profile footer names memory: {f}");
        assert!(
            f.contains("whole-image") || f.contains("whole image") || f.contains("carving"),
            "profile footer names whole-image carving: {f}"
        );
        assert!(
            f.contains("not"),
            "footer frames work as NOT attempted: {f}"
        );
    }

    fn carved_artifact(url: &str, offset: u64) -> browser_forensic_imagecarve::CarvedArtifact {
        browser_forensic_imagecarve::CarvedArtifact {
            kind: browser_forensic_imagecarve::CarvedArtifactKind::SqliteRecord,
            url: url.to_string(),
            image_offset: offset,
            visit_time_raw: Some(13_300_000_000_000_000),
            detail: format!("[\"{url}\", 13300000000000000]"),
        }
    }

    #[test]
    fn whole_image_finding_is_carved_low_with_offset_and_no_fs_context() {
        let arts = vec![carved_artifact("https://carved.example/deleted", 1_048_576)];
        let findings = whole_image_findings(&arts);
        let f = findings.first().expect("a whole-image carve finding");
        assert_eq!(
            f.provenance.source,
            EvidenceSource::Carved,
            "raw-bytes carve is sourced from carving"
        );
        assert_eq!(
            f.provenance.state,
            EvidenceState::Carved,
            "a whole-image carved artifact is Carved, never Live"
        );
        assert_eq!(f.confidence, Confidence::Low);
        let interp = f.interpretation.to_lowercase();
        assert!(
            interp.contains("unallocated space") && interp.contains("no filesystem context"),
            "keeps the no-filesystem-context hedge: {}",
            f.interpretation
        );
        assert!(
            f.evidence.contains("carved.example"),
            "shows the full recovered URL: {}",
            f.evidence
        );
        assert!(
            f.evidence.contains("1048576"),
            "shows the absolute byte offset as provenance: {}",
            f.evidence
        );
    }

    #[test]
    fn footer_whole_image_states_carving_ran() {
        let f = recover_footer(RecoverScope::WholeImage, "/ev/disk.dd").to_lowercase();
        assert!(
            f.contains("whole-image") && f.contains("ran"),
            "whole-image footer states the carve RAN: {f}"
        );
        assert!(
            !f.contains("carving was not run") && !f.contains("carving is n/a"),
            "the whole-image footer must NOT claim carving was skipped: {f}"
        );
    }

    #[test]
    fn footer_profile_states_whole_image_is_na_not_a_raw_image() {
        let f = recover_footer(RecoverScope::Profile, "/ev").to_lowercase();
        assert!(
            f.contains("n/a") && f.contains("not a raw image"),
            "profile footer frames whole-image carving as N/A (not a raw image): {f}"
        );
    }

    #[test]
    fn footer_memory_image_names_profile_recovery_not_run() {
        let f = recover_footer(RecoverScope::MemoryImage, "/ev/mem.raw").to_lowercase();
        assert!(
            f.contains("profile"),
            "memory-image footer names profile recovery not run: {f}"
        );
        assert!(f.contains("not"), "framed as NOT attempted: {f}");
    }

    #[test]
    fn render_summary_always_has_footer_and_cue_note() {
        let out = render_summary(&[], RecoverScope::Profile, "/ev", false);
        assert!(
            out.to_lowercase().contains("not"),
            "the skipped-work footer is always present: {out}"
        );
        assert!(
            out.contains(PRIORITY_CUE_NOTE),
            "the priority-cue note is present"
        );
    }

    #[test]
    fn render_summary_shows_three_axes_and_next() {
        let findings = rank_findings(tamper_findings(&[IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/ev/Default/History"),
            detected_at_ns: 0,
        }]));
        let out = render_summary(&findings, RecoverScope::Profile, "/ev", false);
        for label in ["Priority:", "Confidence:", "Interpretation:", "Next:"] {
            assert!(out.contains(label), "render shows `{label}`: {out}");
        }
    }

    #[test]
    fn render_summary_caps_visible_and_notes_more() {
        let mut indicators = Vec::new();
        for i in 0..(MAX_VISIBLE_FINDINGS + 3) {
            indicators.push(IntegrityIndicator::WalPresent {
                path: PathBuf::from(format!("/ev/Default/History-wal-{i}")),
            });
        }
        let findings = rank_findings(tamper_findings(&indicators));
        assert!(findings.len() > MAX_VISIBLE_FINDINGS);
        let out = render_summary(&findings, RecoverScope::Profile, "/ev", false);
        assert!(
            out.to_lowercase().contains("more"),
            "over-cap findings are noted, not silently dropped: {out}"
        );
    }
}
