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
}

/// Read a string attribute from an event, if present and a JSON string.
fn attr_str<'a>(event: &'a BrowserEvent, key: &str) -> Option<&'a str> {
    event.attrs.get(key).and_then(serde_json::Value::as_str)
}

/// Deleted-record findings from SQLite free-page / WAL carving. Each carved row
/// is a *recovered deleted record* — state is never `Live` — hedged as
/// consistent-with routine deletion (VACUUM, history expiry, sync), not proof of
/// a deliberate user act.
#[must_use]
pub fn carved_record_findings(records: &[browser_forensic_carve::CarvedRecord]) -> Vec<Finding> {
    let _ = records;
    Vec::new()
}

/// Orphaned/evicted cache findings from `cache-carve`. The input events are the
/// normalized [`BrowserEvent`]s the cache-carve mapper emits (artifact
/// `Cache`, `artifact_subtype = "cache_carve"`); each is a cached-then-evicted
/// artifact (state `Deleted`), never a deliberate deletion.
#[must_use]
pub fn cache_carve_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    let _ = events;
    Vec::new()
}

/// Recovered-domain findings (Network Persistent State / NEL / DIPS / HSTS): a
/// domain contacted even after history is cleared, recovered from a persistence
/// side effect. State is `Inferred` (contact inferred, not a recorded
/// navigation); it may be a subresource/third-party.
#[must_use]
pub fn recovered_domain_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    let _ = events;
    Vec::new()
}

/// Deleted-bookmark findings: a bookmark present in a Firefox backup but absent
/// from the current set (state `Deleted`), consistent with deletion after that
/// backup — routine reorganization is an innocent alternative.
#[must_use]
pub fn deleted_bookmark_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    let _ = events;
    Vec::new()
}

/// Tamper / anti-forensic findings from integrity indicators. History-clearing
/// variants are the top attention cue (`High`); other anomalies are `Medium`.
/// Each keeps the integrity crate's own observation + innocent alternative.
#[must_use]
pub fn tamper_findings(indicators: &[IntegrityIndicator]) -> Vec<Finding> {
    let _ = indicators;
    Vec::new()
}

/// Memory-carve findings: browser artifacts (URLs, cookies) recovered from a RAM
/// capture. State is `Carved`; a string in RAM is not proof a human acted on it.
#[must_use]
pub fn memory_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    let _ = events;
    Vec::new()
}

/// The always-present skipped-work footer for a scope (RFC 0001 D2). Names what
/// `recover` did NOT attempt for the auto-selected scope so absence of a result
/// is never false reassurance.
#[must_use]
pub fn recover_footer(scope: RecoverScope, path_display: &str) -> String {
    let _ = (scope, path_display);
    String::new()
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
    let _ = (findings, scope, path_display, color);
    String::new()
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
