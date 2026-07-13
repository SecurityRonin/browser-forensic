//! RFC 0001 Phase P3a — the `investigate` golden path.
//!
//! `investigate` drives the existing triage/collect pipeline and turns its
//! results into a **ranked, court-safe attention layer** built entirely on the
//! P0 [`Finding`] model. It is UX assembly over existing forensics, not new
//! forensic logic: the finding-generators here read triage output
//! ([`TriageReport`]) and re-express it as [`Finding`]s carrying the three
//! separate D5 axes (Priority / Confidence / Interpretation), full provenance,
//! and a `next:` drill-down pointer.
//!
//! Three honesty invariants hold here (RFC 0001 D2/D5):
//!
//! * **The summary is an attention layer, never the evidence layer.** Priority
//!   is a triage cue — where to look first — never a finding of malice. Every
//!   finding keeps its structural interpretation hedge (via [`Finding::render`]).
//! * **The skipped-work footer is mandatory and un-suppressible on the human
//!   render.** [`render_summary`] always ends with [`skipped_footer`], which
//!   names what the chosen tier did *not* do, so false reassurance is impossible.
//! * **`--quick` names strictly more skipped work than `--standard`.**

use std::collections::BTreeSet;

use browser_forensic_core::finding::{
    Confidence, EvidenceSource, EvidenceState, Finding, Priority, Provenance, TimestampBasis,
    UserActionClaim,
};
use browser_forensic_core::{ArtifactKind, BrowserEvent};
use browser_forensic_discovery::DiscoveredProfile;
use browser_forensic_integrity::IntegrityIndicator;
use browser_forensic_triage::{TriageOptions, TriageReport};

/// Investigation depth tier (RFC 0001 D2). `Standard` is the bare-verb default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tier {
    /// Live artifacts + cheap integrity checks only.
    Quick,
    /// Quick + bounded deleted-record recovery (SQLite freelist / WAL). Default.
    #[default]
    Standard,
    /// Standard + (not yet wired) whole-image carving, cache reconstruction,
    /// memory scanning. Stubbed in P3a; see [`skipped_footer`].
    Deep,
}

impl Tier {
    /// The [`TriageOptions`] this tier drives the triage pipeline with. Only
    /// `Quick` skips bounded deleted-record carving.
    #[must_use]
    pub fn triage_options(self) -> TriageOptions {
        TriageOptions {
            carve: !matches!(self, Tier::Quick),
        }
    }
}

/// Maximum findings shown on the human render before a "N more" note (D2 — a
/// bounded, scannable summary, not a wall).
pub const MAX_VISIBLE_FINDINGS: usize = 7;

/// The once-per-summary note that frames Priority as a triage cue, not a verdict
/// (RFC 0001 D5).
pub const PRIORITY_CUE_NOTE: &str =
    "Note: Priority ranks where to look first — a triage attention cue, not a finding of malice.";

/// First line of the summary: what was detected and its scope (RFC 0001 D8, the
/// basic P3a form — full confidence-scored auto-detect is P7).
#[must_use]
pub fn detection_header(profiles: &[DiscoveredProfile]) -> String {
    let _ = profiles;
    String::new()
}

/// Produce the full set of court-safe [`Finding`]s from a triage report by
/// running every finding-generator and concatenating their output.
#[must_use]
pub fn findings_from_report(report: &TriageReport) -> Vec<Finding> {
    let _ = report;
    Vec::new()
}

/// Rank findings by [`Priority`] (High → Medium → Info), stable within a tier.
#[must_use]
pub fn rank_findings(findings: Vec<Finding>) -> Vec<Finding> {
    findings
}

/// The always-present skipped-work footer for a tier (RFC 0001 D2). Names what
/// the tier did *not* do so "false reassurance" is impossible; `--quick` names
/// strictly more than `--standard`.
#[must_use]
pub fn skipped_footer(tier: Tier, path_display: &str) -> String {
    let _ = (tier, path_display);
    String::new()
}

/// The full human (TTY) render: detection header, ranked findings (capped, with
/// a "N more" note), the priority-cue note, and the mandatory skipped-work
/// footer. `color` enables ANSI priority cues (a TTY-only affordance).
#[must_use]
pub fn render_summary(
    profiles: &[DiscoveredProfile],
    findings: &[Finding],
    tier: Tier,
    path_display: &str,
    color: bool,
) -> String {
    let _ = (profiles, findings, tier, path_display, color);
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::BrowserFamily;
    use browser_forensic_discovery::DiscoveredProfile;
    use serde_json::json;
    use std::path::PathBuf;

    fn profile(browser: BrowserFamily, name: &str) -> DiscoveredProfile {
        DiscoveredProfile {
            browser,
            name: name.to_string(),
            path: PathBuf::from(format!("/ev/{name}")),
            container: None,
        }
    }

    fn empty_report() -> TriageReport {
        TriageReport {
            events: Vec::new(),
            carved: Vec::new(),
            integrity: Vec::new(),
            profiles: Vec::new(),
            generated_at_ns: 0,
        }
    }

    fn download_event(target: &str) -> BrowserEvent {
        BrowserEvent::new(
            13_300_000_000_000_000,
            BrowserFamily::Chromium,
            ArtifactKind::Downloads,
            "/ev/Default/History",
            format!("downloaded {target}"),
        )
        .with_attr("target_path", json!(target))
        .with_attr("danger_type", json!(0_i32))
    }

    fn cookie_event(host: &str) -> BrowserEvent {
        BrowserEvent::new(
            13_300_000_000_000_000,
            BrowserFamily::Chromium,
            ArtifactKind::Cookies,
            "/ev/Default/Cookies",
            format!("cookie for {host}"),
        )
        .with_attr("host_key", json!(host))
        .with_attr("encrypted_value", json!("ENCRYPTED"))
    }

    fn extension_event(name: &str) -> BrowserEvent {
        BrowserEvent::new(
            13_300_000_000_000_000,
            BrowserFamily::Chromium,
            ArtifactKind::Extensions,
            "/ev/Default/Extensions",
            format!("{name} v1"),
        )
        .with_attr("name", json!(name))
    }

    #[test]
    fn detection_header_names_profiles_and_browsers() {
        let profiles = vec![
            profile(BrowserFamily::Chromium, "Default"),
            profile(BrowserFamily::Firefox, "abcd.default"),
        ];
        let h = detection_header(&profiles);
        assert!(h.contains("Detected:"), "header labels detection: {h}");
        assert!(h.contains('2'), "counts the two profiles: {h}");
        assert!(
            h.to_lowercase().contains("chromium") && h.to_lowercase().contains("firefox"),
            "names both browser families: {h}"
        );
    }

    #[test]
    fn detection_header_empty_is_honest() {
        let h = detection_header(&[]);
        assert!(
            h.to_lowercase().contains("no") && h.to_lowercase().contains("profile"),
            "empty detection is stated, not blank: {h}"
        );
    }

    #[test]
    fn history_cleared_yields_high_priority_finding() {
        let mut report = empty_report();
        report.integrity.push(IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/ev/Default/History"),
            detected_at_ns: 13_300_000_000_000_000,
        });
        let findings = findings_from_report(&report);
        let f = findings
            .iter()
            .find(|f| f.rule_id.contains("integrity"))
            .expect("a history-clearing finding");
        assert_eq!(
            f.priority,
            Priority::High,
            "clearing is a top attention cue"
        );
        assert!(
            f.interpretation.to_lowercase().contains("consistent with"),
            "keeps the court-safe hedge: {}",
            f.interpretation
        );
        assert!(f.next.is_some(), "carries a drill-down pointer");
    }

    #[test]
    fn generic_integrity_anomaly_is_medium_not_high() {
        let mut report = empty_report();
        report.integrity.push(IntegrityIndicator::WalPresent {
            path: PathBuf::from("/ev/Default/History-wal"),
        });
        let findings = findings_from_report(&report);
        let f = findings
            .iter()
            .find(|f| f.rule_id.contains("integrity"))
            .expect("an integrity finding");
        assert_eq!(
            f.priority,
            Priority::Medium,
            "a non-clearing anomaly is a lower attention cue"
        );
    }

    #[test]
    fn executable_download_yields_finding() {
        let mut report = empty_report();
        report
            .events
            .push(download_event("/Users/x/Downloads/evil.exe"));
        let findings = findings_from_report(&report);
        let f = findings
            .iter()
            .find(|f| f.rule_id.contains("exec_download"))
            .expect("an executable-download finding");
        assert_eq!(f.provenance.source, EvidenceSource::Download);
        assert!(
            f.evidence.contains("evil.exe"),
            "shows the full download path: {}",
            f.evidence
        );
        assert!(
            f.next.as_deref().unwrap_or("").contains("downloads"),
            "points at the downloads drill-down"
        );
    }

    #[test]
    fn non_executable_download_not_flagged() {
        let mut report = empty_report();
        report
            .events
            .push(download_event("/Users/x/Downloads/report.pdf"));
        let findings = findings_from_report(&report);
        assert!(
            !findings.iter().any(|f| f.rule_id.contains("exec_download")),
            "a benign document download is not an exec-download finding"
        );
    }

    #[test]
    fn encrypted_cookies_counted() {
        let mut report = empty_report();
        for h in ["a.example", "b.example", "c.example"] {
            report.events.push(cookie_event(h));
        }
        let findings = findings_from_report(&report);
        let f = findings
            .iter()
            .find(|f| f.rule_id.contains("encrypted_cookies"))
            .expect("an encrypted-cookies finding");
        assert!(
            f.evidence.contains('3'),
            "reports the count: {}",
            f.evidence
        );
        assert_eq!(f.provenance.source, EvidenceSource::Cookie);
    }

    #[test]
    fn extensions_surfaced_with_drilldown() {
        let mut report = empty_report();
        report.events.push(extension_event("uBlock Origin"));
        report.events.push(extension_event("Some Sideloaded Ext"));
        let findings = findings_from_report(&report);
        let f = findings
            .iter()
            .find(|f| f.rule_id.contains("extension"))
            .expect("an extensions finding");
        assert!(
            f.next.as_deref().unwrap_or("").contains("extensions"),
            "points at the extensions drill-down: {:?}",
            f.next
        );
        assert!(
            f.interpretation.to_lowercase().contains("consistent with"),
            "hedged interpretation: {}",
            f.interpretation
        );
    }

    #[test]
    fn rank_orders_high_before_info() {
        let mut report = empty_report();
        report.events.push(extension_event("Ext")); // Info
        report.integrity.push(IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/ev/Default/History"),
            detected_at_ns: 0,
        }); // High
        let ranked = rank_findings(findings_from_report(&report));
        assert_eq!(
            ranked.first().map(|f| f.priority),
            Some(Priority::High),
            "the highest-priority finding ranks first"
        );
    }

    #[test]
    fn footer_standard_names_deep_work_and_deep_pointer() {
        let f = skipped_footer(Tier::Standard, "/ev").to_lowercase();
        for token in ["carving", "cache", "memory", "--deep"] {
            assert!(f.contains(token), "standard footer names `{token}`: {f}");
        }
    }

    #[test]
    fn footer_quick_names_strictly_more_than_standard() {
        let q = skipped_footer(Tier::Quick, "/ev").to_lowercase();
        // Everything standard skips, quick also skips …
        for token in ["carving", "cache", "memory"] {
            assert!(q.contains(token), "quick footer names `{token}`: {q}");
        }
        // … plus the bounded deleted-record recovery standard *does* run.
        assert!(
            q.contains("freelist") || q.contains("wal") || q.contains("deleted"),
            "quick additionally names skipped bounded recovery: {q}"
        );
    }

    #[test]
    fn footer_deep_marks_todo() {
        let d = skipped_footer(Tier::Deep, "/ev").to_lowercase();
        assert!(
            d.contains("not yet") || d.contains("todo"),
            "deep is honestly marked unimplemented: {d}"
        );
        assert!(
            d.contains("p3b") || d.contains("p5"),
            "cites the deferring phase: {d}"
        );
    }

    #[test]
    fn render_summary_always_contains_footer_even_with_no_findings() {
        let out = render_summary(&[], &[], Tier::Standard, "/ev", false);
        assert!(
            out.contains("Deep recovery"),
            "the skipped-work footer is always present: {out}"
        );
        assert!(
            out.contains(PRIORITY_CUE_NOTE),
            "the priority-cue note is present"
        );
    }

    #[test]
    fn render_summary_shows_three_axes_and_next() {
        let mut report = empty_report();
        report.integrity.push(IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/ev/Default/History"),
            detected_at_ns: 0,
        });
        let findings = rank_findings(findings_from_report(&report));
        let out = render_summary(&[], &findings, Tier::Standard, "/ev", false);
        for label in ["Priority:", "Confidence:", "Interpretation:", "Next:"] {
            assert!(out.contains(label), "render shows `{label}`: {out}");
        }
    }

    #[test]
    fn render_summary_caps_visible_and_notes_more() {
        let mut report = empty_report();
        for i in 0..(MAX_VISIBLE_FINDINGS + 3) {
            report.integrity.push(IntegrityIndicator::WalPresent {
                path: PathBuf::from(format!("/ev/Default/History-wal-{i}")),
            });
        }
        let findings = rank_findings(findings_from_report(&report));
        assert!(findings.len() > MAX_VISIBLE_FINDINGS);
        let out = render_summary(&[], &findings, Tier::Standard, "/ev", false);
        assert!(
            out.to_lowercase().contains("more"),
            "over-cap findings are noted, not silently dropped: {out}"
        );
    }
}
