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

use crate::recover::RecoverScope;

/// Investigation depth tier (RFC 0001 D2). `Standard` is the bare-verb default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tier {
    /// Live artifacts + cheap integrity checks only.
    Quick,
    /// Quick + bounded deleted-record recovery (SQLite freelist / WAL). Default.
    #[default]
    Standard,
    /// Standard + the full recovery engines (P5b): deleted-record / free-page
    /// carving, orphaned-cache carve, recovered domains, deleted bookmarks,
    /// tamper checks and — over a memory image — RAM carving. Auto-selected by
    /// PATH shape exactly as `recover`; see [`skipped_footer`].
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
    if profiles.is_empty() {
        return "Detected: no browser profiles found".to_string();
    }
    let families: BTreeSet<String> = profiles
        .iter()
        .map(|p| p.browser.to_string().to_lowercase())
        .collect();
    format!(
        "Detected: {} profile(s) across {} browser(s): {}",
        profiles.len(),
        families.len(),
        families.into_iter().collect::<Vec<_>>().join(", "),
    )
}

/// File-name extensions treated as executable/scriptable payloads.
const EXECUTABLE_EXTS: &[&str] = &[
    "exe", "dll", "scr", "msi", "msp", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "jar", "apk", "app", "dmg", "pkg", "deb", "rpm", "sh", "run", "wsf", "hta", "cpl", "msc",
    "gadget", "lnk", "reg", "sys", "iso",
];

/// Read a string attribute from an event, if present and a JSON string.
fn attr_str<'a>(event: &'a BrowserEvent, key: &str) -> Option<&'a str> {
    event.attrs.get(key).and_then(serde_json::Value::as_str)
}

/// The final path component of a `/`- or `\`-separated path.
fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Whether a file name carries a known executable/scriptable extension.
fn is_executable_name(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, ext)| {
        let ext = ext.to_ascii_lowercase();
        EXECUTABLE_EXTS.contains(&ext.as_str())
    })
}

/// The serde variant tag of an integrity indicator (e.g. `"HistoryCleared"`).
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
/// top attention cues (High), as opposed to lower-priority anomalies (Medium).
fn is_clearing_tag(tag: &str) -> bool {
    matches!(
        tag,
        "HistoryCleared" | "AutoIncrementGap" | "HistoryTombstoneFound" | "SqliteSequenceGap"
    )
}

/// History-clearing + integrity-anomaly findings (one per indicator). Uses the
/// integrity crate's own `observation()` / `innocent_alternative()` so the
/// court-safe hedge is preserved verbatim.
fn integrity_findings(indicators: &[IntegrityIndicator]) -> Vec<Finding> {
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
                format!("investigate.integrity.{tag}.v1"),
                format!(
                    "consistent with clearing/tampering; innocent alternative: {}",
                    ind.innocent_alternative()
                ),
                provenance,
                ind.observation(),
            )
            .with_next("br4n6 artifact integrity <PATH>")
        })
        .collect()
}

/// Executable-download findings: a download whose target file name is executable
/// or that the browser itself flagged dangerous (`danger_type != 0`).
fn executable_download_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    events
        .iter()
        .filter(|e| e.artifact == ArtifactKind::Downloads)
        .filter_map(|e| {
            let target = attr_str(e, "target_path").unwrap_or(&e.description);
            let danger = e
                .attrs
                .get("danger_type")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            if !is_executable_name(base_name(target)) && danger == 0 {
                return None;
            }
            let provenance = Provenance::new(
                EvidenceSource::Download,
                EvidenceState::Live,
                TimestampBasis::Explicit,
                UserActionClaim::Downloaded,
            );
            Some(
                Finding::new(
                    Priority::High,
                    Confidence::Medium,
                    "investigate.exec_download.v1",
                    "consistent with an executable file downloaded via the browser; a download \
                     does not by itself establish execution",
                    provenance,
                    target.to_string(),
                )
                .with_browser(e.browser.clone())
                .with_next("br4n6 artifact downloads <PATH>"),
            )
        })
        .collect()
}

/// One aggregate finding counting cookies stored encrypted (values require the
/// profile's key to recover — reported, never silently dropped, RFC 0001 D7).
fn encrypted_cookie_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    let count = events
        .iter()
        .filter(|e| {
            e.artifact == ArtifactKind::Cookies
                && attr_str(e, "encrypted_value") == Some("ENCRYPTED")
        })
        .count();
    if count == 0 {
        return Vec::new();
    }
    let provenance = Provenance::new(
        EvidenceSource::Cookie,
        EvidenceState::Live,
        TimestampBasis::Explicit,
        UserActionClaim::Unknown,
    );
    vec![Finding::new(
        Priority::Info,
        Confidence::High,
        "investigate.encrypted_cookies.v1",
        "consistent with normal OS-bound cookie encryption; plaintext values require the \
         profile's key (add --keys)",
        provenance,
        format!("{count} cookie value(s) stored encrypted (not recoverable without keys)"),
    )
    .with_next("br4n6 artifact cookies <PATH>")]
}

/// One aggregate finding listing installed extensions. Permission scope is not
/// assessed at this tier (the extensions parser does not surface it yet); the
/// finding is a review cue, honestly hedged.
fn extension_findings(events: &[BrowserEvent]) -> Vec<Finding> {
    let names: Vec<String> = events
        .iter()
        .filter(|e| e.artifact == ArtifactKind::Extensions)
        .map(|e| attr_str(e, "name").map_or_else(|| e.description.clone(), str::to_string))
        .collect();
    if names.is_empty() {
        return Vec::new();
    }
    let provenance = Provenance::new(
        EvidenceSource::Extension,
        EvidenceState::Live,
        TimestampBasis::Explicit,
        UserActionClaim::Unknown,
    );
    vec![Finding::new(
        Priority::Info,
        Confidence::Low,
        "investigate.extension_present.v1",
        "consistent with legitimately-installed or sideloaded extensions; permission scope is \
         not assessed at this tier",
        provenance,
        format!(
            "{} extension(s) installed: {}",
            names.len(),
            names.join(", ")
        ),
    )
    .with_next("br4n6 artifact extensions <PATH>")]
}

/// Produce the full set of court-safe [`Finding`]s from a triage report by
/// running every finding-generator and concatenating their output.
#[must_use]
pub fn findings_from_report(report: &TriageReport) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(executable_download_findings(&report.events));
    findings.extend(integrity_findings(&report.integrity));
    findings.extend(encrypted_cookie_findings(&report.events));
    findings.extend(extension_findings(&report.events));
    findings
}

/// Priority ordering weight — higher sorts first.
fn priority_weight(priority: Priority) -> u8 {
    match priority {
        Priority::High => 2,
        Priority::Medium => 1,
        Priority::Info => 0,
    }
}

/// Rank findings by [`Priority`] (High → Medium → Info), stable within a tier.
#[must_use]
pub fn rank_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by_key(|f| std::cmp::Reverse(priority_weight(f.priority)));
    findings
}

/// Drop findings that are the *same observed datum from the same evidence source
/// in the same state* — the case where `--deep` folds a recovery [`Finding`] on
/// top of a standard-tier one for the identical indicator (e.g. a `HistoryCleared`
/// tamper that both the integrity and tamper generators emit). The dedup key is
/// `(evidence, source, state)`, not `rule_id`: the two generators use different
/// rule ids for one datum, so keying on the rule would miss the duplicate. First
/// occurrence wins, so the standard-tier finding (added first) is the one kept.
#[must_use]
pub fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    findings
        .into_iter()
        .filter(|f| {
            seen.insert(format!(
                "{}\u{1f}{}\u{1f}{}",
                f.evidence, f.provenance.source, f.provenance.state
            ))
        })
        .collect()
}

/// The always-present skipped-work footer for a tier (RFC 0001 D2). Names what
/// the tier did *not* do so "false reassurance" is impossible; `--quick` names
/// strictly more than `--standard`. `scope` is only meaningful for [`Tier::Deep`]
/// — the recovery scope auto-selected from the PATH shape, which decides what deep
/// recovery actually ran (and, honestly, what it still did not cover for this
/// path); it is ignored (`None`) for the other tiers.
#[must_use]
pub fn skipped_footer(tier: Tier, scope: Option<RecoverScope>, path_display: &str) -> String {
    match tier {
        Tier::Quick => format!(
            "Deep recovery not run: whole-image carving, cache reconstruction, memory scanning \
             skipped. Bounded deleted-record recovery (SQLite freelist/WAL) is ALSO skipped in \
             --quick — deleted evidence may be missed → br4n6 investigate --standard {path_display} \
             (or --deep {path_display})"
        ),
        Tier::Standard => format!(
            "Deep recovery not run: whole-image carving, cache reconstruction, memory scanning \
             skipped — deleted evidence may be missed → br4n6 investigate --deep {path_display}"
        ),
        Tier::Deep => deep_footer(scope, path_display),
    }
}

/// The deep-tier footer: state what deep recovery ACTUALLY ran for the auto-
/// selected [`RecoverScope`] and, honestly, what it still did not cover for this
/// path (the recover orchestrator's own scope footer carries both halves, so the
/// wording stays in sync with `recover` — no drift). Absent a scope (defensive;
/// deep always resolves one) it falls back to the profile description.
fn deep_footer(scope: Option<RecoverScope>, path_display: &str) -> String {
    let scope = scope.unwrap_or(RecoverScope::Profile);
    format!(
        "Deep recovery ran (standard-tier live-artifact investigation + the recovery engines). {}",
        crate::recover::recover_footer(scope, path_display)
    )
}

/// Colorize a rendered finding's `Priority:` value line as a TTY cue. The
/// severity word is always printed by [`Finding::render`]; color is additive.
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

/// The full human (TTY) render: detection header, ranked findings (capped, with
/// a "N more" note), the priority-cue note, and the mandatory skipped-work
/// footer. `color` enables ANSI priority cues (a TTY-only affordance).
#[must_use]
pub fn render_summary(
    profiles: &[DiscoveredProfile],
    findings: &[Finding],
    tier: Tier,
    scope: Option<RecoverScope>,
    path_display: &str,
    color: bool,
) -> String {
    let mut out = String::new();
    out.push_str(&detection_header(profiles));
    out.push_str("\n\n");
    out.push_str(PRIORITY_CUE_NOTE);
    out.push_str("\n\n");

    if findings.is_empty() {
        out.push_str("No ranked findings from the parsed artifacts at this tier.\n\n");
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
                "… {} more finding(s) not shown, ranked by Priority.\n\n",
                findings.len() - visible
            ));
        }
    }

    out.push_str(&skipped_footer(tier, scope, path_display));
    out.push('\n');
    out
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
        let f = skipped_footer(Tier::Standard, None, "/ev").to_lowercase();
        for token in ["carving", "cache", "memory", "--deep"] {
            assert!(f.contains(token), "standard footer names `{token}`: {f}");
        }
    }

    #[test]
    fn footer_quick_names_strictly_more_than_standard() {
        let q = skipped_footer(Tier::Quick, None, "/ev").to_lowercase();
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
    fn footer_deep_names_what_ran_not_todo() {
        // P5b: deep recovery is WIRED now — the footer must state what actually
        // ran, never "not yet implemented" / a deferring-phase TODO.
        let d = skipped_footer(
            Tier::Deep,
            Some(crate::recover::RecoverScope::Profile),
            "/ev",
        )
        .to_lowercase();
        assert!(
            !d.contains("not yet") && !d.contains("todo"),
            "deep footer no longer claims unimplemented: {d}"
        );
        assert!(
            d.contains("ran"),
            "deep footer states deep recovery RAN: {d}"
        );
        assert!(
            d.contains("tamper"),
            "deep footer names the tamper checks it ran: {d}"
        );
        // Honest about what a profile-dir run does NOT cover: no memory image.
        assert!(
            d.contains("memory"),
            "deep footer names memory (not scanned — no image supplied): {d}"
        );
    }

    #[test]
    fn footer_deep_memory_image_scope_states_ram_carve_ran() {
        let d = skipped_footer(
            Tier::Deep,
            Some(crate::recover::RecoverScope::MemoryImage),
            "/ev/mem.raw",
        )
        .to_lowercase();
        assert!(!d.contains("not yet") && !d.contains("todo"));
        assert!(d.contains("ran"), "states deep recovery ran: {d}");
        assert!(
            d.contains("ram") || d.contains("memory"),
            "names the RAM carve it ran over a memory image: {d}"
        );
    }

    #[test]
    fn footer_deep_whole_image_scope_states_carving_ran() {
        let d = skipped_footer(
            Tier::Deep,
            Some(crate::recover::RecoverScope::WholeImage),
            "/ev/disk.dd",
        )
        .to_lowercase();
        assert!(!d.contains("not yet") && !d.contains("todo"));
        assert!(d.contains("ran"), "states deep recovery ran: {d}");
        assert!(
            d.contains("whole-image") && d.contains("unallocated"),
            "names the whole-image unallocated-space carve it ran over an image: {d}"
        );
    }

    #[test]
    fn dedup_findings_collapses_cross_generator_duplicate() {
        // The same tamper observation surfaces from BOTH the standard integrity
        // generator and the deep tamper generator (different rule_id, identical
        // evidence + source + state). Folding deep into standard must dedup it.
        let prov = || {
            Provenance::new(
                EvidenceSource::History,
                EvidenceState::Deleted,
                TimestampBasis::None,
                UserActionClaim::Unknown,
            )
        };
        let standard = Finding::new(
            Priority::High,
            Confidence::Medium,
            "investigate.integrity.HistoryCleared.v1",
            "consistent with clearing",
            prov(),
            "History cleared @ /ev/Default/History",
        );
        let deep = Finding::new(
            Priority::High,
            Confidence::Medium,
            "recover.tamper.HistoryCleared.v1",
            "consistent with clearing; innocent alternative: sync",
            prov(),
            "History cleared @ /ev/Default/History",
        );
        let distinct = Finding::new(
            Priority::Medium,
            Confidence::Low,
            "recover.carve.deleted_record.v1",
            "consistent with a deleted row",
            Provenance::new(
                EvidenceSource::Carved,
                EvidenceState::Carved,
                TimestampBasis::None,
                UserActionClaim::Unknown,
            ),
            "urls deleted row @offset 4096",
        );
        let out = dedup_findings(vec![standard.clone(), deep, distinct]);
        assert_eq!(
            out.len(),
            2,
            "the duplicate tamper (same evidence+source+state) collapses to one: {out:?}"
        );
        assert!(
            out.iter().any(|f| f.evidence.contains("History cleared")),
            "the shared tamper datum survives once"
        );
        assert!(
            out.iter().any(|f| f.evidence.contains("deleted row")),
            "a genuinely distinct finding is kept"
        );
    }

    #[test]
    fn render_summary_always_contains_footer_even_with_no_findings() {
        let out = render_summary(&[], &[], Tier::Standard, None, "/ev", false);
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
        let out = render_summary(&[], &findings, Tier::Standard, None, "/ev", false);
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
        let out = render_summary(&[], &findings, Tier::Standard, None, "/ev", false);
        assert!(
            out.to_lowercase().contains("more"),
            "over-cap findings are noted, not silently dropped: {out}"
        );
    }
}
