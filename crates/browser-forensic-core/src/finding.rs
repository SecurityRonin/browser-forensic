//! Court-safe forensic finding model (RFC 0001 — D4 provenance, D5 the
//! Priority/Confidence/Interpretation split, D9 multi-user origin).
//!
//! A [`Finding`] keeps the three epistemic axes **structurally separate** so no
//! renderer can collapse them into a bare `HIGH` that reads as *high confidence
//! of wrongdoing*:
//!
//! * [`Priority`] — a triage attention cue (*look here first*), never a verdict.
//! * [`Confidence`] + `rule_id` — how strongly the *interpretation* is supported.
//! * `interpretation` — the hedged *"consistent with …"* statement.
//!
//! Because [`Priority`] and [`Confidence`] are distinct types, the compiler makes
//! it impossible to pass one where the other belongs. There is deliberately **no
//! `Display` impl on [`Finding`]** that could emit an absolute; render a finding
//! with [`Finding::render`], which always shows the three axes separately and
//! always carries the interpretation hedge.

use serde::{Deserialize, Serialize};

use crate::BrowserFamily;

/// Triage attention cue — *where to look first* (RFC 0001 D5).
///
/// Deliberately **not** a confidence or a verdict: `High` means "look here
/// first," never "high confidence of wrongdoing." Kept a separate type from
/// [`Confidence`] so the two axes can never be conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Priority {
    High,
    Medium,
    Info,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Info => write!(f, "Info"),
        }
    }
}

/// How strongly the finding's *interpretation* is supported (RFC 0001 D5).
/// Always travels with a `rule_id` on the [`Finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
        }
    }
}

/// Where the datum was read from — a coarse provenance axis (RFC 0001 D4).
/// A live history hit, a carved string, and a cached resource have different
/// courtroom value; this axis records which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum EvidenceSource {
    History,
    Cache,
    Cookie,
    Download,
    Carved,
    Memory,
}

impl std::fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::History => write!(f, "history"),
            Self::Cache => write!(f, "cache"),
            Self::Cookie => write!(f, "cookie"),
            Self::Download => write!(f, "download"),
            Self::Carved => write!(f, "carved"),
            Self::Memory => write!(f, "memory"),
        }
    }
}

/// Liveness / derivation state of the datum (RFC 0001 D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum EvidenceState {
    Live,
    Deleted,
    Carved,
    Reconstructed,
    Inferred,
}

impl std::fmt::Display for EvidenceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Live => write!(f, "live"),
            Self::Deleted => write!(f, "deleted"),
            Self::Carved => write!(f, "carved"),
            Self::Reconstructed => write!(f, "reconstructed"),
            Self::Inferred => write!(f, "inferred"),
        }
    }
}

/// Basis for the timestamp attached to a finding (RFC 0001 D4/D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum TimestampBasis {
    /// A timestamp the artifact stores explicitly for this record.
    Explicit,
    /// Derived from adjacent data, not stored for this record directly.
    Inferred,
    /// Taken from a surrounding page/resource rather than the datum itself.
    SurroundingPage,
    /// No time basis is available.
    None,
}

impl std::fmt::Display for TimestampBasis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Explicit => write!(f, "explicit"),
            Self::Inferred => write!(f, "inferred"),
            Self::SurroundingPage => write!(f, "surrounding-page"),
            Self::None => write!(f, "none"),
        }
    }
}

/// The user-action the evidence supports — stated as a *claim*, never a verdict
/// (RFC 0001 D4). "Observed string" is the weakest: the term merely appeared in
/// stored bytes, with no proof a human acted on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum UserActionClaim {
    Visited,
    Downloaded,
    Searched,
    ObservedString,
    Unknown,
}

impl std::fmt::Display for UserActionClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Visited => write!(f, "visited"),
            Self::Downloaded => write!(f, "downloaded"),
            Self::Searched => write!(f, "searched"),
            Self::ObservedString => write!(f, "observed-string"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// The four provenance axes (RFC 0001 D4). They travel together so a [`Finding`]
/// can never be constructed without a full provenance record — no silent,
/// misleading default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Provenance {
    /// Where the datum was read from.
    pub source: EvidenceSource,
    /// Its liveness / derivation state.
    pub state: EvidenceState,
    /// The basis for any timestamp on the finding.
    pub timestamp_basis: TimestampBasis,
    /// The user-action the evidence supports, as a claim.
    pub user_action_claim: UserActionClaim,
}

impl Provenance {
    /// Build a full provenance record. All four axes are required.
    #[must_use]
    pub fn new(
        source: EvidenceSource,
        state: EvidenceState,
        timestamp_basis: TimestampBasis,
        user_action_claim: UserActionClaim,
    ) -> Self {
        Self {
            source,
            state,
            timestamp_basis,
            user_action_claim,
        }
    }
}

/// A court-safe forensic finding (RFC 0001 D4/D5/D9).
///
/// Priority, Confidence and Interpretation are three structurally separate axes;
/// provenance ([`Provenance`]) and origin (`user`/`profile`/`browser`) stamp
/// every finding with where it came from. Render with [`Finding::render`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Finding {
    /// Triage attention cue — *look here first*, not a verdict.
    pub priority: Priority,
    /// Confidence in the interpretation (paired with `rule_id`).
    pub confidence: Confidence,
    /// Identifier of the rule that produced this finding.
    pub rule_id: String,
    /// The hedged *"consistent with …"* statement.
    pub interpretation: String,
    /// The four-axis provenance record (D4).
    pub provenance: Provenance,
    /// Originating user (SID or name), when known (D9).
    pub user: Option<String>,
    /// Originating browser profile (e.g. `Chrome/Default`), when known (D9).
    pub profile: Option<String>,
    /// Originating browser family, when known (D9).
    pub browser: Option<BrowserFamily>,
    /// The concrete datum this finding rests on
    /// (e.g. `Chrome History urls rowid gap 128 → 944`).
    pub evidence: String,
    /// A drill-down command pointer for the examiner's next step.
    pub next: Option<String>,
}

impl Finding {
    /// Build a finding from its three separate axes, a full provenance record,
    /// and the concrete evidence datum.
    ///
    /// [`Priority`] and [`Confidence`] are distinct types, so the three axes
    /// cannot be conflated at a call site. Origin (`user`/`profile`/`browser`)
    /// and `next` are attached with the `with_*` builder methods.
    #[must_use]
    pub fn new(
        priority: Priority,
        confidence: Confidence,
        rule_id: impl Into<String>,
        interpretation: impl Into<String>,
        provenance: Provenance,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            priority,
            confidence,
            rule_id: rule_id.into(),
            interpretation: interpretation.into(),
            provenance,
            user: None,
            profile: None,
            browser: None,
            evidence: evidence.into(),
            next: None,
        }
    }

    /// Stamp the originating user (SID or name) (D9).
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Stamp the originating browser profile (D9).
    #[must_use]
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Stamp the originating browser family (D9).
    #[must_use]
    pub fn with_browser(mut self, browser: BrowserFamily) -> Self {
        self.browser = Some(browser);
        self
    }

    /// Attach a drill-down "next step" command pointer.
    #[must_use]
    pub fn with_next(mut self, next: impl Into<String>) -> Self {
        self.next = Some(next.into());
        self
    }

    /// Render the finding as a multi-line, court-safe block.
    ///
    /// The three axes are always shown separately and labelled; Priority is
    /// explicitly framed as a triage attention cue (never a verdict); the
    /// Interpretation hedge is always present. This is the only renderer for a
    /// finding — there is no `Display` impl that could collapse it into a bare
    /// conclusion. (RFC 0001 D5.)
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        // Writing to a String is infallible; the `_ =` keeps that explicit.
        let _ = writeln!(
            out,
            "Priority:       {}  (look here first — a triage attention cue)",
            self.priority
        );
        let _ = writeln!(
            out,
            "Confidence:     {}  (rule {})",
            self.confidence, self.rule_id
        );
        let _ = writeln!(out, "Interpretation: {}", self.interpretation);
        let _ = writeln!(out, "Rule:           {}", self.rule_id);
        let p = &self.provenance;
        let _ = writeln!(
            out,
            "Provenance:     {} · {} · time {} · {}",
            p.source, p.state, p.timestamp_basis, p.user_action_claim
        );
        if let Some(origin) = self.origin_line() {
            let _ = writeln!(out, "Origin:         {origin}");
        }
        let _ = writeln!(out, "Evidence:       {}", self.evidence);
        if let Some(next) = &self.next {
            let _ = writeln!(out, "Next:           {next}");
        }
        out
    }

    /// Compose the D9 origin line from whichever of browser/profile/user are
    /// known. Returns `None` when the finding carries no origin stamp.
    fn origin_line(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(browser) = &self.browser {
            parts.push(browser.to_string());
        }
        if let Some(profile) = &self.profile {
            parts.push(profile.clone());
        }
        if let Some(user) = &self.user {
            parts.push(format!("user {user}"));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" · "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_provenance() -> Provenance {
        Provenance::new(
            EvidenceSource::History,
            EvidenceState::Live,
            TimestampBasis::Explicit,
            UserActionClaim::Visited,
        )
    }

    fn sample_finding() -> Finding {
        Finding::new(
            Priority::High,
            Confidence::Medium,
            "integrity.history.rowid_gap.v1",
            "consistent with manual deletion, DB maintenance, or profile sync",
            sample_provenance(),
            "Chrome History urls rowid gap 128 → 944",
        )
    }

    #[test]
    fn provenance_carries_four_axes() {
        let p = sample_provenance();
        assert_eq!(p.source, EvidenceSource::History);
        assert_eq!(p.state, EvidenceState::Live);
        assert_eq!(p.timestamp_basis, TimestampBasis::Explicit);
        assert_eq!(p.user_action_claim, UserActionClaim::Visited);
    }

    #[test]
    fn new_sets_three_distinct_axes() {
        let f = sample_finding();
        // Three separate axes, each its own value — a High priority does NOT
        // imply high confidence.
        assert_eq!(f.priority, Priority::High);
        assert_eq!(f.confidence, Confidence::Medium);
        assert_eq!(f.rule_id, "integrity.history.rowid_gap.v1");
        assert!(f.interpretation.starts_with("consistent with"));
    }

    #[test]
    fn origin_builder_sets_user_profile_browser() {
        let f = sample_finding()
            .with_user("S-1-5-21-1004")
            .with_profile("Chrome/Default")
            .with_browser(BrowserFamily::Chromium)
            .with_next("br4n6 artifact integrity --rule history.rowid_gap <PATH>");
        assert_eq!(f.user.as_deref(), Some("S-1-5-21-1004"));
        assert_eq!(f.profile.as_deref(), Some("Chrome/Default"));
        assert_eq!(f.browser, Some(BrowserFamily::Chromium));
        assert!(f.next.is_some());
    }

    #[test]
    fn roundtrip_json_preserves_all_fields() {
        let f = sample_finding()
            .with_user("alice")
            .with_profile("Chrome/Default")
            .with_browser(BrowserFamily::Chromium)
            .with_next("br4n6 artifact integrity <PATH>");
        let json = serde_json::to_string(&f).expect("serialize");
        let back: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(f, back, "JSONL round-trip must be faithful");
    }

    #[test]
    fn three_axes_serialize_as_distinct_top_level_fields() {
        let f = sample_finding();
        let v = serde_json::to_value(&f).expect("to_value");
        let obj = v.as_object().expect("finding serializes as an object");
        // The three D5 axes are separate keys carrying separate values — a
        // renderer reading this can never collapse them into one "HIGH".
        assert_eq!(obj.get("priority").and_then(|x| x.as_str()), Some("High"));
        assert_eq!(
            obj.get("confidence").and_then(|x| x.as_str()),
            Some("Medium")
        );
        assert!(
            obj.get("interpretation").is_some(),
            "interpretation is a distinct field"
        );
        assert!(obj.contains_key("rule_id"), "rule_id is a distinct field");
        // Provenance is a distinct, structured sub-record present in JSONL (D4).
        let prov = obj
            .get("provenance")
            .and_then(|x| x.as_object())
            .expect("provenance object present");
        for key in ["source", "state", "timestamp_basis", "user_action_claim"] {
            assert!(prov.contains_key(key), "provenance carries `{key}`");
        }
    }

    #[test]
    fn render_shows_all_three_axes_with_labels() {
        let f = sample_finding();
        let r = f.render();
        assert!(r.contains("Priority:"), "labels the priority axis: {r}");
        assert!(r.contains("Confidence:"), "labels the confidence axis");
        assert!(r.contains("Interpretation:"), "labels the interpretation");
        assert!(
            r.contains("integrity.history.rowid_gap.v1"),
            "shows rule id"
        );
        assert!(
            r.contains("Chrome History urls rowid gap"),
            "shows evidence"
        );
    }

    #[test]
    fn render_labels_priority_as_attention_cue() {
        let f = sample_finding();
        let r = f.render();
        // The word "High" must never stand as a bare verdict: the priority line
        // frames it as a triage attention cue.
        assert!(
            r.contains("attention cue"),
            "priority is framed as a triage attention cue, not a finding of malice: {r}"
        );
    }

    #[test]
    fn render_priority_never_appears_without_interpretation_hedge() {
        let f = sample_finding();
        let r = f.render();
        // Whenever the render shows a Priority, the hedged interpretation is
        // present in the same block — the conclusion can never be read bare.
        assert!(r.contains("Priority:"));
        assert!(
            r.contains(&f.interpretation),
            "the interpretation hedge accompanies every rendered priority: {r}"
        );
    }
}
