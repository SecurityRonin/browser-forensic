//! RFC 0001 Phase P4 — the `find` verb's data model (D4 provenance-first lookup).
//!
//! `find` is the *"did they visit / download / search X?"* front door. It unifies
//! the former `search` / `extract-iocs` / `match-domains` / `recovered-domains`
//! commands into one verb **without homogenizing evidence classes** (D4): a live
//! history visit, a carved deleted record, and a domain recovered from a
//! network-state artifact are DISTINCT rows carrying distinct provenance, never
//! collapsed into a bare *"found X."*
//!
//! This module owns the *pure* half of that verb — TERM auto-classification and
//! the per-hit provenance derivation — reusing the P0 [`Provenance`] /
//! [`Confidence`] axes verbatim ([`browser_forensic_core::finding`]). The
//! I/O-bound half (collecting across sources, matching, rendering) lives in
//! `cli.rs::run_find`.

use browser_forensic_core::finding::{
    Confidence, EvidenceSource, EvidenceState, Provenance, TimestampBasis, UserActionClaim,
};
use browser_forensic_core::{ArtifactKind, BrowserEvent};
use serde::Serialize;

/// The auto-classified kind of a bare `find` TERM (RFC 0001 P4). Explicit
/// `--regex` / `--term` / `--terms-file` bypass classification at the command
/// layer; this covers a single positional token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermKind {
    /// A bare registrable domain / hostname (`evil.com`).
    Domain,
    /// A full URL (`https://evil.com/a`).
    Url,
    /// An IPv4 address (`8.8.8.8`).
    Ipv4,
    /// An IPv6 address (`2001:db8::1`).
    Ipv6,
    /// A file hash, disambiguated by hex length.
    Hash(HashKind),
    /// A literal string forced with `--term` (never guessed).
    Regex,
    /// Anything the shape heuristics do not recognize — matched as a literal
    /// substring.
    Literal,
}

/// A hash TERM, classified by hex length (MD5 = 32, SHA-1 = 40, SHA-256 = 64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Md5,
    Sha1,
    Sha256,
}

/// The `find` provenance table's column headers (D4). The human render is a
/// markdown-clean table with these columns; the machine JSONL carries the same
/// axes structurally. `CONF` + `RULE` sit adjacent (D5 — confidence travels with
/// its rule id).
pub const FIND_HEADERS: [&str; 8] = [
    "TERM",
    "SOURCE",
    "STATE",
    "CONF",
    "RULE",
    "TIME-BASIS",
    "USER-ACTION",
    "MATCH",
];

/// A single `find` hit — one matched record, with its full provenance preserved
/// (D4). Serializes to a JSONL object carrying every axis (machine-faithful,
/// round-trippable); projects to a table row for the human view via [`Self::row`].
#[derive(Debug, Clone, Serialize)]
pub struct FindHit {
    /// The search term this hit matched.
    pub term: String,
    /// Confidence in the interpretation, derived from the evidence state (D5).
    pub confidence: Confidence,
    /// The rule id that classified this hit (`find.<source>.<state>.v1`).
    pub rule_id: String,
    /// The four-axis provenance record (D4) — source/state/timestamp-basis/action.
    pub provenance: Provenance,
    /// The concrete matched value (the URL, domain, or record the term hit).
    #[serde(rename = "match")]
    pub match_value: String,
    /// The record's timestamp in Unix nanoseconds (0 when the source has none).
    pub timestamp_ns: i64,
    /// Originating browser family, when known (D9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    /// Originating profile, when known (D9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Originating user, when known (D9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Auto-classify a bare TERM by shape (RFC 0001 P4). Order matters: a full URL is
/// checked before its host; an IP before a hash; a hash (fixed hex length) before
/// a domain. Anything unrecognized is a [`TermKind::Literal`] substring.
#[must_use]
pub fn classify_term(term: &str) -> TermKind {
    unimplemented!("classify_term (P4 GREEN)")
}

/// A short human label for a classified TERM, for the *"Searching for domain
/// …"* announcement.
#[must_use]
pub fn describe_term(kind: &TermKind) -> &'static str {
    unimplemented!("describe_term (P4 GREEN)")
}

/// Derive the four-axis [`Provenance`] for an event by its artifact kind (D4).
/// A live history row, a recovered domain, and a carved record map to distinct
/// source/state/action tuples so their courtroom value is never conflated.
#[must_use]
pub fn provenance_for(artifact: &ArtifactKind) -> Provenance {
    unimplemented!("provenance_for (P4 GREEN)")
}

/// Map an evidence [`EvidenceState`] to the confidence its interpretation carries
/// (D5): live evidence is high, recovered/reconstructed medium, carved/inferred
/// low.
#[must_use]
pub fn confidence_for(state: EvidenceState) -> Confidence {
    unimplemented!("confidence_for (P4 GREEN)")
}

/// The rule id for a provenance record: `find.<source>.<state>.v1`.
#[must_use]
pub fn rule_for(provenance: &Provenance) -> String {
    unimplemented!("rule_for (P4 GREEN)")
}

impl FindHit {
    /// Build a hit from a matched [`BrowserEvent`], deriving provenance from its
    /// artifact kind (D4). The `match_value` is the most specific locator the
    /// event carries (its URL / domain / target, else its description).
    #[must_use]
    pub fn from_event(term: &str, event: &BrowserEvent) -> Self {
        unimplemented!("FindHit::from_event (P4 GREEN)")
    }

    /// Project the hit to a [`FIND_HEADERS`]-ordered table row for the human view.
    #[must_use]
    pub fn row(&self) -> Vec<String> {
        unimplemented!("FindHit::row (P4 GREEN)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::BrowserFamily;
    use serde_json::json;

    fn event(artifact: ArtifactKind, url_attr: &str) -> BrowserEvent {
        BrowserEvent::new(
            1,
            BrowserFamily::Chromium,
            artifact,
            "/ev/Default/History",
            "desc",
        )
        .with_attr("url", json!(url_attr))
    }

    // ---- TERM auto-classifier ----

    #[test]
    fn classify_bare_domain() {
        assert_eq!(classify_term("evil.com"), TermKind::Domain);
        assert_eq!(classify_term("sub.tracker.evil.co.uk"), TermKind::Domain);
    }

    #[test]
    fn classify_url() {
        assert_eq!(classify_term("https://evil.com/a"), TermKind::Url);
        assert_eq!(classify_term("http://8.8.8.8/x"), TermKind::Url);
    }

    #[test]
    fn classify_ipv4() {
        assert_eq!(classify_term("8.8.8.8"), TermKind::Ipv4);
        assert_eq!(classify_term("192.168.1.1"), TermKind::Ipv4);
    }

    #[test]
    fn classify_ipv6() {
        assert_eq!(classify_term("2001:db8::1"), TermKind::Ipv6);
        assert_eq!(classify_term("::1"), TermKind::Ipv6);
    }

    #[test]
    fn classify_hashes_by_hex_length() {
        assert_eq!(
            classify_term(&"a".repeat(32)),
            TermKind::Hash(HashKind::Md5)
        );
        assert_eq!(
            classify_term(&"9".repeat(40)),
            TermKind::Hash(HashKind::Sha1)
        );
        assert_eq!(
            classify_term(&"f".repeat(64)),
            TermKind::Hash(HashKind::Sha256)
        );
    }

    #[test]
    fn classify_literal_fallback() {
        assert_eq!(classify_term("launder money"), TermKind::Literal);
        // A 32-char string with a non-hex char is not a hash.
        assert_eq!(
            classify_term(&format!("z{}", "a".repeat(31))),
            TermKind::Literal
        );
    }

    #[test]
    fn describe_labels_each_kind() {
        assert_eq!(describe_term(&TermKind::Domain), "domain");
        assert_eq!(describe_term(&TermKind::Url), "URL");
        assert_eq!(describe_term(&TermKind::Ipv4), "IPv4 address");
        assert_eq!(describe_term(&TermKind::Ipv6), "IPv6 address");
        assert_eq!(describe_term(&TermKind::Hash(HashKind::Md5)), "MD5 hash");
        assert_eq!(describe_term(&TermKind::Hash(HashKind::Sha1)), "SHA-1 hash");
        assert_eq!(
            describe_term(&TermKind::Hash(HashKind::Sha256)),
            "SHA-256 hash"
        );
        assert_eq!(describe_term(&TermKind::Regex), "regex");
        assert_eq!(describe_term(&TermKind::Literal), "literal term");
    }

    // ---- provenance derivation (D4): distinct classes never conflated ----

    #[test]
    fn live_history_hit_is_live_visited_high() {
        let hit = FindHit::from_event(
            "evil.com",
            &event(ArtifactKind::History, "https://evil.com/a"),
        );
        assert_eq!(hit.provenance.source, EvidenceSource::History);
        assert_eq!(hit.provenance.state, EvidenceState::Live);
        assert_eq!(hit.provenance.user_action_claim, UserActionClaim::Visited);
        assert_eq!(hit.confidence, Confidence::High);
        assert_eq!(hit.match_value, "https://evil.com/a");
        assert_eq!(hit.rule_id, "find.history.live.v1");
    }

    #[test]
    fn download_hit_is_download_downloaded() {
        let hit = FindHit::from_event(
            "x",
            &event(ArtifactKind::Downloads, "https://evil.com/m.exe"),
        );
        assert_eq!(hit.provenance.source, EvidenceSource::Download);
        assert_eq!(
            hit.provenance.user_action_claim,
            UserActionClaim::Downloaded
        );
    }

    #[test]
    fn recovered_domain_hit_is_recovered_inferred_never_live_or_visited() {
        let e = BrowserEvent::new(
            0,
            BrowserFamily::Chromium,
            ArtifactKind::RecoveredDomain,
            "/ev/Default/Network Persistent State",
            "evil.com — contacted",
        )
        .with_attr("domain", json!("evil.com"));
        let hit = FindHit::from_event("evil.com", &e);
        assert_eq!(hit.provenance.source, EvidenceSource::Recovered);
        assert_eq!(hit.provenance.state, EvidenceState::Inferred);
        // The whole point of D4: a recovered hit is NEVER a confirmed live visit.
        assert_ne!(hit.provenance.state, EvidenceState::Live);
        assert_ne!(hit.provenance.user_action_claim, UserActionClaim::Visited);
        assert_ne!(hit.confidence, Confidence::High);
        assert_eq!(hit.match_value, "evil.com");
    }

    #[test]
    fn timestamp_basis_is_explicit_for_history_none_for_recovered() {
        let live = FindHit::from_event("x", &event(ArtifactKind::History, "u"));
        assert_eq!(live.provenance.timestamp_basis, TimestampBasis::Explicit);
        let e = BrowserEvent::new(
            0,
            BrowserFamily::Chromium,
            ArtifactKind::RecoveredDomain,
            "src",
            "d",
        );
        let rec = FindHit::from_event("x", &e);
        assert_eq!(rec.provenance.timestamp_basis, TimestampBasis::None);
    }

    // ---- row / JSONL projections ----

    #[test]
    fn row_has_one_cell_per_header() {
        let hit = FindHit::from_event(
            "evil.com",
            &event(ArtifactKind::History, "https://evil.com/a"),
        );
        let row = hit.row();
        assert_eq!(row.len(), FIND_HEADERS.len());
        assert_eq!(row[0], "evil.com");
        assert_eq!(row[1], "history");
        assert_eq!(row[2], "live");
        assert_eq!(row[7], "https://evil.com/a");
    }

    #[test]
    fn jsonl_carries_every_axis_structurally() {
        let hit = FindHit::from_event(
            "evil.com",
            &event(ArtifactKind::History, "https://evil.com/a"),
        );
        let v = serde_json::to_value(&hit).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("term"));
        assert!(obj.contains_key("confidence"));
        assert!(obj.contains_key("rule_id"));
        assert!(obj.contains_key("match"), "the concrete matched value");
        let prov = obj
            .get("provenance")
            .and_then(|p| p.as_object())
            .expect("provenance object");
        for k in ["source", "state", "timestamp_basis", "user_action_claim"] {
            assert!(prov.contains_key(k), "provenance carries {k}");
        }
    }
}
