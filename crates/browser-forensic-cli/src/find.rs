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
    let t = term.trim();
    if t.contains("://") {
        return TermKind::Url;
    }
    if t.parse::<std::net::Ipv4Addr>().is_ok() {
        return TermKind::Ipv4;
    }
    if t.parse::<std::net::Ipv6Addr>().is_ok() {
        return TermKind::Ipv6;
    }
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        match t.len() {
            32 => return TermKind::Hash(HashKind::Md5),
            40 => return TermKind::Hash(HashKind::Sha1),
            64 => return TermKind::Hash(HashKind::Sha256),
            _ => {}
        }
    }
    if looks_like_domain(t) {
        return TermKind::Domain;
    }
    TermKind::Literal
}

/// True when `s` has the shape of a bare domain / hostname: dot-separated labels
/// of `[A-Za-z0-9-]` (not leading/trailing a hyphen), no whitespace or path, and
/// a final label (the TLD) that is at least two ASCII letters.
fn looks_like_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.contains(char::is_whitespace) {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let Some(tld) = labels.last() else {
        return false;
    };
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// A short human label for a classified TERM, for the *"Searching for domain
/// …"* announcement.
#[must_use]
pub fn describe_term(kind: &TermKind) -> &'static str {
    match kind {
        TermKind::Domain => "domain",
        TermKind::Url => "URL",
        TermKind::Ipv4 => "IPv4 address",
        TermKind::Ipv6 => "IPv6 address",
        TermKind::Hash(HashKind::Md5) => "MD5 hash",
        TermKind::Hash(HashKind::Sha1) => "SHA-1 hash",
        TermKind::Hash(HashKind::Sha256) => "SHA-256 hash",
        TermKind::Regex => "regex",
        TermKind::Literal => "literal term",
    }
}

/// Derive the four-axis [`Provenance`] for an event by its artifact kind (D4).
/// A live history row, a recovered domain, and a carved record map to distinct
/// source/state/action tuples so their courtroom value is never conflated.
#[must_use]
pub fn provenance_for(artifact: &ArtifactKind) -> Provenance {
    use ArtifactKind as A;
    use EvidenceSource as Src;
    use EvidenceState as St;
    use TimestampBasis as Tb;
    use UserActionClaim as Ua;

    let (source, state, basis, action) = match artifact {
        // A recorded navigation the user made — the strongest "visited" evidence.
        A::History | A::Favicon | A::TopSite | A::Session | A::MediaPlayback => {
            (Src::History, St::Live, Tb::Explicit, Ua::Visited)
        }
        // A saved bookmark the user chose to keep — a deliberate visit.
        A::Bookmarks => (Src::History, St::Live, Tb::Explicit, Ua::Visited),
        // A bookmark present only in a backup — consistent with later deletion.
        A::RecoveredBookmark => (Src::History, St::Deleted, Tb::Inferred, Ua::Visited),
        // A string the user typed into the omnibox / address bar — typed intent.
        A::Shortcut | A::TypedInput | A::NetworkPrediction => {
            (Src::History, St::Live, Tb::Explicit, Ua::Searched)
        }
        // A file the browser downloaded.
        A::Downloads => (Src::Download, St::Live, Tb::Explicit, Ua::Downloaded),
        // A stored cookie — presence shows contact, not a deliberate visit.
        A::Cookies => (Src::Cookie, St::Live, Tb::Explicit, Ua::ObservedString),
        // A cached resource — a stored string; time is the surrounding page's.
        A::Cache => (
            Src::Cache,
            St::Live,
            Tb::SurroundingPage,
            Ua::ObservedString,
        ),
        // An installed extension.
        A::Extensions => (Src::Extension, St::Live, Tb::Explicit, Ua::Unknown),
        // Other live profile stores where the term merely appears as a string.
        A::LoginData
        | A::Autofill
        | A::LocalStorage
        | A::Permission
        | A::CreditCard
        | A::AuthToken
        | A::Annotation
        | A::Preferences
        | A::Integrity => (Src::History, St::Live, Tb::Explicit, Ua::ObservedString),
        // A domain recovered from a network/state artifact after a history wipe —
        // contact is inferred, never a recorded visit (D4).
        A::RecoveredDomain => (Src::Recovered, St::Inferred, Tb::None, Ua::Unknown),
        // A record carved from a deallocated SQLite page / WAL — recovery may be
        // partial, so it carries the weakest liveness state and low confidence.
        A::Carved => (Src::Carved, St::Carved, Tb::None, Ua::Unknown),
        // A string carved from a memory image.
        A::Memory => (Src::Memory, St::Carved, Tb::None, Ua::ObservedString),
    };
    Provenance::new(source, state, basis, action)
}

/// Map an evidence [`EvidenceState`] to the confidence its interpretation carries
/// (D5): live evidence is high, recovered/reconstructed medium, carved/inferred
/// low.
#[must_use]
pub fn confidence_for(state: EvidenceState) -> Confidence {
    match state {
        EvidenceState::Live => Confidence::High,
        EvidenceState::Deleted | EvidenceState::Reconstructed => Confidence::Medium,
        EvidenceState::Carved | EvidenceState::Inferred => Confidence::Low,
    }
}

/// The rule id for a provenance record: `find.<source>.<state>.v1`.
#[must_use]
pub fn rule_for(provenance: &Provenance) -> String {
    format!("find.{}.{}.v1", provenance.source, provenance.state)
}

/// The most specific locator an event carries for the MATCH column: its URL,
/// else a recovered/contacted domain, else a download target, else its
/// description.
fn best_match_value(event: &BrowserEvent) -> String {
    for key in ["url", "domain", "origin", "target_path"] {
        if let Some(s) = event.attrs.get(key).and_then(serde_json::Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    event.description.clone()
}

impl FindHit {
    /// Build a hit from a matched [`BrowserEvent`], deriving provenance from its
    /// artifact kind (D4). The `match_value` is the most specific locator the
    /// event carries (its URL / domain / target, else its description).
    #[must_use]
    pub fn from_event(term: &str, event: &BrowserEvent) -> Self {
        let provenance = provenance_for(&event.artifact);
        let confidence = confidence_for(provenance.state);
        let rule_id = rule_for(&provenance);
        Self {
            term: term.to_string(),
            confidence,
            rule_id,
            provenance,
            match_value: best_match_value(event),
            timestamp_ns: event.timestamp_ns,
            browser: Some(event.browser.to_string()),
            profile: None,
            user: None,
        }
    }

    /// Build a hit from an enumerated IOC (`find --iocs`): the `kind_label` (an
    /// IOC class such as `email`/`ipv4`) fills the TERM column, `value` is the
    /// concrete match, and provenance is derived from the *source* event's
    /// artifact so the evidence class is preserved — but the user-action claim is
    /// forced to [`UserActionClaim::ObservedString`]. An IOC-shaped string merely
    /// *appears* in an artifact; its presence is never a claim the user visited,
    /// searched, or downloaded anything (D4 honesty).
    #[must_use]
    pub fn from_ioc(kind_label: &str, value: &str, event: &BrowserEvent) -> Self {
        let mut provenance = provenance_for(&event.artifact);
        provenance.user_action_claim = UserActionClaim::ObservedString;
        let confidence = confidence_for(provenance.state);
        let rule_id = rule_for(&provenance);
        Self {
            term: kind_label.to_string(),
            confidence,
            rule_id,
            provenance,
            match_value: value.to_string(),
            timestamp_ns: event.timestamp_ns,
            browser: Some(event.browser.to_string()),
            profile: None,
            user: None,
        }
    }

    /// Project the hit to a [`FIND_HEADERS`]-ordered table row for the human view.
    /// Every axis is rendered in full (never ellipsized); the lowercase Display of
    /// each provenance enum is the human label.
    #[must_use]
    pub fn row(&self) -> Vec<String> {
        vec![
            self.term.clone(),
            self.provenance.source.to_string(),
            self.provenance.state.to_string(),
            self.confidence.to_string(),
            self.rule_id.clone(),
            self.provenance.timestamp_basis.to_string(),
            self.provenance.user_action_claim.to_string(),
            self.match_value.clone(),
        ]
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
    fn carved_record_is_carved_state_low_conf_never_visited() {
        let e = BrowserEvent::new(
            0,
            BrowserFamily::Chromium,
            ArtifactKind::Carved,
            "/ev/Default/History",
            "carved row",
        );
        let hit = FindHit::from_event("secret", &e);
        assert_eq!(hit.provenance.source, EvidenceSource::Carved);
        assert_eq!(hit.provenance.state, EvidenceState::Carved);
        assert_ne!(hit.provenance.state, EvidenceState::Live);
        assert_ne!(hit.provenance.user_action_claim, UserActionClaim::Visited);
        assert_eq!(hit.confidence, Confidence::Low);
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
