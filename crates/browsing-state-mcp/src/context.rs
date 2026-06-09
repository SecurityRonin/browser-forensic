//! Tool logic for the MCP surface: turn normalized browsing [`Record`]s into
//! bounded, allow-list-gated, redacted, provenance-tagged results. Pure — no I/O,
//! no secret access — so it is fully unit-testable.

use serde::Serialize;

use crate::redact::{mask_secrets, redact_url};

/// Where a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Visit,
    OpenTab,
    ClosedTab,
    Search,
}

impl RecordKind {
    fn label(self) -> &'static str {
        match self {
            RecordKind::Visit => "visit",
            RecordKind::OpenTab => "open_tab",
            RecordKind::ClosedTab => "closed_tab",
            RecordKind::Search => "search",
        }
    }
}

/// A normalized browsing record (a history visit or a session tab) before
/// policy + redaction are applied.
#[derive(Debug, Clone)]
pub struct Record {
    pub url: String,
    pub title: String,
    pub kind: RecordKind,
    pub time_ns: i64,
    pub browser: String,
    /// Provenance, e.g. `history.visits` or `snss`.
    pub source: &'static str,
    pub is_redirect: bool,
    pub chain_end: bool,
}

/// Domain allow-list — the floor for agent exposure. An empty list permits
/// nothing (secure default); use [`Allowlist::allow_all`] to opt out explicitly.
#[derive(Debug, Clone)]
pub struct Allowlist {
    domains: Vec<String>,
    all: bool,
}

impl Allowlist {
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        let _ = &domains;
        todo!("implemented in the GREEN step")
    }
    pub fn allow_all() -> Self {
        todo!("implemented in the GREEN step")
    }
    /// Whether the URL's host is covered by an allowed domain (eTLD+1 suffix).
    pub fn permits(&self, url: &str) -> bool {
        let _ = url;
        todo!("implemented in the GREEN step")
    }
}

/// One redacted, agent-safe item.
#[derive(Debug, Serialize, PartialEq)]
pub struct ContextItem {
    pub url: String,
    pub title: String,
    pub kind: String,
    pub time_ns: i64,
    pub browser: String,
    pub source: String,
    pub untrusted_evidence: bool,
}

/// A bounded tool result with provenance.
#[derive(Debug, Serialize, PartialEq)]
pub struct ContextResult {
    pub items: Vec<ContextItem>,
    pub omitted_by_policy_count: usize,
    pub timeline_basis: String,
}

/// Recent browsing within `minutes` of `now_ns`: redirect hops collapsed,
/// allow-list-gated, redacted, newest first, capped to `cap`.
pub fn browsing_context(
    records: &[Record],
    now_ns: i64,
    minutes: u32,
    cap: usize,
    allow: &Allowlist,
) -> ContextResult {
    let _ = (records, now_ns, minutes, cap, allow);
    todo!("implemented in the GREEN step")
}

/// Allow-listed records whose URL contains `query` (case-insensitive), redacted.
pub fn did_user_visit(records: &[Record], query: &str, allow: &Allowlist) -> ContextResult {
    let _ = (records, query, allow);
    todo!("implemented in the GREEN step")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(url: &str, title: &str, time_ns: i64, is_redirect: bool, chain_end: bool) -> Record {
        Record {
            url: url.to_string(),
            title: title.to_string(),
            kind: RecordKind::Visit,
            time_ns,
            browser: "Chromium".to_string(),
            source: "history.visits",
            is_redirect,
            chain_end,
        }
    }

    #[test]
    fn allowlist_matches_domain_and_subdomains_only() {
        let a = Allowlist::new(["github.com".to_string()]);
        assert!(a.permits("https://github.com/x"));
        assert!(a.permits("https://api.github.com/y"));
        assert!(!a.permits("https://evil.com/github.com"), "host is evil.com");
        assert!(!a.permits("https://notgithub.com"));
        assert!(!Allowlist::new(std::iter::empty()).permits("https://github.com"));
        assert!(Allowlist::allow_all().permits("https://anything.example"));
    }

    #[test]
    fn browsing_context_windows_collapses_redacts_and_counts_omissions() {
        let now = 1_000_000_000_000_000_000_i64;
        let min_ns = 60_000_000_000_i64;
        let records = vec![
            rec("https://github.com/a?token=X", "Repo a@b.com", now - min_ns, false, false),
            rec("https://github.com/hop", "Hop", now - min_ns, true, false), // redirect hop -> dropped
            rec("https://other.com/x", "Other", now - min_ns, false, false), // not allow-listed
            rec("https://github.com/old", "Old", now - 100 * min_ns, false, false), // out of window
        ];
        let allow = Allowlist::new(["github.com".to_string()]);
        let r = browsing_context(&records, now, 5, 10, &allow);

        assert_eq!(r.items.len(), 1, "only the in-window, allow-listed, non-redirect visit");
        assert_eq!(r.items[0].url, "https://github.com/a", "query string stripped");
        assert!(r.items[0].title.contains("[redacted-email]"), "email masked");
        assert!(r.items[0].untrusted_evidence);
        assert_eq!(r.items[0].source, "history.visits");
        assert_eq!(r.omitted_by_policy_count, 1, "other.com omitted by allow-list");
    }

    #[test]
    fn browsing_context_caps_and_orders_newest_first() {
        let now = 10_000_i64;
        let allow = Allowlist::allow_all();
        let records: Vec<Record> =
            (0..5).map(|i| rec(&format!("https://s{i}.com/"), "t", i as i64, false, false)).collect();
        let r = browsing_context(&records, now, u32::MAX, 2, &allow);
        assert_eq!(r.items.len(), 2, "capped to 2");
        assert!(r.items[0].time_ns >= r.items[1].time_ns, "newest first");
    }

    #[test]
    fn did_user_visit_returns_allowlisted_matches_only() {
        let records = vec![
            rec("https://github.com/h4x0r", "h4x0r", 100, false, false),
            rec("https://secret.com/x", "x", 200, false, false),
        ];
        let allow = Allowlist::new(["github.com".to_string()]);
        let hit = did_user_visit(&records, "github", &allow);
        assert_eq!(hit.items.len(), 1);
        assert_eq!(hit.items[0].url, "https://github.com/h4x0r");

        let miss = did_user_visit(&records, "secret", &allow);
        assert_eq!(miss.items.len(), 0);
        assert_eq!(miss.omitted_by_policy_count, 1, "matched but not allow-listed");
    }
}
