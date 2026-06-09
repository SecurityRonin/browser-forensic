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
        Self { domains: domains.into_iter().map(|d| d.to_lowercase()).collect(), all: false }
    }
    pub fn allow_all() -> Self {
        Self { domains: Vec::new(), all: true }
    }
    /// Whether the URL's host is covered by an allowed domain (eTLD+1 suffix).
    pub fn permits(&self, url: &str) -> bool {
        if self.all {
            return true;
        }
        let Some(host) = host_of(url) else { return false };
        let host = host.to_lowercase();
        self.domains.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }
}

/// Extract the host (text between `://` and the next `/`, `?`, or `#`).
fn host_of(url: &str) -> Option<&str> {
    let after = url.split_once("://")?.1;
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let host = &after[..end];
    (!host.is_empty()).then_some(host)
}

fn to_item(r: &Record) -> ContextItem {
    ContextItem {
        url: redact_url(&r.url),
        title: mask_secrets(&r.title),
        kind: r.kind.label().to_string(),
        time_ns: r.time_ns,
        browser: r.browser.clone(),
        source: r.source.to_string(),
        untrusted_evidence: true,
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
    let window_ns = i64::from(minutes).saturating_mul(60).saturating_mul(1_000_000_000);
    let cutoff = now_ns.saturating_sub(window_ns);

    let mut omitted = 0usize;
    let mut items: Vec<ContextItem> = Vec::new();
    for r in records {
        if r.time_ns < cutoff {
            continue; // outside the time window
        }
        if r.is_redirect && !r.chain_end {
            continue; // intermediate redirect hop — collapsed, not an omission
        }
        if !allow.permits(&r.url) {
            omitted += 1;
            continue;
        }
        items.push(to_item(r));
    }
    items.sort_by(|a, b| b.time_ns.cmp(&a.time_ns)); // newest first
    items.truncate(cap);

    ContextResult {
        items,
        omitted_by_policy_count: omitted,
        timeline_basis: "history.visits + snss (redirect-collapsed, allow-listed)".to_string(),
    }
}

/// Allow-listed records whose URL contains `query` (case-insensitive), redacted.
pub fn did_user_visit(records: &[Record], query: &str, allow: &Allowlist) -> ContextResult {
    let needle = query.to_lowercase();
    let mut omitted = 0usize;
    let mut items: Vec<ContextItem> = Vec::new();
    for r in records {
        if !r.url.to_lowercase().contains(&needle) {
            continue; // not a match
        }
        if !allow.permits(&r.url) {
            omitted += 1;
            continue;
        }
        items.push(to_item(r));
    }
    items.sort_by(|a, b| b.time_ns.cmp(&a.time_ns));
    ContextResult {
        items,
        omitted_by_policy_count: omitted,
        timeline_basis: "history (allow-listed url match)".to_string(),
    }
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
