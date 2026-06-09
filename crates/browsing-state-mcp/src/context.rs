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

    /// Whether this is **state** (a current tab snapshot) rather than **history**
    /// (a timestamped event). State comes from the tab/session artifacts and is a
    /// point-in-time snapshot — it must NOT be filtered by a history-style time
    /// window. History (visits/searches) comes from the History DB and is.
    fn is_state(self) -> bool {
        matches!(self, RecordKind::OpenTab | RecordKind::ClosedTab)
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
        Self {
            domains: domains.into_iter().map(|d| d.to_lowercase()).collect(),
            all: false,
        }
    }
    pub fn allow_all() -> Self {
        Self {
            domains: Vec::new(),
            all: true,
        }
    }
    /// Whether the URL's host is covered by an allowed domain (eTLD+1 suffix).
    pub fn permits(&self, url: &str) -> bool {
        if self.all {
            return true;
        }
        let Some(host) = host_of(url) else {
            return false;
        };
        let host = host.to_lowercase();
        self.domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
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

/// The sectioned result of [`browsing_context`]. **State** (open/closed tabs) and
/// **history** (visits/searches) are deliberately separate: they come from
/// different artifacts (tab/session files vs the History DB) and obey different
/// rules — state is a current snapshot, history is a time window. Conflating them
/// would, e.g., drop a currently-open tab just because its window was last active
/// before the lookback window.
#[derive(Debug, Serialize, PartialEq, Default)]
pub struct BrowsingContext {
    /// Currently-open tabs — a snapshot, NOT time-filtered.
    pub open_tabs: Vec<ContextItem>,
    /// Recently-closed tabs — a snapshot, NOT time-filtered.
    pub recently_closed: Vec<ContextItem>,
    /// History visits within the lookback window (redirect-collapsed).
    pub recent_visits: Vec<ContextItem>,
    /// History searches within the lookback window.
    pub recent_searches: Vec<ContextItem>,
    /// How many otherwise-eligible records the allow-list withheld.
    pub omitted_by_policy_count: usize,
    /// Provenance for the state sections.
    pub state_basis: String,
    /// Provenance for the history sections.
    pub history_basis: String,
}

/// Assemble browsing context, **keeping state and history separate**. State
/// sections (open/recently-closed tabs) are a current snapshot and are NOT
/// time-filtered; history sections (visits/searches) are filtered to the last
/// `minutes` and redirect-collapsed. Every section is allow-list-gated, redacted,
/// newest-first, and capped to `cap`.
pub fn browsing_context(
    records: &[Record],
    now_ns: i64,
    minutes: u32,
    cap: usize,
    allow: &Allowlist,
) -> BrowsingContext {
    let window_ns = i64::from(minutes)
        .saturating_mul(60)
        .saturating_mul(1_000_000_000);
    let cutoff = now_ns.saturating_sub(window_ns);

    let mut out = BrowsingContext {
        state_basis: "session/tab files (current snapshot, not time-filtered)".to_string(),
        history_basis: "history.visits (last N minutes, redirect-collapsed)".to_string(),
        ..Default::default()
    };

    for r in records {
        // Eligibility: state is a snapshot (always eligible); history is filtered
        // to the lookback window, and visit redirect-hops are collapsed away.
        let eligible = if r.kind.is_state() {
            true
        } else if r.time_ns < cutoff {
            false
        } else {
            !(matches!(r.kind, RecordKind::Visit) && r.is_redirect && !r.chain_end)
        };
        if !eligible {
            continue;
        }
        if !allow.permits(&r.url) {
            out.omitted_by_policy_count += 1;
            continue;
        }
        let item = to_item(r);
        match r.kind {
            RecordKind::OpenTab => out.open_tabs.push(item),
            RecordKind::ClosedTab => out.recently_closed.push(item),
            RecordKind::Visit => out.recent_visits.push(item),
            RecordKind::Search => out.recent_searches.push(item),
        }
    }

    for section in [
        &mut out.open_tabs,
        &mut out.recently_closed,
        &mut out.recent_visits,
        &mut out.recent_searches,
    ] {
        section.sort_by_key(|i| std::cmp::Reverse(i.time_ns)); // newest first
        section.truncate(cap);
    }
    out
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
    items.sort_by_key(|i| std::cmp::Reverse(i.time_ns));
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

    fn tab(url: &str, kind: RecordKind, time_ns: i64) -> Record {
        Record {
            url: url.to_string(),
            title: "Tab".to_string(),
            kind,
            time_ns,
            browser: "Chromium".to_string(),
            source: "snss",
            is_redirect: false,
            chain_end: false,
        }
    }

    #[test]
    fn allowlist_matches_domain_and_subdomains_only() {
        let a = Allowlist::new(["github.com".to_string()]);
        assert!(a.permits("https://github.com/x"));
        assert!(a.permits("https://api.github.com/y"));
        assert!(
            !a.permits("https://evil.com/github.com"),
            "host is evil.com"
        );
        assert!(!a.permits("https://notgithub.com"));
        assert!(!Allowlist::new(std::iter::empty()).permits("https://github.com"));
        assert!(Allowlist::allow_all().permits("https://anything.example"));
    }

    #[test]
    fn browsing_context_history_section_windows_collapses_redacts_and_counts() {
        let now = 1_000_000_000_000_000_000_i64;
        let min_ns = 60_000_000_000_i64;
        let records = vec![
            rec(
                "https://github.com/a?token=X",
                "Repo a@b.com",
                now - min_ns,
                false,
                false,
            ),
            rec("https://github.com/hop", "Hop", now - min_ns, true, false), // redirect hop -> dropped
            rec("https://other.com/x", "Other", now - min_ns, false, false), // not allow-listed
            rec(
                "https://github.com/old",
                "Old",
                now - 100 * min_ns,
                false,
                false,
            ), // out of window
        ];
        let allow = Allowlist::new(["github.com".to_string()]);
        let r = browsing_context(&records, now, 5, 10, &allow);

        assert_eq!(
            r.recent_visits.len(),
            1,
            "only the in-window, allow-listed, non-redirect visit"
        );
        assert_eq!(
            r.recent_visits[0].url, "https://github.com/a",
            "query string stripped"
        );
        assert!(
            r.recent_visits[0].title.contains("[redacted-email]"),
            "email masked"
        );
        assert!(r.recent_visits[0].untrusted_evidence);
        assert_eq!(
            r.omitted_by_policy_count, 1,
            "other.com omitted by allow-list"
        );
        assert!(r.open_tabs.is_empty(), "no tabs in this input");
    }

    #[test]
    fn state_section_is_a_snapshot_not_time_filtered() {
        // The decisive separation test: an open tab whose window was last active
        // long BEFORE the lookback window must still appear (state != history).
        let now = 1_000_000_000_000_000_000_i64;
        let min_ns = 60_000_000_000_i64;
        let records = vec![
            tab(
                "https://open.example",
                RecordKind::OpenTab,
                now - 9999 * min_ns,
            ), // ancient
            tab(
                "https://closed.example",
                RecordKind::ClosedTab,
                now - 9999 * min_ns,
            ),
            rec(
                "https://visit.example",
                "v",
                now - 100 * min_ns,
                false,
                false,
            ), // old history -> dropped
            rec("https://recent.example", "v", now - min_ns, false, false), // in-window history
        ];
        let r = browsing_context(&records, now, 5, 10, &Allowlist::allow_all());

        assert_eq!(
            r.open_tabs.len(),
            1,
            "open tab kept despite ancient last-active"
        );
        assert_eq!(r.open_tabs[0].url, "https://open.example");
        assert_eq!(r.recently_closed.len(), 1, "closed tab kept (snapshot)");
        assert_eq!(r.recent_visits.len(), 1, "only the in-window visit");
        assert_eq!(r.recent_visits[0].url, "https://recent.example");
    }

    #[test]
    fn each_section_caps_and_orders_newest_first() {
        let now = 10_000_i64;
        let allow = Allowlist::allow_all();
        let mut records: Vec<Record> = (0..5)
            .map(|i| rec(&format!("https://v{i}.com/"), "t", i, false, false))
            .collect();
        records.extend((0..5).map(|i| tab(&format!("https://t{i}.com/"), RecordKind::OpenTab, i)));
        let r = browsing_context(&records, now, u32::MAX, 2, &allow);
        assert_eq!(r.recent_visits.len(), 2, "visits capped to 2");
        assert_eq!(r.open_tabs.len(), 2, "open tabs capped to 2");
        assert!(
            r.recent_visits[0].time_ns >= r.recent_visits[1].time_ns,
            "newest first"
        );
        assert!(
            r.open_tabs[0].time_ns >= r.open_tabs[1].time_ns,
            "newest first"
        );
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
        assert_eq!(
            miss.omitted_by_policy_count, 1,
            "matched but not allow-listed"
        );
    }
}
