//! Known-bad domain matching against a user-supplied blocklist.
//!
//! There is **no bundled threat intelligence**: the caller supplies the list of
//! domains/hosts to flag. Matching is label-boundary aware — a blocklist entry
//! `evil.com` matches the host `evil.com` and any subdomain `x.evil.com`, but
//! never `notevil.com` or `evil.com.example.org`. A fast Aho-Corasick automaton
//! finds candidate entries across every event's hosts; the label boundary is
//! then confirmed so substrings cannot false-positive.

use aho_corasick::AhoCorasick;
use browser_forensic_core::BrowserEvent;
use serde::Serialize;

use crate::filter::{bound, text_fields};

/// A blocklist domain found on an event's host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainHit {
    /// The blocklist entry that matched.
    pub blocklisted_domain: String,
    /// The host it matched against (from a URL or a bare host/domain field).
    pub host: String,
    /// Index of the source event.
    pub event_index: usize,
    /// The field the host came from (`url`, `origin`, `host`, `domain`, …).
    pub field: String,
}

/// A compiled matcher over a fixed blocklist.
pub struct DomainMatcher {
    domains: Vec<String>,
    automaton: AhoCorasick,
}

impl DomainMatcher {
    /// Parse a blocklist file's contents into a normalized domain list: one
    /// host per line, `#` comments and blank lines skipped, lowercased, a
    /// leading `*.`/`.` stripped, deduplicated.
    #[must_use]
    pub fn parse_blocklist(text: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let host = line
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .to_ascii_lowercase();
            if !host.is_empty() && !out.contains(&host) {
                out.push(host);
            }
        }
        out
    }

    /// Build a matcher from a normalized domain list. Returns `None` when the
    /// list is empty (nothing to match).
    #[must_use]
    pub fn new(domains: &[String]) -> Option<Self> {
        if domains.is_empty() {
            return None;
        }
        // Standard match kind so overlapping iteration is available: every
        // blocklist entry occurring in a host is reported, then filtered to
        // label-boundary suffix matches below.
        let automaton = AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(domains)
            .ok()?;
        Some(Self {
            domains: domains.to_vec(),
            automaton,
        })
    }

    /// Find every blocklist hit across `events`, in `(event, field)` order.
    #[must_use]
    pub fn match_events(&self, events: &[BrowserEvent]) -> Vec<DomainHit> {
        let mut hits = Vec::new();
        for (event_index, event) in events.iter().enumerate() {
            for (field, host) in event_hosts(event) {
                for entry in self.blocklist_hits(&host) {
                    hits.push(DomainHit {
                        blocklisted_domain: entry,
                        host: host.clone(),
                        event_index,
                        field: field.to_string(),
                    });
                }
            }
        }
        hits
    }

    /// Blocklist entries that match `host` at a label boundary: the entry must
    /// be a suffix of `host` ending at its end, and either equal `host` or be
    /// preceded by a `.` (so `evil.com` matches `evil.com` and `x.evil.com`,
    /// but not `notevil.com` or `evil.com.example.org`).
    fn blocklist_hits(&self, host: &str) -> Vec<String> {
        let bytes = host.as_bytes();
        let mut out = Vec::new();
        for m in self.automaton.find_overlapping_iter(host) {
            let (start, end) = (m.start(), m.end());
            let at_end = end == host.len();
            let at_label = start == 0 || bytes.get(start - 1) == Some(&b'.');
            if at_end && at_label {
                if let Some(entry) = self.domains.get(m.pattern().as_usize()) {
                    if !out.contains(entry) {
                        out.push(entry.clone());
                    }
                }
            }
        }
        out
    }
}

/// Attribute names whose value is a bare host (not a full URL).
const BARE_HOST_FIELDS: &[&str] = &["host", "domain", "report_to_host"];

/// Collect `(field, lowercased host)` pairs from an event: the host of every
/// URL found in any text field, plus the raw value of bare-host fields.
fn event_hosts(event: &BrowserEvent) -> Vec<(&str, String)> {
    let mut out: Vec<(&str, String)> = Vec::new();
    for (field, text) in text_fields(event) {
        let text = bound(text);
        if BARE_HOST_FIELDS.contains(&field) && !text.contains("://") {
            let host = text.trim().to_ascii_lowercase();
            if !host.is_empty() {
                out.push((field, host));
            }
            continue;
        }
        let mut finder = linkify::LinkFinder::new();
        finder.kinds(&[linkify::LinkKind::Url]);
        for link in finder.links(text) {
            if let Ok(url) = url::Url::parse(link.as_str()) {
                if let Some(host) = url.host_str() {
                    out.push((field, host.to_ascii_lowercase()));
                }
            }
        }
    }
    out
}
