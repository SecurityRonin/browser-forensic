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
        let _ = domains;
        // GREEN cycle builds the automaton here.
        None
    }

    /// Find every blocklist hit across `events`, in `(event, field)` order.
    #[must_use]
    pub fn match_events(&self, events: &[BrowserEvent]) -> Vec<DomainHit> {
        // GREEN cycle replaces this stub.
        let _ = (events, &self.domains, &self.automaton);
        Vec::new()
    }
}
