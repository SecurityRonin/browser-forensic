//! Per-host (registrable-domain) rollup across artifact kinds.
//!
//! Answers "everything we know about host X in one place": for each registrable
//! domain, how many events of each artifact kind reference it, when it was first
//! and last seen, and which browsers touched it. Each event is attributed to its
//! own primary host (the registrable domain of its `url`/`origin`/… field), so a
//! single event counts once.

use std::collections::{BTreeMap, BTreeSet};

use browser_forensic_core::BrowserEvent;
use serde::Serialize;

use crate::host::primary_registrable_domain;

/// Aggregated cross-artifact view of one registrable host.
#[derive(Debug, Clone, Serialize)]
pub struct HostRollup {
    /// The registrable domain (eTLD+1) this rollup is keyed on.
    pub host: String,
    /// Total events attributed to this host.
    pub total: usize,
    /// Event count per artifact kind (kind name -> count), ordered by kind name.
    pub counts: BTreeMap<String, usize>,
    /// Earliest non-zero timestamp seen for this host, if any.
    pub first_seen_ns: Option<i64>,
    /// Latest non-zero timestamp seen for this host, if any.
    pub last_seen_ns: Option<i64>,
    /// Browser families that referenced this host.
    pub browsers: BTreeSet<String>,
}

/// Build per-host rollups over `events`.
///
/// Events with no derivable primary host are skipped. Output is sorted by total
/// descending, then host ascending (deterministic).
#[must_use]
pub fn host_rollups(events: &[BrowserEvent]) -> Vec<HostRollup> {
    let mut by_host: BTreeMap<String, HostRollup> = BTreeMap::new();

    for event in events {
        let Some(host) = primary_registrable_domain(event) else {
            continue;
        };
        let entry = by_host.entry(host.clone()).or_insert_with(|| HostRollup {
            host,
            total: 0,
            counts: BTreeMap::new(),
            first_seen_ns: None,
            last_seen_ns: None,
            browsers: BTreeSet::new(),
        });
        entry.total += 1;
        *entry.counts.entry(event.artifact.to_string()).or_insert(0) += 1;
        entry.browsers.insert(event.browser.to_string());
        if event.timestamp_ns != 0 {
            entry.first_seen_ns = Some(match entry.first_seen_ns {
                Some(cur) => cur.min(event.timestamp_ns),
                None => event.timestamp_ns,
            });
            entry.last_seen_ns = Some(match entry.last_seen_ns {
                Some(cur) => cur.max(event.timestamp_ns),
                None => event.timestamp_ns,
            });
        }
    }

    let mut out: Vec<HostRollup> = by_host.into_values().collect();
    out.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.host.cmp(&b.host)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;

    fn ev(ts: i64, browser: BrowserFamily, kind: ArtifactKind, url: &str) -> BrowserEvent {
        BrowserEvent::new(ts, browser, kind, "/src", "desc").with_attr("url", json!(url))
    }

    #[test]
    fn aggregates_counts_per_kind_for_a_host() {
        let events = vec![
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://www.example.com/a",
            ),
            ev(
                2000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://example.com/b",
            ),
            ev(
                3000,
                BrowserFamily::Chromium,
                ArtifactKind::Cookies,
                "https://cdn.example.com/",
            ),
        ];
        let rollups = host_rollups(&events);
        assert_eq!(rollups.len(), 1);
        let r = &rollups[0];
        assert_eq!(r.host, "example.com");
        assert_eq!(r.total, 3);
        assert_eq!(r.counts.get("History"), Some(&2));
        assert_eq!(r.counts.get("Cookies"), Some(&1));
    }

    #[test]
    fn records_first_last_seen_and_browsers() {
        let events = vec![
            ev(
                3000,
                BrowserFamily::Firefox,
                ArtifactKind::Cache,
                "https://x.example.com/",
            ),
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://example.com/",
            ),
            ev(
                2000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://example.com/",
            ),
        ];
        let rollups = host_rollups(&events);
        let r = &rollups[0];
        assert_eq!(r.first_seen_ns, Some(1000));
        assert_eq!(r.last_seen_ns, Some(3000));
        assert!(r.browsers.contains("Chromium"));
        assert!(r.browsers.contains("Firefox"));
        assert_eq!(r.browsers.len(), 2);
    }

    #[test]
    fn untimed_only_host_has_no_first_last_but_is_counted() {
        let events = vec![ev(
            0,
            BrowserFamily::Chromium,
            ArtifactKind::TopSite,
            "https://top.example.com/",
        )];
        let rollups = host_rollups(&events);
        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].total, 1);
        assert_eq!(rollups[0].first_seen_ns, None);
        assert_eq!(rollups[0].last_seen_ns, None);
    }

    #[test]
    fn event_without_host_is_skipped() {
        let e = BrowserEvent::new(
            1000,
            BrowserFamily::Chromium,
            ArtifactKind::Integrity,
            "/src",
            "no host",
        );
        assert!(host_rollups(&[e]).is_empty());
    }

    #[test]
    fn sorted_by_total_desc_then_host() {
        let events = vec![
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://rare.example/",
            ),
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://busy.example/",
            ),
            ev(
                2000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://busy.example/x",
            ),
        ];
        let rollups = host_rollups(&events);
        assert_eq!(rollups[0].host, "busy.example");
        assert_eq!(rollups[0].total, 2);
        assert_eq!(rollups[1].host, "rare.example");
    }
}
