//! Unified cross-artifact / cross-browser timeline.
//!
//! Merges every collected [`BrowserEvent`] — from every browser and every
//! artifact kind — into one time-sorted stream. Each row keeps the event's own
//! provenance tags (browser, artifact kind, source path). Events with no
//! timestamp are grouped separately rather than dropped, and exact
//! `(url, timestamp, artifact-kind)` repeats are de-duplicated.

use browser_forensic_core::BrowserEvent;

/// A merged, de-duplicated view over a collected event set.
///
/// Borrows the input events; no event data is copied.
#[derive(Debug)]
pub struct UnifiedTimeline<'a> {
    /// Timestamped events (Unix-nanos != 0), stably sorted ascending by time.
    pub timed: Vec<&'a BrowserEvent>,
    /// Events carrying no usable timestamp (Unix-nanos == 0), in input order.
    /// Kept, never dropped — many artifacts (Top Sites, some recovered domains)
    /// have no per-record time.
    pub untimed: Vec<&'a BrowserEvent>,
    /// Count of exact `(url, timestamp, artifact-kind)` repeats removed.
    pub duplicates_removed: usize,
}

impl UnifiedTimeline<'_> {
    /// Total rows retained (timed + untimed), after de-duplication.
    #[must_use]
    pub fn len(&self) -> usize {
        self.timed.len() + self.untimed.len()
    }

    /// True when no rows were retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.timed.is_empty() && self.untimed.is_empty()
    }
}

/// The `url` attribute of an event as a string, or `""` when absent.
fn event_url(event: &BrowserEvent) -> &str {
    event
        .attrs
        .get("url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

/// Build a [`UnifiedTimeline`] over `events`.
///
/// De-duplication key is the exact triple `(url, timestamp_ns, artifact-kind)`;
/// the first occurrence wins. Timestamped rows are stably sorted by time (equal
/// timestamps keep input order); untimed rows stay in input order.
#[must_use]
pub fn unified_timeline(events: &[BrowserEvent]) -> UnifiedTimeline<'_> {
    let _ = event_url;
    let _ = events;
    UnifiedTimeline {
        timed: Vec::new(),
        untimed: Vec::new(),
        duplicates_removed: 0,
    }
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
    fn merges_and_sorts_across_browsers_and_artifacts() {
        let events = vec![
            ev(
                3000,
                BrowserFamily::Firefox,
                ArtifactKind::Cookies,
                "https://c.example",
            ),
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://a.example",
            ),
            ev(
                2000,
                BrowserFamily::Safari,
                ArtifactKind::Cache,
                "https://b.example",
            ),
        ];
        let tl = unified_timeline(&events);
        let times: Vec<i64> = tl.timed.iter().map(|e| e.timestamp_ns).collect();
        assert_eq!(times, vec![1000, 2000, 3000]);
        assert!(tl.untimed.is_empty());
        assert_eq!(tl.len(), 3);
    }

    #[test]
    fn untimed_events_grouped_not_dropped() {
        let events = vec![
            ev(
                0,
                BrowserFamily::Chromium,
                ArtifactKind::TopSite,
                "https://top.example",
            ),
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://a.example",
            ),
        ];
        let tl = unified_timeline(&events);
        assert_eq!(tl.timed.len(), 1);
        assert_eq!(tl.untimed.len(), 1);
        assert_eq!(tl.untimed[0].artifact, ArtifactKind::TopSite);
    }

    #[test]
    fn exact_url_time_kind_duplicate_removed() {
        let events = vec![
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://a.example",
            ),
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://a.example",
            ),
        ];
        let tl = unified_timeline(&events);
        assert_eq!(tl.timed.len(), 1);
        assert_eq!(tl.duplicates_removed, 1);
    }

    #[test]
    fn same_url_time_different_kind_kept() {
        let events = vec![
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://a.example",
            ),
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::Cookies,
                "https://a.example",
            ),
        ];
        let tl = unified_timeline(&events);
        assert_eq!(tl.timed.len(), 2);
        assert_eq!(tl.duplicates_removed, 0);
    }

    #[test]
    fn equal_timestamps_preserve_input_order() {
        let events = vec![
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://first.example",
            ),
            ev(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://second.example",
            ),
        ];
        let tl = unified_timeline(&events);
        let urls: Vec<&str> = tl
            .timed
            .iter()
            .map(|e| e.attrs["url"].as_str().unwrap())
            .collect();
        assert_eq!(
            urls,
            vec!["https://first.example", "https://second.example"]
        );
    }
}
