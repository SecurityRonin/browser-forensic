//! Behavioural tests for the event search/filter engine: substring, linear-time
//! regex, field scoping, and the inclusive timestamp window.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use browser_forensic_search::{filter_events, EventQuery, Pattern};
use serde_json::json;

fn ev(ts: i64, url: &str, title: &str) -> BrowserEvent {
    BrowserEvent::new(
        ts,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/path/History",
        format!("visited {url}"),
    )
    .with_attr("url", json!(url))
    .with_attr("title", json!(title))
}

fn corpus() -> Vec<BrowserEvent> {
    vec![
        ev(1_000, "https://example.com/login", "Example Login"),
        ev(2_000, "https://malware.test/drop", "Free Prize"),
        ev(3_000, "https://news.example.org/story", "Breaking News"),
    ]
}

#[test]
fn substring_matches_url() {
    let events = corpus();
    let q = EventQuery {
        pattern: Some(Pattern::substring("malware")),
        ..Default::default()
    };
    let hits = filter_events(&events, &q);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].timestamp_ns, 2_000);
}

#[test]
fn substring_matches_title_field() {
    let events = corpus();
    let q = EventQuery {
        pattern: Some(Pattern::substring("Prize")),
        ..Default::default()
    };
    let hits = filter_events(&events, &q);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].timestamp_ns, 2_000);
}

#[test]
fn regex_matches_across_events() {
    let events = corpus();
    let q = EventQuery {
        pattern: Some(Pattern::regex(r"example\.(com|org)").unwrap()),
        ..Default::default()
    };
    let hits = filter_events(&events, &q);
    // example.com (ts 1000) and news.example.org (ts 3000)
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].timestamp_ns, 1_000);
    assert_eq!(hits[1].timestamp_ns, 3_000);
}

#[test]
fn field_scope_restricts_to_named_field() {
    let events = corpus();
    // "example" appears in the URL of two events, but "Example" (capital) only
    // in the first event's title. Scope to title only.
    let q = EventQuery {
        pattern: Some(Pattern::substring("Example")),
        fields: vec!["title".to_string()],
        ..Default::default()
    };
    let hits = filter_events(&events, &q);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].timestamp_ns, 1_000);
}

#[test]
fn field_scope_url_only_ignores_title_match() {
    let events = corpus();
    let q = EventQuery {
        pattern: Some(Pattern::substring("Prize")),
        fields: vec!["url".to_string()],
        ..Default::default()
    };
    // "Prize" is only in a title, so scoping to url yields nothing.
    assert!(filter_events(&events, &q).is_empty());
}

#[test]
fn time_range_from_to_inclusive() {
    let events = corpus();
    let q = EventQuery {
        pattern: None,
        from_ns: Some(2_000),
        to_ns: Some(3_000),
        ..Default::default()
    };
    let hits = filter_events(&events, &q);
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].timestamp_ns, 2_000);
    assert_eq!(hits[1].timestamp_ns, 3_000);
}

#[test]
fn time_range_and_pattern_combine() {
    let events = corpus();
    let q = EventQuery {
        pattern: Some(Pattern::substring("example")),
        from_ns: Some(2_500),
        ..Default::default()
    };
    // "example" is in ts 1000 and 3000 URLs, but from=2500 excludes 1000.
    let hits = filter_events(&events, &q);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].timestamp_ns, 3_000);
}

#[test]
fn no_pattern_no_range_returns_all() {
    let events = corpus();
    let q = EventQuery::default();
    assert_eq!(filter_events(&events, &q).len(), 3);
}

#[test]
fn oversized_field_is_bounded_not_panicking() {
    // A value far larger than MAX_FIELD_LEN must be handled without panic, and
    // a token past the cap is not matched.
    let big = "a".repeat((1 << 20) + 100) + "NEEDLE";
    let events = vec![ev(1, &format!("https://x/{big}"), "t")];
    let q = EventQuery {
        pattern: Some(Pattern::substring("NEEDLE")),
        ..Default::default()
    };
    // Must not panic; the needle is beyond the 1 MiB cap so it is not found.
    assert!(filter_events(&events, &q).is_empty());
}
