//! Known-bad domain matching against a user-supplied blocklist. Matching is
//! label-boundary aware: an entry matches a host or its subdomains, never a
//! lookalike (`notevil.com`) or a deeper-suffix (`evil.com.example.org`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use browser_forensic_search::{DomainHit, DomainMatcher};
use serde_json::json;

fn matcher(entries: &[&str]) -> DomainMatcher {
    let domains: Vec<String> = entries.iter().map(|s| (*s).to_string()).collect();
    DomainMatcher::new(&domains).expect("non-empty blocklist")
}

fn ev_url(idx: i64, url: &str) -> BrowserEvent {
    BrowserEvent::new(
        idx,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/History",
        "visited",
    )
    .with_attr("url", json!(url))
}

#[test]
fn parse_blocklist_skips_comments_and_blanks() {
    let text = "# comment\n\nevil.com\n  bad.example  \n#another\nEVIL.com\n";
    let list = DomainMatcher::parse_blocklist(text);
    // lowercased + deduped: evil.com, bad.example
    assert_eq!(
        list,
        vec!["evil.com".to_string(), "bad.example".to_string()]
    );
}

#[test]
fn parse_blocklist_strips_wildcard_prefix() {
    let list = DomainMatcher::parse_blocklist("*.evil.com\n.bad.net\n");
    assert_eq!(list, vec!["evil.com".to_string(), "bad.net".to_string()]);
}

#[test]
fn empty_blocklist_yields_no_matcher() {
    assert!(DomainMatcher::new(&[]).is_none());
    assert!(DomainMatcher::new(&DomainMatcher::parse_blocklist("# only comments\n")).is_none());
}

#[test]
fn matches_exact_host() {
    let m = matcher(&["evil.com"]);
    let events = vec![ev_url(1, "https://evil.com/path")];
    let hits: Vec<DomainHit> = m.match_events(&events);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].blocklisted_domain, "evil.com");
    assert_eq!(hits[0].host, "evil.com");
    assert_eq!(hits[0].field, "url");
    assert_eq!(hits[0].event_index, 0);
}

#[test]
fn matches_subdomain() {
    let m = matcher(&["evil.com"]);
    let events = vec![ev_url(1, "https://tracker.ads.evil.com/beacon")];
    let hits = m.match_events(&events);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].host, "tracker.ads.evil.com");
    assert_eq!(hits[0].blocklisted_domain, "evil.com");
}

#[test]
fn does_not_match_lookalike_prefix() {
    let m = matcher(&["evil.com"]);
    let events = vec![ev_url(1, "https://notevil.com/")];
    assert!(m.match_events(&events).is_empty());
}

#[test]
fn does_not_match_deeper_suffix() {
    let m = matcher(&["evil.com"]);
    let events = vec![ev_url(1, "https://evil.com.example.org/")];
    assert!(m.match_events(&events).is_empty());
}

#[test]
fn matches_bare_host_field() {
    let m = matcher(&["evil.com"]);
    let events = vec![BrowserEvent::new(
        1,
        BrowserFamily::Chromium,
        ArtifactKind::Cookies,
        "/Cookies",
        "cookie",
    )
    .with_attr("host", json!("mail.evil.com"))];
    let hits = m.match_events(&events);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].host, "mail.evil.com");
    assert_eq!(hits[0].field, "host");
}

#[test]
fn matches_multiple_blocklist_entries() {
    let m = matcher(&["evil.com", "malware.test"]);
    let events = vec![
        ev_url(1, "https://a.evil.com/"),
        ev_url(2, "https://malware.test/drop"),
        ev_url(3, "https://good.example/"),
    ];
    let hits = m.match_events(&events);
    assert_eq!(hits.len(), 2);
}
