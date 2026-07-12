//! Search-term extraction as an IOC class. Terms are read from URL query
//! parameters via browser-forensic-interpret's search_query (a fact, not an
//! inference); the engine name rides in the note.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::option_option)]

use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use browser_forensic_search::extract_iocs;
use browser_forensic_search::ioc::{extract_from_text, IocKind};
use serde_json::json;

fn find_search(text: &str) -> Option<(String, Option<String>)> {
    extract_from_text(text)
        .into_iter()
        .find(|(k, _, _, _)| *k == IocKind::SearchTerm)
        .map(|(_, v, _off, note)| (v, note))
}

#[test]
fn bare_google_url_yields_search_term() {
    let (term, note) =
        find_search("https://www.google.com/search?q=forensic+tools&hl=en").expect("search term");
    assert_eq!(term, "forensic tools");
    assert_eq!(note.as_deref(), Some("Google"));
}

#[test]
fn embedded_url_in_description_yields_search_term() {
    let (term, note) = find_search("user visited https://duckduckgo.com/?q=chain+of+custody today")
        .expect("search term");
    assert_eq!(term, "chain of custody");
    assert_eq!(note.as_deref(), Some("DuckDuckGo"));
}

#[test]
fn offset_points_at_embedded_url() {
    let text = "go https://www.bing.com/search?q=abc";
    let hit = extract_from_text(text)
        .into_iter()
        .find(|(k, _, _, _)| *k == IocKind::SearchTerm)
        .expect("search term");
    let (_, _, offset, _) = hit;
    assert_eq!(offset, 3);
}

#[test]
fn non_search_url_yields_no_term() {
    assert!(find_search("https://www.google.com/maps").is_none());
    assert!(find_search("https://example.com/about").is_none());
}

#[test]
fn aggregator_attributes_search_term_to_event_field() {
    let events = vec![BrowserEvent::new(
        1,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/History",
        "visited",
    )
    .with_attr(
        "url",
        json!("https://www.youtube.com/results?search_query=sqlite+carving"),
    )];
    let iocs = extract_iocs(&events);
    let term = iocs
        .iter()
        .find(|m| m.kind == IocKind::SearchTerm)
        .expect("search term match");
    assert_eq!(term.value, "sqlite carving");
    assert_eq!(term.field, "url");
    assert_eq!(term.event_index, 0);
    assert_eq!(term.note.as_deref(), Some("YouTube"));
}
