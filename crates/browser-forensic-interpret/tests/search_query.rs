//! Behavioural tests for [`search_query`] — multi-engine search-term extraction
//! from URL parameters. Each expected term is the percent-decoded value of the
//! documented query parameter for that provider (facts read from the URL, not
//! inferences).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_interpret::{search_query, SearchQuery};

fn q(url: &str) -> SearchQuery {
    search_query(url).unwrap_or_else(|| panic!("expected a search query for {url}"))
}

#[test]
fn google_q_param() {
    let r = q("https://www.google.com/search?q=forensic+tools&hl=en");
    assert_eq!(r.engine, "Google");
    assert_eq!(r.term, "forensic tools");
}

#[test]
fn bing_q_param() {
    let r = q("https://www.bing.com/search?q=incident+response");
    assert_eq!(r.engine, "Bing");
    assert_eq!(r.term, "incident response");
}

#[test]
fn duckduckgo_q_param() {
    let r = q("https://duckduckgo.com/?q=chain+of+custody&ia=web");
    assert_eq!(r.engine, "DuckDuckGo");
    assert_eq!(r.term, "chain of custody");
}

#[test]
fn youtube_search_query_param() {
    let r = q("https://www.youtube.com/results?search_query=sqlite+carving");
    assert_eq!(r.engine, "YouTube");
    assert_eq!(r.term, "sqlite carving");
}

#[test]
fn amazon_k_param() {
    let r = q("https://www.amazon.com/s?k=faraday+bag&ref=nb");
    assert_eq!(r.engine, "Amazon");
    assert_eq!(r.term, "faraday bag");
}

#[test]
fn amazon_field_keywords_param() {
    let r = q("https://www.amazon.co.uk/s?field-keywords=write+blocker");
    assert_eq!(r.engine, "Amazon");
    assert_eq!(r.term, "write blocker");
}

#[test]
fn generic_query_param_unknown_host() {
    let r = q("https://search.example.org/?query=hello+world");
    assert_eq!(r.engine, "Generic");
    assert_eq!(r.term, "hello world");
}

#[test]
fn generic_p_param_unknown_host() {
    let r = q("https://search.yahoo.com/search?p=timeline+analysis");
    assert_eq!(r.engine, "Generic");
    assert_eq!(r.term, "timeline analysis");
}

#[test]
fn percent_encoded_term_is_decoded() {
    let r = q("https://www.google.com/search?q=caf%C3%A9%20noir");
    assert_eq!(r.term, "café noir");
}

#[test]
fn no_search_param_returns_none() {
    assert!(search_query("https://www.google.com/maps").is_none());
    assert!(search_query("https://example.com/about").is_none());
}

#[test]
fn empty_term_returns_none() {
    assert!(search_query("https://www.google.com/search?q=").is_none());
}

#[test]
fn non_url_returns_none() {
    assert!(search_query("not a url").is_none());
}
