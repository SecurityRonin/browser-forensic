#![no_main]
//! Fuzz the search/IOC analysis layer over arbitrary text. Exercises every
//! byte-level extractor (base58 decode + double-SHA256, bech32 checksum, IPv4/
//! IPv6 parse, Luhn, search-term URL parsing), the substring/regex filter, and
//! the blocklist parser + Aho-Corasick matcher. Invariant: must never panic.
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use browser_forensic_search::ioc::extract_from_text;
use browser_forensic_search::{extract_iocs, filter_events, DomainMatcher, EventQuery, Pattern};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();

    // Raw per-text extraction must not panic on any input.
    let _ = extract_from_text(&text);

    // Wrap the input into an event and run the whole event pipeline.
    let event = BrowserEvent::new(
        0,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "fuzz",
        text.clone(),
    )
    .with_attr("url", serde_json::Value::String(text.clone()))
    .with_attr("host", serde_json::Value::String(text.clone()));
    let events = [event];

    let _ = extract_iocs(&events);

    let query = EventQuery {
        pattern: Some(Pattern::substring("a")),
        ..Default::default()
    };
    let _ = filter_events(&events, &query);

    // The blocklist parser + matcher over the same arbitrary text.
    let domains = DomainMatcher::parse_blocklist(&text);
    if let Some(matcher) = DomainMatcher::new(&domains) {
        let _ = matcher.match_events(&events);
    }
});
