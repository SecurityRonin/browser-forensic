#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tier-1/2 validation against a REAL Firefox profile, env-gated so CI and
//! other machines skip cleanly when no profile is present (fleet Test-Data
//! Provenance Standard). Point `BR4N6_FIREFOX_PROFILE` at a profile directory
//! that holds a real `places.sqlite` (and, ideally, `bookmarkbackups/`):
//!
//! ```sh
//! BR4N6_FIREFOX_PROFILE=/path/to/profile cargo test -p browser-forensic-firefox \
//!     --test real_profile_gated -- --nocapture
//! ```
//!
//! These assert *structural invariants* over whatever the real profile holds,
//! not hard-coded counts, so the test is portable across profiles. The point is
//! that the M17 parsers run on real Mozilla-written artifacts without erroring
//! and produce well-formed events.

use std::path::PathBuf;

fn profile() -> Option<PathBuf> {
    std::env::var_os("BR4N6_FIREFOX_PROFILE").map(PathBuf::from)
}

#[test]
fn typed_input_on_real_profile_is_well_formed() {
    let Some(dir) = profile() else {
        eprintln!("skipping: BR4N6_FIREFOX_PROFILE not set");
        return;
    };
    let places = dir.join("places.sqlite");
    let events = browser_forensic_firefox::parse_typed_input(&places)
        .expect("parse_typed_input on a real places.sqlite");
    eprintln!("typed-input events: {}", events.len());
    for ev in &events {
        assert!(ev.attrs.get("input").and_then(|v| v.as_str()).is_some());
        assert!(ev.attrs.get("url").and_then(|v| v.as_str()).is_some());
        assert!(ev
            .attrs
            .get("use_count")
            .and_then(serde_json::Value::as_f64)
            .is_some());
    }
}

#[test]
fn annotations_on_real_profile_do_not_error() {
    let Some(dir) = profile() else {
        eprintln!("skipping: BR4N6_FIREFOX_PROFILE not set");
        return;
    };
    let places = dir.join("places.sqlite");
    let events = browser_forensic_firefox::parse_annotations(&places)
        .expect("parse_annotations on a real places.sqlite");
    eprintln!("annotation events: {}", events.len());
    for ev in &events {
        assert!(ev.attrs.get("name").and_then(|v| v.as_str()).is_some());
        assert!(ev.attrs.contains_key("content"));
    }
}

#[test]
fn deleted_bookmarks_on_real_profile_are_consistent() {
    let Some(dir) = profile() else {
        eprintln!("skipping: BR4N6_FIREFOX_PROFILE not set");
        return;
    };
    let events = browser_forensic_firefox::recover_deleted_bookmarks(&dir)
        .expect("recover_deleted_bookmarks on a real profile");
    eprintln!("recovered deleted bookmarks: {}", events.len());
    for ev in &events {
        // Each recovered entry must name its source backup and the absence.
        assert!(ev
            .attrs
            .get("source_backup")
            .and_then(|v| v.as_str())
            .is_some());
        assert_eq!(
            ev.attrs.get("status").and_then(|v| v.as_str()),
            Some("absent from current bookmarks")
        );
        // A recovered URL must genuinely be absent from the current bookmarks.
        let url = ev.attrs.get("url").and_then(|v| v.as_str()).unwrap();
        let current = browser_forensic_firefox::parse_bookmarks(&dir.join("places.sqlite"))
            .expect("parse current bookmarks");
        let present = current
            .iter()
            .any(|c| c.attrs.get("url").and_then(|v| v.as_str()) == Some(url));
        assert!(!present, "recovered URL {url} is actually still present");
    }
}
