#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Humble-Object extraction: the `BROWSING_STATE_ALLOWLIST` parsing decision used
//! to live inline in `main::load_allowlist`. `main` now only reads the env var and
//! hands the raw value to this pure parser, so the policy logic is unit-testable
//! and `main` is an irreducible stdio shell.

use browser_forensic_mcp::context::parse_allowlist;

#[test]
fn unset_permits_nothing() {
    let allow = parse_allowlist(None);
    assert!(
        !allow.permits("https://github.com/"),
        "unset is the secure default — nothing exposed"
    );
}

#[test]
fn star_permits_everything() {
    let allow = parse_allowlist(Some("*"));
    assert!(allow.permits("https://anything.example/"));
}

#[test]
fn star_with_surrounding_whitespace_still_permits_all() {
    let allow = parse_allowlist(Some("  *  "));
    assert!(allow.permits("https://anything.example/"));
}

#[test]
fn comma_list_permits_only_listed_domains() {
    let allow = parse_allowlist(Some("github.com, example.org"));
    assert!(allow.permits("https://github.com/x"));
    assert!(allow.permits("https://example.org/y"));
    assert!(!allow.permits("https://evil.test/z"));
}

#[test]
fn empty_string_permits_nothing() {
    let allow = parse_allowlist(Some(""));
    assert!(!allow.permits("https://github.com/"));
}

#[test]
fn blank_entries_are_dropped() {
    // Trailing comma / stray spaces must not become an empty (match-all) domain.
    let allow = parse_allowlist(Some("github.com, ,"));
    assert!(allow.permits("https://github.com/"));
    assert!(!allow.permits("https://other.test/"));
}
