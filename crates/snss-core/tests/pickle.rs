//! Milestone 2 — Pickle decode of UpdateTabNavigation payloads.
//!
//! Two layers of validation:
//!   * **Synthetic golden** (committed, no personal data) pins the exact field
//!     decoding and 4-byte alignment for known inputs.
//!   * **Real-bytes structural** (gitignored fixtures) proves the decoder handles
//!     what Chromium actually wrote — the design's "zero parse failures" claim —
//!     without embedding any personal URL/title in the repo.

use snss::{decode_navigation, NavCommand, PickleError};

mod common;
use common::build::nav as encode_nav;
use common::open_fixture_or_skip;

#[test]
fn decodes_synthetic_navigation_with_padding() {
    // url len 21 (pad 3); title 5 units = 10 bytes (pad 2): exercises both pads.
    let payload = encode_nav(1885529531, 2, "https://example.com/x", "Hello");
    let nav = decode_navigation(&payload).expect("clean decode");
    assert_eq!(
        nav,
        NavCommand {
            tab_id: 1885529531,
            index: 2,
            url: "https://example.com/x".to_string(),
            title: "Hello".to_string(),
        }
    );
}

#[test]
fn decodes_multibyte_title() {
    // '✓' is one UTF-16 code unit; an emoji is a surrogate pair (two units).
    let payload = encode_nav(7, 0, "https://ok", "ok ✓ 🚀");
    let nav = decode_navigation(&payload).expect("clean decode");
    assert_eq!(nav.title, "ok ✓ 🚀");
    assert_eq!(nav.url, "https://ok");
}

#[test]
fn too_short_payload_errors_without_panicking() {
    assert_eq!(decode_navigation(&[0, 1, 2]), Err(PickleError::TooShort));
}

#[test]
fn truncated_field_errors_without_panicking() {
    // Valid header + tab_id + index, then a url length that overruns the buffer.
    let mut p = Vec::new();
    let body: Vec<u8> = [
        &1i32.to_le_bytes()[..],     // tab_id
        &0i32.to_le_bytes()[..],     // index
        &999i32.to_le_bytes()[..],   // url_len far beyond what's present
    ]
    .concat();
    p.extend_from_slice(&(body.len() as u32).to_le_bytes());
    p.extend_from_slice(&body);
    assert!(matches!(decode_navigation(&p), Err(PickleError::Overrun)));
}

/// The headline claim: every navigation record in the real files decodes with
/// zero parse failures, and the counts match the histogram nav totals.
#[test]
fn tabs_navigation_decodes_with_zero_failures() {
    let Some(stream) = open_fixture_or_skip("Tabs_real") else { return };
    let navs: Vec<Result<NavCommand, PickleError>> =
        stream.records.iter().filter(|r| r.id == 1).map(|r| decode_navigation(&r.payload)).collect();

    assert_eq!(navs.len(), 51, "nav-command count (cmd 1)");
    assert!(navs.iter().all(|r| r.is_ok()), "zero parse failures: {:?}",
        navs.iter().filter(|r| r.is_err()).collect::<Vec<_>>());

    let ok: Vec<NavCommand> = navs.into_iter().map(Result::unwrap).collect();
    assert!(ok.iter().any(|n| n.url.starts_with("https://")), "real https URLs present");
    assert!(ok.iter().all(|n| !n.url.is_empty()), "every nav has a URL");
}

#[test]
fn session_navigation_decodes_with_zero_failures() {
    let Some(stream) = open_fixture_or_skip("Session_real") else { return };
    let nav_count = stream.records.iter().filter(|r| r.id == 6).count();
    assert_eq!(nav_count, 1826, "nav-command count (cmd 6)");

    let failures: Vec<PickleError> = stream
        .records
        .iter()
        .filter(|r| r.id == 6)
        .filter_map(|r| decode_navigation(&r.payload).err())
        .collect();
    assert!(failures.is_empty(), "zero parse failures, got: {failures:?}");
}

/// The Apps dialect uses the same Session-style cmd 6 navigation encoding.
#[test]
fn apps_navigation_decodes_with_zero_failures() {
    let Some(stream) = open_fixture_or_skip("Apps_real") else { return };
    let failures: Vec<PickleError> = stream
        .records
        .iter()
        .filter(|r| r.id == 6)
        .filter_map(|r| decode_navigation(&r.payload).err())
        .collect();
    assert!(failures.is_empty(), "zero parse failures, got: {failures:?}");
}
