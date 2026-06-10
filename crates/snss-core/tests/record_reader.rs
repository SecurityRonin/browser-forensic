#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Milestone 1 — record-reader validation against **real, copied** Brave files.
//!
//! The expected command histograms below were derived by an independent decoder
//! (a standalone Python framing reader), not by the code under test, so a shared
//! bug cannot make a wrong parser look correct (Doer-Checker).

use std::collections::BTreeMap;

use snss::{read_records, RecordStream, SUPPORTED_VERSION};

mod common;
use common::open_fixture_or_skip;

fn histogram(stream: &RecordStream) -> BTreeMap<u8, usize> {
    let mut h = BTreeMap::new();
    for r in &stream.records {
        *h.entry(r.id).or_insert(0) += 1;
    }
    h
}

/// Verified `Session_*` dialect: 14,569 commands, navigation cmd 6 = 1826.
#[test]
fn session_histogram_matches_ground_truth() {
    let Some(stream) = open_fixture_or_skip("Session_real") else {
        return;
    };
    assert_eq!(stream.version, SUPPORTED_VERSION);
    assert_eq!(stream.records.len(), 14_569, "total command count");
    assert!(
        stream.warnings.is_empty(),
        "clean file, no truncation: {:?}",
        stream.warnings
    );

    let h = histogram(&stream);
    let expected: &[(u8, usize)] = &[
        (0, 1619),
        (2, 3161),
        (6, 1826),
        (7, 1619),
        (8, 2),
        (9, 1),
        (12, 1545),
        (13, 9),
        (14, 1),
        (19, 1619),
        (21, 1620),
        (23, 2),
        (25, 1542),
        (32, 2),
        (255, 1),
    ];
    assert_eq!(h, expected.iter().copied().collect());
}

/// Verified `Tabs_*` dialect (recently-closed): 132 commands, navigation cmd 1 = 51.
#[test]
fn tabs_histogram_matches_ground_truth() {
    let Some(stream) = open_fixture_or_skip("Tabs_real") else {
        return;
    };
    assert_eq!(stream.records.len(), 132);
    assert!(stream.warnings.is_empty());

    let h = histogram(&stream);
    let expected: &[(u8, usize)] = &[(1, 51), (2, 41), (4, 35), (5, 2), (9, 2), (255, 1)];
    assert_eq!(h, expected.iter().copied().collect());
}

/// Verified `Apps_*` dialect (PWA windows): 27 commands, Session-style nav cmd 6 = 4.
#[test]
fn apps_histogram_matches_ground_truth() {
    let Some(stream) = open_fixture_or_skip("Apps_real") else {
        return;
    };
    assert_eq!(stream.records.len(), 27);
    assert!(stream.warnings.is_empty());

    let h = histogram(&stream);
    let expected: &[(u8, usize)] = &[
        (0, 1),
        (6, 4),
        (7, 5),
        (8, 2),
        (9, 1),
        (12, 1),
        (14, 1),
        (15, 1),
        (16, 1),
        (17, 1),
        (19, 1),
        (20, 1),
        (21, 1),
        (23, 3),
        (32, 2),
        (255, 1),
    ];
    assert_eq!(h, expected.iter().copied().collect());
}

/// Only the trailing cmd-255 sentinel (`size == 1`, id with no payload) is empty;
/// every navigation record carries a non-empty Pickle payload. A framing check
/// independent of the histogram.
#[test]
fn only_the_sentinel_has_an_empty_payload() {
    let Some(stream) = open_fixture_or_skip("Tabs_real") else {
        return;
    };
    let empties: Vec<u8> = stream
        .records
        .iter()
        .filter(|r| r.payload.is_empty())
        .map(|r| r.id)
        .collect();
    assert_eq!(
        empties,
        vec![255],
        "only the cmd-255 sentinel is payload-less"
    );

    // Navigation commands in the Tabs dialect (id 1) always carry URL/title bytes.
    assert!(stream
        .records
        .iter()
        .filter(|r| r.id == 1)
        .all(|r| !r.payload.is_empty()));
}

/// A non-SNSS header is a hard error, not a warning or a silent empty model.
#[test]
fn bad_magic_is_an_error() {
    let bytes: &[u8] = b"NOPEnot-snss-at-all";
    assert!(read_records(bytes).is_err());
}
