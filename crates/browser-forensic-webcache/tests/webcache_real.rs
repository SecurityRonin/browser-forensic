#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tier-1 validation against a REAL `WebCacheV01.dat`.
//!
//! Env-gated on `BR4N6_WEBCACHE` (path to a real WebCacheV01.dat); skips cleanly
//! when unset, like an oracle-binary-gated test. Reconciliation ground truth is
//! produced independently by libesedb `esedbexport`.
//!
//! Ground truth for the Windows 11 sample used in development (`esedbexport` on
//! the same file): 37 rows in the `Containers` master table, 35 `Container_#`
//! data tables totalling 360 records. Of those, 30 tables belong to browsing
//! containers (History / MSHist… / Content / DOMStore / Cookies) and hold
//! **309 records** — the events this crate emits (infrastructure containers such
//! as `BackgroundTransferApi` are skipped). The largest single browsing table is
//! `Container_1` (History, 94 records); the MSHist period partitions add the
//! bulk of the rest.

use std::collections::BTreeMap;
use std::path::PathBuf;

use browser_forensic_core::{ArtifactKind, BrowserFamily};
use browser_forensic_webcache::parse_webcache;

/// Oracle (libesedb `esedbexport`) browsing-event ground truth for the dev
/// sample: 30 browsing `Container_#` tables holding 309 records total.
const EXPECTED_BROWSING_EVENTS: usize = 309;

/// A tagged `Url` value `esedbexport` exports for `Container_1` (History)
/// EntryId 655 — asserted byte-identical to prove tagged-column decoding.
const SAMPLE_URL: &str = "Visited: 4n6h4x0r@ms-gamingoverlay://kglcheck/";

fn sample_path() -> Option<PathBuf> {
    std::env::var_os("BR4N6_WEBCACHE").map(PathBuf::from)
}

#[test]
fn parse_real_webcache_and_reconcile() {
    let Some(path) = sample_path() else {
        eprintln!("SKIP: set BR4N6_WEBCACHE to a real WebCacheV01.dat to run tier-1 validation");
        return;
    };

    // Any parse error is now a hard failure — the ese_core reader traverses the
    // real large-page catalog, so there is no longer a "known blocker" branch.
    let events = parse_webcache(&path).expect("parse_webcache on real WebCacheV01.dat");

    // Group events by the container Name attr for per-container reconciliation.
    let mut by_container: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut with_url = 0usize;
    for ev in &events {
        if let Some(c) = ev.attrs.get("container").and_then(|v| v.as_str()) {
            *by_container.entry(c.to_string()).or_default() += 1;
        }
        *by_kind.entry(format!("{}", ev.artifact)).or_default() += 1;
        if ev.attrs.contains_key("url") {
            with_url += 1;
        }
    }

    eprintln!("── tier-1 WebCache reconciliation ──");
    eprintln!("total events: {}", events.len());
    eprintln!("events carrying a Url: {with_url}");
    eprintln!("by ArtifactKind: {by_kind:?}");
    eprintln!("by container Name: {by_container:?}");

    // Every event is a browsing-container event (infrastructure containers are
    // skipped by classify_container).
    for ev in &events {
        assert!(matches!(
            ev.artifact,
            ArtifactKind::History
                | ArtifactKind::Cookies
                | ArtifactKind::Cache
                | ArtifactKind::Downloads
                | ArtifactKind::LocalStorage
        ));
        assert!(matches!(
            ev.browser,
            BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy
        ));
    }

    // Tier-1 count reconciliation: the browsing containers' records must match
    // the independent esedbexport oracle exactly.
    assert_eq!(
        events.len(),
        EXPECTED_BROWSING_EVENTS,
        "browsing-event count must reconcile with esedbexport ({EXPECTED_BROWSING_EVENTS})"
    );

    // Tier-1 value reconciliation: a specific tagged `Url` (id 256) must be
    // recovered byte-identical to esedbexport — proving the tagged-column
    // decoder, not just the row count, is correct.
    let sample = events
        .iter()
        .find(|e| e.attrs.get("url").and_then(|v| v.as_str()) == Some(SAMPLE_URL));
    assert!(
        sample.is_some(),
        "Container_1 EntryId 655 Url ({SAMPLE_URL:?}) must be recovered byte-identical"
    );
    let sample = sample.unwrap();
    assert_eq!(sample.artifact, ArtifactKind::History);
    assert_eq!(sample.attrs["container"], serde_json::json!("History"));
}
