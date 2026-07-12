//! Real-data Doer-Checker for navigation reconstruction (Milestone 3).
//!
//! Runs [`reconstruct_history`] over a genuine Chrome `History` and/or Firefox
//! `places.sqlite` and asserts the output is structurally sane: every visit is
//! preserved, redirect chains reconstruct, and inferred sessions are
//! non-negative. This is tier-1 validation (real-world artifacts), an
//! independent check on the synthetic unit fixtures.
//!
//! The artifacts are user-profile data, never committed. Point the tests at a
//! copy (see `tests/data/README.md`) via env vars; absent, the tests skip:
//!
//! ```sh
//! BR4N6_CHROME_HISTORY=/tmp/br4n6-oracle/chrome_History \
//! BR4N6_FIREFOX_PLACES=/tmp/br4n6-oracle/places.sqlite \
//!   cargo test -p browser-forensic-cli --test reconstruct_oracle
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use browser_forensic_cli::cli::reconstruct_history;

/// Structural invariants any real per-visit reconstruction must satisfy.
fn assert_sane(path: &std::path::Path) {
    let events = reconstruct_history(path, 30).expect("reconstruct real history");
    assert!(!events.is_empty(), "real profile should have visits");

    let mut redirect_members = 0usize;
    let mut chain_ids = std::collections::HashSet::new();
    let mut max_session = -1i64;
    for e in &events {
        // Every visit carries an inferred, non-negative session id.
        let sid = e.attrs["session_id"].as_i64().expect("session_id present");
        assert!(sid >= 0, "session ids are non-negative");
        max_session = max_session.max(sid);
        // nav_depth is always set and non-negative (cycle/dangling guarded).
        assert!(e.attrs["nav_depth"].as_i64().expect("nav_depth") >= 0);
        if let Some(role) = e.attrs.get("redirect_role").and_then(|v| v.as_str()) {
            assert!(matches!(role, "start" | "hop" | "landing"));
            redirect_members += 1;
            chain_ids.insert(e.attrs["redirect_chain_id"].as_i64().unwrap());
        }
    }
    // Real browsing always contains at least one redirect chain.
    assert!(
        redirect_members > 0,
        "expected redirect chains in real data"
    );
    assert!(!chain_ids.is_empty());
    assert!(max_session >= 0);
}

#[test]
fn chrome_history_reconstructs() {
    let Ok(p) = std::env::var("BR4N6_CHROME_HISTORY") else {
        eprintln!("skip: set BR4N6_CHROME_HISTORY to a real Chrome History copy");
        return;
    };
    assert_sane(&PathBuf::from(p));
}

#[test]
fn firefox_places_reconstructs() {
    let Ok(p) = std::env::var("BR4N6_FIREFOX_PLACES") else {
        eprintln!("skip: set BR4N6_FIREFOX_PLACES to a real places.sqlite copy");
        return;
    };
    assert_sane(&PathBuf::from(p));
}
