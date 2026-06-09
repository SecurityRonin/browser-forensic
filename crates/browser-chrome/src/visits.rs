//! Chromium History `visits` table — the per-visit timeline.
//!
//! Where [`crate::history`] reads the `urls` aggregate (one row per URL,
//! last-visit only), this reads the `visits` table joined to `urls` to recover
//! every individual visit with its time, transition type, and redirect linkage —
//! the source of truth for "what was visited and *when*". Transition qualifiers
//! ([`is_redirect`]/[`is_chain_end`]) let higher layers collapse redirect chains
//! into logical page views.

use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent};

/// The user-intended core transition: `link`, `typed`, `reload`, `form_submit`, …
/// (the low byte of the Chromium `transition` bitmask).
pub fn transition_core(transition: i64) -> &'static str {
    let _ = transition;
    todo!("implemented in the GREEN step")
}

/// Whether the visit was reached via a client- or server-side redirect.
pub fn is_redirect(transition: i64) -> bool {
    let _ = transition;
    todo!("implemented in the GREEN step")
}

/// Whether the visit is the final landing of a redirect chain (`CHAIN_END`).
pub fn is_chain_end(transition: i64) -> bool {
    let _ = transition;
    todo!("implemented in the GREEN step")
}

/// Parse the `visits` table (joined to `urls`) into one [`BrowserEvent`]
/// ([`ArtifactKind::History`]) per visit, in ascending time order. Visits are
/// faithful and *not* redirect-collapsed here — the transition attrs let a
/// consumer collapse them.
///
/// # Errors
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_visits(path: &Path) -> Result<Vec<BrowserEvent>> {
    let _ = path;
    let _: Option<ArtifactKind> = None;
    todo!("implemented in the GREEN step")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::test_utils::sqlite::TestDb;
    use browser_core::BrowserFamily;
    use serde_json::json;

    const SCHEMA: &str = "
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
            from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
    ";

    const SERVER_REDIRECT: i64 = 0x8000_0000;
    const CHAIN_END: i64 = 0x2000_0000;

    fn seed_one_url(db: &TestDb) {
        db.insert(
            "INSERT INTO urls (id,url,title,visit_count,last_visit_time) \
             VALUES (1,'https://example.com','Example',2,13327626000000000)",
            [],
        );
    }

    #[test]
    fn emits_event_per_visit_in_time_order() {
        let db = TestDb::new(SCHEMA);
        seed_one_url(&db);
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition,visit_duration) \
             VALUES (1,13327627000000000,0,0,1000000)",
            [],
        ); // later, link
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition,visit_duration) \
             VALUES (1,13327626000000000,0,1,5000000)",
            [],
        ); // earlier, typed
        let events = parse_visits(db.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].artifact, ArtifactKind::History);
        assert_eq!(events[0].browser, BrowserFamily::Chromium);
        assert!(events[0].timestamp_ns <= events[1].timestamp_ns, "ascending by time");
        assert_eq!(events[0].attrs["transition"], json!("typed"));
        assert_eq!(events[1].attrs["transition"], json!("link"));
        assert_eq!(events[0].attrs["visit_duration_us"], json!(5_000_000));
        assert_eq!(events[0].attrs["url"], json!("https://example.com"));
    }

    #[test]
    fn redirect_visit_is_flagged() {
        let db = TestDb::new(SCHEMA);
        seed_one_url(&db);
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition,visit_duration) \
             VALUES (1,13327626000000000,0,?1,0)",
            [SERVER_REDIRECT],
        );
        let events = parse_visits(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["is_redirect"], json!(true));
    }

    #[test]
    fn skips_zero_visit_time() {
        let db = TestDb::new(SCHEMA);
        seed_one_url(&db);
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (1,0,0,0)",
            [],
        );
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition) \
             VALUES (1,13327626000000000,0,1)",
            [],
        );
        let events = parse_visits(db.path()).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn transition_helpers_decode_core_and_qualifiers() {
        assert_eq!(transition_core(1), "typed");
        assert_eq!(transition_core(0), "link");
        assert_eq!(transition_core(8), "reload");
        assert!(is_redirect(SERVER_REDIRECT));
        assert!(!is_redirect(1));
        assert!(is_chain_end(CHAIN_END | 1));
        assert!(!is_chain_end(1));
    }
}
