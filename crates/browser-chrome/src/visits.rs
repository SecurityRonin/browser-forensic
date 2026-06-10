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
use browser_core::sqlite::open_evidence_db;
use browser_core::timestamp::webkit_micros_to_unix_nanos;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

// Chromium transition bitmask (`ui/base/page_transition_types.h`): core type in
// the low byte, qualifier flags in the high bits.
const CORE_MASK: u32 = 0xFF;
const CHAIN_END: u32 = 0x2000_0000;
const CLIENT_REDIRECT: u32 = 0x4000_0000;
const SERVER_REDIRECT: u32 = 0x8000_0000;
const FROM_ADDRESS_BAR: u32 = 0x0200_0000;

/// The user-intended core transition: `link`, `typed`, `reload`, `form_submit`, …
/// (the low byte of the Chromium `transition` bitmask).
pub fn transition_core(transition: i64) -> &'static str {
    match (transition as u32) & CORE_MASK {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "auto_toplevel",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        _ => "unknown",
    }
}

/// Whether the visit was reached via a client- or server-side redirect.
pub fn is_redirect(transition: i64) -> bool {
    (transition as u32) & (CLIENT_REDIRECT | SERVER_REDIRECT) != 0
}

/// Whether the visit is the final landing of a redirect chain (`CHAIN_END`).
pub fn is_chain_end(transition: i64) -> bool {
    (transition as u32) & CHAIN_END != 0
}

fn from_address_bar(transition: i64) -> bool {
    (transition as u32) & FROM_ADDRESS_BAR != 0
}

/// Parse the `visits` table (joined to `urls`) into one [`BrowserEvent`]
/// ([`ArtifactKind::History`]) per visit, in ascending time order. Visits are
/// faithful and *not* redirect-collapsed here — the transition attrs let a
/// consumer collapse them.
///
/// # Errors
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_visits(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut stmt = conn.prepare(
        "SELECT v.visit_time, v.transition, v.visit_duration, v.from_visit, u.url, u.title \
         FROM visits v JOIN urls u ON u.id = v.url \
         ORDER BY v.visit_time ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let visit_time: i64 = row.get(0)?;
            let transition: i64 = row.get(1)?;
            let visit_duration: i64 = row.get::<_, Option<i64>>(2)?.unwrap_or(0);
            let from_visit: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or(0);
            let url: String = row.get(4)?;
            let title: String = row.get::<_, Option<String>>(5)?.unwrap_or_default();
            Ok((
                visit_time,
                transition,
                visit_duration,
                from_visit,
                url,
                title,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .filter(|(visit_time, ..)| *visit_time > 0)
        .map(
            |(visit_time, transition, visit_duration, from_visit, url, title)| {
                let ts_ns = webkit_micros_to_unix_nanos(visit_time);
                let desc = if title.is_empty() {
                    url.clone()
                } else {
                    title.clone()
                };
                // visit_duration is microseconds, navigation-to-navigation (NOT read
                // time — it includes idle/background); surfaced raw, never ranked on.
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Chromium,
                    ArtifactKind::History,
                    &source,
                    desc,
                )
                .with_attr("url", json!(url))
                .with_attr("title", json!(title))
                .with_attr("transition", json!(transition_core(transition)))
                .with_attr("is_redirect", json!(is_redirect(transition)))
                .with_attr("chain_end", json!(is_chain_end(transition)))
                .with_attr("from_address_bar", json!(from_address_bar(transition)))
                .with_attr("visit_duration_us", json!(visit_duration))
                .with_attr("from_visit", json!(from_visit))
            },
        )
        .collect();
    Ok(events)
}

/// Collapse redirect chains in a [`parse_visits`] result into logical page views.
///
/// A redirect chain is `start → (hop → hop → …) → landing`. The intermediate hops
/// (`is_redirect` and **not** `chain_end`) are transport artifacts, not pages the
/// user meaningfully landed on; keeping them pollutes visit counts and recency.
/// This drops exactly those hops and keeps everything else: the chain start, the
/// final landing (`chain_end`), and every non-redirect visit. Input order (the
/// ascending-time order `parse_visits` guarantees) is preserved.
///
/// Operates on the `is_redirect`/`chain_end` attrs `parse_visits` already records,
/// so it composes with any [`BrowserEvent`] stream those attrs were set on. A visit
/// missing either attr is treated as a non-redirect and kept (fail-open: never drop
/// evidence on absent metadata).
#[must_use]
pub fn collapse_redirects(visits: Vec<BrowserEvent>) -> Vec<BrowserEvent> {
    visits
        .into_iter()
        .filter(|e| {
            let is_redirect = e
                .attrs
                .get("is_redirect")
                .and_then(serde_json::Value::as_bool)
                == Some(true);
            let chain_end = e
                .attrs
                .get("chain_end")
                .and_then(serde_json::Value::as_bool)
                == Some(true);
            // A mid-chain redirect hop: a redirect that is not the chain's landing.
            let is_mid_chain_hop = is_redirect && !chain_end;
            // Drop only those hops; keep starts, landings, and plain visits.
            !is_mid_chain_hop
        })
        .collect()
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
        assert!(
            events[0].timestamp_ns <= events[1].timestamp_ns,
            "ascending by time"
        );
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

    /// Build a redirect chain `typed → 2× server-redirect hop → landing` plus a
    /// standalone typed visit, then assert [`collapse_redirects`] drops only the
    /// intermediate hops (redirect && !`chain_end`) and keeps everything else.
    #[test]
    fn collapse_redirects_drops_intermediate_hops_keeps_landings() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO urls (id,url,title,visit_count,last_visit_time) \
             VALUES (1,'https://start.example','Start',1,13327626000000000)",
            [],
        );
        db.insert(
            "INSERT INTO urls (id,url,title,visit_count,last_visit_time) \
             VALUES (2,'https://hop.example','Hop',1,13327626000000000)",
            [],
        );
        db.insert(
            "INSERT INTO urls (id,url,title,visit_count,last_visit_time) \
             VALUES (3,'https://landing.example','Landing',1,13327626000000000)",
            [],
        );
        db.insert(
            "INSERT INTO urls (id,url,title,visit_count,last_visit_time) \
             VALUES (4,'https://other.example','Other',1,13327626000000000)",
            [],
        );
        // Chain: typed start (chain_start), redirect hop (no chain_end), landing
        // (server-redirect + chain_end). Then an unrelated typed visit.
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (1,13327626000000000,0,1)",
            [],
        ); // typed, not a redirect → kept
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (2,13327626100000000,0,?1)",
            [SERVER_REDIRECT],
        ); // redirect hop, NOT chain_end → dropped
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (3,13327626200000000,0,?1)",
            [SERVER_REDIRECT | CHAIN_END],
        ); // redirect AND chain_end → kept (the landing)
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (4,13327627000000000,0,1)",
            [],
        ); // standalone typed → kept

        let visits = parse_visits(db.path()).unwrap();
        assert_eq!(visits.len(), 4, "parse_visits is faithful (all 4 visits)");

        let collapsed = collapse_redirects(visits);
        let urls: Vec<&str> = collapsed
            .iter()
            .map(|e| e.attrs["url"].as_str().unwrap())
            .collect();
        assert_eq!(
            urls,
            vec![
                "https://start.example",
                "https://landing.example",
                "https://other.example",
            ],
            "intermediate redirect hop dropped; start, landing, and standalone kept"
        );
    }

    #[test]
    fn collapse_redirects_is_identity_when_no_redirects() {
        let db = TestDb::new(SCHEMA);
        seed_one_url(&db);
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition) VALUES (1,13327626000000000,0,1)",
            [],
        );
        let visits = parse_visits(db.path()).unwrap();
        let collapsed = collapse_redirects(visits.clone());
        assert_eq!(collapsed.len(), visits.len());
    }
}
