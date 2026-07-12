//! Firefox `moz_historyvisits` — the per-visit navigation timeline.
//!
//! Where [`crate::history`] reads the `moz_places` aggregate (one row per URL,
//! last-visit only), this reads `moz_historyvisits` joined to `moz_places` to
//! recover every individual visit with its time, visit-type, `from_visit`
//! referrer link, and `session` — the Firefox counterpart to Chromium's
//! `visits` table. It is the input the browser-agnostic reconstruction layer
//! ([`browser_forensic_core::reconstruct`]) consumes to rebuild referrer and
//! redirect chains.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::unix_micros_to_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Map a Firefox `visit_type` to a normalized transition token.
///
/// Values per `toolkit/components/places/nsINavHistoryService.idl`
/// (`TRANSITION_*`): 1=LINK, 2=TYPED, 3=BOOKMARK, 4=EMBED,
/// 5=REDIRECT_PERMANENT, 6=REDIRECT_TEMPORARY, 7=DOWNLOAD, 8=FRAMED_LINK,
/// 9=RELOAD.
#[must_use]
pub fn visit_type_token(visit_type: i64) -> &'static str {
    match visit_type {
        1 => "link",
        2 => "typed",
        3 => "bookmark",
        4 => "embed",
        5 => "redirect_permanent",
        6 => "redirect_temporary",
        7 => "download",
        8 => "framed_link",
        9 => "reload",
        _ => "unknown",
    }
}

/// Whether a Firefox `visit_type` is a redirect.
///
/// Firefox records only server-side HTTP redirects (301 → `REDIRECT_PERMANENT`,
/// 302 → `REDIRECT_TEMPORARY`) as visit types 5/6; it has no distinct
/// client/meta-redirect visit type, so every redirect here is server-side.
#[must_use]
pub fn is_redirect(visit_type: i64) -> bool {
    matches!(visit_type, 5 | 6)
}

/// Parse `moz_historyvisits` (joined to `moz_places`) into one [`BrowserEvent`]
/// ([`ArtifactKind::History`]) per visit, ascending by `visit_date`.
///
/// Each event carries the raw linkage the reconstruction layer needs:
/// `visit_id`, `from_visit`, the `transition` token, `is_redirect`/`redirect_kind`
/// for redirects, and `session` when the profile records one.
///
/// # Errors
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_visits(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut stmt = conn.prepare(
        "SELECT h.id, h.from_visit, h.visit_date, h.visit_type, h.session, p.url, p.title \
         FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id \
         ORDER BY h.visit_date ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let from_visit: i64 = row.get::<_, Option<i64>>(1)?.unwrap_or(0);
            let visit_date: i64 = row.get(2)?;
            let visit_type: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or(0);
            let session: i64 = row.get::<_, Option<i64>>(4)?.unwrap_or(0);
            let url: String = row.get(5)?;
            let title: String = row.get::<_, Option<String>>(6)?.unwrap_or_default();
            Ok((id, from_visit, visit_date, visit_type, session, url, title))
        })?
        .filter_map(std::result::Result::ok)
        .filter(|(_, _, visit_date, ..)| *visit_date > 0)
        .map(
            |(id, from_visit, visit_date, visit_type, session, url, title)| {
                let ts_ns = unix_micros_to_nanos(visit_date);
                let desc = if title.is_empty() {
                    url.clone()
                } else {
                    title.clone()
                };
                let mut ev = BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Firefox,
                    ArtifactKind::History,
                    &source,
                    desc,
                )
                .with_attr("url", json!(url))
                .with_attr("title", json!(title))
                .with_attr("visit_id", json!(id))
                .with_attr("from_visit", json!(from_visit))
                .with_attr("transition", json!(visit_type_token(visit_type)))
                .with_attr("is_redirect", json!(is_redirect(visit_type)));
                if is_redirect(visit_type) {
                    // Firefox only records server-side HTTP redirects as visit types.
                    ev = ev.with_attr("redirect_kind", json!("server"));
                }
                if session != 0 {
                    ev = ev.with_attr("session", json!(session));
                }
                ev
            },
        )
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use serde_json::json;

    const SCHEMA: &str = "
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT,
            visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
            visit_date INTEGER, visit_type INTEGER, session INTEGER);
    ";

    fn seed_place(db: &TestDb, id: i64, url: &str, title: &str) {
        db.insert(
            "INSERT INTO moz_places (id,url,title) VALUES (?1,?2,?3)",
            rusqlite::params![id, url, title],
        );
    }

    #[test]
    fn visit_type_token_decodes_all_known_types() {
        assert_eq!(visit_type_token(1), "link");
        assert_eq!(visit_type_token(2), "typed");
        assert_eq!(visit_type_token(3), "bookmark");
        assert_eq!(visit_type_token(4), "embed");
        assert_eq!(visit_type_token(5), "redirect_permanent");
        assert_eq!(visit_type_token(6), "redirect_temporary");
        assert_eq!(visit_type_token(7), "download");
        assert_eq!(visit_type_token(8), "framed_link");
        assert_eq!(visit_type_token(9), "reload");
        assert_eq!(visit_type_token(99), "unknown");
    }

    #[test]
    fn is_redirect_true_only_for_5_and_6() {
        assert!(is_redirect(5));
        assert!(is_redirect(6));
        assert!(!is_redirect(1));
        assert!(!is_redirect(2));
        assert!(!is_redirect(9));
    }

    #[test]
    fn emits_event_per_visit_in_time_order() {
        let db = TestDb::new(SCHEMA);
        seed_place(&db, 1, "https://example.com", "Example");
        seed_place(&db, 2, "https://later.example", "Later");
        db.insert(
            "INSERT INTO moz_historyvisits (id,from_visit,place_id,visit_date,visit_type,session) \
             VALUES (10,0,2,1648000002000000,1,7)",
            [],
        ); // later, link
        db.insert(
            "INSERT INTO moz_historyvisits (id,from_visit,place_id,visit_date,visit_type,session) \
             VALUES (11,0,1,1648000001000000,2,7)",
            [],
        ); // earlier, typed
        let events = parse_visits(db.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].artifact, ArtifactKind::History);
        assert_eq!(events[0].browser, BrowserFamily::Firefox);
        assert!(events[0].timestamp_ns <= events[1].timestamp_ns);
        assert_eq!(events[0].attrs["transition"], json!("typed"));
        assert_eq!(events[0].attrs["visit_id"], json!(11));
        assert_eq!(events[0].attrs["url"], json!("https://example.com"));
        assert_eq!(events[1].attrs["transition"], json!("link"));
        assert_eq!(events[1].attrs["visit_id"], json!(10));
    }

    #[test]
    fn from_visit_and_session_are_carried() {
        let db = TestDb::new(SCHEMA);
        seed_place(&db, 1, "https://a.example", "A");
        seed_place(&db, 2, "https://b.example", "B");
        db.insert(
            "INSERT INTO moz_historyvisits (id,from_visit,place_id,visit_date,visit_type,session) \
             VALUES (1,0,1,1648000001000000,2,42)",
            [],
        );
        db.insert(
            "INSERT INTO moz_historyvisits (id,from_visit,place_id,visit_date,visit_type,session) \
             VALUES (2,1,2,1648000002000000,1,42)",
            [],
        );
        let events = parse_visits(db.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].attrs["from_visit"], json!(1));
        assert_eq!(events[1].attrs["session"], json!(42));
    }

    #[test]
    fn redirect_visit_is_flagged_as_server() {
        let db = TestDb::new(SCHEMA);
        seed_place(&db, 1, "https://redir.example", "Redir");
        db.insert(
            "INSERT INTO moz_historyvisits (id,from_visit,place_id,visit_date,visit_type,session) \
             VALUES (1,0,1,1648000001000000,5,0)",
            [],
        );
        let events = parse_visits(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["is_redirect"], json!(true));
        assert_eq!(events[0].attrs["redirect_kind"], json!("server"));
        assert_eq!(events[0].attrs["transition"], json!("redirect_permanent"));
        // session 0 is "no session" — not carried.
        assert!(!events[0].attrs.contains_key("session"));
    }

    #[test]
    fn skips_zero_visit_date() {
        let db = TestDb::new(SCHEMA);
        seed_place(&db, 1, "https://ok.example", "Ok");
        db.insert(
            "INSERT INTO moz_historyvisits (id,from_visit,place_id,visit_date,visit_type,session) \
             VALUES (1,0,1,0,1,0)",
            [],
        );
        db.insert(
            "INSERT INTO moz_historyvisits (id,from_visit,place_id,visit_date,visit_type,session) \
             VALUES (2,0,1,1648000001000000,1,0)",
            [],
        );
        let events = parse_visits(db.path()).unwrap();
        assert_eq!(events.len(), 1);
    }
}
