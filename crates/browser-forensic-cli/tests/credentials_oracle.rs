//! Real-data Doer-Checker for Milestone 14 (zero-secret credential/account
//! metadata + per-site permissions).
//!
//! Runs the M14 parsers over genuine Chromium `Login Data`, `Web Data`, and
//! `Preferences` files and cross-checks each event count against an independent
//! query/walk of the same source — and asserts no encrypted secret ever leaks.
//! This is tier-1 validation (real-world artifacts); it complements the
//! synthetic unit fixtures.
//!
//! Profile data is never committed. Point the tests at copies via env vars;
//! absent, they skip:
//!
//! ```sh
//! BR4N6_LOGIN_DATA=/tmp/m14_login.db \
//! BR4N6_WEB_DATA=/tmp/m14_webdata.db \
//! BR4N6_CHROME_PREFERENCES=/tmp/m14_prefs.json \
//!   cargo test -p browser-forensic-cli --test credentials_oracle
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use browser_forensic_chrome::{parse_login_data, parse_permissions, parse_web_data};
use rusqlite::Connection;

/// Count rows of `table` if it exists, else 0 (independent of the parser path).
fn count_table(conn: &Connection, table: &str) -> i64 {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |_| Ok(()),
        )
        .is_ok();
    if !exists {
        return 0;
    }
    conn.query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| {
        r.get(0)
    })
    .unwrap_or(0)
}

#[test]
fn login_data_metadata_matches_oracle_and_hides_secrets() {
    let Ok(p) = std::env::var("BR4N6_LOGIN_DATA") else {
        eprintln!("skip: set BR4N6_LOGIN_DATA to a real Chromium 'Login Data' copy");
        return;
    };
    let path = PathBuf::from(p);
    let conn = Connection::open(&path).expect("open login oracle");
    let expected: i64 = conn
        .query_row(
            "SELECT count(*) FROM logins WHERE date_created > 0 OR blacklisted_by_user = 1",
            [],
            |r| r.get(0),
        )
        .expect("oracle count");

    let events = parse_login_data(&path).expect("parse login data");
    assert_eq!(
        events.len() as i64,
        expected,
        "login event count must match the independent SQL oracle"
    );
    for e in &events {
        assert_eq!(e.attrs["password"], serde_json::json!("ENCRYPTED"));
        assert!(e.attrs.contains_key("signon_realm"));
        // No attr value is a BLOB / raw bytes — everything surfaced is metadata.
        for v in e.attrs.values() {
            assert!(!v.is_array(), "no raw byte arrays should be surfaced");
        }
    }
    eprintln!("login oracle OK: {} credential records", events.len());
}

#[test]
fn web_data_metadata_matches_oracle_and_hides_secrets() {
    let Ok(p) = std::env::var("BR4N6_WEB_DATA") else {
        eprintln!("skip: set BR4N6_WEB_DATA to a real Chromium 'Web Data' copy");
        return;
    };
    let path = PathBuf::from(p);
    let conn = Connection::open(&path).expect("open web data oracle");
    let expected = count_table(&conn, "credit_cards")
        + count_table(&conn, "masked_credit_cards")
        + count_table(&conn, "token_service")
        + count_table(&conn, "autofill_profiles");

    let events = parse_web_data(&path).expect("parse web data");
    assert_eq!(
        events.len() as i64,
        expected,
        "web-data event count must match the independent table-row oracle"
    );
    for e in &events {
        if let Some(cn) = e.attrs.get("card_number") {
            assert_eq!(cn, &serde_json::json!("ENCRYPTED"));
        }
        if let Some(tok) = e.attrs.get("token") {
            assert_eq!(tok, &serde_json::json!("ENCRYPTED"));
        }
    }
    eprintln!(
        "web-data oracle OK: {} account/payment records",
        events.len()
    );
}

#[test]
fn permissions_match_json_oracle() {
    let Ok(p) = std::env::var("BR4N6_CHROME_PREFERENCES") else {
        eprintln!("skip: set BR4N6_CHROME_PREFERENCES to a real Chromium Preferences copy");
        return;
    };
    let path = PathBuf::from(p);
    let data = std::fs::read_to_string(&path).expect("read prefs");
    let root: serde_json::Value = serde_json::from_str(&data).expect("parse prefs json");

    // Independent oracle: sum the per-type exception entry counts.
    let mut expected = 0usize;
    if let Some(exc) = root
        .pointer("/profile/content_settings/exceptions")
        .and_then(|v| v.as_object())
    {
        for entries in exc.values() {
            if let Some(obj) = entries.as_object() {
                expected += obj.len();
            }
        }
    }

    let events = parse_permissions(&path).expect("parse permissions");
    assert_eq!(
        events.len(),
        expected,
        "permission event count must match the independent JSON walk"
    );
    eprintln!("permissions oracle OK: {} per-site grants", events.len());
}
