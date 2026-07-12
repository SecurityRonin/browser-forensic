//! Chromium `DIPS` / `BTM` recovered-domain parser (Bounce-Tracking Mitigation).
//!
//! Chromium 116+ records, per eTLD+1 `site`, when the site received storage,
//! user activation/interaction, a bounce, or a WebAuthn assertion — in the
//! `bounces` table of the `DIPS` SQLite database (`content/browser/btm/
//! btm_storage.cc`, formerly `dips_storage.cc`). These `site` values are
//! **cleartext** and survive a history clear.
//!
//! The `bounces` schema evolved across milestones (columns renamed from
//! `*_user_interaction_time` / `*_site_storage_time` to `*_user_activation_time`
//! / `*_bounce_time`, WebAuthn columns added). Rather than hard-code one
//! generation, this parser **introspects the columns present** via
//! `PRAGMA table_info` and surfaces every `*_time` column it finds — so both old
//! and new databases parse without a schema-version special case.
//!
//! All `*_time` values are `ToDeltaSinceWindowsEpoch().InMicroseconds()` (WebKit
//! microseconds). Honesty: these times are *as recorded by Chromium* (storage /
//! activation / bounce), not proof of a deliberate visit.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

const DIPS_NOTE: &str = "DIPS/BTM bounce-tracking record; the site had storage / activation / \
     bounce activity as recorded by Chromium — times are as recorded, not proof of a \
     deliberate visit";

/// Parse a Chromium `DIPS` (BTM) database's `bounces` table into
/// recovered-domain events, introspecting whatever `*_time` columns exist.
///
/// # Errors
///
/// Returns an error if the SQLite database cannot be opened.
pub fn parse_dips(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let source = path.to_string_lossy().into_owned();

    // Introspect the columns actually present. Skip any pathological identifier
    // (a double-quote would break the quoted SELECT); real schemas never have one.
    let time_cols: Vec<String> = {
        let Ok(mut stmt) = conn.prepare("SELECT name FROM pragma_table_info('bounces')") else {
            return Ok(Vec::new());
        };
        let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) else {
            return Ok(Vec::new());
        };
        rows.filter_map(std::result::Result::ok)
            .filter(|c| c.ends_with("_time") && !c.contains('"'))
            .collect()
    };

    let mut select = String::from("SELECT site");
    for col in &time_cols {
        select.push_str(&format!(", \"{col}\""));
    }
    select.push_str(" FROM bounces WHERE site <> ''");

    let mut stmt = conn.prepare(&select)?;
    let n = time_cols.len();
    let rows = stmt.query_map([], |row| {
        let site: String = row.get(0)?;
        let mut times: Vec<(String, i64)> = Vec::with_capacity(n);
        for (i, col) in time_cols.iter().enumerate() {
            let raw: i64 = row.get::<_, Option<i64>>(i + 1)?.unwrap_or_default();
            times.push((col.clone(), raw));
        }
        Ok((site, times))
    })?;

    let mut events = Vec::new();
    for (site, times) in rows.filter_map(std::result::Result::ok) {
        // Prefer the latest activation/interaction time for the event timestamp;
        // else the latest of any recorded time; else 0 (site presence only).
        let pick_max = |pred: &dyn Fn(&str) -> bool| -> i64 {
            times
                .iter()
                .filter(|(c, v)| *v > 0 && pred(c))
                .map(|(_, v)| *v)
                .max()
                .unwrap_or(0)
        };
        let activation = pick_max(&|c: &str| c.contains("activation") || c.contains("interaction"));
        let chosen = if activation > 0 {
            activation
        } else {
            pick_max(&|_| true)
        };
        let ts_ns = if chosen > 0 {
            webkit_micros_to_unix_nanos(chosen)
        } else {
            0
        };

        let mut ev = BrowserEvent::new(
            ts_ns,
            BrowserFamily::Chromium,
            ArtifactKind::RecoveredDomain,
            &source,
            format!("{site} — recorded by DIPS/BTM"),
        )
        .with_attr("domain", json!(site))
        .with_attr("source_artifact", json!("DIPS"))
        .with_attr("recovery_note", json!(DIPS_NOTE));
        for (col, raw) in &times {
            if *raw > 0 {
                ev = ev.with_attr(col.clone(), json!(webkit_micros_to_unix_nanos(*raw)));
            }
        }
        events.push(ev);
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    // Newer schema (Chrome/Brave ~2025): activation + bounce + webauthn times.
    const NEW_SCHEMA: &str = "CREATE TABLE bounces(
        site TEXT PRIMARY KEY NOT NULL,
        first_user_activation_time INTEGER,
        last_user_activation_time INTEGER,
        first_bounce_time INTEGER,
        last_bounce_time INTEGER,
        first_web_authn_assertion_time INTEGER,
        last_web_authn_assertion_time INTEGER);";

    // Older schema (Chrome 116-era, still shipping in Edge): storage +
    // interaction + stateful-bounce times.
    const OLD_SCHEMA: &str = "CREATE TABLE bounces(
        site TEXT PRIMARY KEY NOT NULL,
        first_site_storage_time INTEGER,
        last_site_storage_time INTEGER,
        first_user_interaction_time INTEGER,
        last_user_interaction_time INTEGER,
        first_stateful_bounce_time INTEGER,
        last_stateful_bounce_time INTEGER);";

    fn webkit_for_unix(unix_secs: i64) -> i64 {
        (unix_secs + 11_644_473_600) * 1_000_000
    }

    #[test]
    fn newer_schema_site_and_activation_timestamp() {
        let db = TestDb::new(NEW_SCHEMA);
        db.insert(
            "INSERT INTO bounces (site, last_user_activation_time, last_bounce_time) VALUES (?1, ?2, ?3)",
            params!["tracker.example.com", webkit_for_unix(1_700_000_000), webkit_for_unix(1_600_000_000)],
        );
        let events = parse_dips(db.path()).expect("parse");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::RecoveredDomain);
        assert_eq!(ev.attrs["domain"], json!("tracker.example.com"));
        assert_eq!(ev.attrs["source_artifact"], json!("DIPS"));
        // Timestamp comes from activation (newer), not bounce.
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn older_schema_site_and_interaction_timestamp() {
        let db = TestDb::new(OLD_SCHEMA);
        db.insert(
            "INSERT INTO bounces (site, last_site_storage_time, last_user_interaction_time) VALUES (?1, ?2, ?3)",
            params!["site.example.org", webkit_for_unix(1_500_000_000), webkit_for_unix(1_700_000_000)],
        );
        let events = parse_dips(db.path()).expect("parse");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.attrs["domain"], json!("site.example.org"));
        // Interaction time wins over storage time.
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
        // The introspected column is surfaced verbatim as an attr.
        assert!(ev.attrs.contains_key("last_user_interaction_time"));
    }

    #[test]
    fn site_with_no_times_emitted_with_zero_timestamp() {
        let db = TestDb::new(NEW_SCHEMA);
        db.insert(
            "INSERT INTO bounces (site) VALUES (?1)",
            params!["nostorage.example.net"],
        );
        let events = parse_dips(db.path()).expect("parse");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["domain"], json!("nostorage.example.net"));
        assert_eq!(events[0].timestamp_ns, 0);
    }

    #[test]
    fn empty_bounces_returns_empty() {
        let db = TestDb::new(NEW_SCHEMA);
        assert!(parse_dips(db.path()).expect("parse").is_empty());
    }
}
