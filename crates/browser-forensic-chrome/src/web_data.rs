//! Chromium `Web Data` account / payment metadata parser.
//!
//! Surfaces the FACTS that prove stored payment cards, sync/OAuth tokens, and
//! saved address profiles existed — **never** the secret values. Encrypted
//! columns (`card_number_encrypted`, `encrypted_token`) are reported as present
//! and opaque; they are never selected or decoded.
//!
//! Tables handled (each is skipped when absent, so this is safe across the many
//! Chromium schema revisions):
//! - `credit_cards`       → [`ArtifactKind::CreditCard`] (local cards; number opaque)
//! - `masked_credit_cards`→ [`ArtifactKind::CreditCard`] (server cards; already masked)
//! - `token_service`      → [`ArtifactKind::AuthToken`]  (token opaque)
//! - `autofill_profiles` (+ `_names`/`_emails`/`_phones`) → [`ArtifactKind::Autofill`]

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use rusqlite::Connection;
use serde_json::json;

/// Return `true` if a table with the given name exists in the database.
fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |_| Ok(()),
    )
    .is_ok()
}

/// Parse account/payment metadata from a Chromium `Web Data` SQLite file.
///
/// CRITICAL: `card_number_encrypted` and `encrypted_token` are never selected.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened. Individual missing
/// tables are skipped, not errors.
pub fn parse_web_data(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    if table_exists(conn, "credit_cards") {
        events.extend(parse_credit_cards(conn, &source)?);
    }
    if table_exists(conn, "masked_credit_cards") {
        events.extend(parse_masked_credit_cards(conn, &source)?);
    }
    if table_exists(conn, "token_service") {
        events.extend(parse_token_service(conn, &source)?);
    }
    if table_exists(conn, "autofill_profiles") {
        events.extend(parse_autofill_profiles(conn, &source)?);
    }

    Ok(events)
}

/// Local `credit_cards`: card number stays encrypted/opaque.
fn parse_credit_cards(conn: &Connection, source: &str) -> Result<Vec<BrowserEvent>> {
    // CRITICAL: card_number_encrypted is NEVER in this query.
    let mut stmt = conn.prepare(
        "SELECT name_on_card, expiration_month, expiration_year, date_modified, use_count, use_date \
         FROM credit_cards",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let name_on_card: String = row.get::<_, Option<String>>(0)?.unwrap_or_default();
            let exp_month: i64 = row.get::<_, Option<i64>>(1)?.unwrap_or_default();
            let exp_year: i64 = row.get::<_, Option<i64>>(2)?.unwrap_or_default();
            let date_modified: i64 = row.get(3)?;
            let use_count: i64 = row.get(4)?;
            let use_date: i64 = row.get(5)?;
            Ok((
                name_on_card,
                exp_month,
                exp_year,
                date_modified,
                use_count,
                use_date,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .map(
            |(name_on_card, exp_month, exp_year, date_modified, use_count, use_date)| {
                let ts_ns = webkit_micros_to_unix_nanos(date_modified);
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Chromium,
                    ArtifactKind::CreditCard,
                    source,
                    format!("stored card: {name_on_card} (exp {exp_month:02}/{exp_year})"),
                )
                .with_attr("name_on_card", json!(name_on_card))
                .with_attr("expiration_month", json!(exp_month))
                .with_attr("expiration_year", json!(exp_year))
                .with_attr("use_count", json!(use_count))
                .with_attr("use_date", json!(use_date))
                .with_attr("card_type", json!("local"))
                .with_attr("card_number", json!("ENCRYPTED"))
            },
        )
        .collect();
    Ok(rows)
}

/// Server `masked_credit_cards`: already masked by design (`last_four` only).
fn parse_masked_credit_cards(conn: &Connection, source: &str) -> Result<Vec<BrowserEvent>> {
    let mut stmt = conn.prepare(
        "SELECT name_on_card, network, last_four, exp_month, exp_year, bank_name \
         FROM masked_credit_cards",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let name_on_card: String = row.get::<_, Option<String>>(0)?.unwrap_or_default();
            let network: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            let last_four: String = row.get::<_, Option<String>>(2)?.unwrap_or_default();
            let exp_month: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or_default();
            let exp_year: i64 = row.get::<_, Option<i64>>(4)?.unwrap_or_default();
            let bank_name: String = row.get::<_, Option<String>>(5)?.unwrap_or_default();
            Ok((
                name_on_card,
                network,
                last_four,
                exp_month,
                exp_year,
                bank_name,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .map(
            |(name_on_card, network, last_four, exp_month, exp_year, bank_name)| {
                BrowserEvent::new(
                    0,
                    BrowserFamily::Chromium,
                    ArtifactKind::CreditCard,
                    source,
                    format!("server card: {network} ****{last_four} ({name_on_card})"),
                )
                .with_attr("name_on_card", json!(name_on_card))
                .with_attr("network", json!(network))
                .with_attr("last_four", json!(last_four))
                .with_attr("expiration_month", json!(exp_month))
                .with_attr("expiration_year", json!(exp_year))
                .with_attr("bank_name", json!(bank_name))
                .with_attr("card_type", json!("masked_server"))
            },
        )
        .collect();
    Ok(rows)
}

/// `token_service`: OAuth/sync token names only; the token stays opaque.
fn parse_token_service(conn: &Connection, source: &str) -> Result<Vec<BrowserEvent>> {
    // CRITICAL: encrypted_token is NEVER in this query.
    let mut stmt = conn.prepare("SELECT service FROM token_service")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(std::result::Result::ok)
        .map(|service| {
            BrowserEvent::new(
                0,
                BrowserFamily::Chromium,
                ArtifactKind::AuthToken,
                source,
                format!("auth token for service: {service}"),
            )
            .with_attr("service", json!(service))
            .with_attr("token", json!("ENCRYPTED"))
        })
        .collect();
    Ok(rows)
}

/// Legacy `autofill_profiles` (+ linked name/email/phone tables). Absent on
/// modern Chromium, which migrated this data to the `addresses` table.
fn parse_autofill_profiles(conn: &Connection, source: &str) -> Result<Vec<BrowserEvent>> {
    let mut stmt =
        conn.prepare("SELECT guid, date_modified, use_count, use_date FROM autofill_profiles")?;
    let profiles: Vec<(String, i64, i64, i64)> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .collect();

    let mut events = Vec::with_capacity(profiles.len());
    for (guid, date_modified, use_count, use_date) in profiles {
        let full_name = joined_linked_value(
            conn,
            "SELECT first_name, middle_name, last_name FROM autofill_profile_names WHERE guid=?1",
            &guid,
            3,
        );
        let email = first_linked_value(
            conn,
            "SELECT email FROM autofill_profile_emails WHERE guid=?1",
            &guid,
        );
        let phone = first_linked_value(
            conn,
            "SELECT number FROM autofill_profile_phones WHERE guid=?1",
            &guid,
        );
        let ts_ns = webkit_micros_to_unix_nanos(date_modified);
        events.push(
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Chromium,
                ArtifactKind::Autofill,
                source,
                format!("autofill profile: {full_name} <{email}> {phone}"),
            )
            .with_attr("guid", json!(guid))
            .with_attr("full_name", json!(full_name))
            .with_attr("email", json!(email))
            .with_attr("phone", json!(phone))
            .with_attr("use_count", json!(use_count))
            .with_attr("use_date", json!(use_date)),
        );
    }
    Ok(events)
}

/// Return the first column of the first matching row, or `""` (table may be absent).
fn first_linked_value(conn: &Connection, sql: &str, guid: &str) -> String {
    conn.query_row(sql, [guid], |row| row.get::<_, Option<String>>(0))
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Join the first `cols` columns of the first matching row with spaces, trimming
/// empty fields. Returns `""` when the table is absent or there is no row.
fn joined_linked_value(conn: &Connection, sql: &str, guid: &str, cols: usize) -> String {
    conn.query_row(sql, [guid], |row| {
        let mut parts = Vec::with_capacity(cols);
        for i in 0..cols {
            let v: Option<String> = row.get(i)?;
            if let Some(s) = v {
                if !s.is_empty() {
                    parts.push(s);
                }
            }
        }
        Ok(parts.join(" "))
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    const SCHEMA: &str = "
        CREATE TABLE credit_cards (
            guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, expiration_month INTEGER,
            expiration_year INTEGER, card_number_encrypted BLOB,
            date_modified INTEGER NOT NULL DEFAULT 0, origin VARCHAR DEFAULT '',
            use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE masked_credit_cards (
            id VARCHAR, name_on_card VARCHAR, network VARCHAR, last_four VARCHAR,
            exp_month INTEGER DEFAULT 0, exp_year INTEGER DEFAULT 0, bank_name VARCHAR);
        CREATE TABLE token_service (
            service VARCHAR PRIMARY KEY NOT NULL, encrypted_token BLOB);
        CREATE TABLE autofill_profiles (
            guid VARCHAR PRIMARY KEY, date_modified INTEGER NOT NULL DEFAULT 0,
            use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE autofill_profile_names (
            guid VARCHAR, first_name VARCHAR, middle_name VARCHAR, last_name VARCHAR);
        CREATE TABLE autofill_profile_emails (guid VARCHAR, email VARCHAR);
        CREATE TABLE autofill_profile_phones (guid VARCHAR, number VARCHAR);
    ";

    #[test]
    fn empty_web_data_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_web_data(db.path()).unwrap().is_empty());
    }

    #[test]
    fn credit_card_number_never_exposed() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO credit_cards (guid, name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified, use_count, use_date) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params!["g1", "A Suspect", 8_i64, 2027_i64, b"SECRETPAN".to_vec(), 13_340_000_000_000_000_i64, 3_i64, 13_350_000_000_000_000_i64],
        );
        let events = parse_web_data(db.path()).unwrap();
        let cc: Vec<_> = events
            .iter()
            .filter(|e| e.artifact == ArtifactKind::CreditCard)
            .collect();
        assert_eq!(cc.len(), 1);
        assert_eq!(cc[0].attrs["card_number"], json!("ENCRYPTED"));
        assert_eq!(cc[0].attrs["name_on_card"], json!("A Suspect"));
        assert_eq!(cc[0].attrs["use_count"], json!(3));
        // No raw PAN anywhere.
        for v in cc[0].attrs.values() {
            assert_ne!(v, &json!("SECRETPAN"));
        }
    }

    #[test]
    fn masked_card_surfaces_last_four_only() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO masked_credit_cards (id, name_on_card, network, last_four, exp_month, exp_year, bank_name) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["m1", "A Suspect", "VISA", "4242", 12_i64, 2028_i64, "Big Bank"],
        );
        let events = parse_web_data(db.path()).unwrap();
        let card = events
            .iter()
            .find(|e| e.attrs.get("card_type") == Some(&json!("masked_server")))
            .expect("masked card event");
        assert_eq!(card.attrs["last_four"], json!("4242"));
        assert_eq!(card.attrs["network"], json!("VISA"));
        assert_eq!(card.attrs["bank_name"], json!("Big Bank"));
    }

    #[test]
    fn token_service_token_never_exposed() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO token_service (service, encrypted_token) VALUES (?1, ?2)",
            params!["https://www.google.com/", b"SECRETTOKEN".to_vec()],
        );
        let events = parse_web_data(db.path()).unwrap();
        let tok = events
            .iter()
            .find(|e| e.artifact == ArtifactKind::AuthToken)
            .expect("auth token event");
        assert_eq!(tok.attrs["service"], json!("https://www.google.com/"));
        assert_eq!(tok.attrs["token"], json!("ENCRYPTED"));
        for v in tok.attrs.values() {
            assert_ne!(v, &json!("SECRETTOKEN"));
        }
    }

    #[test]
    fn autofill_profile_joins_name_email_phone() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO autofill_profiles (guid, date_modified, use_count, use_date) VALUES (?1, ?2, ?3, ?4)",
            params!["p1", 13_340_000_000_000_000_i64, 5_i64, 13_350_000_000_000_000_i64],
        );
        db.insert(
            "INSERT INTO autofill_profile_names (guid, first_name, middle_name, last_name) VALUES (?1, ?2, ?3, ?4)",
            params!["p1", "Ada", "", "Lovelace"],
        );
        db.insert(
            "INSERT INTO autofill_profile_emails (guid, email) VALUES (?1, ?2)",
            params!["p1", "ada@example.com"],
        );
        db.insert(
            "INSERT INTO autofill_profile_phones (guid, number) VALUES (?1, ?2)",
            params!["p1", "+15551234"],
        );
        let events = parse_web_data(db.path()).unwrap();
        let prof = events
            .iter()
            .find(|e| e.attrs.get("guid") == Some(&json!("p1")))
            .expect("autofill profile event");
        assert_eq!(prof.artifact, ArtifactKind::Autofill);
        assert_eq!(prof.attrs["full_name"], json!("Ada Lovelace"));
        assert_eq!(prof.attrs["email"], json!("ada@example.com"));
        assert_eq!(prof.attrs["phone"], json!("+15551234"));
    }

    #[test]
    fn missing_tables_are_skipped_not_errors() {
        // Only one of the target tables present; the rest are absent.
        let db = TestDb::new(
            "CREATE TABLE token_service (service VARCHAR PRIMARY KEY, encrypted_token BLOB);",
        );
        db.insert(
            "INSERT INTO token_service (service, encrypted_token) VALUES (?1, ?2)",
            params!["svc", b"x".to_vec()],
        );
        let events = parse_web_data(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].artifact, ArtifactKind::AuthToken);
    }
}
