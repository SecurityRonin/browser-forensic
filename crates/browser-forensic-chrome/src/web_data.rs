//! Chromium `Web Data` account / payment metadata parser (RED stub).

use std::path::Path;

use anyhow::Result;
#[cfg(test)]
use browser_forensic_core::ArtifactKind;
use browser_forensic_core::BrowserEvent;
#[cfg(test)]
use serde_json::json;

/// RED stub — returns nothing until the GREEN implementation lands.
///
/// # Errors
/// Never errors in the stub.
pub fn parse_web_data(_path: &Path) -> Result<Vec<BrowserEvent>> {
    Ok(Vec::new())
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
