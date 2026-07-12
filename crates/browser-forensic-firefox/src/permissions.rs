//! Firefox `permissions.sqlite` (`moz_perms`) parser (RED stub).

use std::path::Path;

use anyhow::Result;
#[cfg(test)]
use browser_forensic_core::ArtifactKind;
use browser_forensic_core::BrowserEvent;
#[cfg(test)]
use browser_forensic_core::BrowserFamily;
#[cfg(test)]
use serde_json::json;

/// RED stub — returns nothing until the GREEN implementation lands.
///
/// # Errors
/// Never errors in the stub.
pub fn parse_permissions(_path: &Path) -> Result<Vec<BrowserEvent>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    const SCHEMA: &str = "CREATE TABLE moz_perms (
        id               INTEGER PRIMARY KEY,
        origin           TEXT,
        type             TEXT,
        permission       INTEGER,
        expireType       INTEGER,
        expireTime       INTEGER,
        modificationTime INTEGER
    );";

    #[test]
    fn empty_perms_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_permissions(db.path()).unwrap().is_empty());
    }

    #[test]
    fn emits_permission_with_label_and_time() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO moz_perms (origin, type, permission, expireType, expireTime, modificationTime) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "https://mail.example.com",
                "desktop-notification",
                1_i64,
                0_i64,
                0_i64,
                1_650_000_000_000_i64
            ],
        );
        let events = parse_permissions(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Permission);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["origin"], json!("https://mail.example.com"));
        assert_eq!(ev.attrs["permission"], json!("desktop-notification"));
        assert_eq!(ev.attrs["setting_label"], json!("allow"));
        assert_eq!(ev.timestamp_ns, 1_650_000_000_000_i64 * 1_000_000);
    }

    #[test]
    fn deny_action_labelled_block() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO moz_perms (origin, type, permission, modificationTime) VALUES (?1, ?2, ?3, ?4)",
            params!["https://ads.example.com", "geo", 2_i64, 0_i64],
        );
        let events = parse_permissions(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["setting_label"], json!("block"));
    }
}
