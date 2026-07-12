//! Firefox `permissions.sqlite` (`moz_perms`) parser.
//!
//! Firefox's permission manager stores per-origin permission decisions in the
//! `moz_perms` table: `origin`, `type` (e.g. `geo`, `desktop-notification`,
//! `camera`), `permission` (1 = allow, 2 = deny, 0 = prompt), and
//! `modificationTime` (Unix milliseconds) — a dated record of a privacy choice.
//!
//! Schema reference: Mozilla `PermissionManager` / `nsPermissionManager`
//! (`extensions/permissions`), which defines `moz_perms(id, origin, type,
//! permission, expireType, expireTime, modificationTime)`.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::unix_millis_to_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Map a Firefox permission-manager action code to a human label.
fn permission_label(permission: i64) -> &'static str {
    match permission {
        1 => "allow",
        2 => "block",
        0 => "prompt",
        _ => "unknown",
    }
}

/// Parse a Firefox `permissions.sqlite` file's `moz_perms` table.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or `moz_perms` cannot be
/// queried.
pub fn parse_permissions(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut stmt = conn
        .prepare("SELECT origin, type, permission, expireTime, modificationTime FROM moz_perms")?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let origin: String = row.get::<_, Option<String>>(0)?.unwrap_or_default();
            let perm_type: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            let permission: i64 = row.get(2)?;
            let expire_time: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or_default();
            let modification_time: i64 = row.get::<_, Option<i64>>(4)?.unwrap_or_default();
            Ok((
                origin,
                perm_type,
                permission,
                expire_time,
                modification_time,
            ))
        })?
        .filter_map(std::result::Result::ok)
        .map(
            |(origin, perm_type, permission, expire_time, modification_time)| {
                let ts_ns = unix_millis_to_nanos(modification_time);
                let label = permission_label(permission);
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Firefox,
                    ArtifactKind::Permission,
                    &source,
                    format!("{origin} — {perm_type} = {label}"),
                )
                .with_attr("origin", json!(origin))
                .with_attr("permission", json!(perm_type))
                .with_attr("setting", json!(permission))
                .with_attr("setting_label", json!(label))
                .with_attr("expire_time", json!(expire_time))
                .with_attr("modification_time", json!(modification_time))
            },
        )
        .collect();
    Ok(events)
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
