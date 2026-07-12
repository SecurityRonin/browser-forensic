//! Chromium `Reporting and NEL` recovered-domain parser.
//!
//! Network Error Logging (NEL) + Reporting API state records the **cleartext
//! origins** a page set an NEL policy for and the report-collector endpoints it
//! was told to use — both survive a history clear. Modern Chromium persists this
//! in a SQLite database (`net/extras/sqlite/sqlite_persistent_reporting_and_nel_store.cc`,
//! `SQLitePersistentReportingAndNelStore`) with tables `nel_policies` and
//! `reporting_endpoints`; older builds wrote a JSON `net.nel` / `net.reporting`
//! blob. Both layouts are handled — the file is routed by its SQLite magic.
//!
//! Times are stored as `ToDeltaSinceWindowsEpoch().InMicroseconds()` (WebKit
//! microseconds). Honesty: an origin here is one the browser *contacted*, which
//! may be a subresource / third-party, not a user-navigated site.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::{json, Value};

use crate::network_persistent_state::{host_of, CONTACTED_NOTE};

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// True if the file begins with the SQLite-3 magic header.
fn is_sqlite(path: &Path) -> bool {
    let mut buf = [0u8; 16];
    match std::fs::File::open(path).and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut buf)
    }) {
        Ok(()) => &buf == SQLITE_MAGIC,
        Err(_) => false,
    }
}

/// Parse a Chromium `Reporting and NEL` store (SQLite or legacy JSON) into
/// recovered-domain events.
///
/// # Errors
///
/// Returns an error if the file cannot be read, or (JSON path) is not valid JSON.
pub fn parse_reporting_and_nel(path: &Path) -> Result<Vec<BrowserEvent>> {
    if is_sqlite(path) {
        parse_sqlite(path)
    } else {
        parse_json(path)
    }
}

/// Build one recovered-domain event for a contacted origin host.
fn contacted_event(source: &str, host: &str, ts_ns: i64, group: &str) -> BrowserEvent {
    BrowserEvent::new(
        ts_ns,
        BrowserFamily::Chromium,
        ArtifactKind::RecoveredDomain,
        source,
        format!("{host} — contacted (NEL/Reporting)"),
    )
    .with_attr("domain", json!(host))
    .with_attr("source_artifact", json!("Reporting and NEL"))
    .with_attr("report_group", json!(group))
    .with_attr("recovery_note", json!(CONTACTED_NOTE))
}

fn parse_sqlite(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    // nel_policies: origin_host is cleartext; last_access is WebKit micros.
    if let Ok(mut stmt) = conn.prepare(
        "SELECT origin_host, group_name, last_access_us_since_epoch \
         FROM nel_policies WHERE origin_host <> ''",
    ) {
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                row.get::<_, Option<i64>>(2)?.unwrap_or_default(),
            ))
        });
        if let Ok(rows) = rows {
            for (host, group, last_access) in rows.filter_map(std::result::Result::ok) {
                events.push(contacted_event(
                    &source,
                    &host,
                    webkit_micros_to_unix_nanos(last_access),
                    &group,
                ));
            }
        }
    }

    // reporting_endpoints: origin_host contacted; url is the report collector
    // (itself a contacted host, surfaced as an attribute).
    if let Ok(mut stmt) = conn.prepare(
        "SELECT origin_host, group_name, url FROM reporting_endpoints WHERE origin_host <> ''",
    ) {
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ))
        });
        if let Ok(rows) = rows {
            for (host, group, url) in rows.filter_map(std::result::Result::ok) {
                let mut ev = contacted_event(&source, &host, 0, &group);
                if let Some(report_host) = host_of(&url) {
                    ev = ev.with_attr("report_to_host", json!(report_host));
                }
                events.push(ev);
            }
        }
    }

    Ok(events)
}

fn parse_json(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read_to_string(path)?;
    let root: Value = serde_json::from_str(&data)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    // Legacy NEL policies: net.nel.policies[].origin ("https://host:port").
    if let Some(policies) = root.pointer("/net/nel/policies").and_then(Value::as_array) {
        for p in policies {
            let group = p
                .get("report_to")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if let Some(host) = p.get("origin").and_then(Value::as_str).and_then(host_of) {
                events.push(contacted_event(&source, &host, 0, group));
            }
        }
    }

    // Legacy Reporting endpoints: net.reporting.endpoints[] with origin + url.
    if let Some(endpoints) = root
        .pointer("/net/reporting/endpoints")
        .and_then(Value::as_array)
    {
        for e in endpoints {
            let group = e.get("group").and_then(Value::as_str).unwrap_or_default();
            if let Some(host) = e.get("origin").and_then(Value::as_str).and_then(host_of) {
                let mut ev = contacted_event(&source, &host, 0, group);
                if let Some(report_host) = e.get("url").and_then(Value::as_str).and_then(host_of) {
                    ev = ev.with_attr("report_to_host", json!(report_host));
                }
                events.push(ev);
            }
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const NEL_SCHEMA: &str = "CREATE TABLE nel_policies (
        nik TEXT NOT NULL DEFAULT '',
        origin_scheme TEXT NOT NULL DEFAULT '',
        origin_host TEXT NOT NULL DEFAULT '',
        origin_port INTEGER NOT NULL DEFAULT 0,
        received_ip_address TEXT NOT NULL DEFAULT '',
        group_name TEXT NOT NULL DEFAULT '',
        expires_us_since_epoch INTEGER NOT NULL DEFAULT 0,
        success_fraction REAL NOT NULL DEFAULT 0,
        failure_fraction REAL NOT NULL DEFAULT 0,
        is_include_subdomains INTEGER NOT NULL DEFAULT 0,
        last_access_us_since_epoch INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE reporting_endpoints (
        nik TEXT NOT NULL DEFAULT '',
        origin_scheme TEXT NOT NULL DEFAULT '',
        origin_host TEXT NOT NULL DEFAULT '',
        origin_port INTEGER NOT NULL DEFAULT 0,
        group_name TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL DEFAULT '',
        priority INTEGER NOT NULL DEFAULT 0,
        weight INTEGER NOT NULL DEFAULT 0
    );";

    fn write_json_file(json_data: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");
        f
    }

    #[test]
    fn sqlite_nel_policy_origin_host_recovered_with_timestamp() {
        // WebKit micros for 2023-11-14 22:13:20 UTC.
        let webkit = (1_700_000_000_i64 + 11_644_473_600) * 1_000_000;
        let db = TestDb::new(NEL_SCHEMA);
        db.insert(
            "INSERT INTO nel_policies (origin_scheme, origin_host, origin_port, group_name, last_access_us_since_epoch) \
             VALUES ('https', 'nel.example.com', 443, 'default', ?1)",
            params![webkit],
        );
        let events = parse_reporting_and_nel(db.path()).expect("parse");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::RecoveredDomain);
        assert_eq!(ev.attrs["domain"], json!("nel.example.com"));
        assert_eq!(ev.attrs["source_artifact"], json!("Reporting and NEL"));
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
        assert!(ev.attrs["recovery_note"]
            .as_str()
            .unwrap()
            .contains("history"));
    }

    #[test]
    fn sqlite_reporting_endpoint_surfaces_origin_and_collector() {
        let db = TestDb::new(NEL_SCHEMA);
        db.insert(
            "INSERT INTO reporting_endpoints (origin_host, group_name, url) \
             VALUES ('site.example.org', 'default', 'https://collector.thirdparty.net/report')",
            params![],
        );
        let events = parse_reporting_and_nel(db.path()).expect("parse");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.attrs["domain"], json!("site.example.org"));
        assert_eq!(
            ev.attrs["report_to_host"],
            json!("collector.thirdparty.net")
        );
    }

    #[test]
    fn legacy_json_nel_policies_recovered() {
        let f = write_json_file(
            r#"{"net":{"nel":{"policies":[
                {"origin":"https://legacy.example.com:443","report_to":"default"}
            ]}}}"#,
        );
        let events = parse_reporting_and_nel(f.path()).expect("parse");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["domain"], json!("legacy.example.com"));
    }

    #[test]
    fn empty_sqlite_store_returns_empty() {
        let db = TestDb::new(NEL_SCHEMA);
        assert!(parse_reporting_and_nel(db.path())
            .expect("parse")
            .is_empty());
    }

    #[test]
    fn malformed_json_returns_error() {
        let f = write_json_file("{not json");
        assert!(parse_reporting_and_nel(f.path()).is_err());
    }
}
