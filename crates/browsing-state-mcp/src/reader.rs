//! Collect normalized [`Record`]s from the local profile using **only** the
//! non-secret readers. This module imports `browser_chrome::parse_visits` and
//! `browser_chrome::parse_session` and nothing else from the artifact crates —
//! the cookie/login/autofill readers are never named here, so the MCP cannot
//! serve a secret (wall 1).

use std::path::Path;

use anyhow::Result;

use crate::context::{Record, RecordKind};

/// Build [`Record`]s from a Chromium `History` DB (the `visits` table).
pub fn records_from_history(path: &Path) -> Result<Vec<Record>> {
    let _ = path;
    todo!("implemented in the GREEN step")
}

/// Build [`Record`]s from a Chromium SNSS session/tabs file.
pub fn records_from_session(path: &Path) -> Result<Vec<Record>> {
    let _ = path;
    todo!("implemented in the GREEN step")
}

/// Discover the default profiles and collect history + session records. Best
/// effort: unreadable files are skipped. I/O glue (exercised when the server runs).
pub fn collect_default() -> Result<Vec<Record>> {
    todo!("implemented in the GREEN step")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::test_utils::sqlite::TestDb;
    use std::path::PathBuf;

    const SCHEMA: &str = "
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
            from_visit INTEGER, transition INTEGER NOT NULL, visit_duration INTEGER);
    ";

    #[test]
    fn records_from_history_maps_visits_with_redirect_flag() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO urls (id,url,title,visit_count,last_visit_time) \
             VALUES (1,'https://example.com','Example',1,13327626000000000)",
            [],
        );
        db.insert(
            "INSERT INTO visits (url,visit_time,from_visit,transition,visit_duration) \
             VALUES (1,13327626000000000,0,?1,0)",
            [0x8000_0000_i64], // SERVER_REDIRECT
        );
        let recs = records_from_history(db.path()).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].kind, RecordKind::Visit);
        assert_eq!(recs[0].url, "https://example.com");
        assert!(recs[0].is_redirect, "redirect flag mapped from attrs");
        assert_eq!(recs[0].source, "history.visits");
        assert!(recs[0].time_ns > 0);
    }

    // Minimal SNSS builder (header + one UpdateTabNavigation pickle).
    fn nav_payload(tab_id: i32, url: &str, title: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&tab_id.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&(url.len() as i32).to_le_bytes());
        body.extend_from_slice(url.as_bytes());
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let units: Vec<u16> = title.encode_utf16().collect();
        body.extend_from_slice(&(units.len() as i32).to_le_bytes());
        for u in &units {
            body.extend_from_slice(&u.to_le_bytes());
        }
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    fn write_session(dir: &Path, name: &str, cmd_id: u8, payload: Vec<u8>) -> PathBuf {
        let mut bytes = b"SNSS".to_vec();
        bytes.extend_from_slice(&3i32.to_le_bytes());
        let size = (payload.len() + 1) as u16;
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.push(cmd_id);
        bytes.extend_from_slice(&payload);
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn records_from_session_maps_open_tabs() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_session(dir.path(), "Session_1", 6, nav_payload(10, "https://tab.example", "Tab"));
        let recs = records_from_session(&p).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].kind, RecordKind::OpenTab);
        assert_eq!(recs[0].url, "https://tab.example");
        assert_eq!(recs[0].source, "snss");
    }
}
