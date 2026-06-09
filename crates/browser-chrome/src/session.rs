//! Chromium SNSS session parser.
//!
//! Reads Chrome/Brave/Edge session state from the `SNSS` command stream
//! (`Session_*`/`Tabs_*`/`Apps_*` files, and the modern `Sessions/` folder) via
//! the `snss` decoder and emits [`BrowserEvent`]s with [`ArtifactKind::Session`]
//! — one per open (or recently-closed) tab's current entry. This is the fleet's
//! Chromium counterpart to [`crate`]'s Firefox `sessionstore` reader.

use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{anyhow, Result};
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Chromium SNSS session/tabs file into [`BrowserEvent`]s.
///
/// The dialect is chosen from the file name: `Tabs_*` files are the recently-
/// closed restore list (navigation command id 1); everything else (`Session_*`,
/// `Apps_*`) uses the live-window dialect (command id 6).
///
/// # Errors
/// Returns an error if the file cannot be read or is not a valid SNSS container.
pub fn parse_session(path: &Path) -> Result<Vec<BrowserEvent>> {
    let bytes = std::fs::read(path)?;
    let stream = snss::read_records(&bytes[..]).map_err(|e| anyhow!("SNSS decode: {e}"))?;

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let dialect = if name.starts_with("Tabs") {
        snss::Dialect::Tabs
    } else {
        snss::Dialect::Session
    };
    let replayed = snss::replay(&stream, dialect);

    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();
    for window in &replayed.windows {
        let ts_ns = window
            .last_active
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        for tab in &window.tabs {
            let Some(nav) = tab.history.get(tab.current) else {
                continue;
            };
            let desc = if nav.title.is_empty() {
                nav.url.clone()
            } else {
                nav.title.clone()
            };
            events.push(
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Chromium,
                    ArtifactKind::Session,
                    &source,
                    desc,
                )
                .with_attr("url", json!(nav.url))
                .with_attr("title", json!(nav.title))
                .with_attr("tab_id", json!(tab.id))
                .with_attr("window_id", json!(window.id))
                .with_attr("pinned", json!(tab.pinned))
                .with_attr("index", json!(nav.index)),
            );
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::path::PathBuf;

    fn pad4(v: &mut Vec<u8>) {
        while v.len() % 4 != 0 {
            v.push(0);
        }
    }

    /// Encode an UpdateTabNavigation Pickle payload (4-byte LE length header +
    /// 4-byte-aligned tab_id, index, UTF-8 url, UTF-16-LE title).
    fn nav_payload(tab_id: i32, index: i32, url: &str, title: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&tab_id.to_le_bytes());
        body.extend_from_slice(&index.to_le_bytes());
        body.extend_from_slice(&(url.len() as i32).to_le_bytes());
        body.extend_from_slice(url.as_bytes());
        pad4(&mut body);
        let units: Vec<u16> = title.encode_utf16().collect();
        body.extend_from_slice(&(units.len() as i32).to_le_bytes());
        for u in &units {
            body.extend_from_slice(&u.to_le_bytes());
        }
        pad4(&mut body);
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// Assemble an SNSS v3 file from `(command_id, payload)` records.
    fn snss_bytes(records: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = b"SNSS".to_vec();
        out.extend_from_slice(&3i32.to_le_bytes());
        for (id, payload) in records {
            let size = (payload.len() + 1) as u16;
            out.extend_from_slice(&size.to_le_bytes());
            out.push(*id);
            out.extend_from_slice(payload);
        }
        out
    }

    fn write_snss(dir: &Path, name: &str, records: &[(u8, Vec<u8>)]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, snss_bytes(records)).unwrap();
        p
    }

    #[test]
    fn parse_session_emits_event_per_open_tab() {
        let dir = tempfile::tempdir().unwrap();
        // Session dialect (nav cmd id 6): two tabs, one current entry each.
        let p = write_snss(
            dir.path(),
            "Session_123",
            &[
                (6, nav_payload(10, 0, "https://a.example", "Alpha")),
                (6, nav_payload(11, 0, "https://b.example", "Beta")),
            ],
        );
        let events = parse_session(&p).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.browser == BrowserFamily::Chromium));
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::Session));
        assert!(events.iter().all(|e| e.attrs.contains_key("tab_id")));
        let urls: Vec<String> = events
            .iter()
            .map(|e| e.attrs["url"].as_str().unwrap().to_string())
            .collect();
        assert!(urls.contains(&"https://a.example".to_string()));
        assert!(urls.contains(&"https://b.example".to_string()));
    }

    #[test]
    fn parse_session_decodes_tabs_dialect_recently_closed() {
        let dir = tempfile::tempdir().unwrap();
        // Tabs dialect uses nav cmd id 1.
        let p = write_snss(
            dir.path(),
            "Tabs_456",
            &[(1, nav_payload(20, 0, "https://closed.example", "Closed"))],
        );
        let events = parse_session(&p).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["url"], json!("https://closed.example"));
        assert_eq!(events[0].artifact, ArtifactKind::Session);
    }

    #[test]
    fn parse_session_invalid_magic_fails() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Session_789");
        std::fs::write(&p, b"NOT-SNSS-DATA-AT-ALL").unwrap();
        assert!(parse_session(&p).is_err());
    }
}
