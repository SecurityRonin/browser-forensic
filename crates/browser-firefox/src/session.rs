//! Firefox `sessionstore.jsonlz4` parser.
//!
//! Reads Firefox session state from the mozLz4 compressed file and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Session`] for each open tab.

use std::path::Path;

use anyhow::{anyhow, Result};
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// The magic bytes at the start of a Firefox sessionstore file.
const MOZLZ4_MAGIC: &[u8; 8] = b"mozLz40\0";

/// Parse a Firefox `sessionstore.jsonlz4` file.
///
/// # Errors
///
/// Returns an error if the file cannot be read, has wrong magic, or decompression fails.
pub fn parse_session(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read(path)?;

    if data.len() < 12 {
        return Err(anyhow!("file too short to be a valid mozLz4 file"));
    }

    if &data[..8] != MOZLZ4_MAGIC {
        return Err(anyhow!("invalid mozLz4 magic bytes"));
    }

    let uncompressed_size = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    let decompressed = lz4_flex::block::decompress(&data[12..], uncompressed_size)
        .map_err(|e| anyhow!("LZ4 decompression failed: {e}"))?;

    let session: serde_json::Value = serde_json::from_slice(&decompressed)?;

    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    if let Some(windows) = session.get("windows").and_then(|w| w.as_array()) {
        for window in windows {
            if let Some(tabs) = window.get("tabs").and_then(|t| t.as_array()) {
                for tab in tabs {
                    let last_accessed_ms = tab.get("lastAccessed")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    let ts_ns = last_accessed_ms * 1_000_000;

                    // Take last entry from entries array
                    let entries = tab.get("entries").and_then(|e| e.as_array());
                    if let Some(entries) = entries {
                        if let Some(entry) = entries.last() {
                            let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let title = entry.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let desc = if title.is_empty() { url.clone() } else { title.clone() };
                            let ev = BrowserEvent::new(ts_ns, BrowserFamily::Firefox, ArtifactKind::Session, &source, desc)
                                .with_attr("url", json!(url))
                                .with_attr("title", json!(title));
                            events.push(ev);
                        }
                    }
                }
            }
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_mozlz4_file(json_value: &serde_json::Value) -> NamedTempFile {
        let json_bytes = json_value.to_string().into_bytes();
        let uncompressed_size = json_bytes.len() as u32;
        let compressed = lz4_flex::block::compress(&json_bytes);

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(MOZLZ4_MAGIC).unwrap();
        f.write_all(&uncompressed_size.to_le_bytes()).unwrap();
        f.write_all(&compressed).unwrap();
        f
    }

    #[test]
    fn parse_empty_session_returns_empty() {
        let session_json = json!({
            "windows": [{
                "tabs": []
            }]
        });
        let f = create_mozlz4_file(&session_json);
        let events = parse_session(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_session_with_single_tab() {
        let last_accessed_ms = 1_648_000_000_000_i64;
        let session_json = json!({
            "windows": [{
                "tabs": [{
                    "lastAccessed": last_accessed_ms,
                    "entries": [{
                        "url": "https://example.com",
                        "title": "Example"
                    }]
                }]
            }]
        });
        let f = create_mozlz4_file(&session_json);
        let events = parse_session(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.artifact, ArtifactKind::Session);
        assert_eq!(ev.attrs["url"], json!("https://example.com"));
        assert_eq!(ev.timestamp_ns, last_accessed_ms * 1_000_000);
    }

    #[test]
    fn parse_session_invalid_magic_fails() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"INVALID_MAGIC_BYTES_HERE").unwrap();
        let result = parse_session(f.path());
        assert!(result.is_err());
    }
}
