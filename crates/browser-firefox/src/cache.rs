//! Firefox cache2 parser (best-effort).
//!
//! Walks the `cache2/entries/` directory and attempts to extract URLs
//! from the metadata sections of cache entry files.

use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Firefox `cache2/entries/` directory (best-effort).
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub fn parse_cache(cache_dir: &Path) -> Result<Vec<BrowserEvent>> {
    let source = cache_dir.to_string_lossy().into_owned();
    let mut events = Vec::new();

    let entries = match std::fs::read_dir(cache_dir) {
        Ok(e) => e,
        Err(_) => return Ok(events),
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let file_path = entry.path();
        if !file_path.is_file() {
            continue;
        }

        let data = match std::fs::read(&file_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let file_len = data.len();
        if file_len < 4 {
            continue;
        }

        // Last 4 bytes = metadata offset (big-endian u32)
        let metadata_offset = u32::from_be_bytes(data[file_len - 4..].try_into().unwrap()) as usize;

        if metadata_offset >= file_len - 4 {
            continue;
        }

        let metadata = &data[metadata_offset..file_len - 4];

        // Find "http" in metadata
        let http_needle = b"http";
        let http_pos = metadata
            .windows(http_needle.len())
            .position(|w| w == http_needle);

        if let Some(pos) = http_pos {
            let url_slice = &metadata[pos..];
            // Extract until null byte, newline, or end
            let end = url_slice
                .iter()
                .position(|&b| b == b'\0' || b == b'\n')
                .unwrap_or(url_slice.len());
            let url = match std::str::from_utf8(&url_slice[..end]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            let ev = BrowserEvent::new(
                0,
                BrowserFamily::Firefox,
                ArtifactKind::Cache,
                &source,
                url.clone(),
            )
            .with_attr("url", json!(url));
            events.push(ev);
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    /// Create a fake Firefox cache entry file.
    /// Structure: [header/data...] [metadata containing URL] [4-byte BE metadata offset]
    fn create_ff_cache_file(dir: &TempDir, filename: &str, url: &str) {
        let header = b"FAKE_DATA_BEFORE_METADATA\x00";
        let metadata = url.as_bytes();
        let metadata_offset = header.len() as u32;

        let mut content = Vec::new();
        content.extend_from_slice(header);
        content.extend_from_slice(metadata);
        content.extend_from_slice(&metadata_offset.to_be_bytes());

        let path = dir.path().join(filename);
        fs::write(path, content).unwrap();
    }

    #[test]
    fn parse_empty_cache_dir_returns_empty() {
        let dir = TempDir::new().unwrap();
        let events = parse_cache(dir.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_ff_cache_extracts_url() {
        let dir = TempDir::new().unwrap();
        create_ff_cache_file(
            &dir,
            "ABCDEF1234567890ABCDEF",
            "https://example.com/style.css",
        );
        let events = parse_cache(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.artifact, ArtifactKind::Cache);
        let url = ev.attrs["url"].as_str().unwrap();
        assert!(url.contains("http"));
    }
}
