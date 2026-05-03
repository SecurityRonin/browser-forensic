//! Chromium-family browser cache parser (best-effort).
//!
//! Walks the `Cache/` directory and attempts to extract URLs from
//! SimpleCache EOF records.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Chromium `Cache/` directory (best-effort).
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub fn parse_cache(_cache_dir: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    /// Create a fake cache entry file with a URL embedded before the EOF record.
    fn create_cache_file(dir: &TempDir, filename: &str, url: &str) {
        // Structure: [padding...] [url bytes] [24-byte EOF record]
        // EOF record bytes 8-12 = key_size (u32 LE)
        let key_size = url.len() as u32;
        let mut eof_record = vec![0u8; 24];
        // bytes 8-12 = key_size
        eof_record[8..12].copy_from_slice(&key_size.to_le_bytes());

        let mut content = Vec::new();
        // Some padding before the key
        content.extend_from_slice(b"\x00\x00\x00\x00");
        content.extend_from_slice(url.as_bytes());
        content.extend_from_slice(&eof_record);

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
    fn parse_cache_extracts_url_from_entry() {
        let dir = TempDir::new().unwrap();
        create_cache_file(&dir, "abcdef1234567890", "https://example.com/resource.js");
        let events = parse_cache(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.artifact, ArtifactKind::Cache);
        assert_eq!(ev.attrs["url"], json!("https://example.com/resource.js"));
    }
}
