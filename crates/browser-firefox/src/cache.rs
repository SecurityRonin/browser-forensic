//! Firefox cache2 parser (best-effort).
//!
//! Walks the `cache2/entries/` directory and attempts to extract URLs
//! from the metadata sections of cache entry files.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Firefox `cache2/entries/` directory (best-effort).
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
        create_ff_cache_file(&dir, "ABCDEF1234567890ABCDEF", "https://example.com/style.css");
        let events = parse_cache(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.artifact, ArtifactKind::Cache);
        let url = ev.attrs["url"].as_str().unwrap();
        assert!(url.contains("http"));
    }
}
