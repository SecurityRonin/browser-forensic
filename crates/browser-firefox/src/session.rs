//! Firefox `sessionstore.jsonlz4` parser.
//!
//! Reads Firefox session state from the mozLz4 compressed file and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Session`] for each open tab.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// The magic bytes at the start of a Firefox sessionstore file.
const MOZLZ4_MAGIC: &[u8; 8] = b"mozLz40\0";

/// Parse a Firefox `sessionstore.jsonlz4` file.
///
/// # Errors
///
/// Returns an error if the file cannot be read, has wrong magic, or decompression fails.
pub fn parse_session(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
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
