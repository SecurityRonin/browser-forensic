//! Chromium-family browser cache parser (best-effort).
//!
//! Walks the `Cache/` directory and attempts to extract URLs from
//! `SimpleCache` EOF records.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Chromium `Cache/` directory (best-effort).
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

    for entry in entries.filter_map(std::result::Result::ok) {
        let file_path = entry.path();
        // Only walk immediate files, not subdirectories
        if !file_path.is_file() {
            continue;
        }

        let data = match std::fs::read(&file_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let file_len = data.len();
        if file_len < 24 {
            continue;
        }

        // EOF record is last 24 bytes
        let eof_start = file_len - 24;
        let eof_record = &data[eof_start..];

        // Bytes 8-12 of EOF record = key_size as u32 LE. `eof_record` is the
        // trailing 24 bytes (guaranteed by the `file_len < 24` guard above), so
        // `[8..12]` is always exactly 4 bytes; the fallback never fires.
        let key_size =
            u32::from_le_bytes(eof_record[8..12].try_into().unwrap_or([0u8; 4])) as usize;

        if key_size == 0 || key_size > 8192 {
            continue;
        }

        if eof_start < key_size {
            continue;
        }

        let key_start = eof_start - key_size;
        let key_bytes = &data[key_start..eof_start];

        let url = match std::str::from_utf8(key_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        if !url.contains("http") {
            continue;
        }

        let ev = BrowserEvent::new(
            0,
            BrowserFamily::Chromium,
            ArtifactKind::Cache,
            &source,
            url.clone(),
        )
        .with_attr("url", json!(url));
        events.push(ev);
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
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
    fn truncated_entry_files_never_panic() {
        // A cache entry file truncated to any length — including lengths shorter
        // than the 24-byte EOF record the key_size read lives in — must be
        // skipped, not panic.
        let mut full = Vec::new();
        full.extend_from_slice(b"\x00\x00\x00\x00https://example.com/resource.js");
        let mut eof_record = vec![0u8; 24];
        eof_record[8..12]
            .copy_from_slice(&("https://example.com/resource.js".len() as u32).to_le_bytes());
        full.extend_from_slice(&eof_record);
        for len in 0..=full.len() {
            let dir = TempDir::new().unwrap();
            fs::write(dir.path().join("entry0001"), &full[..len]).unwrap();
            let _ = parse_cache(dir.path()).unwrap();
        }
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
