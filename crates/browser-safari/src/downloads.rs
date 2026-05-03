//! Safari `Downloads.plist` parser.
//!
//! Reads Safari download history from `Downloads.plist` and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Downloads`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

use crate::history::safari_to_unix_ns;

/// Parse a Safari `Downloads.plist` file.
///
/// # Errors
///
/// Returns an error if the plist file cannot be opened or parsed.
pub fn parse_downloads(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use plist::Value;
    use serde_json::json;
    use std::collections::BTreeMap;
    use tempfile::NamedTempFile;

    fn create_safari_downloads_plist(entries: &[(&str, &str, f64, i64)]) -> NamedTempFile {
        // entries: (url, path, date_added_core_data, total_bytes)
        let mut download_array: Vec<Value> = Vec::new();
        for (url, path, date_added, total_bytes) in entries {
            let mut dict: BTreeMap<String, Value> = BTreeMap::new();
            dict.insert("DownloadEntryURL".to_string(), Value::String(url.to_string()));
            dict.insert("DownloadEntryPath".to_string(), Value::String(path.to_string()));
            dict.insert("DownloadEntryDateAddedKey".to_string(), Value::Real(*date_added));
            dict.insert("DownloadEntryProgressTotalToLoad".to_string(), Value::Integer((*total_bytes).into()));
            download_array.push(Value::Dictionary(dict.into_iter().collect()));
        }
        let mut root: BTreeMap<String, Value> = BTreeMap::new();
        root.insert("DownloadHistory".to_string(), Value::Array(download_array));
        let root_value = Value::Dictionary(root.into_iter().collect());
        let f = NamedTempFile::new().unwrap();
        plist::to_file_binary(f.path(), &root_value).unwrap();
        f
    }

    #[test]
    fn parse_empty_safari_downloads() {
        let f = create_safari_downloads_plist(&[]);
        let events = parse_downloads(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_safari_download() {
        let f = create_safari_downloads_plist(&[(
            "https://example.com/file.zip",
            "/Users/test/Downloads/file.zip",
            700_000_000.0,
            1024,
        )]);
        let events = parse_downloads(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Safari);
        assert_eq!(ev.artifact, ArtifactKind::Downloads);
        assert_eq!(ev.attrs["url"], json!("https://example.com/file.zip"));
        assert_eq!(ev.timestamp_ns, safari_to_unix_ns(700_000_000.0));
    }
}
