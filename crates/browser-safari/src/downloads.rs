//! Safari `Downloads.plist` parser.
//!
//! Reads Safari download history from `Downloads.plist` and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Downloads`].

use std::path::Path;

use anyhow::{anyhow, Result};
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

use browser_core::timestamp::core_data_secs_to_unix_nanos;

/// Parse a Safari `Downloads.plist` file.
///
/// # Errors
///
/// Returns an error if the plist file cannot be opened or parsed.
pub fn parse_downloads(path: &Path) -> Result<Vec<BrowserEvent>> {
    let value = plist::Value::from_file(path)?;
    let root = value
        .as_dictionary()
        .ok_or_else(|| anyhow!("plist root is not a dictionary"))?;
    let history = root
        .get("DownloadHistory")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("DownloadHistory not found or not an array"))?;

    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    for entry in history {
        let dict = match entry.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        let url = dict
            .get("DownloadEntryURL")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let dl_path = dict
            .get("DownloadEntryPath")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let date_added = dict
            .get("DownloadEntryDateAddedKey")
            .and_then(|v| v.as_real())
            .unwrap_or(0.0);
        let total_bytes = dict
            .get("DownloadEntryProgressTotalToLoad")
            .and_then(|v| v.as_signed_integer())
            .unwrap_or(0);

        let ts_ns = core_data_secs_to_unix_nanos(date_added);
        let filename = std::path::Path::new(&dl_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| dl_path.clone());
        let desc = format!("{filename} from {url}");

        let ev = BrowserEvent::new(
            ts_ns,
            BrowserFamily::Safari,
            ArtifactKind::Downloads,
            &source,
            desc,
        )
        .with_attr("url", json!(url))
        .with_attr("path", json!(dl_path))
        .with_attr("total_bytes", json!(total_bytes));
        events.push(ev);
    }

    Ok(events)
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
            dict.insert(
                "DownloadEntryURL".to_string(),
                Value::String(url.to_string()),
            );
            dict.insert(
                "DownloadEntryPath".to_string(),
                Value::String(path.to_string()),
            );
            dict.insert(
                "DownloadEntryDateAddedKey".to_string(),
                Value::Real(*date_added),
            );
            dict.insert(
                "DownloadEntryProgressTotalToLoad".to_string(),
                Value::Integer((*total_bytes).into()),
            );
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
        assert_eq!(ev.timestamp_ns, core_data_secs_to_unix_nanos(700_000_000.0));
    }
}
