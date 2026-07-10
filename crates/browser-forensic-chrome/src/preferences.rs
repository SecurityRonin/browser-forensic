//! Chromium `Preferences` / `Secure Preferences` JSON parser.
//!
//! Extracts a curated set of forensically interesting settings — homepage,
//! startup URLs, download directory, signed-in accounts, and the
//! **last-clear-browsing-data time** (a strong history-clearing signal) — from
//! the profile's `Preferences` JSON file.

use std::path::Path;

use anyhow::Result;
#[allow(unused_imports)]
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
#[allow(unused_imports)]
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
#[allow(unused_imports)]
use serde_json::json;

/// Parse a Chromium `Preferences` (or `Secure Preferences`) JSON file.
///
/// Emits one [`BrowserEvent`] per extracted setting. WebKit-microsecond time
/// preferences (`profile.creation_time`,
/// `browser.last_clear_browsing_data_time`) carry a real event timestamp.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not valid JSON.
#[allow(unused_variables)]
pub fn parse_preferences(_path: &Path) -> Result<Vec<BrowserEvent>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_prefs(json_data: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");
        f
    }

    #[test]
    fn extracts_homepage_and_download_dir() {
        let f = write_prefs(
            r#"{
                "homepage": "https://start.example.com/",
                "download": {"default_directory": "/home/u/Downloads"}
            }"#,
        );
        let events = parse_preferences(f.path()).expect("parse");
        assert!(events
            .iter()
            .any(|e| e.description.contains("https://start.example.com/")));
        assert!(events
            .iter()
            .any(|e| e.description.contains("/home/u/Downloads")));
        assert!(events
            .iter()
            .all(|e| e.artifact == ArtifactKind::Preferences));
    }

    #[test]
    fn extracts_account_info() {
        let f = write_prefs(
            r#"{"account_info": [
                {"email": "suspect@example.com", "full_name": "A Suspect", "gaia": "1234567890"}
            ]}"#,
        );
        let events = parse_preferences(f.path()).expect("parse");
        assert!(events
            .iter()
            .any(|e| e.description.contains("suspect@example.com")));
    }

    #[test]
    fn last_clear_browsing_data_time_carries_timestamp() {
        // WebKit micros for 2023-11-14 22:13:20 UTC = (1700000000 + 11644473600) * 1e6
        let webkit = (1_700_000_000_i64 + 11_644_473_600) * 1_000_000;
        let f = write_prefs(&format!(
            r#"{{"browser": {{"last_clear_browsing_data_time": "{webkit}"}}}}"#
        ));
        let events = parse_preferences(f.path()).expect("parse");
        let ev = events
            .iter()
            .find(|e| e.description.contains("last_clear_browsing_data_time"))
            .expect("clear-data event present");
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn empty_prefs_returns_empty() {
        let f = write_prefs("{}");
        let events = parse_preferences(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn missing_file_returns_error() {
        assert!(parse_preferences(Path::new("/nonexistent/Preferences")).is_err());
    }
}
