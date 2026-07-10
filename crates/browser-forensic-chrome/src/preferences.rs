//! Chromium `Preferences` / `Secure Preferences` JSON parser.
//!
//! Extracts a curated set of forensically interesting settings — homepage,
//! startup URLs, download directory, signed-in accounts, and the
//! **last-clear-browsing-data time** (a strong history-clearing signal) — from
//! the profile's `Preferences` JSON file.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::{json, Value};

/// Scalar settings pulled by JSON pointer. `(pointer, label)`.
const SCALAR_PREFS: &[(&str, &str)] = &[
    ("/homepage", "homepage"),
    ("/homepage_is_newtabpage", "homepage_is_newtabpage"),
    ("/session/restore_on_startup", "session.restore_on_startup"),
    ("/download/default_directory", "download.default_directory"),
    ("/savefile/default_directory", "savefile.default_directory"),
    ("/profile/name", "profile.name"),
    ("/profile/created_by_version", "profile.created_by_version"),
    ("/profile/exit_type", "profile.exit_type"),
    (
        "/google/services/last_username",
        "google.services.last_username",
    ),
    (
        "/google/services/last_account_id",
        "google.services.last_account_id",
    ),
    ("/intl/accept_languages", "intl.accept_languages"),
    ("/intl/selected_languages", "intl.selected_languages"),
    (
        "/extensions/last_chrome_version",
        "extensions.last_chrome_version",
    ),
    ("/credentials_enable_service", "credentials_enable_service"),
    ("/autofill/enabled", "autofill.enabled"),
    ("/safebrowsing/enabled", "safebrowsing.enabled"),
];

/// Time settings (WebKit microseconds, stored as a string or number).
/// `(pointer, label)`.
const TIME_PREFS: &[(&str, &str)] = &[
    ("/profile/creation_time", "profile.creation_time"),
    (
        "/browser/last_clear_browsing_data_time",
        "browser.last_clear_browsing_data_time",
    ),
];

/// Read a WebKit-microsecond value that may be a JSON string or number.
fn webkit_value(v: &Value) -> Option<i64> {
    match v {
        Value::String(s) => s.parse::<i64>().ok(),
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// Render a scalar JSON value compactly for a description/attr.
fn scalar_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Parse a Chromium `Preferences` (or `Secure Preferences`) JSON file.
///
/// Emits one [`BrowserEvent`] per extracted setting. WebKit-microsecond time
/// preferences (`profile.creation_time`,
/// `browser.last_clear_browsing_data_time`) carry a real event timestamp.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not valid JSON.
pub fn parse_preferences(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read_to_string(path)?;
    let root: Value = serde_json::from_str(&data)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    let pref_event = |label: &str, value: String, ts_ns: i64| {
        BrowserEvent::new(
            ts_ns,
            BrowserFamily::Chromium,
            ArtifactKind::Preferences,
            &source,
            format!("{label} = {value}"),
        )
        .with_attr("key", json!(label))
        .with_attr("value", json!(value))
    };

    for (pointer, label) in SCALAR_PREFS {
        if let Some(v) = root.pointer(pointer) {
            events.push(pref_event(label, scalar_string(v), 0));
        }
    }
    for (pointer, label) in TIME_PREFS {
        if let Some(v) = root.pointer(pointer) {
            let ts_ns = webkit_value(v).map_or(0, webkit_micros_to_unix_nanos);
            events.push(pref_event(label, scalar_string(v), ts_ns));
        }
    }

    // Signed-in accounts: account_info is an array of {email, full_name, gaia}.
    if let Some(accounts) = root.get("account_info").and_then(Value::as_array) {
        for acct in accounts {
            let email = acct.get("email").and_then(Value::as_str).unwrap_or("");
            let full_name = acct.get("full_name").and_then(Value::as_str).unwrap_or("");
            let gaia = acct.get("gaia").and_then(Value::as_str).unwrap_or("");
            let desc = format!("account_info = {email} ({full_name}) gaia={gaia}");
            events.push(
                BrowserEvent::new(
                    0,
                    BrowserFamily::Chromium,
                    ArtifactKind::Preferences,
                    &source,
                    desc,
                )
                .with_attr("key", json!("account_info"))
                .with_attr("email", json!(email))
                .with_attr("full_name", json!(full_name))
                .with_attr("gaia", json!(gaia)),
            );
        }
    }

    // Session startup URLs: session.startup_urls is an array of strings.
    if let Some(urls) = root
        .pointer("/session/startup_urls")
        .and_then(Value::as_array)
    {
        for u in urls.iter().filter_map(Value::as_str) {
            events.push(pref_event("session.startup_urls", u.to_string(), 0));
        }
    }

    Ok(events)
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
