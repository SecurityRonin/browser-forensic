//! Chromium per-site permission grants from `Preferences` / `Secure Preferences`.
//!
//! Chromium stores every per-origin content setting under
//! `profile.content_settings.exceptions.<type>`, keyed by an origin pattern pair
//! (`"https://site:443,*"`). Each entry records the `setting` the user chose
//! (allow / block / ask …) and, usually, a `last_modified` WebKit-microsecond
//! timestamp — a dated, per-site record of a privacy decision.
//!
//! Every exception *type* present is surfaced (not a fixed allow-list), so new
//! or vendor-specific permission types appear automatically.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::{json, Value};

/// Map a Chromium `ContentSetting` integer to a human label.
/// (`components/content_settings/core/common/content_settings.h`.)
fn setting_label(setting: i64) -> &'static str {
    match setting {
        0 => "default",
        1 => "allow",
        2 => "block",
        3 => "ask",
        4 => "session_only",
        5 => "detect_important_content",
        _ => "unknown",
    }
}

/// Read a WebKit-microsecond value stored as a JSON string or number.
fn webkit_value(v: &Value) -> Option<i64> {
    match v {
        Value::String(s) => s.parse::<i64>().ok(),
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// Parse per-site permission grants from a Chromium `Preferences` (or
/// `Secure Preferences`) JSON file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not valid JSON.
pub fn parse_permissions(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read_to_string(path)?;
    let root: Value = serde_json::from_str(&data)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    let Some(exceptions) = root
        .pointer("/profile/content_settings/exceptions")
        .and_then(Value::as_object)
    else {
        return Ok(events);
    };

    for (perm_type, entries) in exceptions {
        let Some(entries) = entries.as_object() else {
            continue;
        };
        for (origin_pattern, entry) in entries {
            let setting = entry.get("setting").and_then(Value::as_i64);
            let last_modified = entry
                .get("last_modified")
                .and_then(webkit_value)
                .filter(|&us| us > 0);
            let ts_ns = last_modified.map_or(0, webkit_micros_to_unix_nanos);
            let label = setting.map_or("unspecified", setting_label);

            let mut ev = BrowserEvent::new(
                ts_ns,
                BrowserFamily::Chromium,
                ArtifactKind::Permission,
                &source,
                format!("{origin_pattern} — {perm_type} = {label}"),
            )
            .with_attr("origin", json!(origin_pattern))
            .with_attr("permission", json!(perm_type))
            .with_attr("setting_label", json!(label));
            if let Some(s) = setting {
                ev = ev.with_attr("setting", json!(s));
            }
            events.push(ev);
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
    fn extracts_notification_grant_with_timestamp() {
        // WebKit micros for 2023-11-14 22:13:20 UTC.
        let webkit = (1_700_000_000_i64 + 11_644_473_600) * 1_000_000;
        let f = write_prefs(&format!(
            r#"{{"profile":{{"content_settings":{{"exceptions":{{
                "notifications":{{
                    "https://mail.example.com:443,*":{{"setting":1,"last_modified":"{webkit}"}}
                }}
            }}}}}}}}"#
        ));
        let events = parse_permissions(f.path()).expect("parse");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Permission);
        assert_eq!(ev.attrs["permission"], json!("notifications"));
        assert_eq!(ev.attrs["origin"], json!("https://mail.example.com:443,*"));
        assert_eq!(ev.attrs["setting_label"], json!("allow"));
        assert_eq!(ev.attrs["setting"], json!(1));
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn block_setting_labelled_block() {
        let f = write_prefs(
            r#"{"profile":{"content_settings":{"exceptions":{
                "geolocation":{"https://tracker.example.com:443,*":{"setting":2}}
            }}}}"#,
        );
        let events = parse_permissions(f.path()).expect("parse");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["setting_label"], json!("block"));
        assert_eq!(events[0].timestamp_ns, 0);
    }

    #[test]
    fn surfaces_all_permission_types_generally() {
        let f = write_prefs(
            r#"{"profile":{"content_settings":{"exceptions":{
                "media_stream_camera":{"https://a.example.com:443,*":{"setting":1}},
                "media_stream_mic":{"https://a.example.com:443,*":{"setting":2}},
                "cookies":{"https://b.example.com:443,*":{"setting":1}},
                "some_future_permission":{"https://c.example.com:443,*":{"setting":1}}
            }}}}"#,
        );
        let events = parse_permissions(f.path()).expect("parse");
        assert_eq!(events.len(), 4);
        let perms: std::collections::HashSet<_> = events
            .iter()
            .map(|e| e.attrs["permission"].as_str().unwrap().to_string())
            .collect();
        assert!(perms.contains("media_stream_camera"));
        assert!(perms.contains("some_future_permission"));
    }

    #[test]
    fn no_content_settings_returns_empty() {
        let f = write_prefs(r#"{"profile":{"name":"Default"}}"#);
        assert!(parse_permissions(f.path()).expect("parse").is_empty());
    }

    #[test]
    fn malformed_json_returns_error() {
        let f = write_prefs("{not json");
        assert!(parse_permissions(f.path()).is_err());
    }
}
