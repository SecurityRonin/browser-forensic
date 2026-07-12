//! Chromium per-site permission grants (RED stub).

use std::path::Path;

use anyhow::Result;
#[cfg(test)]
use browser_forensic_core::ArtifactKind;
use browser_forensic_core::BrowserEvent;
#[cfg(test)]
use serde_json::json;

/// RED stub — returns nothing until the GREEN implementation lands.
///
/// # Errors
/// Never errors in the stub.
pub fn parse_permissions(_path: &Path) -> Result<Vec<BrowserEvent>> {
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
