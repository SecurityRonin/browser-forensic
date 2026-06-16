//! Chrome Local State JSON parser.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Chrome `Local State` JSON file.
///
/// Extracts profile metadata from `profile.info_cache`, including
/// profile names, associated email addresses, and last active times.
pub fn parse_local_state(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&data)?;

    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    if let Some(info_cache) = root
        .get("profile")
        .and_then(|p| p.get("info_cache"))
        .and_then(|ic| ic.as_object())
    {
        for (profile_dir, info) in info_cache {
            let name = info
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("Unknown");
            let user_name = info.get("user_name").and_then(|u| u.as_str()).unwrap_or("");
            let active_time = info
                .get("active_time")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            let ts_ns = browser_forensic_core::timestamp::unix_secs_to_nanos(active_time as i64);

            let desc = if user_name.is_empty() {
                format!("Profile {profile_dir}: {name}")
            } else {
                format!("Profile {profile_dir}: {name} ({user_name})")
            };

            events.push(
                BrowserEvent::new(
                    ts_ns,
                    BrowserFamily::Chromium,
                    ArtifactKind::Session,
                    &source,
                    desc,
                )
                .with_attr("profile_dir", json!(profile_dir))
                .with_attr("profile_name", json!(name))
                .with_attr("user_name", json!(user_name))
                .with_attr("active_time", json!(active_time)),
            );
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::ArtifactKind;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_local_state_extracts_profiles() {
        let json_data = r#"{
            "profile": {
                "info_cache": {
                    "Default": {
                        "name": "Person 1",
                        "user_name": "user@example.com",
                        "is_using_default_name": false,
                        "active_time": 1700000000.0
                    },
                    "Profile 1": {
                        "name": "Work",
                        "user_name": "work@example.com",
                        "is_using_default_name": false,
                        "active_time": 1700000001.0
                    }
                },
                "last_used": "Default"
            }
        }"#;
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");

        let events = parse_local_state(f.path()).expect("parse");
        assert!(!events.is_empty(), "should extract profile events");
        assert!(events.iter().any(|e| e.description.contains("Person 1")));
        assert!(events.iter().any(|e| e.description.contains("Work")));
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::Session));
    }

    #[test]
    fn parse_local_state_empty_profiles_returns_empty() {
        let json_data = r#"{"profile": {"info_cache": {}}}"#;
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");

        let events = parse_local_state(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_local_state_missing_file_returns_error() {
        let result = parse_local_state(std::path::Path::new("/nonexistent/Local State"));
        assert!(result.is_err());
    }
}
