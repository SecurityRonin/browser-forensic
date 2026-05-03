//! Firefox `logins.json` parser.
//!
//! Reads saved logins from `logins.json` and emits [`BrowserEvent`]s with
//! [`ArtifactKind::LoginData`].
//!
//! **Security note**: `encryptedPassword` is NEVER read or exposed.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Firefox `logins.json` file.
///
/// CRITICAL: `encryptedPassword` is never read or returned.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn parse_login_data(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_logins_json(logins: &serde_json::Value) -> NamedTempFile {
        let content = json!({ "logins": logins });
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.to_string().as_bytes()).unwrap();
        f
    }

    #[test]
    fn parse_empty_logins_returns_empty() {
        let f = create_logins_json(&json!([]));
        let events = parse_login_data(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn ff_login_password_never_exposed() {
        let f = create_logins_json(&json!([{
            "hostname": "https://example.com",
            "formSubmitURL": "https://example.com/login",
            "usernameField": "email",
            "encryptedPassword": "SHOULD_NEVER_APPEAR",
            "timeCreated": 1_648_000_000_000_i64
        }]));
        let events = parse_login_data(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["password"], json!("ENCRYPTED"));
        for (_k, v) in &events[0].attrs {
            assert_ne!(v, &json!("SHOULD_NEVER_APPEAR"));
        }
    }

    #[test]
    fn ff_login_emits_hostname() {
        let time_created_ms = 1_648_000_000_000_i64;
        let f = create_logins_json(&json!([{
            "hostname": "https://example.com",
            "formSubmitURL": "https://example.com/login",
            "usernameField": "email",
            "timeCreated": time_created_ms
        }]));
        let events = parse_login_data(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::LoginData);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["hostname"], json!("https://example.com"));
        assert_eq!(ev.timestamp_ns, time_created_ms * 1_000_000);
    }
}
