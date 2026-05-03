//! Firefox `extensions.json` parser.
//!
//! Reads installed add-ons from `extensions.json` and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Extensions`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Firefox `extensions.json` file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn parse_extensions(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_extensions_json(addons: &serde_json::Value) -> NamedTempFile {
        let content = json!({ "addons": addons });
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.to_string().as_bytes()).unwrap();
        f
    }

    #[test]
    fn parse_empty_addons_array() {
        let f = create_extensions_json(&json!([]));
        let events = parse_extensions(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_firefox_addon() {
        let install_date_ms = 1_648_000_000_000_i64;
        let f = create_extensions_json(&json!([{
            "id": "uBlock0@raymondhill.net",
            "version": "1.44.0",
            "defaultLocale": {"name": "uBlock Origin"},
            "installDate": install_date_ms
        }]));
        let events = parse_extensions(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Extensions);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["name"], json!("uBlock Origin"));
        assert_eq!(ev.attrs["version"], json!("1.44.0"));
        assert_eq!(ev.timestamp_ns, install_date_ms * 1_000_000);
    }
}
