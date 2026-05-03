//! Chromium-family browser extensions parser.
//!
//! Walks the `Extensions/` directory and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Extensions`] for each installed extension.

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Chromium `Extensions/` directory.
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub fn parse_extensions(_extensions_dir: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    fn create_extension(dir: &TempDir, id: &str, version: &str, manifest: &serde_json::Value) {
        let ext_path = dir.path().join(id).join(version);
        fs::create_dir_all(&ext_path).unwrap();
        let manifest_path = ext_path.join("manifest.json");
        fs::write(&manifest_path, manifest.to_string()).unwrap();
    }

    #[test]
    fn parse_empty_extensions_dir() {
        let dir = TempDir::new().unwrap();
        let events = parse_extensions(dir.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_extension() {
        let dir = TempDir::new().unwrap();
        create_extension(&dir, "abcdefghijk", "1.0.0", &json!({
            "name": "My Extension",
            "version": "1.0.0",
            "description": "A test extension",
            "permissions": ["tabs", "storage"]
        }));
        let events = parse_extensions(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Extensions);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs["name"], json!("My Extension"));
        assert_eq!(ev.attrs["version"], json!("1.0.0"));
        assert_eq!(ev.attrs["id"], json!("abcdefghijk"));
    }

    #[test]
    fn parse_highest_version_only() {
        let dir = TempDir::new().unwrap();
        let id = "testextension";
        create_extension(&dir, id, "1.0.0", &json!({
            "name": "Old Version",
            "version": "1.0.0",
            "description": ""
        }));
        create_extension(&dir, id, "2.0.0", &json!({
            "name": "New Version",
            "version": "2.0.0",
            "description": ""
        }));
        let events = parse_extensions(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["name"], json!("New Version"));
    }
}
