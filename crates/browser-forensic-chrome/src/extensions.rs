//! Chromium-family browser extensions parser.
//!
//! Walks the `Extensions/` directory and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Extensions`] for each installed extension.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Chromium `Extensions/` directory.
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub fn parse_extensions(extensions_dir: &Path) -> Result<Vec<BrowserEvent>> {
    let source = extensions_dir.to_string_lossy().into_owned();
    let mut events = Vec::new();

    let entries = match std::fs::read_dir(extensions_dir) {
        Ok(e) => e,
        Err(_) => return Ok(events),
    };

    for entry in entries.filter_map(std::result::Result::ok) {
        let id_path = entry.path();
        if !id_path.is_dir() {
            continue;
        }
        let ext_id = id_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        // Find the highest-version subdirectory (sort by name, take last)
        let mut versions: Vec<std::path::PathBuf> = match std::fs::read_dir(&id_path) {
            Ok(v) => v
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect(),
            Err(_) => continue,
        };
        versions.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
        let version_dir = match versions.last() {
            Some(v) => v.clone(),
            None => continue,
        };

        let manifest_path = version_dir.join("manifest.json");
        let manifest_file = match std::fs::File::open(&manifest_path) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let manifest: serde_json::Value = match serde_json::from_reader(manifest_file) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let name = manifest
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = manifest
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let description = manifest
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Use mtime of manifest.json as timestamp (0 if unavailable)
        let ts_ns = std::fs::metadata(&manifest_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as i64);

        let desc = format!("{name} v{version}");
        let ev = BrowserEvent::new(
            ts_ns,
            BrowserFamily::Chromium,
            ArtifactKind::Extensions,
            &source,
            desc,
        )
        .with_attr("name", json!(name))
        .with_attr("version", json!(version))
        .with_attr("id", json!(ext_id))
        .with_attr("description", json!(description));
        events.push(ev);
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
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
        create_extension(
            &dir,
            "abcdefghijk",
            "1.0.0",
            &json!({
                "name": "My Extension",
                "version": "1.0.0",
                "description": "A test extension",
                "permissions": ["tabs", "storage"]
            }),
        );
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
        create_extension(
            &dir,
            id,
            "1.0.0",
            &json!({
                "name": "Old Version",
                "version": "1.0.0",
                "description": ""
            }),
        );
        create_extension(
            &dir,
            id,
            "2.0.0",
            &json!({
                "name": "New Version",
                "version": "2.0.0",
                "description": ""
            }),
        );
        let events = parse_extensions(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["name"], json!("New Version"));
    }
}
