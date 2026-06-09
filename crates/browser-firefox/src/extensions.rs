//! Firefox `extensions.json` parser.
//!
//! Reads installed add-ons from `extensions.json` and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Extensions`].

use std::path::Path;

use anyhow::Result;
use browser_core::timestamp::unix_millis_to_nanos;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Firefox `extensions.json` file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn parse_extensions(path: &Path) -> Result<Vec<BrowserEvent>> {
    let file = std::fs::File::open(path)?;
    let root: serde_json::Value = serde_json::from_reader(file)?;

    let addons = match root.get("addons").and_then(|a| a.as_array()) {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };

    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    for addon in addons {
        let id = addon
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = addon
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = addon
            .get("defaultLocale")
            .and_then(|dl| dl.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let install_date_ms = addon
            .get("installDate")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let ts_ns = unix_millis_to_nanos(install_date_ms);
        let desc = format!("{name} v{version}");
        let ev = BrowserEvent::new(
            ts_ns,
            BrowserFamily::Firefox,
            ArtifactKind::Extensions,
            &source,
            desc,
        )
        .with_attr("id", json!(id))
        .with_attr("name", json!(name))
        .with_attr("version", json!(version));
        events.push(ev);
    }

    Ok(events)
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
