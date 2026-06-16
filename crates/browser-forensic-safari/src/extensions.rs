//! Safari `Extensions/Extensions.plist` parser.
//!
//! Reads installed Safari extensions and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Extensions`].

use std::path::Path;

use anyhow::{anyhow, Result};
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Safari `Extensions/Extensions.plist` file.
///
/// # Errors
///
/// Returns an error if the plist file cannot be opened or parsed.
pub fn parse_extensions(path: &Path) -> Result<Vec<BrowserEvent>> {
    let value = plist::Value::from_file(path)?;
    let root = value
        .as_dictionary()
        .ok_or_else(|| anyhow!("plist root is not a dictionary"))?;
    let installed = root
        .get("Installed Extensions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("Installed Extensions not found or not an array"))?;

    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    for entry in installed {
        let dict = match entry.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        let bundle_name = dict
            .get("Bundle Directory Name")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let enabled = dict
            .get("Enabled")
            .and_then(plist::Value::as_boolean)
            .unwrap_or(false);

        let ev = BrowserEvent::new(
            0,
            BrowserFamily::Safari,
            ArtifactKind::Extensions,
            &source,
            bundle_name.clone(),
        )
        .with_attr("bundle_name", json!(bundle_name))
        .with_attr("enabled", json!(enabled));
        events.push(ev);
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use plist::Value;
    use serde_json::json;
    use std::collections::BTreeMap;
    use tempfile::NamedTempFile;

    fn create_extensions_plist(entries: &[(&str, bool)]) -> NamedTempFile {
        // entries: (bundle_dir_name, enabled)
        let ext_array: Vec<Value> = entries
            .iter()
            .map(|(bundle, enabled)| {
                let mut d: BTreeMap<String, Value> = BTreeMap::new();
                d.insert(
                    "Bundle Directory Name".to_string(),
                    Value::String((*bundle).to_string()),
                );
                d.insert("Enabled".to_string(), Value::Boolean(*enabled));
                d.insert(
                    "Archive File Name".to_string(),
                    Value::String(format!("{bundle}.safariextz")),
                );
                Value::Dictionary(d.into_iter().collect())
            })
            .collect();

        let mut root: BTreeMap<String, Value> = BTreeMap::new();
        root.insert("Installed Extensions".to_string(), Value::Array(ext_array));
        let root_value = Value::Dictionary(root.into_iter().collect());
        let f = NamedTempFile::new().unwrap();
        plist::to_file_binary(f.path(), &root_value).unwrap();
        f
    }

    #[test]
    fn parse_empty_extensions_plist() {
        let f = create_extensions_plist(&[]);
        let events = parse_extensions(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_safari_extension() {
        let f = create_extensions_plist(&[("com.example.MyExtension", true)]);
        let events = parse_extensions(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Safari);
        assert_eq!(ev.artifact, ArtifactKind::Extensions);
        assert_eq!(ev.attrs["bundle_name"], json!("com.example.MyExtension"));
        assert_eq!(ev.attrs["enabled"], json!(true));
    }
}
