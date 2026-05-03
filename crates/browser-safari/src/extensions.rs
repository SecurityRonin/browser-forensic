//! Safari `Extensions/Extensions.plist` parser.
//!
//! Reads installed Safari extensions and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Extensions`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Safari `Extensions/Extensions.plist` file.
///
/// # Errors
///
/// Returns an error if the plist file cannot be opened or parsed.
pub fn parse_extensions(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use plist::Value;
    use serde_json::json;
    use std::collections::BTreeMap;
    use tempfile::NamedTempFile;

    fn create_extensions_plist(entries: &[(&str, bool)]) -> NamedTempFile {
        // entries: (bundle_dir_name, enabled)
        let ext_array: Vec<Value> = entries.iter().map(|(bundle, enabled)| {
            let mut d: BTreeMap<String, Value> = BTreeMap::new();
            d.insert("Bundle Directory Name".to_string(), Value::String(bundle.to_string()));
            d.insert("Enabled".to_string(), Value::Boolean(*enabled));
            d.insert("Archive File Name".to_string(), Value::String(format!("{bundle}.safariextz")));
            Value::Dictionary(d.into_iter().collect())
        }).collect();

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
