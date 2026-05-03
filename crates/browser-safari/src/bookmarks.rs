//! Safari `Bookmarks.plist` parser.
//!
//! Reads Safari bookmarks from `Bookmarks.plist` and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Bookmarks`].

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

/// Parse a Safari `Bookmarks.plist` file.
///
/// # Errors
///
/// Returns an error if the plist file cannot be opened or parsed.
pub fn parse_bookmarks(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
    use plist::Value;
    use std::collections::BTreeMap;
    use tempfile::NamedTempFile;

    fn leaf(url: &str, title: &str) -> Value {
        let mut d: BTreeMap<String, Value> = BTreeMap::new();
        d.insert("WebBookmarkType".to_string(), Value::String("WebBookmarkTypeLeaf".to_string()));
        d.insert("URLString".to_string(), Value::String(url.to_string()));
        let mut uri_dict: BTreeMap<String, Value> = BTreeMap::new();
        uri_dict.insert("title".to_string(), Value::String(title.to_string()));
        d.insert("URIDictionary".to_string(), Value::Dictionary(uri_dict.into_iter().collect()));
        Value::Dictionary(d.into_iter().collect())
    }

    fn folder(children: Vec<Value>) -> Value {
        let mut d: BTreeMap<String, Value> = BTreeMap::new();
        d.insert("WebBookmarkType".to_string(), Value::String("WebBookmarkTypeList".to_string()));
        d.insert("Children".to_string(), Value::Array(children));
        Value::Dictionary(d.into_iter().collect())
    }

    fn write_plist(value: &Value) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        plist::to_file_binary(f.path(), value).unwrap();
        f
    }

    #[test]
    fn parse_safari_bookmarks_finds_leaf_urls() {
        let root = folder(vec![leaf("https://example.com", "Example")]);
        let f = write_plist(&root);
        let events = parse_bookmarks(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.browser, BrowserFamily::Safari);
        assert_eq!(ev.artifact, ArtifactKind::Bookmarks);
        assert_eq!(ev.attrs["url"], serde_json::json!("https://example.com"));
        assert_eq!(ev.attrs["title"], serde_json::json!("Example"));
    }

    #[test]
    fn parse_safari_bookmarks_excludes_folders() {
        let root = folder(vec![folder(vec![])]);
        let f = write_plist(&root);
        let events = parse_bookmarks(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn nested_safari_bookmarks_all_found() {
        let root = folder(vec![
            leaf("https://a.com", "A"),
            folder(vec![leaf("https://b.com", "B")]),
        ]);
        let f = write_plist(&root);
        let events = parse_bookmarks(f.path()).unwrap();
        assert_eq!(events.len(), 2);
    }
}
