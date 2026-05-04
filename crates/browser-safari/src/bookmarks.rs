//! Safari `Bookmarks.plist` parser.
//!
//! Reads Safari bookmarks from `Bookmarks.plist` and emits
//! [`BrowserEvent`]s with [`ArtifactKind::Bookmarks`].

use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use plist::Value;
use serde_json::json;

/// Parse a Safari `Bookmarks.plist` file.
///
/// # Errors
///
/// Returns an error if the plist file cannot be opened or parsed.
pub fn parse_bookmarks(path: &Path) -> Result<Vec<BrowserEvent>> {
    let value = Value::from_file(path)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();
    walk_safari_bookmarks(&value, &source, &mut events);
    Ok(events)
}

fn walk_safari_bookmarks(node: &Value, source: &str, events: &mut Vec<BrowserEvent>) {
    let dict = match node.as_dictionary() {
        Some(d) => d,
        None => return,
    };
    let bm_type = dict.get("WebBookmarkType")
        .and_then(|v| v.as_string())
        .unwrap_or("");

    if bm_type == "WebBookmarkTypeLeaf" {
        let url = dict.get("URLString")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let title = dict.get("URIDictionary")
            .and_then(|v| v.as_dictionary())
            .and_then(|d| d.get("title"))
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let ev = BrowserEvent::new(0, BrowserFamily::Safari, ArtifactKind::Bookmarks, source, title.clone())
            .with_attr("url", json!(url))
            .with_attr("title", json!(title));
        events.push(ev);
    } else if bm_type == "WebBookmarkTypeList" {
        if let Some(children) = dict.get("Children").and_then(|v| v.as_array()) {
            for child in children {
                walk_safari_bookmarks(child, source, events);
            }
        }
    }
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
