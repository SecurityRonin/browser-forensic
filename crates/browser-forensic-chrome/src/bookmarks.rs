//! Chromium-family browser bookmarks parser.
//!
//! Reads the `Bookmarks` JSON file and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Bookmarks`] for URL bookmark nodes (not folders).

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;

/// Parse a Chromium `Bookmarks` JSON file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn parse_bookmarks(path: &Path) -> Result<Vec<BrowserEvent>> {
    let file = std::fs::File::open(path)?;
    let root: serde_json::Value = serde_json::from_reader(file)?;

    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    let roots = root.get("roots").and_then(|r| r.as_object());
    if let Some(roots) = roots {
        for key in &["bookmark_bar", "other", "synced"] {
            if let Some(node) = roots.get(*key) {
                walk_bookmarks(node, &source, &mut events);
            }
        }
    }

    Ok(events)
}

fn walk_bookmarks(node: &serde_json::Value, source: &str, events: &mut Vec<BrowserEvent>) {
    let node_type = node.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if node_type == "url" {
        let url = node
            .get("url")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        let name = node
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let date_added = node
            .get("date_added")
            .and_then(|d| d.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let ts_ns = webkit_micros_to_unix_nanos(date_added);
        let ev = BrowserEvent::new(
            ts_ns,
            BrowserFamily::Chromium,
            ArtifactKind::Bookmarks,
            source,
            name.clone(),
        )
        .with_attr("url", json!(url))
        .with_attr("name", json!(name));
        events.push(ev);
    } else if node_type == "folder" {
        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
            for child in children {
                walk_bookmarks(child, source, events);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_bookmarks_file(content: &serde_json::Value) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.to_string().as_bytes()).unwrap();
        f
    }

    #[test]
    fn parse_empty_chrome_bookmarks() {
        let content = json!({
            "roots": {
                "bookmark_bar": {"children": [], "type": "folder", "name": "Bookmarks bar"},
                "other": {"children": [], "type": "folder", "name": "Other bookmarks"},
                "synced": {"children": [], "type": "folder", "name": "Mobile bookmarks"}
            }
        });
        let f = create_bookmarks_file(&content);
        let events = parse_bookmarks(f.path()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_chrome_bookmarks_flat() {
        let date_str = "13327626000000000";
        let content = json!({
            "roots": {
                "bookmark_bar": {
                    "type": "folder",
                    "name": "Bookmarks bar",
                    "children": [
                        {
                            "type": "url",
                            "name": "Example",
                            "url": "https://example.com",
                            "date_added": date_str
                        },
                        {
                            "type": "folder",
                            "name": "A Folder",
                            "children": [
                                {
                                    "type": "url",
                                    "name": "Nested",
                                    "url": "https://nested.example.com",
                                    "date_added": date_str
                                }
                            ]
                        }
                    ]
                },
                "other": {"children": [], "type": "folder", "name": "Other"},
                "synced": {"children": [], "type": "folder", "name": "Synced"}
            }
        });
        let f = create_bookmarks_file(&content);
        let events = parse_bookmarks(f.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::Bookmarks));
        assert!(events.iter().all(|e| e.browser == BrowserFamily::Chromium));
    }

    #[test]
    fn bookmark_timestamp_uses_webkit_epoch() {
        let date_added: i64 = 13_327_626_000_000_000;
        let content = json!({
            "roots": {
                "bookmark_bar": {
                    "type": "folder",
                    "name": "Bookmarks bar",
                    "children": [{
                        "type": "url",
                        "name": "TS Test",
                        "url": "https://ts.example.com",
                        "date_added": date_added.to_string()
                    }]
                },
                "other": {"children": [], "type": "folder", "name": "Other"},
                "synced": {"children": [], "type": "folder", "name": "Synced"}
            }
        });
        let f = create_bookmarks_file(&content);
        let events = parse_bookmarks(f.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].timestamp_ns,
            webkit_micros_to_unix_nanos(date_added)
        );
    }
}
