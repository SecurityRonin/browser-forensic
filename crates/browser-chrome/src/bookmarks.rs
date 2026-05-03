//! Chromium-family browser bookmarks parser.
//!
//! Reads the `Bookmarks` JSON file and emits [`BrowserEvent`]s with
//! [`ArtifactKind::Bookmarks`] for URL bookmark nodes (not folders).

use std::path::Path;

use anyhow::Result;
use browser_core::BrowserEvent;

use crate::history::webkit_to_unix_ns;

/// Parse a Chromium `Bookmarks` JSON file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn parse_bookmarks(_path: &Path) -> Result<Vec<BrowserEvent>> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};
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
        assert_eq!(events[0].timestamp_ns, webkit_to_unix_ns(date_added));
    }
}
