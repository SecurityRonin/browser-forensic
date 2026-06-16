//! Safari TopSites.plist parser.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse Safari's `TopSites.plist` file.
///
/// Extracts frequently visited sites. These are forensically relevant
/// because they reveal habitual browsing patterns even when history
/// has been cleared.
pub fn parse_topsites(path: &Path) -> Result<Vec<BrowserEvent>> {
    let value: plist::Value = plist::from_file(path)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    let dict = value
        .as_dictionary()
        .ok_or_else(|| anyhow::anyhow!("TopSites.plist root is not a dictionary"))?;

    let sites = match dict.get("TopSites").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Ok(events),
    };

    for site in sites {
        let site_dict = match site.as_dictionary() {
            Some(d) => d,
            None => continue,
        };

        let url = site_dict
            .get("TopSiteURLString")
            .and_then(|v| v.as_string())
            .unwrap_or("");
        let title = site_dict
            .get("TopSiteTitle")
            .and_then(|v| v.as_string())
            .unwrap_or("");

        if url.is_empty() {
            continue;
        }

        let desc = if title.is_empty() {
            url.to_string()
        } else {
            format!("{title} -- {url}")
        };

        events.push(
            BrowserEvent::new(
                0,
                BrowserFamily::Safari,
                ArtifactKind::History,
                &source,
                desc,
            )
            .with_attr("url", json!(url))
            .with_attr("title", json!(title))
            .with_attr("source_type", json!("topsites")),
        );
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::ArtifactKind;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_topsites_from_xml_plist() {
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TopSites</key>
    <array>
        <dict>
            <key>TopSiteURLString</key>
            <string>https://example.com</string>
            <key>TopSiteTitle</key>
            <string>Example</string>
        </dict>
        <dict>
            <key>TopSiteURLString</key>
            <string>https://news.example.com</string>
            <key>TopSiteTitle</key>
            <string>News</string>
        </dict>
    </array>
</dict>
</plist>"#;

        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(plist_xml.as_bytes()).expect("write");

        let events = parse_topsites(f.path()).expect("parse");
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e.description.contains("Example")));
        assert!(events.iter().any(|e| e.description.contains("News")));
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::History));
    }

    #[test]
    fn parse_topsites_empty_returns_empty() {
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TopSites</key>
    <array/>
</dict>
</plist>"#;

        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(plist_xml.as_bytes()).expect("write");

        let events = parse_topsites(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_topsites_missing_file_returns_error() {
        let result = parse_topsites(std::path::Path::new("/nonexistent/TopSites.plist"));
        assert!(result.is_err());
    }
}
