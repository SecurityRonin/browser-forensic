//! Safari TopSites.plist parser.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::ArtifactKind;
    use tempfile::NamedTempFile;
    use std::io::Write;

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
