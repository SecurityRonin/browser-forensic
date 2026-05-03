//! Core types for browser forensic analysis.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Browser engine family.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowserFamily {
    Chromium,
    Firefox,
}

/// Kind of browser artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactKind {
    History,
    Cookies,
    Downloads,
    Extensions,
    LoginData,
    Cache,
}

/// A single browser forensic event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserEvent {
    pub timestamp_ns: i64,
    pub browser: BrowserFamily,
    pub artifact: ArtifactKind,
    pub source: String,
    pub description: String,
    pub attrs: HashMap<String, serde_json::Value>,
}

impl BrowserEvent {
    #[must_use]
    pub fn new(
        timestamp_ns: i64,
        browser: BrowserFamily,
        artifact: ArtifactKind,
        source: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_ns,
            browser,
            artifact,
            source: source.into(),
            description: description.into(),
            attrs: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_attr(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attrs.insert(key.into(), value);
        self
    }
}

/// Detect the browser family from a file path.
///
/// Returns `None` if the path does not match a known browser artifact.
#[must_use]
pub fn detect_browser(path: &Path) -> Option<BrowserFamily> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    let path_str = path.to_string_lossy().to_lowercase();

    let chromium_browsers = ["chrome", "chromium", "edge", "brave", "opera"];
    let is_chromium_path = chromium_browsers.iter().any(|b| path_str.contains(b));

    if name == "history" && is_chromium_path {
        return Some(BrowserFamily::Chromium);
    }
    if name == "cookies" && is_chromium_path {
        return Some(BrowserFamily::Chromium);
    }
    if name == "places.sqlite" {
        return Some(BrowserFamily::Firefox);
    }
    if name == "cookies.sqlite"
        && (path_str.contains("firefox") || path_str.contains("mozilla"))
    {
        return Some(BrowserFamily::Firefox);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_chrome_history() {
        let p = Path::new("/home/user/.config/google-chrome/Default/History");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Chromium));
    }

    #[test]
    fn detect_edge_history() {
        let p = Path::new("/home/user/.config/microsoft-edge/Default/History");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Chromium));
    }

    #[test]
    fn detect_firefox_places() {
        let p = Path::new("/home/user/.mozilla/firefox/abc.default/places.sqlite");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Firefox));
    }

    #[test]
    fn detect_firefox_cookies() {
        let p = Path::new("/home/user/.mozilla/firefox/abc.default/cookies.sqlite");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Firefox));
    }

    #[test]
    fn detect_unknown_returns_none() {
        assert_eq!(detect_browser(Path::new("/tmp/foo.db")), None);
    }

    #[test]
    fn browser_event_with_attr() {
        use serde_json::json;
        let ev = BrowserEvent::new(
            1_000_000,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "/path/to/History",
            "example.com",
        )
        .with_attr("url", json!("https://example.com"));
        assert_eq!(ev.attrs["url"], json!("https://example.com"));
        assert_eq!(ev.timestamp_ns, 1_000_000);
    }
}
