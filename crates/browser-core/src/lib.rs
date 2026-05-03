//! Core types for browser forensic analysis.

pub mod analyze;

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Browser engine family.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowserFamily {
    Chromium,
    Firefox,
    Safari,
}

impl std::fmt::Display for BrowserFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chromium => write!(f, "Chromium"),
            Self::Firefox  => write!(f, "Firefox"),
            Self::Safari   => write!(f, "Safari"),
        }
    }
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
    Bookmarks,
    Autofill,
    Session,
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::History    => write!(f, "History"),
            Self::Cookies    => write!(f, "Cookies"),
            Self::Downloads  => write!(f, "Downloads"),
            Self::Extensions => write!(f, "Extensions"),
            Self::LoginData  => write!(f, "LoginData"),
            Self::Cache      => write!(f, "Cache"),
            Self::Bookmarks  => write!(f, "Bookmarks"),
            Self::Autofill   => write!(f, "Autofill"),
            Self::Session    => write!(f, "Session"),
        }
    }
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
    let name     = path.file_name()?.to_string_lossy().to_lowercase();
    let path_str = path.to_string_lossy().to_lowercase();

    // Safari
    if path_str.contains("safari") {
        let safari_files = ["history.db", "cookies.db", "downloads.plist", "bookmarks.plist"];
        if safari_files.contains(&name.as_str()) {
            return Some(BrowserFamily::Safari);
        }
    }

    // Chromium family
    let chromium_vendors = ["chrome", "chromium", "edge", "brave", "opera", "vivaldi", "arc"];
    let is_chromium_path = chromium_vendors.iter().any(|b| path_str.contains(b));
    let chromium_files   = ["history", "cookies", "login data", "web data", "bookmarks"];
    if chromium_files.contains(&name.as_str()) && is_chromium_path {
        return Some(BrowserFamily::Chromium);
    }

    // Firefox family
    if name == "places.sqlite" || name == "formhistory.sqlite" {
        return Some(BrowserFamily::Firefox);
    }
    let firefox_files = ["cookies.sqlite", "logins.json", "extensions.json", "sessionstore.jsonlz4"];
    if firefox_files.contains(&name.as_str())
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
    fn browser_family_has_safari_variant() {
        let _safari = BrowserFamily::Safari;
    }

    #[test]
    fn artifact_kind_has_bookmarks() {
        let _bk = ArtifactKind::Bookmarks;
    }

    #[test]
    fn artifact_kind_has_autofill() {
        let _af = ArtifactKind::Autofill;
    }

    #[test]
    fn artifact_kind_has_session() {
        let _s = ArtifactKind::Session;
    }

    #[test]
    fn detect_safari_history_db() {
        let p = Path::new("/Users/test/Library/Safari/History.db");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Safari));
    }

    #[test]
    fn detect_brave_history() {
        let p = Path::new(
            "/Users/test/Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
        );
        assert_eq!(detect_browser(p), Some(BrowserFamily::Chromium));
    }

    #[test]
    fn browser_family_display() {
        assert_eq!(format!("{}", BrowserFamily::Chromium), "Chromium");
        assert_eq!(format!("{}", BrowserFamily::Firefox), "Firefox");
        assert_eq!(format!("{}", BrowserFamily::Safari), "Safari");
    }

    #[test]
    fn artifact_kind_display() {
        assert_eq!(format!("{}", ArtifactKind::History), "History");
        assert_eq!(format!("{}", ArtifactKind::Cookies), "Cookies");
        assert_eq!(format!("{}", ArtifactKind::Bookmarks), "Bookmarks");
        assert_eq!(format!("{}", ArtifactKind::Autofill), "Autofill");
        assert_eq!(format!("{}", ArtifactKind::Session), "Session");
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
