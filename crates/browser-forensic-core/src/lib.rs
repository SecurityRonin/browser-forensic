#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::no_effect_underscore_binding
    )
)]
//! Core types for browser forensic analysis.

pub mod analyze;
pub mod sqlite;
pub mod test_utils;
pub mod timestamp;

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use forensicnomicon::evidence::EvidenceStrength;

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
            Self::Firefox => write!(f, "Firefox"),
            Self::Safari => write!(f, "Safari"),
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
    Integrity,
    Carved,
    Memory,
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::History => write!(f, "History"),
            Self::Cookies => write!(f, "Cookies"),
            Self::Downloads => write!(f, "Downloads"),
            Self::Extensions => write!(f, "Extensions"),
            Self::LoginData => write!(f, "LoginData"),
            Self::Cache => write!(f, "Cache"),
            Self::Bookmarks => write!(f, "Bookmarks"),
            Self::Autofill => write!(f, "Autofill"),
            Self::Session => write!(f, "Session"),
            Self::Integrity => write!(f, "Integrity"),
            Self::Carved => write!(f, "Carved"),
            Self::Memory => write!(f, "Memory"),
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

/// Forensic metadata from forensicnomicon for a specific browser artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMeta {
    pub artifact_id: String,
    pub evidence_strength: Option<String>,
    pub volatility: Option<String>,
    pub caveats: Vec<String>,
}

impl ForensicMeta {
    /// Look up forensic metadata for the given artifact ID.
    /// Returns `None` if the artifact is not in forensicnomicon's catalog.
    #[must_use]
    pub fn lookup(artifact_id: &str) -> Option<Self> {
        let desc = forensicnomicon::evidence::evidence_for(artifact_id)?;
        Some(Self {
            artifact_id: artifact_id.to_string(),
            evidence_strength: desc.evidence_strength.map(|s| format!("{s:?}")),
            volatility: desc.volatility.map(|v| format!("{v:?}")),
            caveats: desc
                .evidence_caveats
                .iter()
                .map(|c| (*c).to_string())
                .collect(),
        })
    }
}

/// Detect the browser family from a file path.
///
/// Returns `None` if the path does not match a known browser artifact.
#[must_use]
pub fn detect_browser(path: &Path) -> Option<BrowserFamily> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    let path_str = path.to_string_lossy().to_lowercase();

    // Safari
    if path_str.contains("safari") {
        let safari_files = [
            "history.db",
            "cookies.db",
            "downloads.plist",
            "bookmarks.plist",
        ];
        if safari_files.contains(&name.as_str()) {
            return Some(BrowserFamily::Safari);
        }
    }

    // Chromium family
    let chromium_vendors = [
        "chrome", "chromium", "edge", "brave", "opera", "vivaldi", "arc",
    ];
    let is_chromium_path = chromium_vendors.iter().any(|b| path_str.contains(b));
    let chromium_files = ["history", "cookies", "login data", "web data", "bookmarks"];
    if chromium_files.contains(&name.as_str()) && is_chromium_path {
        return Some(BrowserFamily::Chromium);
    }

    // Firefox family
    if name == "places.sqlite" || name == "formhistory.sqlite" {
        return Some(BrowserFamily::Firefox);
    }
    let firefox_files = [
        "cookies.sqlite",
        "logins.json",
        "extensions.json",
        "sessionstore.jsonlz4",
    ];
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

    #[test]
    fn artifact_kind_has_integrity_variant() {
        let _ik = ArtifactKind::Integrity;
        assert_eq!(format!("{}", ArtifactKind::Integrity), "Integrity");
    }

    #[test]
    fn artifact_kind_has_carved_variant() {
        let _c = ArtifactKind::Carved;
        assert_eq!(format!("{}", ArtifactKind::Carved), "Carved");
    }

    #[test]
    fn artifact_kind_has_memory_variant() {
        let _m = ArtifactKind::Memory;
        assert_eq!(format!("{}", ArtifactKind::Memory), "Memory");
    }

    #[test]
    fn artifact_kind_has_preferences_variant() {
        let _p = ArtifactKind::Preferences;
        assert_eq!(format!("{}", ArtifactKind::Preferences), "Preferences");
    }

    #[test]
    fn artifact_kind_has_local_storage_variant() {
        let _ls = ArtifactKind::LocalStorage;
        assert_eq!(format!("{}", ArtifactKind::LocalStorage), "LocalStorage");
    }

    #[test]
    fn forensic_meta_lookup_chrome_history() {
        let meta = ForensicMeta::lookup("browser_chrome_history");
        assert!(meta.is_some());
        let meta = meta.unwrap();
        assert_eq!(meta.artifact_id, "browser_chrome_history");
        assert!(meta.evidence_strength.is_some());
    }

    #[test]
    fn forensic_meta_lookup_unknown_returns_none() {
        let meta = ForensicMeta::lookup("nonexistent_artifact_xyz");
        assert!(meta.is_none());
    }

    #[test]
    fn forensic_meta_all_browser_artifacts_have_profiles() {
        let artifact_ids = [
            "browser_chrome_history",
            "browser_chrome_cookies",
            "browser_chrome_downloads",
            "browser_chrome_bookmarks",
            "browser_chrome_extensions",
            "browser_chrome_autofill",
            "browser_chrome_cache",
            "browser_chrome_session",
            "browser_firefox_history",
            "browser_firefox_cookies",
            "browser_firefox_downloads",
            "browser_safari_history",
        ];

        for id in &artifact_ids {
            let meta = ForensicMeta::lookup(id);
            assert!(
                meta.is_some(),
                "ForensicMeta::lookup({id}) should return Some"
            );
        }
    }

    #[test]
    fn forensic_meta_evidence_strength_is_populated() {
        let meta = ForensicMeta::lookup("browser_chrome_downloads").expect("should exist");
        assert!(
            meta.evidence_strength.is_some(),
            "evidence_strength should be Some"
        );
        // Downloads are Strong evidence
        let strength = meta
            .evidence_strength
            .as_deref()
            .expect("should have value");
        assert!(
            strength.contains("Strong"),
            "Downloads should be Strong evidence, got: {strength}"
        );
    }
}
