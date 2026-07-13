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
pub mod reconstruct;
pub mod sqlite;
pub mod test_utils;
pub mod timestamp;

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use forensicnomicon::evidence::EvidenceStrength;

/// Browser engine family.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    Preferences,
    LocalStorage,
    /// Per-site permission grant (geolocation, camera, mic, notifications, …).
    Permission,
    /// Stored payment-card metadata. The card number is never decrypted.
    CreditCard,
    /// OAuth / sync auth-token metadata. The token itself is never decrypted.
    AuthToken,
    /// A domain/origin the browser contacted, recovered from a network/state
    /// artifact that survives a history wipe (HTTP server properties, NEL/
    /// Reporting, DIPS/BTM bounce records, HSTS). Read-only, no secrets.
    RecoveredDomain,
    /// A page the browser stored a favicon for (Chromium `Favicons`). The
    /// `page_url` is an independent, cleartext source of visited URLs.
    Favicon,
    /// A most-visited page cached for the new-tab page (Chromium `Top Sites`).
    /// Frecency-ranked; no per-visit timestamp.
    TopSite,
    /// A string the user typed into the omnibox and the URL they selected
    /// (Chromium `Shortcuts`). Direct evidence of user intent.
    Shortcut,
    /// A (often partial) omnibox string the user typed and the URL Chromium
    /// learned to predict (Chromium `Network Action Predictor`).
    NetworkPrediction,
    /// Audio/video playback recorded by Chromium `Media History` (watch time,
    /// resume position, media title).
    MediaPlayback,
    /// A string the user typed into the address bar and the page it resolved to
    /// (Firefox `moz_inputhistory`). Direct evidence of typed intent; carries a
    /// decayed `use_count`, not a per-keystroke timestamp.
    TypedInput,
    /// A page annotation recorded by Firefox (`moz_annos` +
    /// `moz_anno_attributes`): a named key/value the browser attached to a page
    /// (reading-list state, visit-count metadata, …). Stated as recorded.
    Annotation,
    /// A bookmark found in a Firefox `bookmarkbackups/*.jsonlz4` backup but
    /// absent from the current `moz_bookmarks` — consistent with deletion after
    /// that backup was written. The backup date bounds *when*, not who or why.
    RecoveredBookmark,
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
            Self::Preferences => write!(f, "Preferences"),
            Self::LocalStorage => write!(f, "LocalStorage"),
            Self::Permission => write!(f, "Permission"),
            Self::CreditCard => write!(f, "CreditCard"),
            Self::AuthToken => write!(f, "AuthToken"),
            Self::RecoveredDomain => write!(f, "RecoveredDomain"),
            Self::Favicon => write!(f, "Favicon"),
            Self::TopSite => write!(f, "TopSite"),
            Self::Shortcut => write!(f, "Shortcut"),
            Self::NetworkPrediction => write!(f, "NetworkPrediction"),
            Self::MediaPlayback => write!(f, "MediaPlayback"),
            Self::TypedInput => write!(f, "TypedInput"),
            Self::Annotation => write!(f, "Annotation"),
            Self::RecoveredBookmark => write!(f, "RecoveredBookmark"),
        }
    }
}

/// A single browser forensic event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// Generate the JSON Schema (draft 2020-12) for [`BrowserEvent`] and its
/// sub-types.
///
/// The schema is *derived* from the Rust types via schemars, so it never drifts
/// from the serialized shape. `br4n6 schema` emits it, and a sync test keeps the
/// committed `docs/browserevent.schema.json` in step.
#[cfg(feature = "schema")]
#[must_use]
pub fn browser_event_schema() -> schemars::Schema {
    schemars::schema_for!(BrowserEvent)
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

#[cfg(all(test, feature = "schema"))]
mod schema_tests {
    #[test]
    fn browser_event_schema_describes_the_event_fields() {
        let schema = super::browser_event_schema();
        let json = serde_json::to_value(&schema).expect("schema serializes");
        let props = json
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .expect("BrowserEvent schema has a properties object");
        for field in [
            "timestamp_ns",
            "browser",
            "artifact",
            "source",
            "description",
            "attrs",
        ] {
            assert!(
                props.contains_key(field),
                "schema should describe the `{field}` field of BrowserEvent"
            );
        }
        // The sub-types must be present as reusable definitions.
        let defs = json
            .get("$defs")
            .and_then(serde_json::Value::as_object)
            .expect("schema exposes $defs for the sub-types");
        assert!(defs.contains_key("BrowserFamily"), "BrowserFamily in $defs");
        assert!(defs.contains_key("ArtifactKind"), "ArtifactKind in $defs");
    }
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
    fn artifact_kind_has_permission_variant() {
        let _p = ArtifactKind::Permission;
        assert_eq!(format!("{}", ArtifactKind::Permission), "Permission");
    }

    #[test]
    fn artifact_kind_has_credit_card_variant() {
        let _c = ArtifactKind::CreditCard;
        assert_eq!(format!("{}", ArtifactKind::CreditCard), "CreditCard");
    }

    #[test]
    fn artifact_kind_has_auth_token_variant() {
        let _t = ArtifactKind::AuthToken;
        assert_eq!(format!("{}", ArtifactKind::AuthToken), "AuthToken");
    }

    #[test]
    fn artifact_kind_has_recovered_domain_variant() {
        let _r = ArtifactKind::RecoveredDomain;
        assert_eq!(
            format!("{}", ArtifactKind::RecoveredDomain),
            "RecoveredDomain"
        );
    }

    #[test]
    fn artifact_kind_has_favicon_variant() {
        let _f = ArtifactKind::Favicon;
        assert_eq!(format!("{}", ArtifactKind::Favicon), "Favicon");
    }

    #[test]
    fn artifact_kind_has_top_site_variant() {
        let _t = ArtifactKind::TopSite;
        assert_eq!(format!("{}", ArtifactKind::TopSite), "TopSite");
    }

    #[test]
    fn artifact_kind_has_shortcut_variant() {
        let _s = ArtifactKind::Shortcut;
        assert_eq!(format!("{}", ArtifactKind::Shortcut), "Shortcut");
    }

    #[test]
    fn artifact_kind_has_network_prediction_variant() {
        let _n = ArtifactKind::NetworkPrediction;
        assert_eq!(
            format!("{}", ArtifactKind::NetworkPrediction),
            "NetworkPrediction"
        );
    }

    #[test]
    fn artifact_kind_has_media_playback_variant() {
        let _m = ArtifactKind::MediaPlayback;
        assert_eq!(format!("{}", ArtifactKind::MediaPlayback), "MediaPlayback");
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
