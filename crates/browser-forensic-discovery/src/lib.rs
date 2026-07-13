#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Auto-detection of browser profiles on the local filesystem.

use std::path::{Path, PathBuf};

use browser_forensic_core::BrowserFamily;
use forensicnomicon::browser_profiles::{
    attribute_container, chromium_profile_markers, firefox_profile_markers, AppKind, ContainerApp,
    MarkerKind, ProfileMarker, FIREFOX_PROFILE_MARKER_SUFFIXES,
};
use serde::Serialize;

/// A browser profile discovered on the filesystem.
#[derive(Debug, Serialize)]
pub struct DiscoveredProfile {
    pub browser: BrowserFamily,
    pub name: String,
    pub path: PathBuf,
    /// Container-app attribution when the path matched a known app; `None` for a
    /// profile-shaped directory that matched no catalog entry (still discovered,
    /// just generically labelled).
    pub container: Option<ContainerAttribution>,
}

/// Attribution of a discovered container to a known app, derived from
/// [`forensicnomicon::browser_profiles::attribute_container`]. A compact view of
/// the catalog entry (name / vendor / kind) rather than the full record, so a
/// swept inventory stays readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ContainerAttribution {
    /// App name (e.g. `"Slack"`, `"OneDrive"`).
    pub app: &'static str,
    /// Vendor / publisher.
    pub vendor: &'static str,
    /// How the app embeds Chromium (`Browser` / `Electron` / `WebView2` / `Cef`).
    pub kind: AppKind,
}

impl From<&'static ContainerApp> for ContainerAttribution {
    fn from(a: &'static ContainerApp) -> Self {
        Self {
            app: a.name,
            vendor: a.vendor,
            kind: a.kind,
        }
    }
}

/// Attribute a filesystem path to a known container app, if any.
fn attribution_for(path: &Path) -> Option<ContainerAttribution> {
    attribute_container(&path.to_string_lossy()).map(ContainerAttribution::from)
}

/// Maximum directory depth the sweep descends below `root`. Browser containers
/// sit within the first several levels; this bounds worst-case cost and caps
/// recursion so a pathologically deep tree cannot overflow the stack.
const SWEEP_MAX_DEPTH: usize = 24;

/// Subdirectory names that, together with an app-token path, mark a directory as
/// an embedded container even when it lacks a full Chromium/Firefox signature.
const EMBEDDED_CONTAINER_SUBDIRS: &[&str] = &[
    "Cache",
    "Local Storage",
    "IndexedDB",
    "Session Storage",
    "Extensions",
];

/// Recursively sweep an evidence tree rooted at `root` for Chromium/Firefox
/// profiles and embedded-Chromium containers (Electron / WebView2 / CEF),
/// attributing each match to a known app where possible.
///
/// This is a *structural* sweep: a directory is a container if it carries a
/// Chromium or Firefox profile signature (see
/// [`forensicnomicon::browser_profiles`]), regardless of its name — so an
/// unknown app is still discovered, just without attribution. The walk never
/// follows symlinks, is depth-bounded, reads each directory once, and is
/// panic-free, so it is safe to point at a whole evidence tree.
#[must_use]
pub fn sweep_containers(root: &Path) -> Vec<DiscoveredProfile> {
    let mut out = Vec::new();
    sweep_dir(root, 0, &mut out);
    out
}

fn sweep_dir(dir: &Path, depth: usize, out: &mut Vec<DiscoveredProfile>) {
    if depth > SWEEP_MAX_DEPTH {
        return;
    }
    // Read children once and reuse for classification and recursion. A directory
    // we cannot read is skipped — a best-effort sweep, never a hard failure.
    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.flatten().collect(),
        Err(_) => return,
    };

    if let Some(profile) = classify_dir(dir, &entries) {
        out.push(profile);
        // A matched profile's children are its own artifacts (Cache, IndexedDB,
        // Local Storage, …), not nested profiles — do not descend into them.
        return;
    }

    for entry in &entries {
        // Never follow symlinks: cycle-safe and prevents escaping the tree.
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        sweep_dir(&entry.path(), depth + 1, out);
    }
}

/// Classify a single directory as a Chromium profile, a Firefox profile, an
/// attributed embedded container, or nothing.
fn classify_dir(dir: &Path, entries: &[std::fs::DirEntry]) -> Option<DiscoveredProfile> {
    if has_chromium_signature(dir, entries) {
        return Some(make_profile(BrowserFamily::Chromium, dir));
    }
    if has_firefox_signature(dir, entries) {
        return Some(make_profile(BrowserFamily::Firefox, dir));
    }
    // Embedded fallback: an app-token path carrying a web-container subdir but no
    // strict profile signature is still a container.
    if let Some(app) = attribute_container(&dir.to_string_lossy()) {
        if has_embedded_container_subdir(entries) {
            return Some(DiscoveredProfile {
                browser: BrowserFamily::Chromium,
                name: dir_name(dir),
                path: dir.to_path_buf(),
                container: Some(ContainerAttribution::from(app)),
            });
        }
    }
    None
}

fn make_profile(browser: BrowserFamily, dir: &Path) -> DiscoveredProfile {
    DiscoveredProfile {
        browser,
        name: dir_name(dir),
        path: dir.to_path_buf(),
        container: attribution_for(dir),
    }
}

fn dir_name(dir: &Path) -> String {
    dir.file_name().map_or_else(
        || dir.to_string_lossy().into_owned(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn has_chromium_signature(dir: &Path, entries: &[std::fs::DirEntry]) -> bool {
    chromium_profile_markers()
        .iter()
        .any(|m| marker_present(dir, entries, m))
}

fn has_firefox_signature(dir: &Path, entries: &[std::fs::DirEntry]) -> bool {
    if firefox_profile_markers()
        .iter()
        .any(|m| marker_present(dir, entries, m))
    {
        return true;
    }
    // Any regular file with a mozLz4 session/bookmark extension also marks a
    // Firefox profile.
    entries.iter().any(|e| {
        e.file_type().is_ok_and(|t| t.is_file()) && {
            let name = e.file_name();
            let name = name.to_string_lossy();
            FIREFOX_PROFILE_MARKER_SUFFIXES
                .iter()
                .any(|s| name.ends_with(s))
        }
    })
}

/// Is a single profile marker present in `dir`? Top-level markers are matched by
/// name and kind against the already-read `entries` (no extra stat); nested
/// markers (`Local Storage/leveldb`, `Network/Cookies`) require the first path
/// segment as a child directory, then a single stat of the leaf.
fn marker_present(dir: &Path, entries: &[std::fs::DirEntry], m: &ProfileMarker) -> bool {
    let first = match m.relative_path.split('/').next() {
        Some(f) => f,
        None => return false,
    };
    if m.relative_path.contains('/') {
        if !entries
            .iter()
            .any(|e| entry_matches(e, first, MarkerKind::Dir))
        {
            return false;
        }
        let full = dir.join(m.relative_path);
        match m.kind {
            MarkerKind::File => full.is_file(),
            MarkerKind::Dir => full.is_dir(),
        }
    } else {
        entries.iter().any(|e| entry_matches(e, first, m.kind))
    }
}

fn entry_matches(e: &std::fs::DirEntry, name: &str, kind: MarkerKind) -> bool {
    if e.file_name().to_string_lossy() != name {
        return false;
    }
    e.file_type().is_ok_and(|t| match kind {
        MarkerKind::File => t.is_file(),
        MarkerKind::Dir => t.is_dir(),
    })
}

fn has_embedded_container_subdir(entries: &[std::fs::DirEntry]) -> bool {
    entries.iter().any(|e| {
        e.file_type().is_ok_and(|t| t.is_dir()) && {
            let name = e.file_name();
            let name = name.to_string_lossy();
            EMBEDDED_CONTAINER_SUBDIRS
                .iter()
                .any(|s| name.eq_ignore_ascii_case(s))
        }
    })
}

/// Known Chromium-based browser base directories relative to `home`.
static CHROMIUM_BASES: &[&str] = &[
    // macOS
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/BraveSoftware/Brave-Browser",
    "Library/Application Support/Vivaldi",
    "Library/Application Support/com.operasoftware.Opera",
    "Library/Application Support/Arc/User Data",
    "Library/Application Support/Chromium",
    // Linux
    ".config/google-chrome",
    ".config/microsoft-edge",
    ".config/BraveSoftware/Brave-Browser",
    ".config/vivaldi",
    ".config/opera",
    ".config/chromium",
    // Windows
    "AppData/Local/Google/Chrome/User Data",
    "AppData/Local/Microsoft/Edge/User Data",
    "AppData/Local/BraveSoftware/Brave-Browser/User Data",
    "AppData/Local/Vivaldi/User Data",
    "AppData/Roaming/Opera Software/Opera Stable",
    "AppData/Local/Chromium/User Data",
];

/// Known Firefox profile base directories relative to `home`.
static FIREFOX_BASES: &[&str] = &[
    // macOS
    "Library/Application Support/Firefox/Profiles",
    // Linux
    ".mozilla/firefox",
    // Windows
    "AppData/Roaming/Mozilla/Firefox/Profiles",
];

/// Discover all browser profiles found under `home`.
///
/// Checks known macOS and Linux profile directories for Chrome, Firefox,
/// and Safari.
pub fn discover_profiles(home: &Path) -> Vec<DiscoveredProfile> {
    let mut profiles = Vec::new();
    discover_chromium_profiles(home, &mut profiles);
    discover_firefox_profiles(home, &mut profiles);
    discover_safari_profiles(home, &mut profiles);
    discover_webcache_profiles(home, &mut profiles);
    profiles
}

/// Walk each known Chromium base directory and collect subdirectories that
/// contain a `History` file.
fn discover_chromium_profiles(home: &Path, out: &mut Vec<DiscoveredProfile>) {
    for base_rel in CHROMIUM_BASES {
        let base = home.join(base_rel);
        if !base.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && path.join("History").is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let container = attribution_for(&path);
                    out.push(DiscoveredProfile {
                        browser: BrowserFamily::Chromium,
                        name,
                        path,
                        container,
                    });
                }
            }
        }
    }
}

/// Walk each known Firefox base directory and collect subdirectories that
/// contain a `places.sqlite` file.
fn discover_firefox_profiles(home: &Path, out: &mut Vec<DiscoveredProfile>) {
    for base_rel in FIREFOX_BASES {
        let base = home.join(base_rel);
        if !base.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && path.join("places.sqlite").is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let container = attribution_for(&path);
                    out.push(DiscoveredProfile {
                        browser: BrowserFamily::Firefox,
                        name,
                        path,
                        container,
                    });
                }
            }
        }
    }
}

/// Check the Safari directory: if `Library/Safari/History.db` exists, emit a
/// single "Default" profile.
fn discover_safari_profiles(home: &Path, out: &mut Vec<DiscoveredProfile>) {
    let safari = home.join("Library/Safari");
    if safari.join("History.db").is_file() {
        let container = attribution_for(&safari);
        out.push(DiscoveredProfile {
            browser: BrowserFamily::Safari,
            name: "Default".to_string(),
            path: safari,
            container,
        });
    }
}

/// Check the Windows WebCache directory: if
/// `AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat` exists (the ESE
/// store shared by Internet Explorer and legacy EdgeHTML/Spartan Edge), emit a
/// single profile. Tagged [`BrowserFamily::InternetExplorer`] at the profile
/// level; the WebCache parser refines IE-vs-Edge per container.
fn discover_webcache_profiles(home: &Path, out: &mut Vec<DiscoveredProfile>) {
    let webcache = home.join("AppData/Local/Microsoft/Windows/WebCache");
    if webcache.join("WebCacheV01.dat").is_file() {
        let container = attribution_for(&webcache);
        out.push(DiscoveredProfile {
            browser: BrowserFamily::InternetExplorer,
            name: "WebCache".to_string(),
            path: webcache,
            container,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn discover_chrome_profile_macos_layout() {
        let home = TempDir::new().unwrap();
        let chrome_default = home
            .path()
            .join("Library/Application Support/Google/Chrome/Default");
        fs::create_dir_all(&chrome_default).unwrap();
        fs::write(chrome_default.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::Chromium && p.name == "Default"));
    }

    #[test]
    fn discover_firefox_profiles_macos_layout() {
        let home = TempDir::new().unwrap();
        let ff = home
            .path()
            .join("Library/Application Support/Firefox/Profiles/abc123.default-release");
        fs::create_dir_all(&ff).unwrap();
        fs::write(ff.join("places.sqlite"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::Firefox && p.name == "abc123.default-release"));
    }

    #[test]
    fn discover_safari_profile() {
        let home = TempDir::new().unwrap();
        let safari = home.path().join("Library/Safari");
        fs::create_dir_all(&safari).unwrap();
        fs::write(safari.join("History.db"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles.iter().any(|p| p.browser == BrowserFamily::Safari));
    }

    #[test]
    fn discover_webcache_profile() {
        let home = TempDir::new().unwrap();
        let webcache = home.path().join("AppData/Local/Microsoft/Windows/WebCache");
        fs::create_dir_all(&webcache).unwrap();
        fs::write(webcache.join("WebCacheV01.dat"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::InternetExplorer && p.name == "WebCache"));
    }

    #[test]
    fn discover_multiple_chrome_profiles() {
        let home = TempDir::new().unwrap();
        let base = home
            .path()
            .join("Library/Application Support/Google/Chrome");
        for name in &["Default", "Profile 1", "Profile 2"] {
            let dir = base.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("History"), b"").unwrap();
        }

        let profiles = discover_profiles(home.path());
        let n = profiles
            .iter()
            .filter(|p| p.browser == BrowserFamily::Chromium)
            .count();
        assert_eq!(n, 3);
    }

    #[test]
    fn discover_empty_home_returns_empty() {
        let home = TempDir::new().unwrap();
        assert!(discover_profiles(home.path()).is_empty());
    }

    #[test]
    fn discover_edge_profile() {
        let home = TempDir::new().unwrap();
        let edge = home
            .path()
            .join("Library/Application Support/Microsoft Edge/Default");
        fs::create_dir_all(&edge).unwrap();
        fs::write(edge.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::Chromium));
    }

    #[test]
    fn discover_brave_profile() {
        let home = TempDir::new().unwrap();
        let brave = home
            .path()
            .join("Library/Application Support/BraveSoftware/Brave-Browser/Default");
        fs::create_dir_all(&brave).unwrap();
        fs::write(brave.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::Chromium));
    }

    #[test]
    fn discover_chrome_linux_layout() {
        let home = TempDir::new().unwrap();
        let chrome = home.path().join(".config/google-chrome/Default");
        fs::create_dir_all(&chrome).unwrap();
        fs::write(chrome.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::Chromium));
    }

    #[test]
    fn discover_firefox_linux_layout() {
        let home = TempDir::new().unwrap();
        let ff = home.path().join(".mozilla/firefox/xyz.default");
        fs::create_dir_all(&ff).unwrap();
        fs::write(ff.join("places.sqlite"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles.iter().any(|p| p.browser == BrowserFamily::Firefox));
    }

    #[test]
    fn discover_chrome_windows_layout() {
        let home = TempDir::new().unwrap();
        let chrome = home
            .path()
            .join("AppData/Local/Google/Chrome/User Data/Default");
        fs::create_dir_all(&chrome).unwrap();
        fs::write(chrome.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(
            profiles
                .iter()
                .any(|p| p.browser == BrowserFamily::Chromium && p.name == "Default"),
            "should discover Chrome profile from Windows path layout"
        );
    }

    #[test]
    fn discover_firefox_windows_layout() {
        let home = TempDir::new().unwrap();
        let ff = home
            .path()
            .join("AppData/Roaming/Mozilla/Firefox/Profiles/abc.default-release");
        fs::create_dir_all(&ff).unwrap();
        fs::write(ff.join("places.sqlite"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(
            profiles.iter().any(|p| p.browser == BrowserFamily::Firefox),
            "should discover Firefox profile from Windows path layout"
        );
    }

    #[test]
    fn discover_edge_windows_layout() {
        let home = TempDir::new().unwrap();
        let edge = home
            .path()
            .join("AppData/Local/Microsoft/Edge/User Data/Default");
        fs::create_dir_all(&edge).unwrap();
        fs::write(edge.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::Chromium));
    }

    // -- sweep_containers: structural signature sweep over an evidence tree -----

    fn find<'a>(profiles: &'a [DiscoveredProfile], name: &str) -> Option<&'a DiscoveredProfile> {
        profiles.iter().find(|p| p.name == name)
    }

    #[test]
    fn sweep_finds_and_attributes_chrome_profile() {
        let root = TempDir::new().unwrap();
        let default = root
            .path()
            .join("Users/x/AppData/Local/Google/Chrome/User Data/Default");
        fs::create_dir_all(&default).unwrap();
        fs::write(default.join("History"), b"").unwrap();

        let hits = sweep_containers(root.path());
        let p = find(&hits, "Default").expect("Default profile discovered");
        assert_eq!(p.browser, BrowserFamily::Chromium);
        let c = p.container.expect("attributed");
        assert_eq!(c.app, "Google Chrome");
    }

    #[test]
    fn sweep_finds_webview2_ebwebview_container() {
        let root = TempDir::new().unwrap();
        // OneDrive WebView2 UDF: version folder between OneDrive and EBWebView.
        let profile = root
            .path()
            .join("Users/x/AppData/Local/Microsoft/OneDrive/25.1/EBWebView/Default");
        fs::create_dir_all(profile.join("Local Storage/leveldb")).unwrap();

        let hits = sweep_containers(root.path());
        let one = hits
            .iter()
            .find(|p| p.container.map(|c| c.app) == Some("OneDrive"))
            .expect("OneDrive EBWebView discovered");
        assert_eq!(one.container.unwrap().kind, AppKind::WebView2);
    }

    #[test]
    fn sweep_finds_electron_slack_local_storage() {
        let root = TempDir::new().unwrap();
        let slack = root
            .path()
            .join("Users/x/Library/Application Support/Slack");
        fs::create_dir_all(slack.join("Local Storage/leveldb")).unwrap();

        let hits = sweep_containers(root.path());
        let s = hits
            .iter()
            .find(|p| p.container.map(|c| c.app) == Some("Slack"))
            .expect("Slack container discovered");
        assert_eq!(s.container.unwrap().kind, AppKind::Electron);
    }

    #[test]
    fn sweep_finds_firefox_profile() {
        let root = TempDir::new().unwrap();
        let ff = root.path().join("evidence/abc.default-release");
        fs::create_dir_all(&ff).unwrap();
        fs::write(ff.join("places.sqlite"), b"").unwrap();

        let hits = sweep_containers(root.path());
        let p = find(&hits, "abc.default-release").expect("Firefox profile discovered");
        assert_eq!(p.browser, BrowserFamily::Firefox);
    }

    #[test]
    fn sweep_discovers_unknown_chromium_dir_generically() {
        // The generalization test: an unknown-named Chromium-shaped directory is
        // still discovered, just without attribution (container == None).
        let root = TempDir::new().unwrap();
        let mystery = root.path().join("some/RandomToolThatEmbedsChromium");
        fs::create_dir_all(&mystery).unwrap();
        fs::write(mystery.join("Web Data"), b"").unwrap();

        let hits = sweep_containers(root.path());
        let p = find(&hits, "RandomToolThatEmbedsChromium").expect("still discovered");
        assert_eq!(p.browser, BrowserFamily::Chromium);
        assert!(
            p.container.is_none(),
            "unknown app must be generic, not attributed"
        );
    }

    #[test]
    fn sweep_empty_tree_is_empty() {
        let root = TempDir::new().unwrap();
        assert!(sweep_containers(root.path()).is_empty());
    }

    #[test]
    fn sweep_nonexistent_root_does_not_panic() {
        let hits = sweep_containers(Path::new("/no/such/path/hopefully"));
        assert!(hits.is_empty());
    }

    #[test]
    fn sweep_does_not_descend_into_matched_profile_artifacts() {
        // A profile's own IndexedDB/Local Storage subtree must not be re-emitted
        // as nested profiles.
        let root = TempDir::new().unwrap();
        let default = root.path().join("Chrome/User Data/Default");
        fs::create_dir_all(default.join("IndexedDB")).unwrap();
        fs::write(default.join("History"), b"").unwrap();

        let hits = sweep_containers(root.path());
        let chromium = hits
            .iter()
            .filter(|p| p.browser == BrowserFamily::Chromium)
            .count();
        assert_eq!(
            chromium, 1,
            "should emit exactly one profile, not nested ones"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sweep_does_not_follow_symlink_cycles() {
        use std::os::unix::fs::symlink;
        let root = TempDir::new().unwrap();
        let sub = root.path().join("a/b");
        fs::create_dir_all(&sub).unwrap();
        // b/loop -> a (a cycle); sweep must terminate.
        symlink(root.path().join("a"), sub.join("loop")).unwrap();
        let _ = sweep_containers(root.path());
    }
}
