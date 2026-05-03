//! Auto-detection of browser profiles on the local filesystem.

use std::path::{Path, PathBuf};

use browser_core::BrowserFamily;

/// A browser profile discovered on the filesystem.
pub struct DiscoveredProfile {
    pub browser: BrowserFamily,
    pub name: String,
    pub path: PathBuf,
}

/// Discover all browser profiles found under `home`.
///
/// Checks known macOS and Linux profile directories for Chrome, Firefox,
/// and Safari.
pub fn discover_profiles(_home: &Path) -> Vec<DiscoveredProfile> {
    unimplemented!("discover_profiles not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn discover_chrome_profile_macos_layout() {
        let home = TempDir::new().unwrap();
        let chrome_default = home.path()
            .join("Library/Application Support/Google/Chrome/Default");
        fs::create_dir_all(&chrome_default).unwrap();
        fs::write(chrome_default.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles.iter().any(|p|
            p.browser == BrowserFamily::Chromium && p.name == "Default"
        ));
    }

    #[test]
    fn discover_firefox_profiles_macos_layout() {
        let home = TempDir::new().unwrap();
        let ff = home.path()
            .join("Library/Application Support/Firefox/Profiles/abc123.default-release");
        fs::create_dir_all(&ff).unwrap();
        fs::write(ff.join("places.sqlite"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles.iter().any(|p|
            p.browser == BrowserFamily::Firefox && p.name == "abc123.default-release"
        ));
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
    fn discover_multiple_chrome_profiles() {
        let home = TempDir::new().unwrap();
        let base = home.path().join("Library/Application Support/Google/Chrome");
        for name in &["Default", "Profile 1", "Profile 2"] {
            let dir = base.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("History"), b"").unwrap();
        }

        let profiles = discover_profiles(home.path());
        let n = profiles.iter().filter(|p| p.browser == BrowserFamily::Chromium).count();
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
        let edge = home.path()
            .join("Library/Application Support/Microsoft Edge/Default");
        fs::create_dir_all(&edge).unwrap();
        fs::write(edge.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles.iter().any(|p| p.browser == BrowserFamily::Chromium));
    }

    #[test]
    fn discover_brave_profile() {
        let home = TempDir::new().unwrap();
        let brave = home.path()
            .join("Library/Application Support/BraveSoftware/Brave-Browser/Default");
        fs::create_dir_all(&brave).unwrap();
        fs::write(brave.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles.iter().any(|p| p.browser == BrowserFamily::Chromium));
    }

    #[test]
    fn discover_chrome_linux_layout() {
        let home = TempDir::new().unwrap();
        let chrome = home.path().join(".config/google-chrome/Default");
        fs::create_dir_all(&chrome).unwrap();
        fs::write(chrome.join("History"), b"").unwrap();

        let profiles = discover_profiles(home.path());
        assert!(profiles.iter().any(|p| p.browser == BrowserFamily::Chromium));
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
}
