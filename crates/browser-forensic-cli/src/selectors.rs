//! Multi-user / multi-profile selectors (RFC 0001 D9).
//!
//! `--user <SID|name>`, `--profile "Chrome/Default"`, and `--browser chrome`
//! SCOPE a run to a subset of the discovered profiles, and every emitted finding
//! is stamped with its origin (`user`/`profile`/`browser`). A selector that
//! matches nothing is a LOUD error naming what WAS found — never a silent empty
//! result (which would be indistinguishable from a genuinely clean profile).

use anyhow::Result;
use browser_forensic_core::finding::Finding;
use browser_forensic_core::{BrowserEvent, BrowserFamily};
use browser_forensic_discovery::DiscoveredProfile;

/// The three scoping selectors, parsed from the CLI flags.
#[derive(Debug, Clone, Default)]
pub struct Selectors {
    /// `--user <SID|name>`.
    pub user: Option<String>,
    /// `--profile "<Browser>/<name>"` (or just `<name>`).
    pub profile: Option<String>,
    /// `--browser <family>` (`chrome`/`chromium`/`edge`/… → Chromium, etc.).
    pub browser: Option<String>,
}

impl Selectors {
    /// Build from the raw flag values.
    #[must_use]
    pub fn new(user: Option<String>, profile: Option<String>, browser: Option<String>) -> Self {
        Self {
            user,
            profile,
            browser,
        }
    }

    /// Whether any selector is set (an inactive selector leaves the run unscoped).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.user.is_some() || self.profile.is_some() || self.browser.is_some()
    }

    /// Scope `profiles` to those matching every set selector. Returns a loud error
    /// naming what WAS present when a selector eliminates everything.
    ///
    /// # Errors
    /// Returns an error when a set selector matches no discovered profile, or the
    /// `--browser` value is not a recognized family.
    pub fn filter(&self, profiles: Vec<DiscoveredProfile>) -> Result<Vec<DiscoveredProfile>> {
        if !self.is_active() {
            return Ok(profiles);
        }
        // Snapshots of what was present, for a loud, specific non-match error.
        let present_profiles: Vec<String> = profiles.iter().map(profile_label).collect();
        let present_browsers = present_browser_list(&profiles);
        let present_users = present_user_list(&profiles);

        let mut kept = profiles;

        if let Some(sel) = &self.browser {
            let family = parse_browser(sel)?;
            kept.retain(|p| p.browser == family);
            if kept.is_empty() {
                anyhow::bail!("--browser {sel} not found; browsers present: {present_browsers}");
            }
        }
        if let Some(sel) = &self.profile {
            kept.retain(|p| profile_matches(sel, p));
            if kept.is_empty() {
                anyhow::bail!(
                    "--profile \"{sel}\" not found; profiles present: {}",
                    present_profiles.join(", ")
                );
            }
        }
        if let Some(sel) = &self.user {
            kept.retain(|p| user_matches(sel, p));
            if kept.is_empty() {
                anyhow::bail!("--user {sel} not found; users present: {present_users}");
            }
        }
        Ok(kept)
    }
}

/// Stamp every finding with a profile's origin (user/profile/browser) — RFC 0001
/// D9. The profile label and browser family always attach; the user only when it
/// can be recovered from the profile path.
#[must_use]
pub fn stamp(findings: Vec<Finding>, profile: &DiscoveredProfile) -> Vec<Finding> {
    let label = profile_label(profile);
    let user = user_of(profile);
    findings
        .into_iter()
        .map(|f| {
            let f = f
                .with_profile(label.clone())
                .with_browser(profile.browser.clone());
            match &user {
                Some(u) => f.with_user(u.clone()),
                None => f,
            }
        })
        .collect()
}

/// Stamp a browser event with its originating user/profile/browser into `attrs`
/// (RFC 0001 D9), so a scoped run's JSONL surfaces where each event came from.
pub fn stamp_event(event: &mut BrowserEvent, profile: &DiscoveredProfile) {
    event.attrs.insert(
        "profile".to_string(),
        serde_json::Value::String(profile_label(profile)),
    );
    event.attrs.insert(
        "browser_profile".to_string(),
        serde_json::Value::String(browser_short(&profile.browser).to_string()),
    );
    if let Some(user) = user_of(profile) {
        event
            .attrs
            .insert("user".to_string(), serde_json::Value::String(user));
    }
}

/// The short display name for a browser family used in a profile label
/// (`Chrome`/`Firefox`/`Safari`/`WebCache`), matching the RFC's `Chrome/Default`.
#[must_use]
pub fn browser_short(family: &BrowserFamily) -> &'static str {
    match family {
        BrowserFamily::Chromium => "Chrome",
        BrowserFamily::Firefox => "Firefox",
        BrowserFamily::Safari => "Safari",
        BrowserFamily::InternetExplorer => "IE",
        BrowserFamily::EdgeLegacy => "EdgeLegacy",
    }
}

/// A stable profile label, e.g. `Chrome/Default` or `Firefox/default-release`.
#[must_use]
pub fn profile_label(p: &DiscoveredProfile) -> String {
    format!("{}/{}", browser_short(&p.browser), p.name)
}

/// The originating user recovered from a profile path: the component following a
/// `Users` or `home` path segment (case-insensitive). `None` when the layout
/// carries no user segment (e.g. a bare profile directory).
#[must_use]
pub fn user_of(p: &DiscoveredProfile) -> Option<String> {
    let comps: Vec<String> = p
        .path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    for (i, c) in comps.iter().enumerate() {
        let lc = c.to_lowercase();
        if (lc == "users" || lc == "home") && i + 1 < comps.len() {
            return Some(comps[i + 1].clone());
        }
    }
    None
}

/// Whether a `--profile` selector matches a discovered profile. Accepts the
/// canonical `Chrome/Default` label, the family Display form `Chromium/Default`,
/// or just the bare profile name — all case-insensitive.
fn profile_matches(sel: &str, p: &DiscoveredProfile) -> bool {
    let sel = sel.to_lowercase();
    let label = profile_label(p).to_lowercase();
    let display = format!("{}/{}", p.browser, p.name).to_lowercase();
    let name = p.name.to_lowercase();
    sel == label || sel == display || sel == name
}

/// Whether a `--user` selector matches: the recovered user (case-insensitive), or
/// the value appearing as a path component (covers a SID or name in the layout).
fn user_matches(sel: &str, p: &DiscoveredProfile) -> bool {
    let sel_lc = sel.to_lowercase();
    if user_of(p).is_some_and(|u| u.to_lowercase() == sel_lc) {
        return true;
    }
    p.path
        .components()
        .any(|c| c.as_os_str().to_string_lossy().to_lowercase() == sel_lc)
}

/// Parse a `--browser` value into a family. Chromium covers every Chromium-based
/// vendor (Chrome/Edge/Brave/Opera/Vivaldi/Arc).
fn parse_browser(sel: &str) -> Result<BrowserFamily> {
    match sel.to_lowercase().as_str() {
        "chrome" | "chromium" | "edge" | "brave" | "opera" | "vivaldi" | "arc" => {
            Ok(BrowserFamily::Chromium)
        }
        "firefox" | "mozilla" => Ok(BrowserFamily::Firefox),
        "safari" => Ok(BrowserFamily::Safari),
        "ie" | "internetexplorer" | "internet-explorer" => Ok(BrowserFamily::InternetExplorer),
        "edge-legacy" | "edgelegacy" => Ok(BrowserFamily::EdgeLegacy),
        other => anyhow::bail!(
            "unknown --browser {other}; try one of: chrome, firefox, safari, edge, brave"
        ),
    }
}

/// A comma-separated list of the distinct browser families present (for errors).
fn present_browser_list(profiles: &[DiscoveredProfile]) -> String {
    let mut names: Vec<String> = profiles.iter().map(|p| p.browser.to_string()).collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        "<none>".to_string()
    } else {
        names.join(", ")
    }
}

/// A comma-separated list of the distinct users present (for errors).
fn present_user_list(profiles: &[DiscoveredProfile]) -> String {
    let mut users: Vec<String> = profiles.iter().filter_map(user_of).collect();
    users.sort();
    users.dedup();
    if users.is_empty() {
        "<none>".to_string()
    } else {
        users.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn profile(browser: BrowserFamily, name: &str, path: &str) -> DiscoveredProfile {
        DiscoveredProfile {
            browser,
            name: name.to_string(),
            path: PathBuf::from(path),
            container: None,
        }
    }

    fn two() -> Vec<DiscoveredProfile> {
        vec![
            profile(
                BrowserFamily::Chromium,
                "Default",
                "/ev/Users/alice/AppData/Local/Google/Chrome/User Data/Default",
            ),
            profile(
                BrowserFamily::Firefox,
                "abcd.default-release",
                "/ev/Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release",
            ),
        ]
    }

    #[test]
    fn label_uses_short_browser_name() {
        assert_eq!(profile_label(&two()[0]), "Chrome/Default");
        assert_eq!(profile_label(&two()[1]), "Firefox/abcd.default-release");
    }

    #[test]
    fn user_recovered_from_users_segment() {
        assert_eq!(user_of(&two()[0]).as_deref(), Some("alice"));
    }

    #[test]
    fn profile_selector_scopes_to_one() {
        let s = Selectors::new(None, Some("Chrome/Default".to_string()), None);
        let kept = s.filter(two()).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].browser, BrowserFamily::Chromium);
    }

    #[test]
    fn browser_selector_scopes() {
        let s = Selectors::new(None, None, Some("firefox".to_string()));
        let kept = s.filter(two()).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].browser, BrowserFamily::Firefox);
    }

    #[test]
    fn nonmatching_profile_names_present() {
        let s = Selectors::new(None, Some("Chrome/Nope".to_string()), None);
        let err = s.filter(two()).unwrap_err().to_string();
        assert!(err.contains("not found"), "{err}");
        assert!(err.contains("Chrome/Default"), "{err}");
        assert!(err.contains("Firefox/abcd.default-release"), "{err}");
    }

    #[test]
    fn nonmatching_browser_names_present() {
        let s = Selectors::new(None, None, Some("safari".to_string()));
        let err = s.filter(two()).unwrap_err().to_string();
        assert!(err.contains("Chromium") && err.contains("Firefox"), "{err}");
    }

    #[test]
    fn inactive_selectors_pass_everything_through() {
        let s = Selectors::default();
        assert_eq!(s.filter(two()).unwrap().len(), 2);
    }

    #[test]
    fn stamp_attaches_origin() {
        use browser_forensic_core::finding::{
            Confidence, EvidenceSource, EvidenceState, Priority, Provenance, TimestampBasis,
            UserActionClaim,
        };
        let f = Finding::new(
            Priority::Info,
            Confidence::Low,
            "r.v1",
            "consistent with X",
            Provenance::new(
                EvidenceSource::History,
                EvidenceState::Live,
                TimestampBasis::Explicit,
                UserActionClaim::Visited,
            ),
            "evidence",
        );
        let stamped = stamp(vec![f], &two()[0]);
        assert_eq!(stamped[0].profile.as_deref(), Some("Chrome/Default"));
        assert_eq!(stamped[0].user.as_deref(), Some("alice"));
        assert_eq!(stamped[0].browser, Some(BrowserFamily::Chromium));
    }
}
