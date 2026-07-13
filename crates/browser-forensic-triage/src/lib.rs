#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! `RapidTriage` orchestration for browser forensics.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use browser_forensic_carve::CarvedRecord;
use browser_forensic_core::{BrowserEvent, BrowserFamily};
use browser_forensic_discovery::DiscoveredProfile;
use browser_forensic_integrity::IntegrityIndicator;

/// Consolidated triage report combining all forensic data sources.
#[derive(Debug, Serialize)]
pub struct TriageReport {
    /// Browser events from history, cookies, downloads, etc.
    pub events: Vec<BrowserEvent>,
    /// Records recovered from carving (free pages, WAL, etc.).
    pub carved: Vec<CarvedRecord>,
    /// Integrity anomalies (clearing, tampering, corruption).
    pub integrity: Vec<IntegrityIndicator>,
    /// Discovered browser profiles.
    pub profiles: Vec<DiscoveredProfile>,
    /// Timestamp when this report was generated (Unix nanos).
    pub generated_at_ns: i64,
}

/// Triage a single browser profile directory.
pub fn triage_profile(profile_path: &Path, browser: BrowserFamily) -> Result<TriageReport> {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);

    let mut events = Vec::new();
    let mut integrity = Vec::new();
    let mut carved = Vec::new();

    match browser {
        BrowserFamily::Chromium => {
            triage_chromium_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
        BrowserFamily::Firefox => {
            triage_firefox_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
        BrowserFamily::Safari => {
            triage_safari_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
        BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy => {
            triage_webcache_profile(profile_path, &mut events);
        }
    }

    events.sort_by_key(|e| e.timestamp_ns);

    Ok(TriageReport {
        events,
        carved,
        integrity,
        profiles: Vec::new(),
        generated_at_ns: now_ns,
    })
}

/// Triage all browser profiles discovered under a home directory.
pub fn triage(home_dir: &Path) -> Result<TriageReport> {
    Ok(triage_profiles(
        browser_forensic_discovery::discover_profiles(home_dir),
    ))
}

/// Triage every Chromium/Firefox profile and embedded-Chromium container found
/// by a recursive structural sweep of an evidence tree rooted at `root`.
///
/// This is the general path: it discovers browser *and* embedded-Chromium
/// containers (Electron / WebView2 / CEF) anywhere under `root`, not only the
/// canonical per-user profile locations that [`triage`] scans.
pub fn triage_sweep(root: &Path) -> Result<TriageReport> {
    Ok(triage_profiles(
        browser_forensic_discovery::sweep_containers(root),
    ))
}

/// Triage a set of already-discovered profiles into one consolidated report.
fn triage_profiles(profiles: Vec<DiscoveredProfile>) -> TriageReport {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);

    let mut all_events = Vec::new();
    let mut all_integrity = Vec::new();
    let mut all_carved = Vec::new();

    for profile in &profiles {
        let mut events = Vec::new();
        let mut integrity_vec = Vec::new();
        let mut carved_vec = Vec::new();

        match profile.browser {
            BrowserFamily::Chromium => {
                triage_chromium_profile(
                    &profile.path,
                    &mut events,
                    &mut integrity_vec,
                    &mut carved_vec,
                );
            }
            BrowserFamily::Firefox => {
                triage_firefox_profile(
                    &profile.path,
                    &mut events,
                    &mut integrity_vec,
                    &mut carved_vec,
                );
            }
            BrowserFamily::Safari => {
                triage_safari_profile(
                    &profile.path,
                    &mut events,
                    &mut integrity_vec,
                    &mut carved_vec,
                );
            }
            BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy => {
                triage_webcache_profile(&profile.path, &mut events);
            }
        }

        all_events.extend(events);
        all_integrity.extend(integrity_vec);
        all_carved.extend(carved_vec);
    }

    all_events.sort_by_key(|e| e.timestamp_ns);

    TriageReport {
        events: all_events,
        carved: all_carved,
        integrity: all_integrity,
        profiles,
        generated_at_ns: now_ns,
    }
}

/// Collect **recovered-domain** events from a profile directory — domains a user
/// contacted that survive a history clear, drawn from network/state artifacts:
/// Chromium `Network Persistent State`, `Reporting and NEL`, `DIPS`/BTM, and
/// `TransportSecurity` (hashed, non-enumerable), plus Firefox
/// `SiteSecurityServiceState.txt` (cleartext HSTS). Each source is best-effort;
/// per-artifact failures are absorbed so triage stays resilient. The Chromium
/// JSON/SQLite artifacts live either at the profile root or under a `Network/`
/// subdirectory depending on the Chromium version — both are checked.
#[must_use]
pub fn collect_recovered_domains(profile: &Path) -> Vec<BrowserEvent> {
    let mut events = Vec::new();

    for name in [
        "Network Persistent State",
        "Reporting and NEL",
        "TransportSecurity",
    ] {
        for base in [profile.to_path_buf(), profile.join("Network")] {
            let p = base.join(name);
            if !p.is_file() {
                continue;
            }
            let parsed = match name {
                "Network Persistent State" => {
                    browser_forensic_chrome::parse_network_persistent_state(&p)
                }
                "Reporting and NEL" => browser_forensic_chrome::parse_reporting_and_nel(&p),
                _ => browser_forensic_chrome::parse_transport_security(&p),
            };
            if let Ok(mut e) = parsed {
                events.append(&mut e);
            }
        }
    }

    let dips = profile.join("DIPS");
    if dips.is_file() {
        if let Ok(mut e) = browser_forensic_chrome::parse_dips(&dips) {
            events.append(&mut e);
        }
    }

    let ff_hsts = profile.join("SiteSecurityServiceState.txt");
    if ff_hsts.is_file() {
        if let Ok(mut e) = browser_forensic_firefox::parse_site_security(&ff_hsts) {
            events.append(&mut e);
        }
    }

    events
}

fn triage_chromium_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let history_path = path.join("History");
    if history_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_history(&history_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_history_integrity(
            &history_path,
            BrowserFamily::Chromium,
        ) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_database_integrity(&history_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_forensic_carve::carve_sqlite_free_pages(&history_path) {
            carved.extend(result.records);
        }
    }

    let cookies_path = path.join("Cookies");
    if cookies_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_cookies(&cookies_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_cookie_integrity(
            &cookies_path,
            BrowserFamily::Chromium,
        ) {
            integrity.append(&mut ind);
        }
    }

    let ext_cookies_path = path.join("Extension Cookies");
    if ext_cookies_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_extension_cookies(&ext_cookies_path) {
            events.append(&mut evts);
        }
    }

    let bookmarks_path = path.join("Bookmarks");
    if bookmarks_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_bookmarks(&bookmarks_path) {
            events.append(&mut evts);
        }
    }

    let favicons_path = path.join("Favicons");
    if favicons_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_favicons(&favicons_path) {
            events.append(&mut evts);
        }
    }

    let top_sites_path = path.join("Top Sites");
    if top_sites_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_top_sites(&top_sites_path) {
            events.append(&mut evts);
        }
    }

    let shortcuts_path = path.join("Shortcuts");
    if shortcuts_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_shortcuts(&shortcuts_path) {
            events.append(&mut evts);
        }
    }

    let predictor_path = path.join("Network Action Predictor");
    if predictor_path.is_file() {
        if let Ok(mut evts) =
            browser_forensic_chrome::parse_network_action_predictor(&predictor_path)
        {
            events.append(&mut evts);
        }
    }

    let media_history_path = path.join("Media History");
    if media_history_path.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_media_history(&media_history_path) {
            events.append(&mut evts);
        }
    }

    // Credential / account metadata (secrets never decrypted). Per-artifact
    // failures are absorbed so triage stays best-effort.
    let login_data = path.join("Login Data");
    if login_data.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_login_data(&login_data) {
            events.append(&mut evts);
        }
    }
    let web_data = path.join("Web Data");
    if web_data.is_file() {
        if let Ok(mut evts) = browser_forensic_chrome::parse_web_data(&web_data) {
            events.append(&mut evts);
        }
    }
    for prefs_name in ["Preferences", "Secure Preferences"] {
        let prefs = path.join(prefs_name);
        if prefs.is_file() {
            if let Ok(mut evts) = browser_forensic_chrome::parse_preferences(&prefs) {
                events.append(&mut evts);
            }
            if let Ok(mut evts) = browser_forensic_chrome::parse_permissions(&prefs) {
                events.append(&mut evts);
            }
        }
    }

    // Web storage: Local/Session Storage (LevelDB) and IndexedDB. Per-source
    // failures are absorbed inside the collector so triage stays best-effort.
    events.extend(browser_forensic_storage::collect_chromium_web_storage(path));

    // Recovered domains: network/state artifacts that outlive a history clear.
    events.extend(collect_recovered_domains(path));
}

fn triage_firefox_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let places_path = path.join("places.sqlite");
    if places_path.is_file() {
        if let Ok(mut evts) = browser_forensic_firefox::parse_history(&places_path) {
            events.append(&mut evts);
        }
        // Typed address-bar input and page annotations (places.sqlite).
        if let Ok(mut evts) = browser_forensic_firefox::parse_typed_input(&places_path) {
            events.append(&mut evts);
        }
        if let Ok(mut evts) = browser_forensic_firefox::parse_annotations(&places_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_history_integrity(
            &places_path,
            BrowserFamily::Firefox,
        ) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_database_integrity(&places_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_forensic_carve::carve_sqlite_free_pages(&places_path) {
            carved.extend(result.records);
        }
    }

    let cookies_path = path.join("cookies.sqlite");
    if cookies_path.is_file() {
        if let Ok(mut evts) = browser_forensic_firefox::parse_cookies(&cookies_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_cookie_integrity(
            &cookies_path,
            BrowserFamily::Firefox,
        ) {
            integrity.append(&mut ind);
        }
    }

    // Credential / account metadata (secrets never decrypted).
    let logins = path.join("logins.json");
    if logins.is_file() {
        if let Ok(mut evts) = browser_forensic_firefox::parse_login_data(&logins) {
            events.append(&mut evts);
        }
    }
    let perms = path.join("permissions.sqlite");
    if perms.is_file() {
        if let Ok(mut evts) = browser_forensic_firefox::parse_firefox_permissions(&perms) {
            events.append(&mut evts);
        }
    }

    // Web storage: webappsstore.sqlite (Local Storage) and IndexedDB SQLite.
    events.extend(browser_forensic_storage::collect_firefox_web_storage(path));

    // Recovered domains: Firefox HSTS (cleartext) survives a history clear.
    events.extend(collect_recovered_domains(path));

    // Deleted bookmarks: diff bookmarkbackups/*.jsonlz4 against current bookmarks.
    if let Ok(mut evts) = browser_forensic_firefox::recover_deleted_bookmarks(path) {
        events.append(&mut evts);
    }
}

fn triage_safari_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let history_path = path.join("History.db");
    if history_path.is_file() {
        if let Ok(mut evts) = browser_forensic_safari::parse_history(&history_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_history_integrity(
            &history_path,
            BrowserFamily::Safari,
        ) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_forensic_integrity::check_database_integrity(&history_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_forensic_carve::carve_sqlite_free_pages(&history_path) {
            carved.extend(result.records);
        }
    }
}

/// Triage an IE / Edge-Legacy profile: parse the ESE `WebCacheV01.dat` (the
/// consolidated history/cookies/cache/DOM store) if present. `path` may be the
/// WebCache directory itself or a parent containing it. WebCache is ESE, not
/// SQLite, so the SQLite integrity/carve steps do not apply. A parse failure is
/// absorbed so one unreadable store never aborts a multi-profile triage.
fn triage_webcache_profile(path: &Path, events: &mut Vec<BrowserEvent>) {
    let candidates = [
        path.join("WebCacheV01.dat"),
        path.join("WebCache").join("WebCacheV01.dat"),
        path.to_path_buf(),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            if let Ok(mut evts) = browser_forensic_webcache::parse_webcache(&candidate) {
                events.append(&mut evts);
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::BrowserFamily;
    use tempfile::TempDir;

    #[test]
    fn triage_report_serializes() {
        let report = TriageReport {
            events: Vec::new(),
            carved: Vec::new(),
            integrity: Vec::new(),
            profiles: Vec::new(),
            generated_at_ns: 1_700_000_000_000_000_000,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("generated_at_ns"));
        assert!(json.contains("1700000000000000000"));
    }

    #[test]
    fn triage_profile_chrome_returns_report() {
        let dir = TempDir::new().expect("tempdir");
        let history = dir.path().join("History");

        let conn = rusqlite::Connection::open(&history).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
        ).expect("setup");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(
            !report.events.is_empty(),
            "should have parsed history events"
        );
        assert!(report.generated_at_ns > 0);
    }

    #[test]
    fn triage_chrome_includes_credential_and_permission_metadata() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");

        let login = dir.path().join("Login Data");
        let conn = rusqlite::Connection::open(&login).expect("open login");
        conn.execute_batch(
            "CREATE TABLE logins (id INTEGER PRIMARY KEY, origin_url TEXT NOT NULL DEFAULT '', action_url TEXT, username_value TEXT, password_value BLOB, signon_realm TEXT NOT NULL DEFAULT '', date_created INTEGER NOT NULL DEFAULT 0, date_last_used INTEGER NOT NULL DEFAULT 0, date_password_modified INTEGER NOT NULL DEFAULT 0, times_used INTEGER NOT NULL DEFAULT 0, blacklisted_by_user INTEGER NOT NULL DEFAULT 0);
             INSERT INTO logins (origin_url, signon_realm, username_value, date_created, times_used) VALUES ('https://bank.example', 'https://bank.example/', 'u', 13300000000000000, 4);",
        ).expect("setup login");
        drop(conn);

        let webdata = dir.path().join("Web Data");
        let conn = rusqlite::Connection::open(&webdata).expect("open webdata");
        conn.execute_batch(
            "CREATE TABLE credit_cards (guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER NOT NULL DEFAULT 0, use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0);
             INSERT INTO credit_cards (guid, name_on_card, expiration_month, expiration_year, date_modified, use_count, use_date) VALUES ('g', 'A Suspect', 8, 2027, 13340000000000000, 1, 13350000000000000);",
        ).expect("setup webdata");
        drop(conn);

        std::fs::write(
            dir.path().join("Preferences"),
            br#"{"profile":{"exit_type":"Crashed","content_settings":{"exceptions":{"geolocation":{"https://x.example:443,*":{"setting":2}}}}}}"#,
        )
        .expect("setup prefs");

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        let kinds: std::collections::HashSet<_> =
            report.events.iter().map(|e| e.artifact.clone()).collect();
        assert!(
            kinds.contains(&ArtifactKind::LoginData),
            "expected login-data events"
        );
        assert!(
            kinds.contains(&ArtifactKind::CreditCard),
            "expected credit-card metadata events"
        );
        assert!(
            kinds.contains(&ArtifactKind::Permission),
            "expected per-site permission events"
        );
    }

    #[test]
    fn triage_chromium_includes_favicons() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");
        let favicons = dir.path().join("Favicons");
        let conn = rusqlite::Connection::open(&favicons).expect("open favicons");
        conn.execute_batch(
            "CREATE TABLE icon_mapping(id INTEGER PRIMARY KEY, page_url LONGVARCHAR NOT NULL, icon_id INTEGER);
             CREATE TABLE favicons(id INTEGER PRIMARY KEY, url LONGVARCHAR NOT NULL);
             CREATE TABLE favicon_bitmaps(id INTEGER PRIMARY KEY, icon_id INTEGER NOT NULL, last_updated INTEGER DEFAULT 0, width INTEGER DEFAULT 0);
             INSERT INTO favicons VALUES (1, 'https://fav.example/icon.png');
             INSERT INTO icon_mapping (page_url, icon_id) VALUES ('https://visited.example/x', 1);
             INSERT INTO favicon_bitmaps (icon_id, last_updated, width) VALUES (1, 13300000000000000, 32);",
        ).expect("setup favicons");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(
            report
                .events
                .iter()
                .any(|e| e.artifact == ArtifactKind::Favicon
                    && e.attrs.get("page_url")
                        == Some(&serde_json::json!("https://visited.example/x"))),
            "expected Favicon events surfacing the page_url"
        );
    }

    #[test]
    fn triage_chromium_includes_top_sites() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");
        let ts = dir.path().join("Top Sites");
        let conn = rusqlite::Connection::open(&ts).expect("open top sites");
        conn.execute_batch(
            "CREATE TABLE top_sites(url TEXT NOT NULL PRIMARY KEY, url_rank INTEGER NOT NULL, title TEXT NOT NULL);
             INSERT INTO top_sites VALUES ('https://most.example/', 0, 'Most Visited');",
        ).expect("setup top sites");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(
            report
                .events
                .iter()
                .any(|e| e.artifact == ArtifactKind::TopSite
                    && e.attrs.get("url") == Some(&serde_json::json!("https://most.example/"))),
            "expected TopSite events"
        );
    }

    #[test]
    fn triage_chromium_includes_shortcuts() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");
        let sc = dir.path().join("Shortcuts");
        let conn = rusqlite::Connection::open(&sc).expect("open shortcuts");
        conn.execute_batch(
            "CREATE TABLE omni_box_shortcuts (id VARCHAR PRIMARY KEY, text VARCHAR, fill_into_edit VARCHAR, url VARCHAR, contents VARCHAR, last_access_time INTEGER, number_of_hits INTEGER);
             INSERT INTO omni_box_shortcuts (id, text, url, last_access_time, number_of_hits) VALUES ('s1', 'secret site', 'https://secret.example/', 13300000000000000, 2);",
        ).expect("setup shortcuts");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(
            report
                .events
                .iter()
                .any(|e| e.artifact == ArtifactKind::Shortcut
                    && e.attrs.get("typed_text") == Some(&serde_json::json!("secret site"))),
            "expected Shortcut events surfacing the typed text"
        );
    }

    #[test]
    fn triage_chromium_includes_network_action_predictor() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");
        let nap = dir.path().join("Network Action Predictor");
        let conn = rusqlite::Connection::open(&nap).expect("open nap");
        conn.execute_batch(
            "CREATE TABLE network_action_predictor (id TEXT PRIMARY KEY, user_text TEXT, url TEXT, number_of_hits INTEGER, number_of_misses INTEGER);
             INSERT INTO network_action_predictor VALUES ('n1', 'typed thing', 'https://p.example/', 3, 1);",
        ).expect("setup nap");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(
            report
                .events
                .iter()
                .any(|e| e.artifact == ArtifactKind::NetworkPrediction
                    && e.attrs.get("user_text") == Some(&serde_json::json!("typed thing"))),
            "expected NetworkPrediction events surfacing user_text"
        );
    }

    #[test]
    fn triage_chromium_includes_media_history() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");
        let mh = dir.path().join("Media History");
        let conn = rusqlite::Connection::open(&mh).expect("open media history");
        conn.execute_batch(
            "CREATE TABLE playback(id INTEGER PRIMARY KEY, origin_id INTEGER, url TEXT, watch_time_s INTEGER, has_video INTEGER, has_audio INTEGER, last_updated_time_s INTEGER);
             INSERT INTO playback (url, watch_time_s, has_video, has_audio, last_updated_time_s) VALUES ('https://played.example/v', 393, 1, 1, 13344473600);",
        ).expect("setup media history");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(
            report
                .events
                .iter()
                .any(|e| e.artifact == ArtifactKind::MediaPlayback
                    && e.attrs.get("url") == Some(&serde_json::json!("https://played.example/v"))),
            "expected MediaPlayback events"
        );
    }

    #[test]
    fn triage_chromium_includes_extension_cookies() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");
        let ext = dir.path().join("Extension Cookies");
        let conn = rusqlite::Connection::open(&ext).expect("open ext cookies");
        conn.execute_batch(
            "CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value TEXT DEFAULT '', path TEXT NOT NULL, expires_utc INTEGER DEFAULT 0, is_secure INTEGER DEFAULT 0, is_httponly INTEGER DEFAULT 0, samesite INTEGER DEFAULT -1, encrypted_value BLOB DEFAULT '');
             INSERT INTO cookies (creation_utc, host_key, name, path) VALUES (13300000000000000, '.ext.example', 'auth', '/');",
        ).expect("setup ext cookies");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(
            report
                .events
                .iter()
                .any(|e| e.artifact == ArtifactKind::Cookies
                    && e.attrs.get("cookie_store") == Some(&serde_json::json!("extension"))),
            "expected extension-tagged cookie events"
        );
    }

    #[test]
    fn triage_chromium_includes_recovered_domains() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");

        // DIPS bounce record (newer schema) — cleartext site survives history wipe.
        let dips = dir.path().join("DIPS");
        let conn = rusqlite::Connection::open(&dips).expect("open dips");
        conn.execute_batch(
            "CREATE TABLE bounces(site TEXT PRIMARY KEY NOT NULL, first_user_activation_time INTEGER, last_user_activation_time INTEGER, first_bounce_time INTEGER, last_bounce_time INTEGER, first_web_authn_assertion_time INTEGER, last_web_authn_assertion_time INTEGER);
             INSERT INTO bounces (site, last_user_activation_time) VALUES ('recovered.example.com', 13300000000000000);",
        ).expect("setup dips");
        drop(conn);

        // Network Persistent State — HTTP/2/3 server the browser contacted.
        std::fs::write(
            dir.path().join("Network Persistent State"),
            br#"{"net":{"http_server_properties":{"servers":[{"server":"https://cdn.example.net"}]}}}"#,
        )
        .expect("setup nps");

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        let has_recovered = report
            .events
            .iter()
            .any(|e| e.artifact == ArtifactKind::RecoveredDomain);
        assert!(
            has_recovered,
            "expected RecoveredDomain events from DIPS/Network Persistent State"
        );
    }

    #[test]
    fn collect_recovered_domains_reads_firefox_cleartext_hsts() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(
            dir.path().join("SiteSecurityServiceState.txt"),
            b"ff-recovered.example.org:HSTS\t9\t19600\t1800000000000,1,1\n",
        )
        .expect("hsts");
        let events = collect_recovered_domains(dir.path());
        assert!(events
            .iter()
            .any(|e| e.artifact == ArtifactKind::RecoveredDomain
                && e.attrs.get("domain") == Some(&serde_json::json!("ff-recovered.example.org"))));
    }

    #[test]
    fn triage_firefox_includes_login_and_permission_metadata() {
        use browser_forensic_core::ArtifactKind;
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(
            dir.path().join("logins.json"),
            br#"{"logins":[{"hostname":"https://bank.example","timesUsed":3,"timeCreated":1648000000000}]}"#,
        )
        .expect("logins");
        let perms = dir.path().join("permissions.sqlite");
        let conn = rusqlite::Connection::open(&perms).expect("open perms");
        conn.execute_batch(
            "CREATE TABLE moz_perms (id INTEGER PRIMARY KEY, origin TEXT, type TEXT, permission INTEGER, expireType INTEGER, expireTime INTEGER, modificationTime INTEGER);
             INSERT INTO moz_perms (origin, type, permission, modificationTime) VALUES ('https://ff.example', 'geo', 1, 1650000000000);",
        ).expect("setup perms");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Firefox).expect("triage");
        let kinds: std::collections::HashSet<_> =
            report.events.iter().map(|e| e.artifact.clone()).collect();
        assert!(kinds.contains(&ArtifactKind::LoginData));
        assert!(kinds.contains(&ArtifactKind::Permission));
    }

    #[test]
    fn triage_firefox_profile_includes_web_storage() {
        let dir = TempDir::new().expect("tempdir");
        let store = dir.path().join("webappsstore.sqlite");
        let conn = rusqlite::Connection::open(&store).expect("open");
        conn.execute_batch(
            "CREATE TABLE webappsstore2 (scope TEXT, key TEXT, value TEXT);
             INSERT INTO webappsstore2 VALUES ('moc.elpmaxe.:http:80', 'theme', 'dark');",
        )
        .expect("setup");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Firefox).expect("triage");
        assert!(
            report
                .events
                .iter()
                .any(|e| e.attrs.contains_key("storage_type")),
            "triage should include web-storage events"
        );
    }

    #[test]
    fn triage_profile_nonexistent_path_returns_empty_report() {
        let dir = TempDir::new().expect("tempdir");
        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(report.events.is_empty());
    }

    #[test]
    fn triage_report_has_all_fields() {
        let report = TriageReport {
            events: vec![],
            carved: vec![],
            integrity: vec![],
            profiles: vec![],
            generated_at_ns: 0,
        };
        let _ = report.events.len();
        let _ = report.carved.len();
        let _ = report.integrity.len();
        let _ = report.profiles.len();
        let _ = report.generated_at_ns;
    }

    /// A Chrome profile whose `History` has had every row deleted, leaving
    /// free-space the carver can recover — so the default (carving) tier yields
    /// carved records while a `carve: false` pass yields none.
    fn chrome_profile_with_deleted_history() -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        let history = dir.path().join("History");
        let conn = rusqlite::Connection::open(&history).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://secret-one.example', 'One', 3, 13300000000000000);
             INSERT INTO urls VALUES (2, 'https://secret-two.example', 'Two', 5, 13300000000000001);
             INSERT INTO urls VALUES (3, 'https://secret-three.example', 'Three', 7, 13300000000000002);
             DELETE FROM urls;",
        )
        .expect("setup");
        drop(conn);
        dir
    }

    #[test]
    fn carve_true_matches_default_triage_profile() {
        let dir = chrome_profile_with_deleted_history();
        let default = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        let opted = triage_profile_with_options(
            dir.path(),
            BrowserFamily::Chromium,
            TriageOptions { carve: true },
        )
        .expect("triage opts");
        assert_eq!(
            default.carved.len(),
            opted.carved.len(),
            "carve:true must be identical to the default carving triage"
        );
    }

    #[test]
    fn carve_false_skips_carving() {
        let dir = chrome_profile_with_deleted_history();
        let opted = triage_profile_with_options(
            dir.path(),
            BrowserFamily::Chromium,
            TriageOptions { carve: false },
        )
        .expect("triage opts");
        assert!(
            opted.carved.is_empty(),
            "carve:false must skip deleted-record carving entirely"
        );
        // Live-artifact parsing still runs regardless of the carve tier.
        let _ = opted.events;
    }

    #[test]
    fn triage_with_options_home_scan_respects_carve_flag() {
        let dir = TempDir::new().expect("tempdir");
        let report = triage_with_options(dir.path(), TriageOptions { carve: false })
            .expect("triage_with_options");
        assert!(report.carved.is_empty());
    }

    #[test]
    fn triage_sweep_discovers_and_attributes_nested_chrome_profile() {
        let root = TempDir::new().expect("tempdir");
        let default = root
            .path()
            .join("Users/x/AppData/Local/Google/Chrome/User Data/Default");
        std::fs::create_dir_all(&default).expect("mkdir");
        let history = default.join("History");
        let conn = rusqlite::Connection::open(&history).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);",
        )
        .expect("setup");
        drop(conn);

        let report = triage_sweep(root.path()).expect("triage_sweep");
        assert!(
            report
                .profiles
                .iter()
                .any(|p| p.container.map(|c| c.app) == Some("Google Chrome")),
            "sweep should discover + attribute the nested Chrome profile"
        );
        assert!(
            !report.events.is_empty(),
            "should have parsed history events"
        );
    }
}
