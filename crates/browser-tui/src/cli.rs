//! The `br4n6` command-line mode: list browsers, dump history visits
//! (redirect-collapsed where the family supports it), and dump session state —
//! with local search and `text`/`jsonl`/`csv` output. The TUI mode lives in
//! [`crate::tui`].
//!
//! Cross-browser: the [`Family`] auto-detector routes a user-supplied file or
//! profile directory to the matching reader — Chromium (`History`/SNSS via
//! `browser-chrome` + `snss`), Firefox (`places.sqlite`/`sessionstore.jsonlz4`
//! via `browser-firefox`), or Safari (`History.db` via `browser-safari`) — and
//! every reader emits the same normalized [`BrowserEvent`] rows. All SQLite is
//! opened read-only and WAL-safe inside the readers (`open_evidence_db`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use browser_chrome::{collapse_redirects, parse_session, parse_visits};
use browser_core::BrowserEvent;
use browser_discovery::discover_profiles;
use clap::ValueEnum;
use serde_json::json;

/// Browser family a `history`/`sessions` source resolves to. Auto-detected from
/// the file name or, for a profile directory, from the artifact files it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Chromium,
    Firefox,
    Safari,
}

/// Output encoding shared by every CLI subcommand.
#[derive(Clone, Copy, Debug, ValueEnum, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable one line per record.
    #[default]
    Text,
    /// Newline-delimited JSON (one flat object per line).
    Jsonl,
    /// Comma-separated values with a header row.
    Csv,
}

/// Lowercased final path component, or `""` if there is none.
fn file_name_lower(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Classify a history *file* by its name: `places.sqlite` → Firefox,
/// `history.db` → Safari, anything else (`History`) → Chromium.
fn history_family_of_file(path: &Path) -> Family {
    match file_name_lower(path).as_str() {
        "places.sqlite" => Family::Firefox,
        "history.db" => Family::Safari,
        _ => Family::Chromium,
    }
}

/// Resolve a user-supplied history path to a concrete `(family, file)`. A file
/// is classified by name; a directory is probed for each family's history
/// artifact in turn (`places.sqlite` → `History.db` → `History`).
fn resolve_history(path: &Path) -> Result<(Family, PathBuf)> {
    if path.is_dir() {
        for (family, name) in [
            (Family::Firefox, "places.sqlite"),
            (Family::Safari, "History.db"),
            (Family::Chromium, "History"),
        ] {
            let candidate = path.join(name);
            if candidate.is_file() {
                return Ok((family, candidate));
            }
        }
        anyhow::bail!(
            "{} is a directory with no recognized history file \
             (places.sqlite / History.db / History)",
            path.display()
        );
    }
    Ok((history_family_of_file(path), path.to_path_buf()))
}

/// A resolved sessions source: either a Chromium SNSS directory to scan, or a
/// single Firefox `sessionstore`/`recovery` file to decode.
enum SessionSource {
    ChromiumDir(PathBuf),
    FirefoxFile(PathBuf),
}

/// True for a Firefox session file name (`sessionstore.jsonlz4` /
/// `recovery.jsonlz4`, and their `*-backups`/`previous` siblings).
fn is_firefox_session_name(name: &str) -> bool {
    let n = name.to_lowercase();
    n.ends_with(".jsonlz4") && (n.contains("sessionstore") || n.contains("recovery"))
}

/// Resolve a user-supplied sessions path. A Firefox `*.jsonlz4` file routes to
/// Firefox; a `Sessions/` child or any directory routes to the Chromium SNSS
/// scan; a Firefox profile directory containing a session file routes to Firefox.
fn resolve_sessions(path: &Path) -> Result<SessionSource> {
    if path.is_file() {
        if is_firefox_session_name(&file_name_lower(path)) {
            return Ok(SessionSource::FirefoxFile(path.to_path_buf()));
        }
        anyhow::bail!(
            "{} is not a recognized session file (expected sessionstore.jsonlz4)",
            path.display()
        );
    }
    if path.join("Sessions").is_dir() {
        return Ok(SessionSource::ChromiumDir(path.join("Sessions")));
    }
    if path.is_dir() {
        // Prefer a Firefox session file when present, else treat the directory
        // as a Chromium SNSS directory.
        for name in ["sessionstore.jsonlz4", "recovery.jsonlz4"] {
            let candidate = path.join(name);
            if candidate.is_file() {
                return Ok(SessionSource::FirefoxFile(candidate));
            }
        }
        return Ok(SessionSource::ChromiumDir(path.to_path_buf()));
    }
    anyhow::bail!(
        "{} is not a directory or session file (expected a profile, a \
         Chromium `Sessions` dir, or a Firefox sessionstore.jsonlz4)",
        path.display()
    );
}

/// `br4n6 history` — dump history visits for the auto-detected browser family.
/// Chromium redirect chains are collapsed into logical page views unless
/// `no_collapse` is set (Firefox/Safari history is already per-URL, so the flag
/// is a no-op there); `search` filters to visits whose URL or title contains the
/// (case-insensitive) needle.
///
/// # Errors
/// Returns an error if the path cannot be resolved or the history store cannot be
/// opened/queried.
pub fn run_history(
    path: &Path,
    no_collapse: bool,
    search: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let (family, history) = resolve_history(path)?;
    let mut visits = match family {
        Family::Chromium => {
            let mut v = parse_visits(&history).with_context(|| {
                format!("reading Chromium history visits from {}", history.display())
            })?;
            if !no_collapse {
                v = collapse_redirects(v);
            }
            v
        }
        Family::Firefox => browser_firefox::parse_history(&history)
            .with_context(|| format!("reading Firefox history from {}", history.display()))?,
        Family::Safari => browser_safari::parse_history(&history)
            .with_context(|| format!("reading Safari history from {}", history.display()))?,
    };
    if let Some(needle) = search {
        filter_in_place(&mut visits, needle);
    }
    emit_events(&visits, format);
    Ok(())
}

/// `br4n6 sessions` — dump session state (open/recently-closed tabs) for the
/// auto-detected browser family: Chromium SNSS files in a directory, or a
/// Firefox `sessionstore.jsonlz4`.
///
/// # Errors
/// Returns an error if the path cannot be resolved or no session source decodes.
pub fn run_sessions(path: &Path, search: Option<&str>, format: OutputFormat) -> Result<()> {
    let mut events = match resolve_sessions(path)? {
        SessionSource::FirefoxFile(file) => browser_firefox::parse_session(&file)
            .with_context(|| format!("reading Firefox session from {}", file.display()))?,
        SessionSource::ChromiumDir(dir) => read_chromium_sessions(&dir)?,
    };
    if let Some(needle) = search {
        filter_in_place(&mut events, needle);
    }
    emit_events(&events, format);
    Ok(())
}

/// Scan a Chromium SNSS directory, decoding every `Session_*`/`Tabs_*`/`Apps_*`
/// file into [`BrowserEvent`]s. A single unreadable file is non-fatal; the run
/// fails loud only if nothing at all decodes.
fn read_chromium_sessions(dir: &Path) -> Result<Vec<BrowserEvent>> {
    let mut events = Vec::new();
    let mut decoded_any = false;
    let mut last_err: Option<anyhow::Error> = None;
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("listing sessions directory {}", dir.display()))?
    {
        let entry = entry?;
        let file = entry.path();
        let Some(name) = file.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.starts_with("Session") || name.starts_with("Tabs") || name.starts_with("Apps")) {
            continue;
        }
        match parse_session(&file) {
            Ok(mut evs) => {
                decoded_any = true;
                events.append(&mut evs);
            }
            // A single unreadable session file is non-fatal: record it and keep
            // going so the other sources stay usable (fail loud, never silent).
            Err(e) => last_err = Some(e.context(format!("decoding {}", file.display()))),
        }
    }
    if !decoded_any {
        if let Some(e) = last_err {
            return Err(e);
        }
        anyhow::bail!("no Chromium session files found in {}", dir.display());
    }
    Ok(events)
}

/// `br4n6 browsers` — list discovered browser profiles under `home` (defaults to
/// the current user's home directory).
///
/// # Errors
/// Returns an error if the home directory cannot be resolved.
pub fn run_browsers(home: Option<&Path>, format: OutputFormat) -> Result<()> {
    let home = match home {
        Some(h) => h.to_path_buf(),
        None => dirs::home_dir().context("could not resolve the home directory")?,
    };
    let profiles = discover_profiles(&home);
    match format {
        OutputFormat::Text => {
            for p in &profiles {
                println!("{}\t{}\t{}", p.browser, p.name, p.path.display());
            }
        }
        OutputFormat::Jsonl => {
            for p in &profiles {
                println!(
                    "{}",
                    json!({
                        "browser": p.browser.to_string(),
                        "name": p.name,
                        "path": p.path.to_string_lossy(),
                    })
                );
            }
        }
        OutputFormat::Csv => {
            println!("browser,name,path");
            for p in &profiles {
                println!(
                    "{},{},{}",
                    csv_escape(&p.browser.to_string()),
                    csv_escape(&p.name),
                    csv_escape(&p.path.to_string_lossy())
                );
            }
        }
    }
    Ok(())
}

/// Retain only events whose `url` or `title` attr contains `needle`
/// (case-insensitive). Events lacking both attrs are dropped by a search.
fn filter_in_place(events: &mut Vec<BrowserEvent>, needle: &str) {
    let needle = needle.to_lowercase();
    events.retain(|e| {
        let hay = |k: &str| {
            e.attrs
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::to_lowercase)
        };
        hay("url").is_some_and(|u| u.contains(&needle))
            || hay("title").is_some_and(|t| t.contains(&needle))
    });
}

/// Emit a slice of events in the requested format.
fn emit_events(events: &[BrowserEvent], format: OutputFormat) {
    match format {
        OutputFormat::Text => {
            for e in events {
                println!("{}", event_text(e));
            }
        }
        OutputFormat::Jsonl => {
            for e in events {
                println!("{}", event_json(e));
            }
        }
        OutputFormat::Csv => {
            println!("timestamp,browser,artifact,url,title");
            for e in events {
                println!("{}", event_csv(e));
            }
        }
    }
}

fn attr_str(e: &BrowserEvent, key: &str) -> String {
    e.attrs
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

fn event_text(e: &BrowserEvent) -> String {
    let url = attr_str(e, "url");
    format!(
        "[{ts}] {browser}/{artifact}: {desc}  <{url}>",
        ts = format_ts(e.timestamp_ns),
        browser = e.browser,
        artifact = e.artifact,
        desc = e.description,
    )
}

/// Flat per-record JSON: `url`/`title` are hoisted to the top level (the shape a
/// front-end or jq pipeline expects), alongside the timestamp and provenance.
fn event_json(e: &BrowserEvent) -> String {
    let mut obj = json!({
        "timestamp_ns": e.timestamp_ns,
        "timestamp": format_ts(e.timestamp_ns),
        "browser": e.browser.to_string(),
        "artifact": e.artifact.to_string(),
        "source": e.source,
        "description": e.description,
        "url": attr_str(e, "url"),
        "title": attr_str(e, "title"),
    });
    // Carry the remaining attrs (transition, flags, tab/window ids, …) verbatim.
    if let Some(map) = obj.as_object_mut() {
        for (k, v) in &e.attrs {
            if k != "url" && k != "title" {
                map.insert(k.clone(), v.clone());
            }
        }
    }
    serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string())
}

fn event_csv(e: &BrowserEvent) -> String {
    format!(
        "{},{},{},{},{}",
        csv_escape(&format_ts(e.timestamp_ns)),
        csv_escape(&e.browser.to_string()),
        csv_escape(&e.artifact.to_string()),
        csv_escape(&attr_str(e, "url")),
        csv_escape(&attr_str(e, "title")),
    )
}

fn format_ts(ns: i64) -> String {
    use chrono::{DateTime, Utc};
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = u32::try_from(ns.rem_euclid(1_000_000_000)).unwrap_or(0);
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| "invalid".to_string())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserFamily};

    fn visit(url: &str, redirect: bool, chain_end: bool) -> BrowserEvent {
        BrowserEvent::new(
            13_327_626_000_000_000,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "/History",
            url,
        )
        .with_attr("url", json!(url))
        .with_attr("title", json!(""))
        .with_attr("is_redirect", json!(redirect))
        .with_attr("chain_end", json!(chain_end))
    }

    #[test]
    fn filter_in_place_matches_url_case_insensitively() {
        let mut evs = vec![
            visit("https://Alpha.example", false, false),
            visit("https://beta", false, false),
        ];
        filter_in_place(&mut evs, "ALPHA");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].attrs["url"], json!("https://Alpha.example"));
    }

    #[test]
    fn event_json_hoists_url_to_top_level() {
        let e = visit("https://x.example", false, false);
        let v: serde_json::Value = serde_json::from_str(&event_json(&e)).unwrap();
        assert_eq!(v["url"], json!("https://x.example"));
        assert_eq!(v["browser"], json!("Chromium"));
        // attrs are carried through, not nested under `attrs`.
        assert_eq!(v["is_redirect"], json!(false));
    }

    #[test]
    fn resolve_history_appends_history_for_a_profile_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("History"), b"x").unwrap();
        let (family, resolved) = resolve_history(dir.path()).unwrap();
        assert_eq!(family, Family::Chromium);
        assert_eq!(resolved, dir.path().join("History"));
    }

    #[test]
    fn resolve_history_passes_through_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("History");
        std::fs::write(&f, b"x").unwrap();
        let (family, resolved) = resolve_history(&f).unwrap();
        assert_eq!(family, Family::Chromium);
        assert_eq!(resolved, f);
    }

    #[test]
    fn resolve_history_detects_firefox_places_in_a_profile_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("places.sqlite"), b"x").unwrap();
        let (family, resolved) = resolve_history(dir.path()).unwrap();
        assert_eq!(family, Family::Firefox);
        assert_eq!(resolved, dir.path().join("places.sqlite"));
    }

    #[test]
    fn resolve_history_detects_safari_history_db_by_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("History.db");
        std::fs::write(&f, b"x").unwrap();
        let (family, resolved) = resolve_history(&f).unwrap();
        assert_eq!(family, Family::Safari);
        assert_eq!(resolved, f);
    }

    #[test]
    fn resolve_sessions_prefers_sessions_child() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Sessions")).unwrap();
        match resolve_sessions(dir.path()).unwrap() {
            SessionSource::ChromiumDir(p) => assert_eq!(p, dir.path().join("Sessions")),
            SessionSource::FirefoxFile(p) => panic!("expected Chromium dir, got {}", p.display()),
        }
    }

    #[test]
    fn resolve_sessions_routes_firefox_sessionstore_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("sessionstore.jsonlz4");
        std::fs::write(&f, b"x").unwrap();
        match resolve_sessions(&f).unwrap() {
            SessionSource::FirefoxFile(p) => assert_eq!(p, f),
            SessionSource::ChromiumDir(p) => panic!("expected Firefox file, got {}", p.display()),
        }
    }

    #[test]
    fn resolve_sessions_finds_firefox_file_in_a_profile_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sessionstore.jsonlz4"), b"x").unwrap();
        match resolve_sessions(dir.path()).unwrap() {
            SessionSource::FirefoxFile(p) => {
                assert_eq!(p, dir.path().join("sessionstore.jsonlz4"));
            }
            SessionSource::ChromiumDir(p) => panic!("expected Firefox file, got {}", p.display()),
        }
    }

    #[test]
    fn csv_escape_quotes_commas() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("plain"), "plain");
    }

    #[test]
    fn format_ts_is_rfc3339() {
        assert!(format_ts(1_648_000_000_000_000_000).contains('T'));
    }
}
