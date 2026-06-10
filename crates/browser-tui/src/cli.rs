//! The `br4n6` command-line mode: list browsers, dump Chromium history visits
//! (redirect-collapsed by default), and dump session state — with local search
//! and `text`/`jsonl`/`csv` output. The TUI mode lives in [`crate::tui`].
//!
//! Scope is the Chromium MVP (WS-D). Firefox/Safari slot in later behind the same
//! subcommands; the source-resolution helpers ([`resolve_history`],
//! [`resolve_sessions`]) are the seam where other families attach.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use browser_chrome::{collapse_redirects, parse_session, parse_visits};
use browser_core::BrowserEvent;
use browser_discovery::discover_profiles;
use clap::ValueEnum;
use serde_json::json;

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

/// Resolve a user-supplied path to a Chromium `History` SQLite file. A directory
/// is treated as a profile directory and its `History` child is used.
fn resolve_history(path: &Path) -> Result<PathBuf> {
    if path.is_dir() {
        let candidate = path.join("History");
        if candidate.is_file() {
            return Ok(candidate);
        }
        anyhow::bail!(
            "{} is a directory with no `History` file (not a Chromium profile?)",
            path.display()
        );
    }
    Ok(path.to_path_buf())
}

/// Resolve a user-supplied path to a Chromium `Sessions` directory. A `Sessions`
/// child is preferred when `path` is a profile directory; otherwise `path` itself
/// is used as the sessions directory.
fn resolve_sessions(path: &Path) -> Result<PathBuf> {
    if path.join("Sessions").is_dir() {
        return Ok(path.join("Sessions"));
    }
    if path.is_dir() {
        return Ok(path.to_path_buf());
    }
    anyhow::bail!(
        "{} is not a directory (expected a Chromium profile or its `Sessions` dir)",
        path.display()
    );
}

/// `br4n6 history` — dump Chromium history visits. Redirect chains are collapsed
/// into logical page views unless `no_collapse` is set; `search` filters to visits
/// whose URL or title contains the (case-insensitive) needle.
///
/// # Errors
/// Returns an error if the path cannot be resolved or the `History` DB cannot be
/// opened/queried.
pub fn run_history(
    path: &Path,
    no_collapse: bool,
    search: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let history = resolve_history(path)?;
    let mut visits = parse_visits(&history)
        .with_context(|| format!("reading history visits from {}", history.display()))?;
    if !no_collapse {
        visits = collapse_redirects(visits);
    }
    if let Some(needle) = search {
        filter_in_place(&mut visits, needle);
    }
    emit_events(&visits, format);
    Ok(())
}

/// `br4n6 sessions` — dump Chromium session state (open/recently-closed tabs).
///
/// # Errors
/// Returns an error if the path cannot be resolved or no session file decodes.
pub fn run_sessions(path: &Path, search: Option<&str>, format: OutputFormat) -> Result<()> {
    let dir = resolve_sessions(path)?;
    let mut events = Vec::new();
    let mut decoded_any = false;
    let mut last_err: Option<anyhow::Error> = None;
    for entry in std::fs::read_dir(&dir)
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
    if let Some(needle) = search {
        filter_in_place(&mut events, needle);
    }
    emit_events(&events, format);
    Ok(())
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
        let resolved = resolve_history(dir.path()).unwrap();
        assert_eq!(resolved, dir.path().join("History"));
    }

    #[test]
    fn resolve_history_passes_through_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("History");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(resolve_history(&f).unwrap(), f);
    }

    #[test]
    fn resolve_sessions_prefers_sessions_child() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Sessions")).unwrap();
        assert_eq!(
            resolve_sessions(dir.path()).unwrap(),
            dir.path().join("Sessions")
        );
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
