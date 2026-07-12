//! The `br4n6` / `bw` command-line mode and dispatch ([`run`]): list browsers,
//! dump history visits (redirect-collapsed where the family supports it) and
//! session state with local search, plus the full forensic surface absorbed from
//! the former `bw` binary — any single artifact (cookies / downloads / bookmarks
//! / extensions / login-data / autofill / session / cache / timeline), rare-domain
//! analysis, integrity checks, deleted-record carving, and full triage — all with
//! `text`/`jsonl`/`csv` output. The interactive TUI is launched via the injected
//! `launch_tui` callback.
//!
//! Cross-browser: the [`Family`] auto-detector routes a user-supplied file or
//! profile directory to the matching reader — Chromium (`History`/SNSS via
//! `browser-chrome` + `snss`), Firefox (`places.sqlite`/`sessionstore.jsonlz4`
//! via `browser-firefox`), or Safari (`History.db` via `browser-safari`) — and
//! every reader emits the same normalized [`BrowserEvent`] rows. All SQLite is
//! opened read-only and WAL-safe inside the readers (`open_evidence_db`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use browser_forensic_chrome::{collapse_redirects, parse_session, parse_visits};
use browser_forensic_core::reconstruct::{
    resolve_referrer_chains, sessionize, tag_redirect_chains, SessionConfig,
    DEFAULT_IDLE_GAP_MINUTES,
};
use browser_forensic_core::BrowserEvent;
use browser_forensic_discovery::discover_profiles;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;

/// br4n6 — read-only browser state, history, and forensic-triage front-end.
/// With no subcommand it launches the interactive TUI over the default profile.
#[derive(Parser, Debug)]
#[command(name = "br4n6", version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

/// Shared `PATH` + `--format` arguments for the single-artifact subcommands.
#[derive(Args, Debug)]
struct ArtifactArgs {
    /// Path to the browser artifact file or directory.
    #[arg(value_name = "PATH")]
    path: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List browser profiles discovered on this system.
    Browsers {
        /// Home directory to scan (defaults to the current user's home).
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
        /// Recursively sweep an evidence tree for browser AND embedded-Chromium
        /// containers (Electron / WebView2 / CEF), attributed to their app.
        #[arg(long, value_name = "ROOT")]
        sweep: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Dump history visits (Chromium redirect-collapsed by default).
    History {
        /// A history file, or a profile directory containing one.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Keep every raw visit, including intermediate redirect hops.
        #[arg(long)]
        no_collapse: bool,
        /// Show only visits whose URL or title contains this substring.
        #[arg(long, value_name = "TEXT")]
        search: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Dump session state (open / recently-closed tabs).
    Sessions {
        /// A profile directory, or its `Sessions` directory.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Show only tabs whose URL or title contains this substring.
        #[arg(long, value_name = "TEXT")]
        search: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Reconstruct navigation: referrer + redirect chains and inferred sessions.
    Chains {
        /// A history file, or a profile directory containing one.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Idle-gap threshold (minutes) for inferring session boundaries.
        #[arg(long, value_name = "MINUTES", default_value_t = DEFAULT_IDLE_GAP_MINUTES)]
        idle_gap: i64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Launch the interactive terminal viewer (session state).
    Tui {
        /// A `Sessions` directory to view (defaults to the local profile).
        #[arg(value_name = "SESSIONS_DIR")]
        path: Option<PathBuf>,
    },
    /// Parse browser history into a chronological timeline.
    Timeline(ArtifactArgs),
    /// Parse browser cookies.
    Cookies(ArtifactArgs),
    /// Parse browser downloads.
    Downloads(ArtifactArgs),
    /// Parse browser bookmarks.
    Bookmarks(ArtifactArgs),
    /// Parse browser extensions.
    Extensions(ArtifactArgs),
    /// Parse browser login data (passwords NEVER exposed).
    LoginData(ArtifactArgs),
    /// Parse browser autofill data.
    Autofill(ArtifactArgs),
    /// Parse a browser session store.
    Session(ArtifactArgs),
    /// Parse browser cache.
    Cache(ArtifactArgs),
    /// Parse browser preferences (Chrome `Preferences` / Firefox `prefs.js`).
    Preferences(ArtifactArgs),
    /// List per-site permission grants (Chrome `Preferences` / Firefox `permissions.sqlite`).
    Permissions(ArtifactArgs),
    /// Surface stored account/payment metadata from Chromium `Web Data`
    /// (cards, tokens, autofill profiles). Values are NEVER decrypted.
    Credentials(ArtifactArgs),
    /// Recover domains contacted even after history is cleared, from
    /// network/state artifacts (Network Persistent State, Reporting and NEL,
    /// DIPS/BTM, TransportSecurity, Firefox HSTS). `PATH` is a profile directory
    /// or a single such artifact file.
    RecoveredDomains(ArtifactArgs),
    /// Parse web storage (Local/Session Storage, IndexedDB).
    Storage(ArtifactArgs),
    /// Parse a Chromium `Favicons` database (page_url visited-URL source).
    Favicons(ArtifactArgs),
    /// Parse a Chromium `Top Sites` database (most-visited / frecency).
    TopSites(ArtifactArgs),
    /// Parse a Chromium `Shortcuts` database (omnibox strings the user typed).
    Shortcuts(ArtifactArgs),
    /// Parse a Chromium `Network Action Predictor` (partial typed strings).
    Predictor(ArtifactArgs),
    /// Export a correlated timeline for a profile/home to one file.
    Export {
        /// A profile directory or home directory to collect events from.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Export format.
        #[arg(long, value_enum, default_value_t = crate::export::ExportFormat::Xlsx)]
        format: crate::export::ExportFormat,
        /// Output file (required for xlsx/sqlite; defaults to stdout otherwise).
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
        /// Render timestamps in this IANA timezone (e.g. `America/New_York`).
        #[arg(long, value_name = "TZ")]
        timezone: Option<String>,
        /// Add an interpretation column (search terms, tracking cookies, …).
        #[arg(long)]
        interpret: bool,
    },
    /// Discover browser profiles on this system (bw-style output).
    Profiles {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Analyze browser history for rarely-visited domains.
    Analyze {
        /// Path to a browser history file.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Show domains visited at most this many times (cap).
        #[arg(long, default_value_t = 5)]
        cap: usize,
    },
    /// Run integrity checks on a browser artifact.
    Integrity(ArtifactArgs),
    /// Carve deleted records from a browser SQLite database.
    Carve(ArtifactArgs),
    /// Run full triage: discover profiles, parse, check integrity, carve.
    Triage {
        /// Home directory to scan for browser profiles.
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

/// Parse the process arguments and dispatch. The no-subcommand and `tui` paths
/// call `launch_tui` (injected so this lib stays decoupled from the TUI main
/// loop); every other subcommand runs a scriptable handler in this module.
///
/// # Errors
/// Propagates whatever the selected handler returns.
pub fn run<F, E>(launch_tui: F) -> Result<()>
where
    F: FnOnce(Option<PathBuf>) -> std::result::Result<(), E>,
    E: std::error::Error + Send + Sync + 'static,
{
    let cli = Cli::parse();
    match cli.command {
        None => launch_tui(None).map_err(anyhow::Error::from),
        Some(Command::Tui { path }) => launch_tui(path).map_err(anyhow::Error::from),
        Some(Command::Browsers {
            home,
            sweep,
            format,
        }) => match sweep {
            Some(root) => run_browsers_sweep(&root, format),
            None => run_browsers(home.as_deref(), format),
        },
        Some(Command::History {
            path,
            no_collapse,
            search,
            format,
        }) => run_history(&path, no_collapse, search.as_deref(), format),
        Some(Command::Sessions {
            path,
            search,
            format,
        }) => run_sessions(&path, search.as_deref(), format),
        Some(Command::Chains {
            path,
            idle_gap,
            format,
        }) => run_chains(&path, idle_gap, format),
        Some(Command::Timeline(a)) => run_artifact(&a.path, ArtifactType::History, a.format),
        Some(Command::Cookies(a)) => run_artifact(&a.path, ArtifactType::Cookies, a.format),
        Some(Command::Downloads(a)) => run_artifact(&a.path, ArtifactType::Downloads, a.format),
        Some(Command::Bookmarks(a)) => run_artifact(&a.path, ArtifactType::Bookmarks, a.format),
        Some(Command::Extensions(a)) => run_artifact(&a.path, ArtifactType::Extensions, a.format),
        Some(Command::LoginData(a)) => run_artifact(&a.path, ArtifactType::LoginData, a.format),
        Some(Command::Autofill(a)) => run_artifact(&a.path, ArtifactType::Autofill, a.format),
        Some(Command::Session(a)) => run_artifact(&a.path, ArtifactType::Session, a.format),
        Some(Command::Cache(a)) => run_artifact(&a.path, ArtifactType::Cache, a.format),
        Some(Command::Preferences(a)) => run_artifact(&a.path, ArtifactType::Preferences, a.format),
        Some(Command::Permissions(a)) => run_permissions(&a.path, a.format),
        Some(Command::Credentials(a)) => run_credentials(&a.path, a.format),
        Some(Command::RecoveredDomains(a)) => run_recovered_domains(&a.path, a.format),
        Some(Command::Storage(a)) => run_storage(&a.path, a.format),
        Some(Command::Favicons(a)) => run_favicons(&a.path, a.format),
        Some(Command::TopSites(a)) => run_top_sites(&a.path, a.format),
        Some(Command::Shortcuts(a)) => run_shortcuts(&a.path, a.format),
        Some(Command::Predictor(a)) => run_predictor(&a.path, a.format),
        Some(Command::Export {
            path,
            format,
            output,
            timezone,
            interpret,
        }) => run_export(
            &path,
            format,
            output.as_deref(),
            timezone.as_deref(),
            interpret,
        ),
        Some(Command::Profiles { format }) => run_profiles(format),
        Some(Command::Analyze { path, cap }) => run_analyze(&path, cap),
        Some(Command::Integrity(a)) => run_integrity(&a.path, a.format),
        Some(Command::Carve(a)) => run_carve(&a.path, a.format),
        Some(Command::Triage { home, format }) => run_triage(home.as_deref(), format),
    }
}

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
        Family::Firefox => browser_forensic_firefox::parse_history(&history)
            .with_context(|| format!("reading Firefox history from {}", history.display()))?,
        Family::Safari => browser_forensic_safari::parse_history(&history)
            .with_context(|| format!("reading Safari history from {}", history.display()))?,
    };
    if let Some(needle) = search {
        filter_in_place(&mut visits, needle);
    }
    emit_events(&visits, format);
    Ok(())
}

/// Reconstruct navigation for a history file: parse the per-visit table for the
/// auto-detected family (Chromium `visits` / Firefox `moz_historyvisits`), then
/// enrich each visit with its referrer (`referrer_url`/`nav_depth`), redirect-chain
/// membership (`redirect_chain_id`/`redirect_role`), and an inferred `session_id`
/// (idle-gap heuristic at `idle_gap_minutes`). Safari has no per-visit table, so
/// reconstruction is unavailable there (fail loud).
///
/// # Errors
/// Returns an error if the path cannot be resolved, the family lacks a per-visit
/// table, or the history store cannot be opened/queried.
pub fn reconstruct_history(path: &Path, idle_gap_minutes: i64) -> Result<Vec<BrowserEvent>> {
    let (family, history) = resolve_history(path)?;
    let mut visits = match family {
        Family::Chromium => parse_visits(&history).with_context(|| {
            format!("reading Chromium history visits from {}", history.display())
        })?,
        Family::Firefox => browser_forensic_firefox::parse_visits(&history).with_context(|| {
            format!("reading Firefox history visits from {}", history.display())
        })?,
        Family::Safari => anyhow::bail!(
            "visit-chain reconstruction needs a per-visit table (Chromium `visits` / \
             Firefox `moz_historyvisits`); Safari `History.db` has none"
        ),
    };
    resolve_referrer_chains(&mut visits);
    tag_redirect_chains(&mut visits);
    let idle_gap_ns = idle_gap_minutes.max(0).saturating_mul(60 * 1_000_000_000);
    sessionize(&mut visits, SessionConfig { idle_gap_ns });
    Ok(visits)
}

/// `br4n6 chains` — reconstruct and emit the enriched navigation timeline.
///
/// # Errors
/// Propagates [`reconstruct_history`] errors.
pub fn run_chains(path: &Path, idle_gap_minutes: i64, format: OutputFormat) -> Result<()> {
    let events = reconstruct_history(path, idle_gap_minutes)?;
    emit_events(&events, format);
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
        SessionSource::FirefoxFile(file) => browser_forensic_firefox::parse_session(&file)
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

/// `br4n6 browsers --sweep <ROOT>` — recursively sweep an evidence tree for
/// browser and embedded-Chromium containers (Electron / WebView2 / CEF), each
/// attributed to its app where recognized (unknown Chromium-shaped directories
/// are still listed, with an empty app column).
///
/// # Errors
/// Returns an error if `root` does not exist (a mistyped path must fail loud,
/// not silently report zero containers).
pub fn run_browsers_sweep(root: &Path, format: OutputFormat) -> Result<()> {
    if !root.exists() {
        anyhow::bail!("sweep root does not exist: {}", root.display());
    }
    let profiles = browser_forensic_discovery::sweep_containers(root);
    let kind_label = |p: &browser_forensic_discovery::DiscoveredProfile| {
        p.container
            .map_or_else(String::new, |c| format!("{:?}", c.kind))
    };
    let app_label =
        |p: &browser_forensic_discovery::DiscoveredProfile| p.container.map_or("", |c| c.app);
    match format {
        OutputFormat::Text => {
            for p in &profiles {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    p.browser,
                    app_label(p),
                    kind_label(p),
                    p.name,
                    p.path.display()
                );
            }
        }
        OutputFormat::Jsonl => {
            for p in &profiles {
                println!(
                    "{}",
                    json!({
                        "browser": p.browser.to_string(),
                        "app": p.container.map(|c| c.app),
                        "vendor": p.container.map(|c| c.vendor),
                        "kind": p.container.map(|c| format!("{:?}", c.kind)),
                        "name": p.name,
                        "path": p.path.to_string_lossy(),
                    })
                );
            }
        }
        OutputFormat::Csv => {
            println!("browser,app,kind,name,path");
            for p in &profiles {
                println!(
                    "{},{},{},{},{}",
                    csv_escape(&p.browser.to_string()),
                    csv_escape(app_label(p)),
                    csv_escape(&kind_label(p)),
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
        .map_or_else(|| "invalid".to_string(), |d| d.to_rfc3339())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ===========================================================================
// Forensic CLI surface absorbed from the former `bw` binary.
//
// These subcommands (timeline / cookies / downloads / bookmarks / extensions /
// login-data / autofill / session / cache / profiles / analyze / integrity /
// carve / triage) keep `bw`'s exact machine-readable output contracts — the
// `fmt` submodule below is the byte-for-byte `bw` event format (5-column CSV,
// full-`serde` JSONL, `[ts] browser/artifact: desc` text). The Humble-Object decision
// helpers (`merge_carve_stats`, `triage_summary_lines`, `infer_browser_from_filename`)
// stay pure and directly unit-testable.
// ===========================================================================

use browser_forensic_core::BrowserFamily;

/// Output formatting for browser forensic events — the stable `bw` contract:
/// 5-column CSV (`timestamp,browser,artifact,source,description`), full-`serde`
/// JSONL, and a `[ts] browser/artifact: desc` text line.
pub mod fmt {
    use browser_forensic_core::BrowserEvent;

    /// CSV header for timeline/artifact output.
    pub const TIMELINE_CSV_HEADER: &str = "timestamp,browser,artifact,source,description";

    /// Escape a string for CSV: wraps in double quotes if it contains commas or quotes.
    #[must_use]
    pub fn csv_escape(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            let escaped = s.replace('"', "\"\"");
            format!("\"{escaped}\"")
        } else {
            s.to_string()
        }
    }

    /// Format a Unix nanosecond timestamp as RFC3339.
    #[must_use]
    pub fn format_timestamp_ns(ns: i64) -> String {
        if ns == 0 {
            return "1970-01-01T00:00:00Z".to_string();
        }
        use chrono::{DateTime, Utc};
        let secs = ns / 1_000_000_000;
        let nanos = u32::try_from(ns % 1_000_000_000).unwrap_or(0);
        DateTime::<Utc>::from_timestamp(secs, nanos)
            .map_or_else(|| "invalid".to_string(), |d| d.to_rfc3339())
    }

    /// Format a [`BrowserEvent`] as a human-readable text line.
    #[must_use]
    pub fn event_to_text(ev: &BrowserEvent) -> String {
        let ts = format_timestamp_ns(ev.timestamp_ns);
        format!(
            "[{ts}] {browser}/{artifact}: {desc}",
            browser = ev.browser,
            artifact = ev.artifact,
            desc = ev.description
        )
    }

    /// Format a [`BrowserEvent`] as a JSONL (newline-delimited JSON) string.
    #[must_use]
    pub fn event_to_jsonl(ev: &BrowserEvent) -> String {
        serde_json::to_string(ev).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format a [`BrowserEvent`] as a CSV row (5 fields).
    #[must_use]
    pub fn event_to_csv_row(ev: &BrowserEvent) -> String {
        let ts = format_timestamp_ns(ev.timestamp_ns);
        let browser = ev.browser.to_string();
        let artifact = ev.artifact.to_string();
        format!(
            "{},{},{},{},{}",
            csv_escape(&ts),
            csv_escape(&browser),
            csv_escape(&artifact),
            csv_escape(&ev.source),
            csv_escape(&ev.description)
        )
    }
}

/// Sum two carve passes (free-page + WAL) into one aggregate stat block.
#[must_use]
pub fn merge_carve_stats(
    a: &browser_forensic_carve::CarveStats,
    b: &browser_forensic_carve::CarveStats,
) -> browser_forensic_carve::CarveStats {
    browser_forensic_carve::CarveStats {
        bytes_scanned: a.bytes_scanned + b.bytes_scanned,
        pages_scanned: a.pages_scanned + b.pages_scanned,
        free_pages_found: a.free_pages_found + b.free_pages_found,
        records_recovered: a.records_recovered + b.records_recovered,
        records_partial: a.records_partial + b.records_partial,
    }
}

/// The header/summary lines of the text-format triage report (everything above the
/// per-event timeline).
#[must_use]
pub fn triage_summary_lines(report: &browser_forensic_triage::TriageReport) -> Vec<String> {
    vec![
        "Browser Forensic Triage Report".to_string(),
        "==============================".to_string(),
        format!("Generated: {}", report.generated_at_ns),
        format!("Profiles found: {}", report.profiles.len()),
        format!("Events parsed: {}", report.events.len()),
        format!("Integrity indicators: {}", report.integrity.len()),
        format!("Carved records: {}", report.carved.len()),
    ]
}

/// Infer a browser family from a bare artifact file name when content sniffing
/// can't (e.g. Firefox JSON/sqlite artifacts and Safari's `history.db`). Returns
/// `None` for anything not uniquely tied to a family by name (e.g. `History`).
#[must_use]
pub fn infer_browser_from_filename(path: &Path) -> Option<BrowserFamily> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name == "history.db" {
        return Some(BrowserFamily::Safari);
    }
    if name == "places.sqlite"
        || name == "formhistory.sqlite"
        || name == "cookies.sqlite"
        || name == "extensions.json"
        || name == "logins.json"
        || name == "sessionstore.jsonlz4"
    {
        return Some(BrowserFamily::Firefox);
    }
    None
}

/// The single-artifact kinds dispatched by [`run_artifact`].
#[derive(Clone, Copy, Debug)]
pub enum ArtifactType {
    History,
    Cookies,
    Downloads,
    Bookmarks,
    Extensions,
    LoginData,
    Autofill,
    Session,
    Cache,
    Preferences,
}

/// Infer a browser family from a preferences file name: `prefs.js`/`user.js` →
/// Firefox, `Preferences`/`Secure Preferences` → Chromium. Returns `None` for
/// anything else.
#[must_use]
pub fn preferences_family(path: &Path) -> Option<BrowserFamily> {
    match path.file_name()?.to_string_lossy().to_lowercase().as_str() {
        "prefs.js" | "user.js" => Some(BrowserFamily::Firefox),
        "preferences" | "secure preferences" => Some(BrowserFamily::Chromium),
        _ => None,
    }
}

/// `br4n6 <artifact> PATH` — detect the browser family, parse the requested
/// artifact, sort by timestamp, and emit it in the requested format. Mirrors the
/// historic `bw` artifact pipeline.
///
/// # Errors
/// Returns an error if the browser family cannot be determined, the artifact is
/// unsupported for that family, or the underlying parser fails.
pub fn run_artifact(path: &Path, artifact: ArtifactType, format: OutputFormat) -> Result<()> {
    use browser_forensic_core::detect_browser;

    let family = detect_browser(path)
        .or_else(|| infer_browser_from_filename(path))
        .or_else(|| preferences_family(path))
        .with_context(|| format!("cannot determine browser from path: {}", path.display()))?;

    let mut events = match (family, artifact) {
        (BrowserFamily::Chromium, ArtifactType::History) => {
            browser_forensic_chrome::parse_history(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::History) => {
            browser_forensic_firefox::parse_history(path)?
        }
        (BrowserFamily::Safari, ArtifactType::History) => {
            browser_forensic_safari::parse_history(path)?
        }

        (BrowserFamily::Chromium, ArtifactType::Cookies) => {
            browser_forensic_chrome::parse_cookies(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::Cookies) => {
            browser_forensic_firefox::parse_cookies(path)?
        }
        (BrowserFamily::Safari, ArtifactType::Cookies) => {
            browser_forensic_safari::parse_cookies(path)?
        }

        (BrowserFamily::Chromium, ArtifactType::Downloads) => {
            browser_forensic_chrome::parse_downloads(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::Downloads) => {
            browser_forensic_firefox::parse_downloads(path)?
        }
        (BrowserFamily::Safari, ArtifactType::Downloads) => {
            browser_forensic_safari::parse_downloads(path)?
        }

        (BrowserFamily::Chromium, ArtifactType::Bookmarks) => {
            browser_forensic_chrome::parse_bookmarks(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::Bookmarks) => {
            browser_forensic_firefox::parse_bookmarks(path)?
        }
        (BrowserFamily::Safari, ArtifactType::Bookmarks) => {
            browser_forensic_safari::parse_bookmarks(path)?
        }

        (BrowserFamily::Chromium, ArtifactType::Extensions) => {
            browser_forensic_chrome::parse_extensions(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::Extensions) => {
            browser_forensic_firefox::parse_extensions(path)?
        }
        (BrowserFamily::Safari, ArtifactType::Extensions) => {
            browser_forensic_safari::parse_extensions(path)?
        }

        (BrowserFamily::Chromium, ArtifactType::LoginData) => {
            browser_forensic_chrome::parse_login_data(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::LoginData) => {
            browser_forensic_firefox::parse_login_data(path)?
        }
        (BrowserFamily::Safari, ArtifactType::LoginData) => {
            anyhow::bail!("Safari login data not supported");
        }

        (BrowserFamily::Chromium, ArtifactType::Autofill) => {
            browser_forensic_chrome::parse_autofill(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::Autofill) => {
            browser_forensic_firefox::parse_autofill(path)?
        }
        (BrowserFamily::Safari, ArtifactType::Autofill) => {
            anyhow::bail!("Safari autofill not supported");
        }

        (BrowserFamily::Firefox, ArtifactType::Session) => {
            browser_forensic_firefox::parse_session(path)?
        }
        (_, ArtifactType::Session) => {
            anyhow::bail!("session only supported for Firefox");
        }

        (BrowserFamily::Chromium, ArtifactType::Cache) => {
            browser_forensic_chrome::parse_cache(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::Cache) => {
            browser_forensic_firefox::parse_cache(path)?
        }
        (BrowserFamily::Safari, ArtifactType::Cache) => {
            anyhow::bail!("Safari cache not supported");
        }

        (BrowserFamily::Chromium, ArtifactType::Preferences) => {
            browser_forensic_chrome::parse_preferences(path)?
        }
        (BrowserFamily::Firefox, ArtifactType::Preferences) => {
            browser_forensic_firefox::parse_firefox_preferences(path)?
        }
        (BrowserFamily::Safari, ArtifactType::Preferences) => {
            anyhow::bail!("Safari preferences not supported");
        }
    };

    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// Print a slice of events using the stable `bw` format contract.
fn print_events(events: &[BrowserEvent], format: OutputFormat) {
    match format {
        OutputFormat::Csv => {
            println!("{}", fmt::TIMELINE_CSV_HEADER);
            for ev in events {
                println!("{}", fmt::event_to_csv_row(ev));
            }
        }
        OutputFormat::Jsonl => {
            for ev in events {
                println!("{}", fmt::event_to_jsonl(ev));
            }
        }
        OutputFormat::Text => {
            for ev in events {
                println!("{}", fmt::event_to_text(ev));
            }
        }
    }
}

/// Detect a browser family from the artifact files directly inside a single
/// profile directory: `History` → Chromium, `places.sqlite` → Firefox,
/// `History.db` → Safari. Returns `None` if none is present.
#[must_use]
pub fn profile_family(dir: &Path) -> Option<BrowserFamily> {
    if dir.join("History").is_file() {
        Some(BrowserFamily::Chromium)
    } else if dir.join("places.sqlite").is_file() {
        Some(BrowserFamily::Firefox)
    } else if dir.join("History.db").is_file() {
        Some(BrowserFamily::Safari)
    } else {
        None
    }
}

/// `br4n6 export` — collect a correlated timeline for a profile/home directory
/// and write it as one file (XLSX / SQLite) or stream (JSONL / CSV / text), with
/// an optional interpretation column and an IANA timezone for timestamps.
///
/// # Errors
/// Returns an error if the timezone is unknown, collection fails, a file-only
/// format is requested without `--output`, or writing fails.
pub fn run_export(
    path: &Path,
    format: crate::export::ExportFormat,
    output: Option<&Path>,
    timezone: Option<&str>,
    interpret: bool,
) -> Result<()> {
    use crate::export::{self, ExportFormat};

    let tz = match timezone {
        Some(name) => Some(
            name.parse::<chrono_tz::Tz>()
                .map_err(|_| anyhow::anyhow!("unknown IANA timezone: {name}"))?,
        ),
        None => None,
    };

    // Try a home-directory scan first (discovers profiles under `path`); if that
    // finds nothing, fall back to treating `path` itself as a single profile
    // directory (the Hindsight "point at a profile" model).
    let mut report = browser_forensic_triage::triage(path)
        .with_context(|| format!("collecting timeline from {}", path.display()))?;
    if report.profiles.is_empty() && report.events.is_empty() {
        if let Some(family) = profile_family(path) {
            report = browser_forensic_triage::triage_profile(path, family)
                .with_context(|| format!("collecting timeline from profile {}", path.display()))?;
        }
    }
    let mut events = report.events;
    if interpret {
        export::apply_interpretation(&mut events);
    }
    events.sort_by_key(|e| e.timestamp_ns);

    match format {
        ExportFormat::Sqlite => {
            let out = output.context("--output FILE is required for --format sqlite")?;
            export::write_sqlite(&events, tz, out)?;
            eprintln!("wrote {} events to {}", events.len(), out.display());
        }
        ExportFormat::Xlsx => {
            let out = output.context("--output FILE is required for --format xlsx")?;
            export::write_xlsx(&events, tz, out)?;
            eprintln!("wrote {} events to {}", events.len(), out.display());
        }
        ExportFormat::Text | ExportFormat::Jsonl | ExportFormat::Csv => {
            if let Some(p) = output {
                let mut f = std::fs::File::create(p)
                    .with_context(|| format!("creating {}", p.display()))?;
                export::write_stream(&events, format, tz, &mut f)?;
            } else {
                let stdout = std::io::stdout();
                let mut lock = stdout.lock();
                export::write_stream(&events, format, tz, &mut lock)?;
            }
        }
    }
    Ok(())
}

/// `br4n6 profiles` — discover browser profiles under the current user's home,
/// in the historic `bw` output shape (em-dash text line / hand-rolled JSONL /
/// `browser,name,path` CSV).
///
/// # Errors
/// Never errors today; returns `Result` for a uniform dispatcher signature.
pub fn run_profiles(format: OutputFormat) -> Result<()> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
    let profiles = discover_profiles(&home);

    match format {
        OutputFormat::Csv => {
            println!("browser,name,path");
            for p in &profiles {
                println!(
                    "{},{},{}",
                    p.browser,
                    fmt::csv_escape(&p.name),
                    fmt::csv_escape(&p.path.to_string_lossy())
                );
            }
        }
        OutputFormat::Jsonl => {
            for p in &profiles {
                println!(
                    "{{\"browser\":\"{}\",\"name\":\"{}\",\"path\":\"{}\"}}",
                    p.browser,
                    p.name,
                    p.path.display()
                );
            }
        }
        OutputFormat::Text => {
            for p in &profiles {
                println!("{} \u{2014} {} ({})", p.browser, p.name, p.path.display());
            }
        }
    }
    Ok(())
}

/// `br4n6 analyze PATH --cap N` — list domains visited at most `cap` times.
///
/// # Errors
/// Returns an error if the browser family cannot be determined or parsing fails.
pub fn run_analyze(path: &Path, cap: usize) -> Result<()> {
    use browser_forensic_core::detect_browser;

    let family = detect_browser(path)
        .or_else(|| infer_browser_from_filename(path))
        .with_context(|| format!("cannot determine browser from path: {}", path.display()))?;

    let events = match family {
        BrowserFamily::Chromium => browser_forensic_chrome::parse_history(path)?,
        BrowserFamily::Firefox => browser_forensic_firefox::parse_history(path)?,
        BrowserFamily::Safari => browser_forensic_safari::parse_history(path)?,
    };

    let domains = browser_forensic_core::analyze::rare_domains(&events, cap);
    for (domain, count) in &domains {
        println!("{count}\t{domain}");
    }
    Ok(())
}

/// `br4n6 integrity PATH` — run the integrity-indicator family over a database.
///
/// # Errors
/// Never errors today; returns `Result` for a uniform dispatcher signature.
pub fn run_integrity(path: &Path, format: OutputFormat) -> Result<()> {
    // Generic SQLite files are treated as Chromium for the family-specific checks.
    let family = BrowserFamily::Chromium;

    let mut indicators = Vec::new();
    if let Ok(mut ind) = browser_forensic_integrity::check_database_integrity(path) {
        indicators.append(&mut ind);
    }
    if let Ok(mut ind) = browser_forensic_integrity::check_wal_state(path) {
        indicators.append(&mut ind);
    }
    if let Ok(mut ind) = browser_forensic_integrity::check_history_integrity(path, family.clone()) {
        indicators.append(&mut ind);
    }
    if let Ok(mut ind) = browser_forensic_integrity::check_cookie_integrity(path, family) {
        indicators.append(&mut ind);
    }

    if indicators.is_empty() {
        match format {
            OutputFormat::Text => println!("No integrity issues detected."),
            OutputFormat::Jsonl => println!("{{\"status\":\"clean\"}}"),
            OutputFormat::Csv => {
                println!("type,path,detail");
                println!("clean,{},no issues", path.display());
            }
        }
    } else {
        match format {
            OutputFormat::Text => {
                println!("Found {} integrity indicator(s):", indicators.len());
                for ind in &indicators {
                    println!("  {ind:?}");
                }
            }
            OutputFormat::Jsonl => {
                for ind in &indicators {
                    if let Ok(json) = serde_json::to_string(ind) {
                        println!("{json}");
                    }
                }
            }
            OutputFormat::Csv => {
                println!("type,detail");
                for ind in &indicators {
                    if let Ok(json) = serde_json::to_string(ind) {
                        println!("{json}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// `br4n6 storage PATH` — parse web storage (Local/Session Storage, IndexedDB)
/// for the auto-detected browser family. `PATH` may be a single LevelDB
/// directory, a `webappsstore.sqlite` / IndexedDB `*.sqlite` file, or a profile
/// directory (every web-storage source beneath it is aggregated).
///
/// # Errors
/// Returns an error if the path holds no recognized web storage or cannot be read.
pub fn run_storage(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_storage::parse_path(path)
        .with_context(|| format!("parsing web storage from {}", path.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    emit_events(&events, format);
    Ok(())
}

/// `br4n6 permissions PATH` — surface per-site permission grants. `PATH` is a
/// Chromium `Preferences` / `Secure Preferences` JSON file, or a Firefox
/// `permissions.sqlite`. Metadata only; no secrets are involved.
///
/// # Errors
/// Returns an error if the family cannot be determined from the file name, or
/// the underlying parser fails.
pub fn run_permissions(path: &Path, format: OutputFormat) -> Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mut events = if name == "permissions.sqlite" {
        browser_forensic_firefox::parse_firefox_permissions(path)?
    } else if matches!(preferences_family(path), Some(BrowserFamily::Chromium)) {
        browser_forensic_chrome::parse_permissions(path)?
    } else {
        anyhow::bail!(
            "unrecognized permissions source: {} (expected Chromium Preferences / \
             Secure Preferences, or Firefox permissions.sqlite)",
            path.display()
        );
    };
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 credentials PATH` — surface stored account/payment metadata from a
/// Chromium `Web Data` database: saved cards, sync/OAuth tokens, and autofill
/// address profiles. Card numbers and tokens are surfaced as opaque
/// `ENCRYPTED`; they are never decrypted.
///
/// # Errors
/// Returns an error if the `Web Data` database cannot be opened.
pub fn run_credentials(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_chrome::parse_web_data(path)
        .with_context(|| format!("parsing Web Data account metadata from {}", path.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 favicons PATH` — parse a Chromium `Favicons` database. Every stored
/// favicon is joined back to the `page_url` it was fetched for, an independent
/// cleartext source of visited URLs. Chromium-only.
///
/// # Errors
/// Returns an error if the `Favicons` database cannot be opened.
pub fn run_favicons(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_chrome::parse_favicons(path)
        .with_context(|| format!("parsing Favicons from {}", path.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 top-sites PATH` — parse a Chromium `Top Sites` database (the
/// profile's most-visited pages, frecency-ranked). Chromium-only.
///
/// # Errors
/// Returns an error if the `Top Sites` database cannot be opened.
pub fn run_top_sites(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_chrome::parse_top_sites(path)
        .with_context(|| format!("parsing Top Sites from {}", path.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 predictor PATH` — parse a Chromium `Network Action Predictor`: the
/// (often partial) omnibox strings the user typed and the URLs Chromium learned
/// to predict from them. Chromium-only.
///
/// # Errors
/// Returns an error if the database cannot be opened.
pub fn run_predictor(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_chrome::parse_network_action_predictor(path)
        .with_context(|| format!("parsing Network Action Predictor from {}", path.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 shortcuts PATH` — parse a Chromium `Shortcuts` database: the omnibox
/// strings the user typed and the URLs they selected. Chromium-only.
///
/// # Errors
/// Returns an error if the `Shortcuts` database cannot be opened.
pub fn run_shortcuts(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_chrome::parse_shortcuts(path)
        .with_context(|| format!("parsing Shortcuts from {}", path.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 recovered-domains PATH` — recover domains the user contacted that
/// survive a history clear, from network/state artifacts. `PATH` is a profile
/// directory (every recovered-domain source beneath it is aggregated) or a
/// single artifact file (`Network Persistent State`, `Reporting and NEL`,
/// `DIPS`, `TransportSecurity`, or Firefox `SiteSecurityServiceState.txt`).
///
/// Read-only, no secrets. Chromium HSTS hosts are hashed and surfaced as
/// non-enumerable; every other source yields cleartext hosts, labelled
/// "contacted (may be a subresource/third-party), recovered independently of
/// history".
///
/// # Errors
/// Returns an error only for a single file whose name is not a recognized
/// recovered-domain source. A directory with no such sources yields no events.
pub fn run_recovered_domains(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = if path.is_dir() {
        browser_forensic_triage::collect_recovered_domains(path)
    } else {
        recovered_domains_for_file(path)?
    };
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// Dispatch a single recovered-domain artifact file to its parser by file name.
fn recovered_domains_for_file(path: &Path) -> Result<Vec<BrowserEvent>> {
    match file_name_lower(path).as_str() {
        "network persistent state" => Ok(browser_forensic_chrome::parse_network_persistent_state(
            path,
        )?),
        "reporting and nel" => Ok(browser_forensic_chrome::parse_reporting_and_nel(path)?),
        "dips" => Ok(browser_forensic_chrome::parse_dips(path)?),
        "transportsecurity" => Ok(browser_forensic_chrome::parse_transport_security(path)?),
        "sitesecurityservicestate.txt" => Ok(browser_forensic_firefox::parse_site_security(path)?),
        _ => anyhow::bail!(
            "unrecognized recovered-domain source: {} (expected a profile directory, or one of: \
             Network Persistent State / Reporting and NEL / DIPS / TransportSecurity / \
             SiteSecurityServiceState.txt)",
            path.display()
        ),
    }
}

/// `br4n6 carve PATH` — recover deleted records from free pages and the WAL.
///
/// # Errors
/// Never errors today; returns `Result` for a uniform dispatcher signature.
pub fn run_carve(path: &Path, format: OutputFormat) -> Result<()> {
    let empty = || browser_forensic_carve::CarveResult {
        records: Vec::new(),
        integrity: Vec::new(),
        stats: browser_forensic_carve::CarveStats::default(),
    };
    let free_result =
        browser_forensic_carve::carve_sqlite_free_pages(path).unwrap_or_else(|_| empty());
    let wal_result = browser_forensic_carve::recover_from_wal(path).unwrap_or_else(|_| empty());

    let mut all_records = free_result.records;
    all_records.extend(wal_result.records);

    let total_stats = merge_carve_stats(&free_result.stats, &wal_result.stats);

    match format {
        OutputFormat::Text => {
            println!(
                "Carve stats: {} bytes scanned, {} pages, {} free pages, {} records recovered ({} partial)",
                total_stats.bytes_scanned,
                total_stats.pages_scanned,
                total_stats.free_pages_found,
                total_stats.records_recovered,
                total_stats.records_partial,
            );
            for rec in &all_records {
                println!(
                    "  offset={} table={} method={:?} quality={:?} fields={}",
                    rec.offset,
                    rec.table,
                    rec.method,
                    rec.quality,
                    serde_json::to_string(&rec.fields).unwrap_or_default(),
                );
            }
        }
        OutputFormat::Jsonl => {
            if let Ok(json) = serde_json::to_string(&total_stats) {
                println!("{json}");
            }
            for rec in &all_records {
                if let Ok(json) = serde_json::to_string(rec) {
                    println!("{json}");
                }
            }
        }
        OutputFormat::Csv => {
            println!("offset,table,method,quality,fields");
            for rec in &all_records {
                println!(
                    "{},{},{:?},{:?},{}",
                    rec.offset,
                    fmt::csv_escape(&rec.table),
                    rec.method,
                    rec.quality,
                    fmt::csv_escape(&serde_json::to_string(&rec.fields).unwrap_or_default()),
                );
            }
        }
    }
    Ok(())
}

/// `br4n6 triage --home DIR` — discover profiles, parse, check integrity, and
/// carve across every browser under `home`.
///
/// # Errors
/// Returns an error if the triage orchestration fails.
pub fn run_triage(home: Option<&Path>, format: OutputFormat) -> Result<()> {
    let home = home.map_or_else(
        || dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")),
        Path::to_path_buf,
    );

    let report = browser_forensic_triage::triage(&home)?;

    match format {
        OutputFormat::Text => {
            for line in triage_summary_lines(&report) {
                println!("{line}");
            }
            if !report.events.is_empty() {
                println!("\nTimeline ({} events):", report.events.len());
                for ev in report.events.iter().take(50) {
                    println!("  {}", fmt::event_to_text(ev));
                }
                if report.events.len() > 50 {
                    println!("  ... and {} more events", report.events.len() - 50);
                }
            }
        }
        OutputFormat::Jsonl => {
            if let Ok(json) = serde_json::to_string(&report) {
                println!("{json}");
            }
        }
        OutputFormat::Csv => {
            println!("{}", fmt::TIMELINE_CSV_HEADER);
            for ev in &report.events {
                println!("{}", fmt::event_to_csv_row(ev));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};

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

    // ---- migrated bw handlers: exercise every output-format branch + the
    // ---- per-family parse arms against in-test SQLite fixtures ----

    use rusqlite::Connection;

    /// Chrome `History` DB with one URL, under a Chrome-looking profile dir so
    /// `detect_browser` resolves Chromium.
    fn chrome_history_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("google-chrome").join("Default");
        std::fs::create_dir_all(&profile).unwrap();
        let conn = Connection::open(profile.join("History")).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '', visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0, visit_duration INTEGER DEFAULT 0);
             INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES ('https://example.com', 'Example', 1, 13327626000000000);
             INSERT INTO visits (url, visit_time, visit_duration) VALUES (1, 13327626000000000, 0);",
        )
        .unwrap();
        dir
    }

    fn chrome_history_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path()
            .join("google-chrome")
            .join("Default")
            .join("History")
    }

    #[test]
    fn reconstruct_history_enriches_referrer_redirect_and_session() {
        const CS: i64 = 0x1000_0000;
        const CE: i64 = 0x2000_0000;
        const CR: i64 = 0x4000_0000;
        const SR: i64 = 0x8000_0000;
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("google-chrome").join("Default");
        std::fs::create_dir_all(&profile).unwrap();
        let hist = profile.join("History");
        let conn = Connection::open(&hist).unwrap();
        // 1 origin(typed, chain_start) -> 2 server-redirect -> 3 client-redirect
        // landing; 4 a far-later visit that must fall in a new inferred session.
        conn.execute_batch(&format!(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '', visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0, visit_duration INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1,'https://origin.example','O',1,13327626000000000);
             INSERT INTO urls VALUES (2,'https://hop.example','H',1,13327626000000000);
             INSERT INTO urls VALUES (3,'https://land.example','L',1,13327626000000000);
             INSERT INTO urls VALUES (4,'https://later.example','La',1,13327626000000000);
             INSERT INTO visits VALUES (1,1,13327626000000000,0,{cs},0);
             INSERT INTO visits VALUES (2,2,13327626001000000,1,{sr},0);
             INSERT INTO visits VALUES (3,3,13327626002000000,2,{cr},0);
             INSERT INTO visits VALUES (4,4,16327626000000000,0,1,0);",
            cs = CS | 1,
            sr = SR,
            cr = CR | CE,
        ))
        .unwrap();

        let events = reconstruct_history(&hist, 30).unwrap();
        assert_eq!(events.len(), 4);
        let by_url = |u: &str| {
            events
                .iter()
                .find(|e| e.attrs["url"] == json!(u))
                .unwrap_or_else(|| panic!("missing {u}"))
        };
        assert_eq!(
            by_url("https://hop.example").attrs["referrer_url"],
            json!("https://origin.example")
        );
        assert_eq!(
            by_url("https://origin.example").attrs["redirect_role"],
            json!("start")
        );
        assert_eq!(
            by_url("https://land.example").attrs["redirect_role"],
            json!("landing")
        );
        assert_eq!(
            by_url("https://hop.example").attrs["redirect_kind"],
            json!("server")
        );
        let s0 = by_url("https://origin.example").attrs["session_id"]
            .as_i64()
            .unwrap();
        let s_last = by_url("https://later.example").attrs["session_id"]
            .as_i64()
            .unwrap();
        assert_ne!(s0, s_last, "a far-later visit is a new inferred session");
    }

    #[test]
    fn reconstruct_history_rejects_safari() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("History.db");
        Connection::open(&p)
            .unwrap()
            .execute_batch("CREATE TABLE history_items (id INTEGER);")
            .unwrap();
        assert!(reconstruct_history(&p, 30).is_err());
    }

    /// Firefox `places.sqlite` with one URL.
    fn firefox_places() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("places.sqlite");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, visit_date INTEGER NOT NULL);
             INSERT INTO moz_places (url, title, visit_count, last_visit_date) VALUES ('https://ff.example', 'FF', 1, 1648000000000000);
             INSERT INTO moz_historyvisits (place_id, visit_date) VALUES (1, 1648000000000000);",
        )
        .unwrap();
        (dir, p)
    }

    #[test]
    fn run_artifact_history_all_formats_chromium() {
        let dir = chrome_history_dir();
        let p = chrome_history_path(&dir);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_artifact(&p, ArtifactType::History, fmt).unwrap();
        }
    }

    #[test]
    fn run_artifact_history_all_formats_firefox() {
        let (_d, p) = firefox_places();
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_artifact(&p, ArtifactType::History, fmt).unwrap();
        }
    }

    #[test]
    fn run_artifact_unknown_path_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("History"); // bare name → undetectable family
        std::fs::write(&p, b"x").unwrap();
        assert!(run_artifact(&p, ArtifactType::History, OutputFormat::Text).is_err());
    }

    #[test]
    fn run_favicons_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Favicons");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE icon_mapping(id INTEGER PRIMARY KEY, page_url LONGVARCHAR NOT NULL, icon_id INTEGER);
             CREATE TABLE favicons(id INTEGER PRIMARY KEY, url LONGVARCHAR NOT NULL);
             CREATE TABLE favicon_bitmaps(id INTEGER PRIMARY KEY, icon_id INTEGER NOT NULL, last_updated INTEGER DEFAULT 0, width INTEGER DEFAULT 0);
             INSERT INTO favicons VALUES (1, 'https://ex.example/fav.ico');
             INSERT INTO icon_mapping (page_url, icon_id) VALUES ('https://ex.example/p', 1);
             INSERT INTO favicon_bitmaps (icon_id, last_updated, width) VALUES (1, 13327626000000000, 16);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_favicons(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_top_sites_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Top Sites");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE top_sites(url TEXT NOT NULL PRIMARY KEY, url_rank INTEGER NOT NULL, title TEXT NOT NULL);
             INSERT INTO top_sites VALUES ('https://a.example/', 0, 'A');",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_top_sites(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_shortcuts_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Shortcuts");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE omni_box_shortcuts (id VARCHAR PRIMARY KEY, text VARCHAR, fill_into_edit VARCHAR, url VARCHAR, contents VARCHAR, last_access_time INTEGER, number_of_hits INTEGER);
             INSERT INTO omni_box_shortcuts (id, text, url, last_access_time, number_of_hits) VALUES ('s1', 'gh', 'https://github.com/', 13327626000000000, 3);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_shortcuts(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_predictor_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Network Action Predictor");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE network_action_predictor (id TEXT PRIMARY KEY, user_text TEXT, url TEXT, number_of_hits INTEGER, number_of_misses INTEGER);
             INSERT INTO network_action_predictor VALUES ('n1', 'se', 'https://search.example/', 1, 2);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_predictor(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_storage_webappsstore_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("webappsstore.sqlite");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE webappsstore2 (scope TEXT, key TEXT, value TEXT);
             INSERT INTO webappsstore2 VALUES ('moc.elpmaxe.:http:80', 'theme', 'dark');",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_storage(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_storage_nonexistent_errors() {
        assert!(run_storage(
            Path::new("/nonexistent/webappsstore.sqlite"),
            OutputFormat::Text
        )
        .is_err());
    }

    #[test]
    fn run_permissions_chrome_preferences_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Preferences");
        std::fs::write(
            &p,
            br#"{"profile":{"content_settings":{"exceptions":{
                "geolocation":{"https://x.example.com:443,*":{"setting":2}}
            }}}}"#,
        )
        .unwrap();
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_permissions(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_permissions_firefox_moz_perms_ok() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("permissions.sqlite");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_perms (id INTEGER PRIMARY KEY, origin TEXT, type TEXT, permission INTEGER, expireType INTEGER, expireTime INTEGER, modificationTime INTEGER);
             INSERT INTO moz_perms (origin, type, permission, modificationTime) VALUES ('https://ff.example', 'geo', 1, 1650000000000);",
        )
        .unwrap();
        drop(conn);
        run_permissions(&p, OutputFormat::Jsonl).unwrap();
    }

    #[test]
    fn run_permissions_unknown_path_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("random.dat");
        std::fs::write(&p, b"x").unwrap();
        assert!(run_permissions(&p, OutputFormat::Text).is_err());
    }

    #[test]
    fn run_credentials_web_data_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Web Data");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE credit_cards (guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER NOT NULL DEFAULT 0, use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0);
             INSERT INTO credit_cards (guid, name_on_card, expiration_month, expiration_year, date_modified, use_count, use_date) VALUES ('g', 'A Suspect', 8, 2027, 13340000000000000, 2, 13350000000000000);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_credentials(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_credentials_nonexistent_errors() {
        assert!(run_credentials(Path::new("/nonexistent/Web Data"), OutputFormat::Text).is_err());
    }

    #[test]
    fn run_recovered_domains_dips_dir_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("DIPS")).unwrap();
        conn.execute_batch(
            "CREATE TABLE bounces(site TEXT PRIMARY KEY NOT NULL, first_user_activation_time INTEGER, last_user_activation_time INTEGER, first_bounce_time INTEGER, last_bounce_time INTEGER, first_web_authn_assertion_time INTEGER, last_web_authn_assertion_time INTEGER);
             INSERT INTO bounces (site, last_user_activation_time) VALUES ('recovered.example.com', 13300000000000000);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_recovered_domains(dir.path(), fmt).unwrap();
        }
    }

    #[test]
    fn run_recovered_domains_network_persistent_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Network Persistent State");
        std::fs::write(
            &p,
            br#"{"net":{"http_server_properties":{"servers":[{"server":"https://cdn.example.net"}]}}}"#,
        )
        .unwrap();
        run_recovered_domains(&p, OutputFormat::Jsonl).unwrap();
    }

    #[test]
    fn run_recovered_domains_unknown_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("random.dat");
        std::fs::write(&p, b"x").unwrap();
        assert!(run_recovered_domains(&p, OutputFormat::Text).is_err());
    }

    #[test]
    fn run_artifact_session_rejects_non_firefox() {
        let dir = chrome_history_dir();
        let p = chrome_history_path(&dir);
        // Chromium + Session is an unsupported pairing → loud error.
        assert!(run_artifact(&p, ArtifactType::Session, OutputFormat::Text).is_err());
    }

    #[test]
    fn run_analyze_chromium_ok() {
        let dir = chrome_history_dir();
        run_analyze(&chrome_history_path(&dir), 5).unwrap();
    }

    #[test]
    fn run_analyze_unknown_path_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("History");
        std::fs::write(&p, b"x").unwrap();
        assert!(run_analyze(&p, 5).is_err());
    }

    #[test]
    fn run_integrity_all_formats_clean_and_dirty() {
        // Clean DB → the "no issues" arm of each format.
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean.db");
        let conn = Connection::open(&clean).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_integrity(&clean, fmt).unwrap();
        }

        // Cleared-history DB → the "found indicators" arm of each format.
        let dirty = dir.path().join("dirty.db");
        let conn = Connection::open(&dirty).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             UPDATE sqlite_sequence SET seq = 500 WHERE name = 'urls';
             DELETE FROM urls;",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_integrity(&dirty, fmt).unwrap();
        }
    }

    #[test]
    fn run_carve_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("c.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
             INSERT INTO urls VALUES (1, 'https://example.com');",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_carve(&db, fmt).unwrap();
        }
    }

    #[test]
    fn run_profiles_all_formats() {
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_profiles(fmt).unwrap();
        }
    }

    #[test]
    fn run_triage_all_formats_with_events() {
        let home = tempfile::tempdir().unwrap();
        let chrome = home
            .path()
            .join("Library/Application Support/Google/Chrome/Default");
        std::fs::create_dir_all(&chrome).unwrap();
        let conn = Connection::open(chrome.join("History")).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_triage(Some(home.path()), fmt).unwrap();
        }
    }

    #[test]
    fn run_triage_empty_home_all_formats() {
        let home = tempfile::tempdir().unwrap();
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_triage(Some(home.path()), fmt).unwrap();
        }
    }

    #[test]
    fn fmt_event_round_trips_each_format() {
        let ev = BrowserEvent::new(
            1_648_000_000_000_000_000,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "/History",
            "Example",
        )
        .with_attr("url", json!("https://x,y.example"));
        // text / jsonl / csv (the comma forces csv_escape quoting)
        assert!(fmt::event_to_text(&ev).starts_with('['));
        let _: serde_json::Value = serde_json::from_str(&fmt::event_to_jsonl(&ev)).unwrap();
        assert!(fmt::event_to_csv_row(&ev).contains("Chromium"));
        assert_eq!(fmt::format_timestamp_ns(0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt::csv_escape("a,b"), "\"a,b\"");
    }

    /// Firefox `places.sqlite`-style DB also carrying cookies/downloads tables so
    /// the per-artifact Firefox arms can be exercised.
    fn firefox_cookies() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cookies.sqlite");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER DEFAULT 0);
             INSERT INTO moz_cookies (host, name, value, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, sameSite) VALUES ('.example.com', 'sid', 'abc', '/', 0, 1648000000000000, 1648000000000000, 1, 1, 0);",
        )
        .unwrap();
        (dir, p)
    }

    #[test]
    fn run_browsers_all_formats() {
        let home = tempfile::tempdir().unwrap();
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_browsers(Some(home.path()), fmt).unwrap();
        }
        // None → resolves the real home dir; just exercise the path.
        run_browsers(None, OutputFormat::Text).unwrap();
    }

    #[test]
    fn run_browsers_sweep_all_formats() {
        let root = tempfile::tempdir().unwrap();
        let default = root
            .path()
            .join("Users/x/AppData/Local/Google/Chrome/User Data/Default");
        std::fs::create_dir_all(&default).unwrap();
        std::fs::write(default.join("History"), b"").unwrap();
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_browsers_sweep(root.path(), fmt).unwrap();
        }
    }

    #[test]
    fn run_browsers_sweep_missing_root_errors() {
        let err = run_browsers_sweep(Path::new("/no/such/sweep/root"), OutputFormat::Text)
            .expect_err("missing root must fail loud");
        assert!(err.to_string().contains("sweep root does not exist"));
    }

    #[test]
    fn run_history_chromium_collapsed_and_raw_all_formats() {
        let dir = chrome_history_dir();
        let profile = dir.path().join("google-chrome").join("Default");
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_history(&profile, false, None, fmt).unwrap();
        }
        // raw (no collapse) + a search needle that matches.
        run_history(&profile, true, Some("example"), OutputFormat::Jsonl).unwrap();
        // search needle that matches nothing → empty emit.
        run_history(&profile, false, Some("zzz-nomatch"), OutputFormat::Csv).unwrap();
    }

    #[test]
    fn run_history_firefox_and_directory_errors() {
        let (_d, p) = firefox_places();
        run_history(&p, false, None, OutputFormat::Text).unwrap();
        // Empty dir → bail (no recognized history file).
        let empty = tempfile::tempdir().unwrap();
        assert!(run_history(empty.path(), false, None, OutputFormat::Text).is_err());
    }

    #[test]
    fn run_sessions_firefox_file_and_dir_errors() {
        // A non-session file → bail.
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("not-a-session.txt");
        std::fs::write(&bogus, b"x").unwrap();
        assert!(run_sessions(&bogus, None, OutputFormat::Text).is_err());
        // A nonexistent path → bail.
        assert!(run_sessions(&dir.path().join("nope"), None, OutputFormat::Text).is_err());
    }

    #[test]
    fn run_artifact_firefox_cookies_all_formats() {
        let (_d, p) = firefox_cookies();
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_artifact(&p, ArtifactType::Cookies, fmt).unwrap();
        }
    }

    #[test]
    fn run_artifact_safari_unsupported_arms_error() {
        // Safari `history.db` name → inferred Safari; these artifacts are
        // unsupported and must bail loudly rather than silently produce nothing.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("history.db");
        std::fs::write(&p, b"x").unwrap();
        for art in [
            ArtifactType::LoginData,
            ArtifactType::Autofill,
            ArtifactType::Cache,
        ] {
            assert!(run_artifact(&p, art, OutputFormat::Text).is_err());
        }
    }

    #[test]
    fn merge_carve_stats_and_summary_helpers() {
        let s = browser_forensic_carve::CarveStats {
            bytes_scanned: 1,
            pages_scanned: 2,
            free_pages_found: 3,
            records_recovered: 4,
            records_partial: 5,
        };
        let m = merge_carve_stats(&s, &s);
        assert_eq!(m.bytes_scanned, 2);
        let report = browser_forensic_triage::TriageReport {
            events: Vec::new(),
            carved: Vec::new(),
            integrity: Vec::new(),
            profiles: Vec::new(),
            generated_at_ns: 7,
        };
        assert_eq!(
            triage_summary_lines(&report)[0],
            "Browser Forensic Triage Report"
        );
    }
}
