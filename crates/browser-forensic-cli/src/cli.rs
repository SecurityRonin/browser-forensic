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
    Cookies {
        /// Path to the cookies artifact file or profile directory.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// OPT-IN: decrypt Chromium `v10` cookie values via the macOS login
        /// Keychain (prompts for authorization). Off by default.
        #[arg(long)]
        decrypt_macos: bool,
        /// Keychain service holding the "… Safe Storage" password.
        #[arg(long, value_name = "SERVICE", default_value = "Chrome Safe Storage")]
        keychain_service: String,
        /// OPT-IN: decrypt Windows Chromium `v10`/`v11` cookie values. Needs
        /// `--local-state` and a DPAPI secret (below). Off by default; `v20`
        /// App-Bound values are refused, never fabricated.
        #[arg(long)]
        decrypt_win: bool,
        /// Path to the profile's `Local State` file (holds the DPAPI-wrapped key).
        #[arg(long, value_name = "PATH")]
        local_state: Option<PathBuf>,
        /// DPAPI secret: a pre-decrypted 64-byte master key as hex. Mutually
        /// exclusive with the `--dpapi-password`/`--dpapi-sid`/…-file trio.
        #[arg(long, value_name = "HEX")]
        dpapi_masterkey: Option<String>,
        /// DPAPI secret: the user's logon password (with `--dpapi-sid` and
        /// `--dpapi-masterkey-file`).
        #[arg(long, value_name = "PASSWORD")]
        dpapi_password: Option<String>,
        /// DPAPI secret: the user SID (e.g. `S-1-5-21-…-1001`).
        #[arg(long, value_name = "SID")]
        dpapi_sid: Option<String>,
        /// DPAPI secret: the user's master-key file
        /// (`%APPDATA%/Microsoft/Protect/<SID>/<GUID>`).
        #[arg(long, value_name = "PATH")]
        dpapi_masterkey_file: Option<PathBuf>,
    },
    /// Parse browser downloads.
    Downloads(ArtifactArgs),
    /// Parse browser bookmarks.
    Bookmarks(ArtifactArgs),
    /// Parse browser extensions.
    Extensions(ArtifactArgs),
    /// Parse browser login data (passwords NEVER exposed unless explicitly
    /// opted in with `--decrypt --include-passwords`).
    LoginData {
        /// A `logins.json`/`key4.db`/`Login Data` file, or a profile directory.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// OPT-IN: decrypt saved usernames (Firefox NSS). Needs the profile's
        /// `key4.db`. Off by default (values stay `ENCRYPTED`).
        #[arg(long)]
        decrypt: bool,
        /// Firefox master password (empty when none is set). Used with `--decrypt`.
        #[arg(long, value_name = "PASSWORD", default_value = "")]
        master_password: String,
        /// EXTRA OPT-IN: also decrypt and show plaintext passwords (crown jewel).
        /// Requires `--decrypt`. Default output never contains a password.
        #[arg(long)]
        include_passwords: bool,
    },
    /// Parse browser autofill data.
    Autofill(ArtifactArgs),
    /// Parse a browser session store.
    Session(ArtifactArgs),
    /// Parse browser cache.
    Cache(ArtifactArgs),
    /// Recover Service Worker CacheStorage (Cache API) responses. `PATH` is a
    /// `Service Worker/CacheStorage` directory (or one `<origin-hash>` subdir).
    Cachestorage(ArtifactArgs),
    /// Reconstruct viewable pages from browser cache. `PATH` is a cache
    /// directory or a whole profile. Writes a self-contained single-file HTML
    /// page, a replayable WARC, or a cached-image gallery to `--out`. Every
    /// artifact carries a provenance manifest of found vs missing sub-resources:
    /// a cache reconstruction is a *consistent-with* artifact, NOT a rendered
    /// capture (JS/SPA/lazy-loaded/auth-gated content may be absent).
    Reconstruct {
        /// A cache directory or profile directory to read.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Output directory for the reconstructed artifact(s).
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Target page URL (html/warc). Omit to reconstruct every cached page
        /// (html) or the whole cache (warc).
        #[arg(long, value_name = "TARGET")]
        url: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ReconstructFormat::Html)]
        format: ReconstructFormat,
    },
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
    /// Decode a Chromium IndexedDB LevelDB directory directly: database and
    /// object-store names, keys, and Blink/V8-serialized values. `PATH` is a
    /// single `*.indexeddb.leveldb` directory.
    Indexeddb(ArtifactArgs),
    /// Parse a Chromium `Favicons` database (page_url visited-URL source).
    Favicons(ArtifactArgs),
    /// Parse a Chromium `Top Sites` database (most-visited / frecency).
    TopSites(ArtifactArgs),
    /// Parse a Chromium `Shortcuts` database (omnibox strings the user typed).
    Shortcuts(ArtifactArgs),
    /// Parse a Chromium `Network Action Predictor` (partial typed strings).
    Predictor(ArtifactArgs),
    /// Parse a Chromium `Media History` database (audio/video playback).
    MediaHistory(ArtifactArgs),
    /// Parse a Chromium `Extension Cookies` jar (tagged cookie_store=extension).
    ExtensionCookies(ArtifactArgs),
    /// List strings the user typed into the Firefox address bar (`places.sqlite`
    /// `moz_inputhistory`). `PATH` is a `places.sqlite` file or a profile
    /// directory. Firefox-only; direct evidence of typed intent.
    TypedInput(ArtifactArgs),
    /// List Firefox page annotations (`places.sqlite` `moz_annos`). `PATH` is a
    /// `places.sqlite` file or a profile directory. Firefox-only; stated as
    /// recorded.
    Annotations(ArtifactArgs),
    /// Recover deleted bookmarks by diffing Firefox `bookmarkbackups/*.jsonlz4`
    /// against the current `moz_bookmarks`: bookmarks present in a backup but
    /// absent now, consistent with deletion after that backup. `PATH` is a
    /// profile directory (or its `places.sqlite`). Firefox-only.
    DeletedBookmarks(ArtifactArgs),
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
        /// Also write a chain-of-custody manifest (SHA-256/MD5 of every input) here.
        #[arg(long, value_name = "FILE")]
        manifest: Option<PathBuf>,
    },
    /// Write a DFIR-interop / court-ready report for a profile/home directory:
    /// a TSK bodyfile, plaso l2t_csv, or a self-contained HTML report.
    Report {
        /// A profile directory or home directory to collect events from.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Report format.
        #[arg(long, value_enum, default_value_t = crate::report::ReportFormat::Html)]
        format: crate::report::ReportFormat,
        /// Output file (defaults to stdout).
        #[arg(long = "out", short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
        /// Render timestamps in this IANA timezone (e.g. `America/New_York`).
        #[arg(long, value_name = "TZ")]
        timezone: Option<String>,
        /// Also write a chain-of-custody manifest (SHA-256/MD5 of every input) here.
        #[arg(long, value_name = "FILE")]
        manifest: Option<PathBuf>,
    },
    /// Write a case-level chain-of-custody manifest (JSON): for every evidence
    /// file read, its absolute path, size, SHA-256, MD5, and mtime, plus run
    /// metadata (tool + version, invocation, acquisition time, host OS). Records
    /// the integrity of the extracted inputs — not the provenance of the device.
    Manifest {
        /// A single evidence file, a profile directory, or a home directory.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Write the manifest JSON here (defaults to stdout).
        #[arg(long = "out", short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
        /// Render the acquisition time in this IANA timezone (e.g. `America/New_York`).
        #[arg(long, value_name = "TZ")]
        timezone: Option<String>,
    },
    /// Search collected events with a substring or linear-time regex, scoped by
    /// field and an inclusive time range. `PATH` is a profile or home directory.
    Search {
        /// A profile directory or home directory to collect events from.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Linear-time regex pattern to match (mutually useful with --substring).
        #[arg(long, value_name = "PAT")]
        regex: Option<String>,
        /// Case-sensitive substring to match.
        #[arg(long, value_name = "TEXT")]
        substring: Option<String>,
        /// Restrict matching to these fields (repeatable; default: all text).
        #[arg(long = "field", value_name = "NAME")]
        fields: Vec<String>,
        /// Inclusive lower time bound (RFC3339, `YYYY-MM-DD`, or Unix nanos).
        #[arg(long, value_name = "TS")]
        from: Option<String>,
        /// Inclusive upper time bound (RFC3339, `YYYY-MM-DD`, or Unix nanos).
        #[arg(long, value_name = "TS")]
        to: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Extract candidate entities/IOCs from collected events: emails, IPs,
    /// crypto-address candidates, Luhn-valid card candidates, and search terms.
    /// Every match is a candidate, never a confirmed identifier. `PATH` is a
    /// profile or home directory.
    ExtractIocs {
        /// A profile directory or home directory to collect events from.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Flag events whose host matches a user-supplied domain blocklist (no
    /// bundled threat intel — the list is an input). `PATH` is a profile or home
    /// directory.
    MatchDomains {
        /// A profile directory or home directory to collect events from.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Blocklist file: one host per line, `#` comments allowed.
        #[arg(long, value_name = "FILE")]
        list: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
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
    /// Check for anti-forensic / tampering indicators (history clearing,
    /// timestamp anomalies, manual DB edits, incognito residue). Every finding is
    /// consistent-with clearing/tampering, NOT proof of it, and is reported with
    /// an innocent alternative. PATH may be a database file or a profile directory.
    TamperCheck(ArtifactArgs),
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
    /// Correlate all collected events into a unified cross-artifact / cross-browser
    /// timeline and a per-host (registrable-domain) rollup. `PATH` is a profile or
    /// home directory. Correlation is co-occurrence by URL/host/time — not proof of
    /// intent or causation.
    Correlate {
        /// A profile directory or home directory to collect events from.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Build an entity graph over registrable hosts: referrer/redirect edges from
    /// recorded visit chains (M3) plus time-windowed co-occurrence edges. `PATH` is
    /// a profile or home directory. A co-occurrence edge means "same window", never
    /// deliberate navigation.
    Graph {
        /// A profile directory or home directory to collect events from.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = GraphFormat::Json)]
        format: GraphFormat,
        /// Output file (defaults to stdout).
        #[arg(long = "out", short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
        /// Co-occurrence window in seconds (<= 0 disables co-occurrence edges).
        #[arg(long, value_name = "SECONDS", default_value_t = browser_forensic_correlate::graph::DEFAULT_COOCCURRENCE_WINDOW_SECS)]
        window: i64,
    },
}

/// Parse the process arguments and dispatch. The no-subcommand and `tui` paths
/// call `launch_tui` (injected so this lib stays decoupled from the TUI main
/// loop); every other subcommand runs a scriptable handler in this module.
///
/// # Errors
/// Propagates whatever the selected handler returns.
#[allow(clippy::too_many_lines)] // pure subcommand dispatcher; grows one arm per command
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
        Some(Command::Cookies {
            path,
            format,
            decrypt_macos,
            keychain_service,
            decrypt_win,
            local_state,
            dpapi_masterkey,
            dpapi_password,
            dpapi_sid,
            dpapi_masterkey_file,
        }) => dispatch_cookies(
            &path,
            format,
            decrypt_macos,
            &keychain_service,
            CookieWinDecrypt {
                enabled: decrypt_win,
                local_state,
                dpapi_masterkey,
                dpapi_password,
                dpapi_sid,
                dpapi_masterkey_file,
            },
        ),
        Some(Command::Downloads(a)) => run_artifact(&a.path, ArtifactType::Downloads, a.format),
        Some(Command::Bookmarks(a)) => run_artifact(&a.path, ArtifactType::Bookmarks, a.format),
        Some(Command::Extensions(a)) => run_artifact(&a.path, ArtifactType::Extensions, a.format),
        Some(Command::LoginData {
            path,
            format,
            decrypt,
            master_password,
            include_passwords,
        }) => dispatch_login_data(&path, format, decrypt, &master_password, include_passwords),
        Some(Command::Autofill(a)) => run_artifact(&a.path, ArtifactType::Autofill, a.format),
        Some(Command::Session(a)) => run_artifact(&a.path, ArtifactType::Session, a.format),
        Some(Command::Cache(a)) => run_artifact(&a.path, ArtifactType::Cache, a.format),
        Some(Command::Cachestorage(a)) => run_cachestorage(&a.path, a.format),
        Some(Command::Reconstruct {
            path,
            out,
            url,
            format,
        }) => run_reconstruct(&path, &out, url.as_deref(), format),
        Some(Command::Preferences(a)) => run_artifact(&a.path, ArtifactType::Preferences, a.format),
        Some(Command::Permissions(a)) => run_permissions(&a.path, a.format),
        Some(Command::Credentials(a)) => run_credentials(&a.path, a.format),
        Some(Command::RecoveredDomains(a)) => run_recovered_domains(&a.path, a.format),
        Some(Command::Storage(a)) => run_storage(&a.path, a.format),
        Some(Command::Indexeddb(a)) => run_indexeddb(&a.path, a.format),
        Some(Command::Favicons(a)) => run_favicons(&a.path, a.format),
        Some(Command::TopSites(a)) => run_top_sites(&a.path, a.format),
        Some(Command::Shortcuts(a)) => run_shortcuts(&a.path, a.format),
        Some(Command::Predictor(a)) => run_predictor(&a.path, a.format),
        Some(Command::MediaHistory(a)) => run_media_history(&a.path, a.format),
        Some(Command::ExtensionCookies(a)) => run_extension_cookies(&a.path, a.format),
        Some(Command::TypedInput(a)) => run_typed_input(&a.path, a.format),
        Some(Command::Annotations(a)) => run_annotations(&a.path, a.format),
        Some(Command::DeletedBookmarks(a)) => run_deleted_bookmarks(&a.path, a.format),
        Some(Command::Export {
            path,
            format,
            output,
            timezone,
            interpret,
            manifest,
        }) => run_export(
            &path,
            format,
            output.as_deref(),
            timezone.as_deref(),
            interpret,
            manifest.as_deref(),
        ),
        Some(Command::Report {
            path,
            format,
            output,
            timezone,
            manifest,
        }) => run_report(
            &path,
            format,
            output.as_deref(),
            timezone.as_deref(),
            manifest.as_deref(),
        ),
        Some(Command::Manifest {
            path,
            out,
            timezone,
        }) => run_manifest(&path, out.as_deref(), timezone.as_deref()),
        Some(Command::Search {
            path,
            regex,
            substring,
            fields,
            from,
            to,
            format,
        }) => run_search(
            &path,
            regex.as_deref(),
            substring.as_deref(),
            &fields,
            from.as_deref(),
            to.as_deref(),
            format,
        ),
        Some(Command::ExtractIocs { path, format }) => run_extract_iocs(&path, format),
        Some(Command::MatchDomains { path, list, format }) => {
            run_match_domains(&path, &list, format)
        }
        Some(Command::Profiles { format }) => run_profiles(format),
        Some(Command::Analyze { path, cap }) => run_analyze(&path, cap),
        Some(Command::Integrity(a)) => run_integrity(&a.path, a.format),
        Some(Command::TamperCheck(a)) => run_tamper_check(&a.path, a.format),
        Some(Command::Carve(a)) => run_carve(&a.path, a.format),
        Some(Command::Triage { home, format }) => run_triage(home.as_deref(), format),
        Some(Command::Correlate { path, format }) => run_correlate(&path, format),
        Some(Command::Graph {
            path,
            format,
            out,
            window,
        }) => run_graph(&path, format, out.as_deref(), window),
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

/// Entity-graph output format for `br4n6 graph`.
#[derive(Clone, Copy, Debug, ValueEnum, Default, PartialEq, Eq)]
pub enum GraphFormat {
    /// JSON document with `nodes` and `edges` arrays.
    #[default]
    Json,
    /// Graphviz DOT digraph.
    Dot,
}

/// Reconstruction output format for `br4n6 reconstruct`.
#[derive(Clone, Copy, Debug, ValueEnum, Default, PartialEq, Eq)]
pub enum ReconstructFormat {
    /// Self-contained single-file HTML page(s).
    #[default]
    Html,
    /// Replayable WARC (ISO 28500) archive.
    Warc,
    /// Cached-image gallery.
    Gallery,
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

/// Decrypt Firefox saved credentials (opt-in). Locates `key4.db` + `logins.json`
/// from `path` (a profile directory or either file), then decrypts. Usernames
/// are always returned; a password is only decrypted and returned when
/// `include_passwords` is set. Returns [`BrowserEvent`]s for rendering.
///
/// # Errors
/// Returns an error when the profile files are missing, the master password is
/// wrong, or a blob cannot be decrypted.
pub fn decrypt_firefox_credentials(
    path: &Path,
    master_password: &str,
    include_passwords: bool,
) -> Result<Vec<BrowserEvent>> {
    use browser_forensic_core::{ArtifactKind, BrowserFamily};

    let (key4_db, logins_json) = resolve_firefox_profile(path)?;
    let logins = browser_forensic_decrypt::decrypt_firefox_logins(
        &key4_db,
        &logins_json,
        master_password,
        include_passwords,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let source = logins_json.to_string_lossy().into_owned();
    let events = logins
        .into_iter()
        .map(|login| {
            let password = login.password.map_or_else(
                || json!("(not decrypted — pass --include-passwords)"),
                serde_json::Value::String,
            );
            BrowserEvent::new(
                0,
                BrowserFamily::Firefox,
                ArtifactKind::LoginData,
                &source,
                login.hostname.clone(),
            )
            .with_attr("hostname", json!(login.hostname))
            .with_attr("username", json!(login.username))
            .with_attr("password", password)
        })
        .collect();
    Ok(events)
}

/// Locate a Firefox profile's `key4.db` and `logins.json` from `path`, which may
/// be the profile directory or either of the two files.
fn resolve_firefox_profile(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let dir = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    };
    let key4 = dir.join("key4.db");
    let logins = dir.join("logins.json");
    if !key4.exists() {
        anyhow::bail!(
            "no key4.db found in {} — Firefox credential decryption needs the NSS key database",
            dir.display()
        );
    }
    if !logins.exists() {
        anyhow::bail!("no logins.json found in {}", dir.display());
    }
    Ok((key4, logins))
}

/// Decrypt Chromium `v10` cookie values from a `Cookies` SQLite DB using an
/// already-derived macOS storage key. Each row becomes a [`BrowserEvent`] whose
/// `value` attr is the decrypted cookie, or a loud `DECRYPT_FAILED: …` marker on
/// failure — never a fabricated value.
///
/// # Errors
/// Returns an error if the database cannot be opened or queried.
pub fn decrypt_chromium_cookies(path: &Path, storage_key: &[u8; 16]) -> Result<Vec<BrowserEvent>> {
    use browser_forensic_core::sqlite::open_evidence_db;
    use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};

    let db = open_evidence_db(path)?;
    let mut stmt = db.conn.prepare(
        "SELECT creation_utc, host_key, name, path, encrypted_value \
         FROM cookies WHERE creation_utc > 0 ORDER BY creation_utc ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let rows = stmt.query_map([], |row| {
        let creation_utc: i64 = row.get(0)?;
        let host_key: String = row.get(1)?;
        let name: String = row.get(2)?;
        let cookie_path: String = row.get(3)?;
        let encrypted: Vec<u8> = row.get(4)?;
        Ok((creation_utc, host_key, name, cookie_path, encrypted))
    })?;

    let mut events = Vec::new();
    for row in rows {
        let (creation_utc, host_key, name, cookie_path, encrypted) = row?;
        // A wrong key / non-v10 blob surfaces the loud reason, never a fake value.
        // On success, strip Chromium's SHA-256(host_key) domain-binding prefix
        // (schema v24+); a mismatch surfaces the raw value with domain_bound=false.
        let (value, domain_bound) =
            match browser_forensic_decrypt::decrypt_chromium_value_macos(&encrypted, storage_key) {
                Ok(bytes) => {
                    let (clean, bound) =
                        browser_forensic_decrypt::strip_domain_hash_prefix(&bytes, &host_key);
                    (String::from_utf8_lossy(&clean).into_owned(), bound)
                }
                Err(e) => (format!("DECRYPT_FAILED: {e}"), false),
            };
        let ts_ns = webkit_micros_to_unix_nanos(creation_utc);
        let desc = format!("{host_key} \u{2014} {name} (path={cookie_path})");
        events.push(
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Chromium,
                ArtifactKind::Cookies,
                &source,
                desc,
            )
            .with_attr("host", json!(host_key))
            .with_attr("name", json!(name))
            .with_attr("path", json!(cookie_path))
            .with_attr("value", json!(value))
            .with_attr("domain_bound", json!(domain_bound)),
        );
    }
    Ok(events)
}

/// Recover the 32-byte Windows Chromium AES-256-GCM key from a `Local State`
/// file and an opt-in DPAPI secret. Supply EITHER a pre-decrypted 64-byte master
/// key as hex (`dpapi_masterkey_hex`), OR all three of `password` + `sid` +
/// `masterkey_file`. STUB — implemented in the GREEN step.
///
/// # Errors
/// STUB.
pub fn resolve_dpapi_key(
    local_state: &Path,
    dpapi_masterkey_hex: Option<&str>,
    password: Option<&str>,
    sid: Option<&str>,
    masterkey_file: Option<&Path>,
) -> Result<[u8; 32]> {
    use browser_forensic_decrypt::DpapiSecret;

    let local_state_json = std::fs::read_to_string(local_state)
        .with_context(|| format!("reading Local State from {}", local_state.display()))?;

    // Secret is opt-in: a pre-decrypted 64-byte master key (hex) takes
    // precedence; otherwise all three of password + SID + master-key file.
    if let Some(hex) = dpapi_masterkey_hex {
        let bytes = decode_hex(hex).with_context(|| "--dpapi-masterkey must be hex".to_string())?;
        let mk: [u8; 64] = bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!(
                "--dpapi-masterkey must decode to exactly 64 bytes (a DPAPI master key), got {}",
                v.len()
            )
        })?;
        return browser_forensic_decrypt::decrypt_chromium_key_dpapi(
            &local_state_json,
            &DpapiSecret::MasterKey(mk),
        )
        .map_err(|e| anyhow::anyhow!("{e}"));
    }

    match (password, sid, masterkey_file) {
        (Some(password), Some(sid), Some(mkf_path)) => {
            let mkf = std::fs::read(mkf_path)
                .with_context(|| format!("reading DPAPI master-key file {}", mkf_path.display()))?;
            browser_forensic_decrypt::decrypt_chromium_key_dpapi(
                &local_state_json,
                &DpapiSecret::UserPassword {
                    password,
                    sid,
                    masterkey_file: &mkf,
                },
            )
            .map_err(|e| anyhow::anyhow!("{e}"))
        }
        _ => anyhow::bail!(
            "Windows Chromium decryption needs a DPAPI secret: supply either \
             --dpapi-masterkey <HEX> (a 64-byte master key), or all of \
             --dpapi-password, --dpapi-sid and --dpapi-masterkey-file"
        ),
    }
}

/// Decode a lowercase/uppercase hex string into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("hex string has an odd length ({})", s.len());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex at offset {i}: {e}"))
        })
        .collect()
}

/// Decrypt Windows Chromium `v10`/`v11` cookie values from a `Cookies` SQLite DB
/// with an already-recovered 32-byte key. A wrong key / `v20` / tampered blob
/// yields a loud `DECRYPT_FAILED: …` marker on that row, never a fabricated value.
///
/// # Errors
/// Returns an error if the database cannot be opened or queried.
pub fn decrypt_chromium_cookies_win(path: &Path, key: &[u8; 32]) -> Result<Vec<BrowserEvent>> {
    use browser_forensic_core::sqlite::open_evidence_db;
    use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};

    let db = open_evidence_db(path)?;
    let mut stmt = db.conn.prepare(
        "SELECT creation_utc, host_key, name, path, encrypted_value \
         FROM cookies WHERE creation_utc > 0 ORDER BY creation_utc ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let rows = stmt.query_map([], |row| {
        let creation_utc: i64 = row.get(0)?;
        let host_key: String = row.get(1)?;
        let name: String = row.get(2)?;
        let cookie_path: String = row.get(3)?;
        let encrypted: Vec<u8> = row.get(4)?;
        Ok((creation_utc, host_key, name, cookie_path, encrypted))
    })?;

    let mut events = Vec::new();
    for row in rows {
        let (creation_utc, host_key, name, cookie_path, encrypted) = row?;
        // Strip the platform-independent SHA-256(host_key) domain-binding prefix
        // (schema v24+) on success; a mismatch keeps the raw value, domain_bound=false.
        let (value, domain_bound) =
            match browser_forensic_decrypt::decrypt_chromium_value_win(&encrypted, key) {
                Ok(bytes) => {
                    let (clean, bound) =
                        browser_forensic_decrypt::strip_domain_hash_prefix(&bytes, &host_key);
                    (String::from_utf8_lossy(&clean).into_owned(), bound)
                }
                Err(e) => (format!("DECRYPT_FAILED: {e}"), false),
            };
        let ts_ns = webkit_micros_to_unix_nanos(creation_utc);
        let desc = format!("{host_key} \u{2014} {name} (path={cookie_path})");
        events.push(
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Chromium,
                ArtifactKind::Cookies,
                &source,
                desc,
            )
            .with_attr("host", json!(host_key))
            .with_attr("name", json!(name))
            .with_attr("path", json!(cookie_path))
            .with_attr("value", json!(value))
            .with_attr("domain_bound", json!(domain_bound)),
        );
    }
    Ok(events)
}

/// Opt-in Windows Chromium cookie-decryption inputs (grouped so the `cookies`
/// dispatch takes one coherent choice, not six loose flags).
struct CookieWinDecrypt {
    enabled: bool,
    local_state: Option<PathBuf>,
    dpapi_masterkey: Option<String>,
    dpapi_password: Option<String>,
    dpapi_sid: Option<String>,
    dpapi_masterkey_file: Option<PathBuf>,
}

/// Route `cookies`: opt-in Windows or macOS `v10` decryption, else plain parser.
fn dispatch_cookies(
    path: &Path,
    format: OutputFormat,
    decrypt_macos: bool,
    keychain_service: &str,
    win: CookieWinDecrypt,
) -> Result<()> {
    if win.enabled {
        run_cookies_decrypt_win(path, &win, format)
    } else if decrypt_macos {
        run_cookies_decrypt_macos(path, keychain_service, format)
    } else {
        run_artifact(path, ArtifactType::Cookies, format)
    }
}

/// `br4n6 cookies PATH --decrypt-win` handler: recover the DPAPI key, decrypt.
fn run_cookies_decrypt_win(
    path: &Path,
    win: &CookieWinDecrypt,
    format: OutputFormat,
) -> Result<()> {
    let local_state = win.local_state.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--decrypt-win requires --local-state <PATH> (the profile's Local State)")
    })?;
    eprintln!("[decrypt] opt-in Windows Chromium cookie decryption — output contains plaintext");
    let key = resolve_dpapi_key(
        local_state,
        win.dpapi_masterkey.as_deref(),
        win.dpapi_password.as_deref(),
        win.dpapi_sid.as_deref(),
        win.dpapi_masterkey_file.as_deref(),
    )?;
    let mut events = decrypt_chromium_cookies_win(path, &key)?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// Route `login-data`: opt-in Firefox credential decryption, else the plain
/// parser. `--include-passwords` is meaningless without `--decrypt`.
fn dispatch_login_data(
    path: &Path,
    format: OutputFormat,
    decrypt: bool,
    master_password: &str,
    include_passwords: bool,
) -> Result<()> {
    if decrypt {
        run_credentials_decrypt(path, master_password, include_passwords, format)
    } else if include_passwords {
        anyhow::bail!("--include-passwords requires --decrypt")
    } else {
        run_artifact(path, ArtifactType::LoginData, format)
    }
}

/// `br4n6 login-data PATH --decrypt` handler: warn, decrypt, render.
fn run_credentials_decrypt(
    path: &Path,
    master_password: &str,
    include_passwords: bool,
    format: OutputFormat,
) -> Result<()> {
    eprintln!(
        "[decrypt] opt-in credential decryption enabled — output contains sensitive plaintext{}",
        if include_passwords {
            " INCLUDING PASSWORDS"
        } else {
            ""
        }
    );
    let mut events = decrypt_firefox_credentials(path, master_password, include_passwords)?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 cookies PATH --decrypt-macos` handler: read the Keychain key, decrypt.
fn run_cookies_decrypt_macos(path: &Path, service: &str, format: OutputFormat) -> Result<()> {
    eprintln!("[decrypt] reading '{service}' from the macOS login Keychain (may prompt)…");
    let password = browser_forensic_decrypt::fetch_macos_keychain_key(service)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let key = browser_forensic_decrypt::derive_chromium_macos_key(password.as_bytes());
    let mut events = decrypt_chromium_cookies(path, &key)?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
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

/// Collect a profile/home directory's correlated events, the same way `export`
/// does: a home-directory triage scan first, falling back to treating `path` as
/// a single profile directory.
///
/// # Errors
/// Returns an error if collection fails.
fn collect_profile_events(path: &Path) -> Result<Vec<BrowserEvent>> {
    // Bootstrap check: a nonexistent path is a loud error, not a silent empty
    // result (which would be indistinguishable from a genuinely empty profile).
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    let mut report = browser_forensic_triage::triage(path)
        .with_context(|| format!("collecting events from {}", path.display()))?;
    if report.profiles.is_empty() && report.events.is_empty() {
        if let Some(family) = profile_family(path) {
            report = browser_forensic_triage::triage_profile(path, family)
                .with_context(|| format!("collecting events from profile {}", path.display()))?;
        }
    }
    let mut events = report.events;
    events.sort_by_key(|e| e.timestamp_ns);
    Ok(events)
}

/// The history file inside a profile directory for a given family, if present.
fn history_file_for(profile: &Path, family: BrowserFamily) -> Option<PathBuf> {
    let name = match family {
        BrowserFamily::Chromium => "History",
        BrowserFamily::Firefox => "places.sqlite",
        BrowserFamily::Safari => "History.db",
    };
    let candidate = profile.join(name);
    candidate.is_file().then_some(candidate)
}

/// Per-visit history events (carrying `from_visit`/`visit_id`) for every
/// discovered profile under `path`, so navigation reconstruction (M3) has the
/// linkage the redirect-collapsed triage `History` view drops.
///
/// Chromium and Firefox record `from_visit`; Safari does not, so it is left to
/// the collapsed view. Returns the per-visit events plus the set of families
/// they cover (so the caller can drop the collapsed `History` only for those).
fn collect_visit_history(path: &Path) -> (Vec<BrowserEvent>, Vec<BrowserFamily>) {
    let mut targets: Vec<(BrowserFamily, PathBuf)> = Vec::new();
    for profile in browser_forensic_discovery::discover_profiles(path) {
        if let Some(hf) = history_file_for(&profile.path, profile.browser.clone()) {
            targets.push((profile.browser, hf));
        }
    }
    if targets.is_empty() {
        if let Some(family) = profile_family(path) {
            if let Some(hf) = history_file_for(path, family.clone()) {
                targets.push((family, hf));
            }
        }
    }

    let mut events = Vec::new();
    let mut families: Vec<BrowserFamily> = Vec::new();
    for (family, hf) in targets {
        let parsed = match family {
            BrowserFamily::Chromium => browser_forensic_chrome::parse_visits(&hf),
            BrowserFamily::Firefox => browser_forensic_firefox::parse_visits(&hf),
            BrowserFamily::Safari => continue,
        };
        if let Ok(mut evts) = parsed {
            if !evts.is_empty() {
                events.append(&mut evts);
                if !families.contains(&family) {
                    families.push(family);
                }
            }
        }
    }
    (events, families)
}

/// Collect events for `correlate`/`graph`. Same artifacts as
/// [`collect_profile_events`], but the redirect-collapsed `History` view is
/// replaced (per family) with the per-visit stream so referrer/redirect edges
/// have the `from_visit` linkage M3 needs. Non-history artifacts are unchanged.
///
/// # Errors
/// Returns an error if collection fails.
fn collect_correlation_events(path: &Path) -> Result<Vec<BrowserEvent>> {
    let mut events = collect_profile_events(path)?;
    let (visits, families) = collect_visit_history(path);
    if !visits.is_empty() {
        events.retain(|e| {
            e.artifact != browser_forensic_core::ArtifactKind::History
                || !families.contains(&e.browser)
        });
        events.extend(visits);
        events.sort_by_key(|e| e.timestamp_ns);
    }
    Ok(events)
}

/// `br4n6 search` — filter collected events by substring/regex, field scope, and
/// an inclusive time range.
///
/// # Errors
/// Returns an error if a timestamp or regex is invalid, or collection fails.
#[allow(clippy::too_many_arguments)]
pub fn run_search(
    path: &Path,
    regex: Option<&str>,
    substring: Option<&str>,
    fields: &[String],
    from: Option<&str>,
    to: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    use browser_forensic_search::{filter_events, EventQuery, Pattern};

    let pattern = match (regex, substring) {
        (Some(_), Some(_)) => {
            anyhow::bail!("pass only one of --regex or --substring, not both")
        }
        (Some(pat), None) => {
            Some(Pattern::regex(pat).with_context(|| format!("invalid regex: {pat}"))?)
        }
        (None, Some(s)) => Some(Pattern::substring(s)),
        (None, None) => None,
    };

    let query = EventQuery {
        pattern,
        fields: fields.to_vec(),
        from_ns: from.map(parse_timestamp_ns).transpose()?,
        to_ns: to.map(parse_timestamp_ns).transpose()?,
    };

    let events = collect_profile_events(path)?;
    let matched: Vec<BrowserEvent> = filter_events(&events, &query)
        .into_iter()
        .cloned()
        .collect();
    emit_events(&matched, format);
    Ok(())
}

/// Parse a timestamp argument to Unix nanoseconds: an RFC3339 datetime, a
/// `YYYY-MM-DD` date (midnight UTC), or a raw integer already in nanoseconds.
fn parse_timestamp_ns(s: &str) -> Result<i64> {
    use chrono::{DateTime, NaiveDate};

    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.timestamp_nanos_opt().unwrap_or(0));
    }
    if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        if let Some(dt) = date.and_hms_opt(0, 0, 0) {
            return Ok(dt.and_utc().timestamp_nanos_opt().unwrap_or(0));
        }
    }
    if let Ok(ns) = s.parse::<i64>() {
        return Ok(ns);
    }
    anyhow::bail!("unrecognized timestamp {s:?} (want RFC3339, YYYY-MM-DD, or Unix nanoseconds)")
}

/// `br4n6 extract-iocs` — extract candidate entities from collected events.
///
/// # Errors
/// Returns an error if collection fails.
pub fn run_extract_iocs(path: &Path, format: OutputFormat) -> Result<()> {
    let events = collect_profile_events(path)?;
    let iocs = browser_forensic_search::extract_iocs(&events);
    emit_iocs(&iocs, &events, format);
    // Honesty note on the human view only; machine streams stay data-only.
    if matches!(format, OutputFormat::Text) {
        eprintln!(
            "{} candidate entities (shape/checksum matches, not confirmed identifiers)",
            iocs.len()
        );
    }
    Ok(())
}

/// `br4n6 match-domains` — flag events whose host matches a blocklist file.
///
/// # Errors
/// Returns an error if the list is missing/empty or collection fails.
pub fn run_match_domains(path: &Path, list: &Path, format: OutputFormat) -> Result<()> {
    use browser_forensic_search::DomainMatcher;

    let text = std::fs::read_to_string(list)
        .with_context(|| format!("reading blocklist {}", list.display()))?;
    let domains = DomainMatcher::parse_blocklist(&text);
    let matcher = DomainMatcher::new(&domains).with_context(|| {
        format!(
            "blocklist {} contains no usable domains (empty after removing blanks/comments)",
            list.display()
        )
    })?;

    let events = collect_profile_events(path)?;
    let hits = matcher.match_events(&events);
    emit_domain_hits(&hits, &events, format);
    Ok(())
}

/// Render IOC matches. Human `text` shows type, full value, provenance, and the
/// honesty note; machine `jsonl`/`csv` stay faithful and round-trippable.
fn emit_iocs(
    iocs: &[browser_forensic_search::IocMatch],
    events: &[BrowserEvent],
    format: OutputFormat,
) {
    match format {
        OutputFormat::Text => {
            for m in iocs {
                let ts = events
                    .get(m.event_index)
                    .map_or_else(String::new, |e| format_ts(e.timestamp_ns));
                let note = m
                    .note
                    .as_deref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default();
                println!(
                    "{kind}\t{value}{note}\t[{ts} {field}@{offset}]",
                    kind = m.kind.label(),
                    value = m.value,
                    field = m.field,
                    offset = m.offset,
                );
            }
        }
        OutputFormat::Jsonl => {
            for m in iocs {
                let ts = events.get(m.event_index).map(|e| format_ts(e.timestamp_ns));
                let mut obj = serde_json::to_value(m).unwrap_or_else(|_| json!({}));
                if let (Some(map), Some(ts)) = (obj.as_object_mut(), ts) {
                    map.insert("timestamp".to_string(), json!(ts));
                }
                println!(
                    "{}",
                    serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string())
                );
            }
        }
        OutputFormat::Csv => {
            println!("kind,value,event_index,field,offset,note");
            for m in iocs {
                println!(
                    "{},{},{},{},{},{}",
                    csv_escape(m.kind.label()),
                    csv_escape(&m.value),
                    m.event_index,
                    csv_escape(&m.field),
                    m.offset,
                    csv_escape(m.note.as_deref().unwrap_or_default()),
                );
            }
        }
    }
}

/// Render blocklist domain hits in text/jsonl/csv.
fn emit_domain_hits(
    hits: &[browser_forensic_search::DomainHit],
    events: &[BrowserEvent],
    format: OutputFormat,
) {
    match format {
        OutputFormat::Text => {
            for h in hits {
                let ts = events
                    .get(h.event_index)
                    .map_or_else(String::new, |e| format_ts(e.timestamp_ns));
                println!(
                    "{domain}\t{host}\t[{ts} {field}]",
                    domain = h.blocklisted_domain,
                    host = h.host,
                    field = h.field,
                );
            }
        }
        OutputFormat::Jsonl => {
            for h in hits {
                let ts = events.get(h.event_index).map(|e| format_ts(e.timestamp_ns));
                let mut obj = serde_json::to_value(h).unwrap_or_else(|_| json!({}));
                if let (Some(map), Some(ts)) = (obj.as_object_mut(), ts) {
                    map.insert("timestamp".to_string(), json!(ts));
                }
                println!(
                    "{}",
                    serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string())
                );
            }
        }
        OutputFormat::Csv => {
            println!("blocklisted_domain,host,event_index,field");
            for h in hits {
                println!(
                    "{},{},{},{}",
                    csv_escape(&h.blocklisted_domain),
                    csv_escape(&h.host),
                    h.event_index,
                    csv_escape(&h.field),
                );
            }
        }
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
    manifest_out: Option<&Path>,
) -> Result<()> {
    use crate::export::{self, ExportFormat};

    let tz = parse_tz(timezone)?;

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
    if let Some(mp) = manifest_out {
        let json = build_manifest_json(path, tz)?;
        std::fs::write(mp, json.as_bytes())
            .with_context(|| format!("writing manifest {}", mp.display()))?;
        eprintln!("wrote chain-of-custody manifest to {}", mp.display());
    }
    Ok(())
}

/// `br4n6 report` — collect a profile/home directory's events (same model as
/// `export`) and write one DFIR-interop / court-ready report: a TSK bodyfile,
/// plaso `l2t_csv`, or a self-contained HTML document. Read-only; writes to
/// `output` (or stdout).
///
/// # Errors
/// Returns an error if the timezone is unknown, collection fails, or writing
/// the output file fails.
pub fn run_report(
    path: &Path,
    format: crate::report::ReportFormat,
    output: Option<&Path>,
    timezone: Option<&str>,
    manifest_out: Option<&Path>,
) -> Result<()> {
    use std::io::Write as _;

    use crate::report::{self, ReportFormat};

    let tz = parse_tz(timezone)?;

    // Same collection model as `export`: scan `path` as a home directory, then
    // fall back to treating it as a single profile directory.
    let mut collected = browser_forensic_triage::triage(path)
        .with_context(|| format!("collecting timeline from {}", path.display()))?;
    if collected.profiles.is_empty() && collected.events.is_empty() {
        if let Some(family) = profile_family(path) {
            collected = browser_forensic_triage::triage_profile(path, family)
                .with_context(|| format!("collecting timeline from profile {}", path.display()))?;
        }
    }
    let mut events = std::mem::take(&mut collected.events);
    events.sort_by_key(|e| e.timestamp_ns);

    let rendered = match format {
        ReportFormat::Bodyfile => report::to_bodyfile(&events),
        ReportFormat::L2t => report::to_l2t_csv(&events, tz),
        ReportFormat::Html => {
            let meta = report::ReportMeta {
                case: None,
                examiner: None,
                tool: "br4n6".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                timezone: tz.map_or_else(|| "UTC".to_string(), |t| t.name().to_string()),
                generated_at_ns: collected.generated_at_ns,
                flags: report_flags(&collected),
            };
            report::to_html_report(&events, &meta)
        }
    };

    if let Some(p) = output {
        std::fs::write(p, rendered.as_bytes())
            .with_context(|| format!("writing {}", p.display()))?;
        eprintln!("wrote {} events to {}", events.len(), p.display());
    } else {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        lock.write_all(rendered.as_bytes())?;
    }
    if let Some(mp) = manifest_out {
        let json = build_manifest_json(path, tz)?;
        std::fs::write(mp, json.as_bytes())
            .with_context(|| format!("writing manifest {}", mp.display()))?;
        eprintln!("wrote chain-of-custody manifest to {}", mp.display());
    }
    Ok(())
}

/// Parse an optional IANA timezone name into a `chrono_tz::Tz`.
///
/// # Errors
/// Returns an error naming the offending value when the timezone is unknown.
fn parse_tz(timezone: Option<&str>) -> Result<Option<chrono_tz::Tz>> {
    match timezone {
        Some(name) => {
            Ok(Some(name.parse::<chrono_tz::Tz>().map_err(|_| {
                anyhow::anyhow!("unknown IANA timezone: {name}")
            })?))
        }
        None => Ok(None),
    }
}

/// Enumerate the evidence under `path`, hash each input, and render the
/// chain-of-custody manifest as deterministic JSON.
///
/// # Errors
/// Returns an error if no recognized evidence files are found under `path`, or
/// if manifest serialization fails.
fn build_manifest_json(path: &Path, tz: Option<chrono_tz::Tz>) -> Result<String> {
    let inputs = browser_forensic_manifest::enumerate_evidence(path);
    if inputs.is_empty() {
        anyhow::bail!(
            "no recognized browser evidence files found under {}",
            path.display()
        );
    }
    let args: Vec<String> = std::env::args().collect();
    let run = browser_forensic_manifest::RunMetadata::capture(
        "br4n6",
        env!("CARGO_PKG_VERSION"),
        &args,
        tz,
    );
    let manifest = browser_forensic_manifest::build_manifest(&inputs, run);
    browser_forensic_manifest::to_json(&manifest).context("serializing manifest")
}

/// `br4n6 manifest` — write a case-level chain-of-custody manifest (SHA-256/MD5
/// + run metadata) for every evidence file under `path`, to `out` or stdout.
///
/// # Errors
/// Returns an error if the timezone is unknown, no evidence is found, or writing
/// the manifest fails.
pub fn run_manifest(path: &Path, out: Option<&Path>, timezone: Option<&str>) -> Result<()> {
    let tz = parse_tz(timezone)?;
    let json = build_manifest_json(path, tz)?;
    match out {
        Some(p) => {
            std::fs::write(p, json.as_bytes())
                .with_context(|| format!("writing {}", p.display()))?;
            eprintln!("wrote chain-of-custody manifest to {}", p.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// Integrity / anti-forensic observations for the HTML report header: one line
/// per integrity indicator (variant tag + offending path), plus a carved-record
/// summary. These live outside the `BrowserEvent` stream, so the caller passes
/// them in via [`crate::report::ReportMeta`].
fn report_flags(report: &browser_forensic_triage::TriageReport) -> Vec<String> {
    let mut flags: Vec<String> = report.integrity.iter().map(integrity_flag).collect();
    if !report.carved.is_empty() {
        flags.push(format!(
            "{} record(s) recovered by carving from free/deleted space",
            report.carved.len()
        ));
    }
    flags
}

/// A concise, court-readable label for one integrity indicator: the variant
/// name and, when present, the offending path (the evidence to look at).
fn integrity_flag(indicator: &browser_forensic_integrity::IntegrityIndicator) -> String {
    let value = serde_json::to_value(indicator).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(map) = &value {
        if let Some((tag, body)) = map.iter().next() {
            if let Some(p) = body.get("path").and_then(serde_json::Value::as_str) {
                return format!("{tag} ({p})");
            }
            return tag.clone();
        }
    }
    format!("{indicator:?}")
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

/// `br4n6 tamper-check PATH` — anti-forensic / tampering indicator sweep.
///
/// `PATH` may be a single database file or a profile directory. For a directory,
/// every history database beneath it is checked and, in addition, network/state
/// residue is compared against history for incognito-usage indicators. Every
/// finding is an observation *consistent with* clearing/tampering, reported with
/// an innocent alternative — never a conclusion.
///
/// # Errors
/// Never fails on a per-artifact problem (best-effort); returns an error only if
/// the path itself cannot be interpreted.
pub fn run_tamper_check(path: &Path, format: OutputFormat) -> Result<()> {
    let mut indicators = Vec::new();
    if path.is_dir() {
        gather_profile_tamper_indicators(path, &mut indicators);
    } else {
        let family = browser_forensic_core::detect_browser(path)
            .or_else(|| infer_browser_from_filename(path))
            .unwrap_or(BrowserFamily::Chromium);
        gather_db_tamper_indicators(path, family, &mut indicators);
    }
    emit_tamper_findings(&indicators, path, format);
    Ok(())
}

/// Run every single-database tamper indicator over `path`, absorbing per-check
/// errors so one unreadable check never suppresses the others.
fn gather_db_tamper_indicators(
    path: &Path,
    family: BrowserFamily,
    out: &mut Vec<browser_forensic_integrity::IntegrityIndicator>,
) {
    if let Ok(mut i) = browser_forensic_integrity::check_page_state(path) {
        out.append(&mut i);
    }
    if let Ok(mut i) = browser_forensic_integrity::check_header_anomalies(path) {
        out.append(&mut i);
    }
    if let Ok(mut i) = browser_forensic_integrity::check_history_integrity(path, family) {
        out.append(&mut i);
    }
    if let Ok(mut i) = browser_forensic_integrity::check_database_integrity(path) {
        out.append(&mut i);
    }
    if let Ok(mut i) = browser_forensic_carve::detect_recovered_deleted_history(path) {
        out.append(&mut i);
    }
}

/// Known history databases per profile, by browser family.
const PROFILE_HISTORY_DBS: &[(&str, BrowserFamily)] = &[
    ("History", BrowserFamily::Chromium),
    ("places.sqlite", BrowserFamily::Firefox),
    ("History.db", BrowserFamily::Safari),
];

/// Run the single-database checks over each history DB in a profile directory,
/// then add the cross-artifact incognito-residue indicator.
fn gather_profile_tamper_indicators(
    dir: &Path,
    out: &mut Vec<browser_forensic_integrity::IntegrityIndicator>,
) {
    for (name, family) in PROFILE_HISTORY_DBS {
        let db = dir.join(name);
        if db.is_file() {
            gather_db_tamper_indicators(&db, family.clone(), out);
        }
    }

    // Incognito residue: domains named in network/state artifacts that survive a
    // clear, with no corresponding history entry.
    let residual: Vec<(String, String)> = browser_forensic_triage::collect_recovered_domains(dir)
        .iter()
        .filter_map(|e| {
            let domain = e.attrs.get("domain")?.as_str()?.to_string();
            let source = e
                .attrs
                .get("source_artifact")
                .and_then(|v| v.as_str())
                .unwrap_or("network/state residue")
                .to_string();
            Some((domain, source))
        })
        .collect();
    let history_domains = profile_history_domains(dir);
    out.extend(browser_forensic_integrity::check_incognito_residue(
        &residual,
        &history_domains,
    ));
}

/// Hosts that appear in the profile's browsing history, for the incognito
/// residue comparison. Best-effort across families.
fn profile_history_domains(dir: &Path) -> Vec<String> {
    let mut events = Vec::new();
    let chrome = dir.join("History");
    if chrome.is_file() {
        if let Ok(e) = browser_forensic_chrome::parse_history(&chrome) {
            events.extend(e);
        }
    }
    let ff = dir.join("places.sqlite");
    if ff.is_file() {
        if let Ok(e) = browser_forensic_firefox::parse_history(&ff) {
            events.extend(e);
        }
    }
    events
        .iter()
        .filter_map(|e| e.attrs.get("url").and_then(|v| v.as_str()))
        .filter_map(tamper_host_of)
        .collect()
}

/// Extract the host component of a URL, or `None` if it has no authority.
fn tamper_host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..end];
    // Drop any userinfo@ and :port so the bare host remains.
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

/// The serialized kind (enum variant name) of an indicator, taken from its JSON
/// object key so it stays in sync with the type automatically.
fn indicator_kind(ind: &browser_forensic_integrity::IntegrityIndicator) -> String {
    match serde_json::to_value(ind) {
        Ok(serde_json::Value::Object(map)) => map
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "Unknown".into()),
        Ok(serde_json::Value::String(s)) => s,
        _ => "Unknown".to_string(),
    }
}

/// Render tamper findings with their observation and innocent alternative.
fn emit_tamper_findings(
    indicators: &[browser_forensic_integrity::IntegrityIndicator],
    path: &Path,
    format: OutputFormat,
) {
    if indicators.is_empty() {
        match format {
            OutputFormat::Text => {
                println!("No tampering indicators detected in {}.", path.display());
            }
            OutputFormat::Jsonl => println!("{{\"status\":\"clean\"}}"),
            OutputFormat::Csv => {
                println!("kind,observation,innocent_alternative");
            }
        }
        return;
    }

    match format {
        OutputFormat::Text => {
            println!(
                "Found {} tampering indicator(s) in {} — each is consistent with \
                 clearing/tampering, NOT proof of it:",
                indicators.len(),
                path.display()
            );
            for (n, ind) in indicators.iter().enumerate() {
                println!("\n[{}] {}", n + 1, indicator_kind(ind));
                println!("    observation: {}", ind.observation());
                println!("    innocent alternative: {}", ind.innocent_alternative());
            }
        }
        OutputFormat::Jsonl => {
            for ind in indicators {
                let obj = json!({
                    "kind": indicator_kind(ind),
                    "observation": ind.observation(),
                    "innocent_alternative": ind.innocent_alternative(),
                    "data": ind,
                });
                if let Ok(line) = serde_json::to_string(&obj) {
                    println!("{line}");
                }
            }
        }
        OutputFormat::Csv => {
            println!("kind,observation,innocent_alternative");
            for ind in indicators {
                println!(
                    "{},{},{}",
                    csv_field(&indicator_kind(ind)),
                    csv_field(&ind.observation()),
                    csv_field(ind.innocent_alternative()),
                );
            }
        }
    }
}

/// CSV-escape a field: neutralize a spreadsheet formula trigger, quote, and
/// double any embedded quotes.
fn csv_field(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
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

/// `br4n6 cachestorage PATH` — recover Service Worker CacheStorage (Cache API)
/// responses. `PATH` is a `Service Worker/CacheStorage` tree or a single
/// `<origin-hash>` directory. Each recovered response becomes one event carrying
/// its cache-name + origin attribution, request method, and body length.
///
/// # Errors
/// Never fails on a malformed tree (best-effort recovery); returns `Ok` with the
/// events that were recovered.
pub fn run_cachestorage(path: &Path, format: OutputFormat) -> Result<()> {
    let resources = browser_forensic_cache::parse_cachestorage_dir(path);
    let mut events: Vec<BrowserEvent> = resources.iter().map(cachestorage_event).collect();
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// Map a recovered CacheStorage response to a normalized [`BrowserEvent`].
fn cachestorage_event(r: &browser_forensic_cache::CacheStorageResource) -> BrowserEvent {
    let ts = r.response_time_ns.or(r.entry_time_ns).unwrap_or(0);
    let mut ev = BrowserEvent::new(
        ts,
        browser_forensic_core::BrowserFamily::Chromium,
        browser_forensic_core::ArtifactKind::Cache,
        r.source_file.display().to_string(),
        r.url.clone(),
    )
    .with_attr("artifact_subtype", json!("cachestorage"))
    .with_attr("cache_name", json!(r.cache_name))
    .with_attr("cache_dir", json!(r.cache_dir))
    .with_attr("body_len", json!(r.body.len()))
    .with_attr("raw_body_len", json!(r.raw_body.len()));
    if let Some(sk) = &r.storage_key {
        ev = ev.with_attr("storage_key", json!(sk));
    }
    if let Some(m) = &r.request_method {
        ev = ev.with_attr("request_method", json!(m));
    }
    if let Some(s) = r.http_status {
        ev = ev.with_attr("http_status", json!(s));
    }
    if let Some(ct) = &r.content_type {
        ev = ev.with_attr("content_type", json!(ct));
    }
    if let Some(ce) = &r.content_encoding {
        ev = ev.with_attr("content_encoding", json!(ce));
    }
    if let Some(mt) = &r.mime_type {
        ev = ev.with_attr("mime_type", json!(mt));
    }
    if let Some(note) = &r.body_note {
        ev = ev.with_attr("body_note", json!(note));
    }
    ev
}

/// `br4n6 reconstruct PATH --out DIR [--url TARGET] [--format ...]` — rebuild
/// viewable pages from browser cache. `PATH` is a cache directory or a whole
/// profile; the reconstructed artifact is written to `--out`.
///
/// A cache reconstruction is a *consistent-with* artifact, not a rendered
/// capture: every output carries a provenance manifest enumerating which
/// sub-resources were found in cache and which were referenced but missing.
///
/// # Errors
/// Returns an error if the output cannot be written, or (html/warc with a
/// `--url`) if the target page is not present in the cache.
pub fn run_reconstruct(
    path: &Path,
    out: &Path,
    url: Option<&str>,
    format: ReconstructFormat,
) -> Result<()> {
    use browser_forensic_reconstruct::{reconstruct_to_dir, OutputFormat, ResourceIndex};

    let index = ResourceIndex::from_cache_dir(path);
    if index.is_empty() {
        anyhow::bail!(
            "no recoverable cached resources under {} (expected a Chromium Cache_Data, \
             Firefox cache2/entries, Safari Cache.db, or Service Worker/CacheStorage path, \
             or a profile directory containing one)",
            path.display()
        );
    }

    let out_format = match format {
        ReconstructFormat::Html => OutputFormat::Html,
        ReconstructFormat::Warc => OutputFormat::Warc,
        ReconstructFormat::Gallery => OutputFormat::Gallery,
    };

    // For html/warc a --url must actually be in the cache; fail loud otherwise.
    if let Some(target) = url {
        if matches!(out_format, OutputFormat::Html | OutputFormat::Warc)
            && index.get(target).is_none()
        {
            anyhow::bail!(
                "target page {target} is not present in the cache under {}",
                path.display()
            );
        }
    }

    let report = reconstruct_to_dir(&index, out, url, out_format)
        .with_context(|| format!("writing reconstruction to {}", out.display()))?;

    if report.files_written.is_empty() {
        anyhow::bail!(
            "nothing reconstructed from {} (no HTML pages found for html format?)",
            path.display()
        );
    }

    println!(
        "Reconstructed from cached resources (consistent-with, NOT a rendered capture; \
         JS/SPA/lazy-loaded/auth-gated content may be absent)."
    );
    match out_format {
        OutputFormat::Html => println!(
            "Wrote {} page(s): {} sub-resource(s) found in cache, {} referenced but MISSING.",
            report.pages, report.found, report.missing
        ),
        OutputFormat::Warc => println!("Wrote {} WARC response record(s).", report.responses),
        OutputFormat::Gallery => println!("Wrote a gallery of {} cached image(s).", report.images),
    }
    for f in &report.files_written {
        println!("  {}", f.display());
    }
    Ok(())
}

/// `br4n6 indexeddb PATH` — decode a Chromium IndexedDB LevelDB directory
/// directly: database/object-store names, keys, and Blink/V8 values.
///
/// # Errors
/// Returns an error if the directory cannot be opened or read as LevelDB.
pub fn run_indexeddb(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_storage::parse_indexeddb(path)
        .with_context(|| format!("decoding IndexedDB from {}", path.display()))?;
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

/// `br4n6 extension-cookies PATH` — parse a Chromium `Extension Cookies` jar
/// (the cookie store for extension background contexts). Same schema as
/// `Cookies`; every event is tagged `cookie_store=extension`. Values are never
/// decrypted. Chromium-only.
///
/// # Errors
/// Returns an error if the `Extension Cookies` database cannot be opened.
pub fn run_extension_cookies(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_chrome::parse_extension_cookies(path)
        .with_context(|| format!("parsing Extension Cookies from {}", path.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// Resolve a `places.sqlite` from `PATH`: the file itself, or a profile
/// directory containing it.
fn resolve_places(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join("places.sqlite")
    } else {
        path.to_path_buf()
    }
}

/// `br4n6 typed-input PATH` — list strings the user typed into the Firefox
/// address bar (`moz_inputhistory`). Firefox-only.
///
/// # Errors
/// Returns an error if `places.sqlite` cannot be opened or queried.
pub fn run_typed_input(path: &Path, format: OutputFormat) -> Result<()> {
    let places = resolve_places(path);
    let events = browser_forensic_firefox::parse_typed_input(&places)
        .with_context(|| format!("parsing typed input from {}", places.display()))?;
    print_events(&events, format);
    Ok(())
}

/// `br4n6 annotations PATH` — list Firefox page annotations (`moz_annos`).
/// Firefox-only; stated as recorded.
///
/// # Errors
/// Returns an error if `places.sqlite` cannot be opened or queried.
pub fn run_annotations(path: &Path, format: OutputFormat) -> Result<()> {
    let places = resolve_places(path);
    let mut events = browser_forensic_firefox::parse_annotations(&places)
        .with_context(|| format!("parsing annotations from {}", places.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 deleted-bookmarks PATH` — recover bookmarks present in a Firefox
/// `bookmarkbackups/*.jsonlz4` backup but absent from the current
/// `moz_bookmarks` (consistent with deletion after that backup). `PATH` is a
/// profile directory or its `places.sqlite`. Firefox-only.
///
/// # Errors
/// Returns an error if `places.sqlite` (the diff baseline) is missing or
/// unreadable.
pub fn run_deleted_bookmarks(path: &Path, format: OutputFormat) -> Result<()> {
    let profile_dir = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    };
    let events =
        browser_forensic_firefox::recover_deleted_bookmarks(&profile_dir).with_context(|| {
            format!(
                "recovering deleted bookmarks from {}",
                profile_dir.display()
            )
        })?;
    print_events(&events, format);
    Ok(())
}

/// `br4n6 media-history PATH` — parse a Chromium `Media History` database:
/// audio/video playback, watch time, resume positions, and media titles.
/// Chromium-only.
///
/// # Errors
/// Returns an error if the `Media History` database cannot be opened.
pub fn run_media_history(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_chrome::parse_media_history(path)
        .with_context(|| format!("parsing Media History from {}", path.display()))?;
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

/// The registrable host (eTLD+1) an event is attributed to, or `""` when none
/// can be derived from its URL/host fields.
fn event_host(e: &BrowserEvent) -> String {
    browser_forensic_correlate::host::primary_registrable_domain(e).unwrap_or_default()
}

/// A unified-timeline event as a human-readable line (tagged browser / artifact
/// / host).
fn correlate_row_text(e: &BrowserEvent) -> String {
    format!(
        "[{ts}] {browser}/{artifact} {host}  {desc}\n",
        ts = format_ts(e.timestamp_ns),
        browser = e.browser,
        artifact = e.artifact,
        host = event_host(e),
        desc = e.description,
    )
}

/// A unified-timeline event as one JSONL object (`record":"event"`).
fn correlate_row_json(e: &BrowserEvent) -> String {
    let obj = json!({
        "record": "event",
        "timestamp_ns": e.timestamp_ns,
        "timestamp": format_ts(e.timestamp_ns),
        "browser": e.browser.to_string(),
        "artifact": e.artifact.to_string(),
        "host": event_host(e),
        "source": e.source,
        "description": e.description,
        "url": attr_str(e, "url"),
    });
    serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string())
}

/// A unified-timeline event as one CSV row.
fn correlate_row_csv(e: &BrowserEvent) -> String {
    format!(
        "{},{},{},{},{},{},{}\n",
        csv_escape(&format_ts(e.timestamp_ns)),
        csv_escape(&e.browser.to_string()),
        csv_escape(&e.artifact.to_string()),
        csv_escape(&event_host(e)),
        csv_escape(&e.source),
        csv_escape(&e.description),
        csv_escape(&attr_str(e, "url")),
    )
}

/// Render the unified cross-artifact timeline and per-host rollup for
/// `br4n6 correlate`.
///
/// - `text`: a human timeline section (untimed rows grouped) followed by the
///   per-host rollup.
/// - `jsonl`: a leading `timeline_summary` record, one `event` record per
///   timeline row, then one `host` record per rollup.
/// - `csv`: the unified timeline rows only (one clean schema); use `jsonl`/`text`
///   for the rollup.
#[must_use]
pub fn correlate_output(events: &[BrowserEvent], format: OutputFormat) -> String {
    use browser_forensic_correlate::rollup::host_rollups;
    use browser_forensic_correlate::timeline::unified_timeline;

    let tl = unified_timeline(events);
    let rollups = host_rollups(events);
    let mut out = String::new();
    match format {
        OutputFormat::Text => {
            out.push_str(&format!(
                "== Unified cross-artifact timeline ({total} event(s): {timed} timed, \
                 {untimed} untimed, {dups} duplicate(s) removed) ==\n",
                total = tl.len(),
                timed = tl.timed.len(),
                untimed = tl.untimed.len(),
                dups = tl.duplicates_removed,
            ));
            for e in &tl.timed {
                out.push_str(&correlate_row_text(e));
            }
            if !tl.untimed.is_empty() {
                out.push_str(&format!("-- untimed ({}) --\n", tl.untimed.len()));
                for e in &tl.untimed {
                    out.push_str(&correlate_row_text(e));
                }
            }
            out.push_str(&format!(
                "\n== Per-host rollup ({} host(s)) ==\n",
                rollups.len()
            ));
            for r in &rollups {
                let kinds = r
                    .counts
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let browsers = r.browsers.iter().cloned().collect::<Vec<_>>().join(", ");
                let span = match (r.first_seen_ns, r.last_seen_ns) {
                    (Some(f), Some(l)) => format!("{}..{}", format_ts(f), format_ts(l)),
                    _ => "(untimed)".to_string(),
                };
                out.push_str(&format!(
                    "  {host}  total={total}  {span}  [{browsers}]  {kinds}\n",
                    host = r.host,
                    total = r.total,
                ));
            }
        }
        OutputFormat::Jsonl => {
            let summary = json!({
                "record": "timeline_summary",
                "total": tl.len(),
                "timed": tl.timed.len(),
                "untimed": tl.untimed.len(),
                "duplicates_removed": tl.duplicates_removed,
            });
            out.push_str(&format!(
                "{}\n",
                serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string())
            ));
            for e in tl.timed.iter().chain(tl.untimed.iter()) {
                out.push_str(&correlate_row_json(e));
                out.push('\n');
            }
            for r in &rollups {
                let mut v = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
                if let Some(map) = v.as_object_mut() {
                    map.insert("record".to_string(), json!("host"));
                }
                out.push_str(&serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string()));
                out.push('\n');
            }
        }
        OutputFormat::Csv => {
            out.push_str("timestamp,browser,artifact,host,source,description,url\n");
            for e in tl.timed.iter().chain(tl.untimed.iter()) {
                out.push_str(&correlate_row_csv(e));
            }
        }
    }
    out
}

/// Render the entity graph for `br4n6 graph` in the requested format.
#[must_use]
pub fn graph_output(events: &[BrowserEvent], format: GraphFormat, window_secs: i64) -> String {
    use browser_forensic_correlate::graph::{entity_graph, GraphConfig};

    let cfg = GraphConfig {
        cooccurrence_window_secs: window_secs,
        ..GraphConfig::default()
    };
    let g = entity_graph(events, cfg);
    match format {
        GraphFormat::Json => browser_forensic_correlate::render::to_json(&g),
        GraphFormat::Dot => browser_forensic_correlate::render::to_dot(&g),
    }
}

/// `br4n6 correlate PATH` — unified cross-artifact timeline + per-host rollup.
///
/// # Errors
/// Returns an error if the path does not exist or event collection fails.
pub fn run_correlate(path: &Path, format: OutputFormat) -> Result<()> {
    let events = collect_correlation_events(path)?;
    print!("{}", correlate_output(&events, format));
    Ok(())
}

/// `br4n6 graph PATH` — entity graph (hosts + referrer/redirect/co-occurrence
/// edges) as JSON or Graphviz DOT, written to `out` or stdout.
///
/// # Errors
/// Returns an error if the path does not exist, event collection fails, or the
/// output file cannot be written.
pub fn run_graph(
    path: &Path,
    format: GraphFormat,
    out: Option<&Path>,
    window_secs: i64,
) -> Result<()> {
    let events = collect_correlation_events(path)?;
    let rendered = graph_output(&events, format, window_secs);
    match out {
        Some(p) => {
            std::fs::write(p, &rendered)
                .with_context(|| format!("writing entity graph to {}", p.display()))?;
            eprintln!("wrote entity graph to {}", p.display());
        }
        None => print!("{rendered}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};

    fn corr_event(ts: i64, browser: BrowserFamily, kind: ArtifactKind, url: &str) -> BrowserEvent {
        BrowserEvent::new(ts, browser, kind, "/src", "desc").with_attr("url", json!(url))
    }

    #[test]
    fn correlate_output_text_has_timeline_and_rollup() {
        let events = vec![
            corr_event(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://www.example.com/a",
            ),
            corr_event(
                2000,
                BrowserFamily::Firefox,
                ArtifactKind::Cookies,
                "https://example.com/b",
            ),
        ];
        let out = correlate_output(&events, OutputFormat::Text);
        assert!(out.contains("Unified cross-artifact timeline"));
        assert!(out.contains("Per-host rollup"));
        assert!(out.contains("example.com"));
        assert!(out.contains("total=2"));
    }

    #[test]
    fn correlate_output_jsonl_typed_records() {
        let events = vec![corr_event(
            1000,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "https://www.example.com/a",
        )];
        let out = correlate_output(&events, OutputFormat::Jsonl);
        let mut kinds = std::collections::HashSet::new();
        for line in out.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            kinds.insert(v["record"].as_str().unwrap().to_string());
        }
        assert!(kinds.contains("timeline_summary"));
        assert!(kinds.contains("event"));
        assert!(kinds.contains("host"));
    }

    #[test]
    fn correlate_output_csv_has_host_column() {
        let events = vec![corr_event(
            1000,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "https://www.example.com/a",
        )];
        let out = correlate_output(&events, OutputFormat::Csv);
        assert!(out.starts_with("timestamp,browser,artifact,host,source,description,url\n"));
        assert!(out.contains(",example.com,"));
    }

    #[test]
    fn graph_output_json_and_dot() {
        let events = vec![
            corr_event(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://a.example/",
            )
            .with_attr("visit_id", json!(1))
            .with_attr("from_visit", json!(0)),
            corr_event(
                2000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "https://b.example/",
            )
            .with_attr("visit_id", json!(2))
            .with_attr("from_visit", json!(1)),
        ];
        let js = graph_output(&events, GraphFormat::Json, 30);
        let v: serde_json::Value = serde_json::from_str(&js).unwrap();
        assert!(v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == "a.example"));
        assert!(js.contains("referrer"));

        let dot = graph_output(&events, GraphFormat::Dot, 30);
        assert!(dot.starts_with("digraph browser_entity_graph {"));
        assert!(dot.contains("\"a.example\" -> \"b.example\""));
    }

    #[test]
    fn correlation_collection_enriches_referrer_edges_from_firefox_visits() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("places.sqlite");
        let conn = rusqlite::Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
             CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, \
               place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER);
             INSERT INTO moz_places VALUES (1,'https://a.example/','A'),(2,'https://b.example/','B');
             INSERT INTO moz_historyvisits VALUES \
               (1,0,1,1648000000000000,1,0),(2,1,2,1648000000001000,1,0);",
        )
        .unwrap();
        drop(conn);

        let events = collect_correlation_events(dir.path()).unwrap();
        // Per-visit enrichment brings the from_visit linkage the collapsed view drops.
        assert!(events.iter().any(|e| e.attrs.contains_key("from_visit")));

        let js = graph_output(&events, GraphFormat::Json, 30);
        let v: serde_json::Value = serde_json::from_str(&js).unwrap();
        let has_ref =
            v["edges"].as_array().unwrap().iter().any(|e| {
                e["kind"] == "referrer" && e["from"] == "a.example" && e["to"] == "b.example"
            });
        assert!(has_ref, "expected M3 referrer edge a.example -> b.example");
    }

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
    fn run_extension_cookies_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Extension Cookies");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value TEXT DEFAULT '', path TEXT NOT NULL, expires_utc INTEGER DEFAULT 0, is_secure INTEGER DEFAULT 0, is_httponly INTEGER DEFAULT 0, samesite INTEGER DEFAULT -1, encrypted_value BLOB DEFAULT '');
             INSERT INTO cookies (creation_utc, host_key, name, path) VALUES (13327626000000000, '.ext.example', 'auth', '/');",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_extension_cookies(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_media_history_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Media History");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE playback(id INTEGER PRIMARY KEY, origin_id INTEGER, url TEXT, watch_time_s INTEGER, has_video INTEGER, has_audio INTEGER, last_updated_time_s INTEGER);
             INSERT INTO playback (url, watch_time_s, has_video, has_audio, last_updated_time_s) VALUES ('https://v.example/', 42, 1, 1, 13344473600);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_media_history(&p, fmt).unwrap();
        }
    }

    /// Build a real IndexedDB LevelDB dir: database "testdb", store "records",
    /// one data record keyed String "k1" whose value is the real captured
    /// Reddit blob decoding to the string "false".
    fn build_idb_leveldb_dir() -> tempfile::TempDir {
        fn hx(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        fn u16be_lp(s: &str) -> Vec<u8> {
            let units: Vec<u16> = s.encode_utf16().collect();
            let mut out = vec![u8::try_from(units.len()).unwrap()];
            for u in units {
                out.extend_from_slice(&u.to_be_bytes());
            }
            out
        }
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("https_example.com_0.indexeddb.leveldb");
        let mut db_name_key = hx("00000000c9");
        db_name_key.extend_from_slice(&u16be_lp("https_example.com_0@1"));
        db_name_key.extend_from_slice(&u16be_lp("testdb"));
        let store_key = hx("00010000320100");
        let store_val: Vec<u8> = "records"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        let mut data_key = hx("00010101");
        data_key.extend_from_slice(&[0x01, 0x02]);
        data_key.extend_from_slice(
            &"k1"
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<u8>>(),
        );
        let data_val = hx("03ff15fe000000000000000000000000ff0f220566616c7365");
        let opt = rusty_leveldb::Options {
            create_if_missing: true,
            ..Default::default()
        };
        let mut db = rusty_leveldb::DB::open(&db_path, opt).unwrap();
        db.put(&db_name_key, &[0x01]).unwrap();
        db.put(&store_key, &store_val).unwrap();
        db.put(&data_key, &data_val).unwrap();
        db.flush().unwrap();
        db.close().unwrap();
        dir
    }

    #[test]
    fn run_indexeddb_decodes_all_formats() {
        let dir = build_idb_leveldb_dir();
        let p = dir.path().join("https_example.com_0.indexeddb.leveldb");
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_indexeddb(&p, fmt).unwrap();
        }
    }

    #[test]
    fn run_indexeddb_nonexistent_errors() {
        assert!(run_indexeddb(Path::new("/nonexistent/idb.leveldb"), OutputFormat::Text).is_err());
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
    fn run_tamper_check_all_formats_clean_and_dirty() {
        let dir = tempfile::tempdir().unwrap();

        let clean = dir.path().join("clean.db");
        let conn = Connection::open(&clean).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_tamper_check(&clean, fmt).unwrap();
        }

        let dirty = dir.path().join("dirty.db");
        let conn = Connection::open(&dirty).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);
             INSERT INTO visits VALUES (50, 1, 13300000001000000, 0, 0);",
        )
        .unwrap();
        drop(conn);
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_tamper_check(&dirty, fmt).unwrap();
        }

        // A profile directory path exercises the directory arm + incognito residue.
        run_tamper_check(dir.path(), OutputFormat::Text).unwrap();
    }

    #[test]
    fn csv_field_guards_formula_and_quotes() {
        assert_eq!(csv_field("=SUM(A1)"), "\"'=SUM(A1)\"");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn tamper_host_of_extracts_bare_host() {
        assert_eq!(
            tamper_host_of("https://user@sub.example.com:443/path?q=1"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(tamper_host_of("not a url"), None);
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
    fn carved_event_tags_recovery_provenance() {
        use browser_forensic_cache::{
            CachedResource, RecoveredResource, RecoveryMechanism, RecoveryQuality,
        };
        let resource = CachedResource {
            url: "https://orphan.example/gone".to_string(),
            http_status: Some(200),
            status_line: Some("HTTP/1.1 200 OK".to_string()),
            headers: vec![("Content-Type".to_string(), "text/html".to_string())],
            content_type: Some("text/html".to_string()),
            content_encoding: None,
            request_time_ns: Some(1_600_000_000_000_000_000),
            response_time_ns: Some(1_600_000_000_000_000_100),
            raw_body: b"orphan-body".to_vec(),
            decoded_body: b"orphan-body".to_vec(),
            body_decoded: true,
            decode_note: None,
            source_file: std::path::PathBuf::from("/Cache/Cache_Data/bbbb2222_0"),
            sparse_file: None,
        };
        let rr = RecoveredResource {
            resource,
            mechanism: RecoveryMechanism::OrphanedSimpleEntry,
            quality: RecoveryQuality::Full,
            note: "consistent with the resource having been cached and then evicted".to_string(),
        };
        let ev = cache_carve_event(&rr);
        assert_eq!(ev.artifact, ArtifactKind::Cache);
        assert_eq!(ev.description, "https://orphan.example/gone");
        // response_time wins over request_time for the event timestamp.
        assert_eq!(ev.timestamp_ns, 1_600_000_000_000_000_100);
        // The load-bearing recovery/provenance tags.
        assert_eq!(
            ev.attrs.get("artifact_subtype").unwrap(),
            &json!("cache_carve")
        );
        assert_eq!(ev.attrs.get("recovered").unwrap(), &json!(true));
        assert_eq!(
            ev.attrs.get("recovery_mechanism").unwrap(),
            &json!("orphaned_simple_entry")
        );
        assert_eq!(ev.attrs.get("recovery_quality").unwrap(), &json!("full"));
        assert_eq!(
            ev.attrs.get("recovery_note").unwrap(),
            &json!("consistent with the resource having been cached and then evicted")
        );
        assert_eq!(ev.attrs.get("http_status").unwrap(), &json!(200));
        assert_eq!(ev.attrs.get("content_type").unwrap(), &json!("text/html"));
    }

    #[test]
    fn carved_event_partial_quality_tag() {
        use browser_forensic_cache::{
            CachedResource, RecoveredResource, RecoveryMechanism, RecoveryQuality,
        };
        let resource = CachedResource {
            url: String::new(),
            http_status: None,
            status_line: None,
            headers: Vec::new(),
            content_type: None,
            content_encoding: None,
            request_time_ns: None,
            response_time_ns: None,
            raw_body: Vec::new(),
            decoded_body: Vec::new(),
            body_decoded: false,
            decode_note: None,
            source_file: std::path::PathBuf::from("/Cache/dddd4444_s"),
            sparse_file: None,
        };
        let rr = RecoveredResource {
            resource,
            mechanism: RecoveryMechanism::DanglingSparseFile,
            quality: RecoveryQuality::Partial,
            note: "dangling sparse body".to_string(),
        };
        let ev = cache_carve_event(&rr);
        assert_eq!(ev.timestamp_ns, 0);
        assert_eq!(ev.attrs.get("recovered").unwrap(), &json!(true));
        assert_eq!(
            ev.attrs.get("recovery_mechanism").unwrap(),
            &json!("dangling_sparse_file")
        );
        assert_eq!(ev.attrs.get("recovery_quality").unwrap(), &json!("partial"));
    }

    #[test]
    fn run_cache_carve_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        // A `[hash]_s` sparse body with no companion `_0` is a dangling fragment;
        // with a `the-real-index` present it is claimed recovered.
        let hash: u64 = 0x0000_0000_dddd_4444;
        std::fs::write(dir.path().join(format!("{hash:016x}_s")), b"sparse ranges").unwrap();
        // Build an empty `the-real-index` pickle (no live hashes).
        let mut payload = Vec::new();
        payload.extend_from_slice(&browser_forensic_cache::carve::INDEX_MAGIC.to_le_bytes());
        payload.extend_from_slice(&9u32.to_le_bytes()); // version
        payload.extend_from_slice(&0u64.to_le_bytes()); // entry_count
        payload.extend_from_slice(&0u64.to_le_bytes()); // cache_size
        payload.extend_from_slice(&0u32.to_le_bytes()); // reason
        payload.extend_from_slice(&0i64.to_le_bytes()); // cache_modified
        let mut idx = Vec::new();
        idx.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_le_bytes());
        idx.extend_from_slice(&0u32.to_le_bytes()); // crc (not enforced)
        idx.extend_from_slice(&payload);
        let idx_dir = dir.path().join("index-dir");
        std::fs::create_dir_all(&idx_dir).unwrap();
        std::fs::write(idx_dir.join("the-real-index"), &idx).unwrap();

        assert!(
            !browser_forensic_cache::carve_cache_dir(dir.path()).is_empty(),
            "the dangling sparse fragment should be recovered"
        );
        for fmt in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
            run_cache_carve(dir.path(), fmt).unwrap();
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

    // ---- Windows Chromium DPAPI + AES-256-GCM (Milestone 2b) ----
    //
    // Vectors from the decrypt crate's impacket-confirmed / NIST fixture. The
    // recovered Local-State key equals the GCM key (both are bytes 0x00..0x1f),
    // so the recovered key decrypts the v10 value end-to-end.
    const WIN_VECTORS: &str =
        include_str!("../../browser-forensic-decrypt/tests/data/win_dpapi_vectors.json");

    fn win_vec() -> serde_json::Value {
        serde_json::from_str(WIN_VECTORS).unwrap()
    }

    fn win_unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn write_win_profile(dir: &Path, v10_blob: &[u8]) -> (PathBuf, PathBuf) {
        let v = win_vec();
        let local_state = dir.join("Local State");
        std::fs::write(&local_state, v["LOCAL_STATE_JSON"].as_str().unwrap()).unwrap();
        let cookies = dir.join("Cookies");
        let conn = rusqlite::Connection::open(&cookies).unwrap();
        conn.execute_batch(
            "CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, \
             name TEXT NOT NULL, path TEXT NOT NULL, encrypted_value BLOB DEFAULT '');",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cookies (creation_utc, host_key, name, path, encrypted_value) \
             VALUES (13327626000000000, '.example.com', 'session', '/', ?1)",
            rusqlite::params![v10_blob],
        )
        .unwrap();
        drop(conn);
        (local_state, cookies)
    }

    #[test]
    fn resolve_dpapi_key_via_masterkey_hex_recovers_known_key() {
        let v = win_vec();
        let dir = tempfile::tempdir().unwrap();
        let (local_state, _cookies) = write_win_profile(dir.path(), &[]);
        let key = resolve_dpapi_key(
            &local_state,
            Some(v["MASTERKEY64_HEX"].as_str().unwrap()),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            key.to_vec(),
            win_unhex(v["CHROMIUM_KEY_HEX"].as_str().unwrap())
        );
    }

    #[test]
    fn resolve_dpapi_key_via_password_recovers_known_key() {
        let v = win_vec();
        let dir = tempfile::tempdir().unwrap();
        let (local_state, _cookies) = write_win_profile(dir.path(), &[]);
        let mkf_path = dir.path().join("masterkey");
        std::fs::write(
            &mkf_path,
            win_unhex(v["MASTERKEY_FILE_HEX"].as_str().unwrap()),
        )
        .unwrap();
        let key = resolve_dpapi_key(
            &local_state,
            None,
            Some(v["PASSWORD"].as_str().unwrap()),
            Some(v["SID"].as_str().unwrap()),
            Some(&mkf_path),
        )
        .unwrap();
        assert_eq!(
            key.to_vec(),
            win_unhex(v["CHROMIUM_KEY_HEX"].as_str().unwrap())
        );
    }

    #[test]
    fn resolve_dpapi_key_requires_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let (local_state, _cookies) = write_win_profile(dir.path(), &[]);
        assert!(resolve_dpapi_key(&local_state, None, None, None, None).is_err());
    }

    #[test]
    fn resolve_dpapi_key_rejects_bad_masterkey_hex() {
        let dir = tempfile::tempdir().unwrap();
        let (local_state, _cookies) = write_win_profile(dir.path(), &[]);
        assert!(resolve_dpapi_key(&local_state, Some("abcd"), None, None, None).is_err());
    }

    #[test]
    fn decrypt_chromium_cookies_win_recovers_plaintext_end_to_end() {
        let v = win_vec();
        let dir = tempfile::tempdir().unwrap();
        let v10 = win_unhex(v["V10_BLOB_HEX"].as_str().unwrap());
        let (local_state, cookies) = write_win_profile(dir.path(), &v10);
        let key = resolve_dpapi_key(
            &local_state,
            Some(v["MASTERKEY64_HEX"].as_str().unwrap()),
            None,
            None,
            None,
        )
        .unwrap();
        let events = decrypt_chromium_cookies_win(&cookies, &key).unwrap();
        assert_eq!(events.len(), 1);
        let value = events[0].attrs.get("value").unwrap().as_str().unwrap();
        assert_eq!(value, v["GCM_PLAINTEXT"].as_str().unwrap());
        // This synthetic value is short and unprefixed, so it is not domain-bound
        // and passes through intact — domain_bound is surfaced as false, not absent.
        assert!(!events[0]
            .attrs
            .get("domain_bound")
            .unwrap()
            .as_bool()
            .unwrap());
    }

    // Real Python AES-128-CBC oracle blob: `v10 || CBC(derive_chromium_macos_key(
    // b"peanuts"), iv=0x20*16, PKCS7)(SHA-256("127.0.0.1") || "br4n6-tier1-probe-
    // 7f3a91c2")`. Mirrors the captured tier-1 macOS vector's plaintext layout.
    const MACOS_V10_PREFIXED_BLOB_HEX: &str = "7631304a665eab81174e4df04f8c7690449f880e573b2732cc6610638b02e07a23fabf95f24a166009f82bea81086c05826bf47988be2c28243ae11cfcfa84db0976e8";

    #[test]
    fn decrypt_chromium_cookies_macos_strips_domain_hash_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let cookies = dir.path().join("Cookies");
        let conn = rusqlite::Connection::open(&cookies).unwrap();
        conn.execute_batch(
            "CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, \
             name TEXT NOT NULL, path TEXT NOT NULL, encrypted_value BLOB DEFAULT '');",
        )
        .unwrap();
        let blob = win_unhex(MACOS_V10_PREFIXED_BLOB_HEX);
        conn.execute(
            "INSERT INTO cookies (creation_utc, host_key, name, path, encrypted_value) \
             VALUES (13327626000000000, '127.0.0.1', 'br4n6probe', '/', ?1)",
            rusqlite::params![blob],
        )
        .unwrap();
        drop(conn);
        let key = browser_forensic_decrypt::derive_chromium_macos_key(b"peanuts");
        let events = decrypt_chromium_cookies(&cookies, &key).unwrap();
        assert_eq!(events.len(), 1);
        // The 32-byte SHA-256("127.0.0.1") prefix is stripped, leaving the exact
        // planted value, and the binding is flagged verified.
        let value = events[0].attrs.get("value").unwrap().as_str().unwrap();
        assert_eq!(value, "br4n6-tier1-probe-7f3a91c2");
        assert!(events[0]
            .attrs
            .get("domain_bound")
            .unwrap()
            .as_bool()
            .unwrap());
    }
}
