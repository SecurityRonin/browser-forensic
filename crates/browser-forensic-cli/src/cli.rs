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

use crate::find::{FindHit, FIND_HEADERS};
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

/// The outcome of the pre-parse bare-path guard (RFC 0001 D3).
#[derive(Debug, Clone, PartialEq, Eq)]
enum BarePath {
    /// The single token is both a command name and an existing path — refuse
    /// with a diagnostic rather than silently pick one.
    Ambiguous(String),
    /// A bare existing path that is not a command — run `investigate` over it.
    Investigate(PathBuf),
    /// Not a bare-path invocation — let clap parse normally.
    Fallthrough,
}

/// Every br4n6 subcommand name + alias, derived from the clap command tree so it
/// never drifts from the actual surface (no hand-maintained list to fall stale).
fn command_names() -> Vec<String> {
    use clap::CommandFactory as _;
    Cli::command()
        .get_subcommands()
        .flat_map(|c| {
            std::iter::once(c.get_name().to_string())
                .chain(c.get_all_aliases().map(ToString::to_string))
        })
        .collect()
}

/// Classify a raw argument vector (program name already stripped) for the
/// bare-path guard. Only a *single-token* invocation is a candidate: `<TOKEN>`
/// (no leading `-`), or `-- <TOKEN>` which forces path interpretation for an
/// awkward (e.g. dash-leading) name. Everything else falls through to clap.
fn classify_bare_path(args: &[String]) -> BarePath {
    // `-- <TOKEN>`: the examiner explicitly marks the token as a path, so the
    // command-name check is bypassed (existence is validated by `investigate`).
    if args.len() == 2 && args[0] == "--" {
        return BarePath::Investigate(PathBuf::from(&args[1]));
    }
    // A lone non-flag token: could be a bare path, a command, or both.
    if args.len() == 1 && !args[0].starts_with('-') {
        let token = &args[0];
        let is_command = command_names().iter().any(|c| c == token);
        let exists = Path::new(token).exists();
        return match (is_command, exists) {
            (true, true) => BarePath::Ambiguous(token.clone()),
            (false, true) => BarePath::Investigate(PathBuf::from(token)),
            // A command with no matching path (`br4n6 schema`) or a nonexistent
            // non-command token — both are clap's job (run it, or error).
            (_, false) => BarePath::Fallthrough,
        };
    }
    BarePath::Fallthrough
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
    /// Investigate a profile / evidence path: drive the bounded triage pipeline
    /// and emit a ranked, court-safe summary (RFC 0001 P3a). On a TTY the summary
    /// is the human render; piped, it is JSONL of the findings. Tiering controls
    /// how much recovery runs, and the summary always ends with what the chosen
    /// tier did NOT do (so "false reassurance" is impossible).
    Investigate {
        /// A browser profile directory, or a home/evidence directory to scan.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Live artifacts + cheap integrity only (skips deleted-record recovery).
        #[arg(long, group = "tier")]
        quick: bool,
        /// Quick + bounded deleted-SQLite/WAL recovery. The default tier.
        #[arg(long, group = "tier")]
        standard: bool,
        /// Standard + whole-image carving, cache, memory — NOT yet wired (TODO P3b/P5).
        #[arg(long, group = "tier")]
        deep: bool,
        /// Output format. Defaults to a human summary on a TTY, JSONL when piped.
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        /// Write/read a resumable checkpoint at this path so a killed or crashed
        /// run resumes from the last completed profile (RFC 0001 P3b). Off by
        /// default — a read-only tool never writes into evidence unasked.
        #[arg(long, value_name = "PATH")]
        checkpoint: Option<PathBuf>,
        /// Ignore any existing checkpoint and start a clean run (alias: --no-resume).
        #[arg(long, visible_alias = "no-resume")]
        restart: bool,
        /// Override the layered auto-detection (RFC 0001 D8): force the input's
        /// artifact kind instead of detecting it. Use on carved / stomped data
        /// the detector guesses wrong; the override is recorded in the manifest.
        #[arg(long = "type", value_enum, value_name = "KIND")]
        forced_type: Option<crate::detect::DetectionKind>,
        /// Also write a chain-of-custody manifest here, recording the detection
        /// basis + confidence for every input (RFC 0001 D8/D11).
        #[arg(long, value_name = "PATH")]
        manifest: Option<PathBuf>,
        /// Scope to one user (SID or name); a non-match errors, naming what was
        /// found. Every finding is stamped with its origin (RFC 0001 D9).
        #[arg(long, value_name = "SID|NAME")]
        user: Option<String>,
        /// Scope to one profile, e.g. `Chrome/Default` (RFC 0001 D9).
        #[arg(long, value_name = "BROWSER/NAME")]
        profile: Option<String>,
        /// Scope to one browser family, e.g. `chrome` (RFC 0001 D9).
        #[arg(long, value_name = "BROWSER")]
        browser: Option<String>,
    },
    /// Find a term across ALL sources — "did they visit / download / search X?"
    /// (RFC 0001 P4). TERM is auto-classified by shape (domain / url / ipv4 /
    /// ipv6 / md5|sha1|sha256 hash) or given explicitly with `--regex` /
    /// `--term` / `--terms-file`; `@file` reads a term list. Each hit is a
    /// provenance-tagged row — a live history visit, a recovered domain, and a
    /// carved deleted record are DISTINCT rows (source · state · confidence ·
    /// time-basis · user-action · match), never collapsed. TTY renders a
    /// markdown-clean table; a pipe emits JSONL carrying every axis.
    Find {
        /// The term to search for (auto-classified). Omit when using `--regex` /
        /// `--term` / `--terms-file`. Prefix with `@` to read a term-list file.
        #[arg(value_name = "TERM")]
        term: Option<String>,
        /// A profile directory or home/evidence directory to search.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        /// Treat the pattern as a linear-time regex (no shape classification).
        #[arg(long, value_name = "PAT")]
        regex: Option<String>,
        /// Treat the value as a literal term — disambiguates a `-`-leading or
        /// otherwise ambiguous term (accepts a leading `-`).
        #[arg(long = "term", value_name = "LITERAL", allow_hyphen_values = true)]
        literal: Option<String>,
        /// Read one term per line from this file (`#` comments allowed).
        #[arg(long, value_name = "FILE")]
        terms_file: Option<PathBuf>,
        /// Enumerate ALL candidate entities/IOCs (emails, IPs, crypto-address and
        /// card candidates, search terms) with no query. Takes no TERM; composes
        /// with `--from`/`--to`/`--source`.
        #[arg(long)]
        iocs: bool,
        /// Inclusive lower time bound (RFC3339, `YYYY-MM-DD`, or Unix nanos).
        #[arg(long, value_name = "TS")]
        from: Option<String>,
        /// Inclusive upper time bound (RFC3339, `YYYY-MM-DD`, or Unix nanos).
        #[arg(long, value_name = "TS")]
        to: Option<String>,
        /// Restrict to these evidence sources (repeatable; default: all).
        #[arg(long = "source", value_enum, value_name = "KIND")]
        sources: Vec<SourceKind>,
        /// Output format. Auto-detected when omitted: a TTY gets the provenance
        /// table, a pipe gets JSONL (announced once on stderr).
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        /// Scope to one user (SID or name) — RFC 0001 D9. A non-match errors,
        /// naming what was found.
        #[arg(long, value_name = "SID|NAME")]
        user: Option<String>,
        /// Scope to one profile, e.g. `Chrome/Default` (RFC 0001 D9).
        #[arg(long, value_name = "BROWSER/NAME")]
        profile: Option<String>,
        /// Scope to one browser family, e.g. `chrome` (RFC 0001 D9).
        #[arg(long, value_name = "BROWSER")]
        browser: Option<String>,
    },
    /// Recover deleted / carved / evicted evidence — ONE orchestrator runs ALL
    /// applicable recovery over PATH and ranks the results; the examiner chooses
    /// no submode (RFC 0001 resolved-decision #2). What runs is auto-selected
    /// from the shape of PATH:
    ///
    /// * a profile / home DIRECTORY → deleted SQLite/WAL records, orphaned/
    ///   evicted cache, recovered domains (Network Persistent State / Reporting
    ///   and NEL / DIPS / HSTS), deleted bookmarks, and tamper / anti-forensic
    ///   indicators;
    /// * a single SQLite DATABASE → deleted-record carving + tamper indicators;
    /// * a MEMORY image → process-attributed RAM carve.
    ///
    /// Every recovered item is a *consistent-with* eviction/clearing artifact
    /// (state deleted/carved/recovered), never asserted as a deliberate user
    /// deletion. For a single TARGETED run an expert can still go narrow via the
    /// specialist commands (`br4n6 integrity`, `br4n6 image`) and the `br4n6
    /// artifact <NAME>` primitives (e.g. `artifact deleted-bookmarks`).
    Recover {
        /// A profile / home directory, a single SQLite database, or a memory
        /// image. What recovery runs is auto-selected from this path's shape.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Volatility-3 ISF symbol file for a memory image (offline symbols);
        /// otherwise the image is auto-profiled. Ignored for on-disk evidence.
        #[arg(long, value_name = "ISF")]
        symbols: Option<PathBuf>,
        /// Output format. Defaults to a human summary on a TTY, JSONL when piped.
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        /// Scope a directory recovery to one user (SID or name) — RFC 0001 D9.
        #[arg(long, value_name = "SID|NAME")]
        user: Option<String>,
        /// Scope a directory recovery to one profile, e.g. `Chrome/Default` (D9).
        #[arg(long, value_name = "BROWSER/NAME")]
        profile: Option<String>,
        /// Scope a directory recovery to one browser family, e.g. `chrome` (D9).
        #[arg(long, value_name = "BROWSER")]
        browser: Option<String>,
    },
    /// Parse a single browser artifact by name — the power / discovery layer.
    /// `br4n6 artifact --list` tabulates every primitive; `br4n6 artifact <NAME>
    /// <PATH>` runs one, each keeping its own flags (e.g. cookie decryption).
    Artifact {
        /// List every artifact primitive (name, browser family, what it records)
        /// and exit.
        #[arg(long)]
        list: bool,
        #[command(subcommand)]
        kind: Option<ArtifactKind>,
    },
    /// Launch the interactive terminal viewer (session state).
    Tui {
        /// A `Sessions` directory to view (defaults to the local profile).
        #[arg(value_name = "SESSIONS_DIR")]
        path: Option<PathBuf>,
    },
    /// Unified cross-artifact chronology for a profile/home (RFC 0001 P5a): the
    /// timed sequence of events across every browser artifact, with a per-host
    /// rollup. `PATH` is a profile directory, a home/evidence directory, or a
    /// single history file. `--around <WHEN> --window <DUR>` pivots on a moment;
    /// `--tz <IANA>` renders timestamps in a zone. This verb absorbs the former
    /// standalone `correlate` (default view), `chains` (`--chains`: referrer /
    /// redirect / inferred-session reconstruction), and `graph` (`--graph
    /// <json|dot>`: the registrable-host entity graph) commands. Correlation is
    /// co-occurrence by URL/host/time — never proof of intent or causation.
    Timeline {
        /// A profile directory, a home/evidence directory, or a history file.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Pivot the chronology on this moment (RFC3339, `YYYY-MM-DD`, or Unix
        /// nanos); only events within `--window` on either side are shown.
        #[arg(long, value_name = "WHEN")]
        around: Option<String>,
        /// Half-width of the `--around` window: an integer with a `s`/`m`/`h`/`d`
        /// suffix (bare number = seconds). Ignored without `--around`.
        #[arg(long, value_name = "DUR", default_value = "1h")]
        window: String,
        /// Render timestamps in this IANA timezone (e.g. `America/New_York`).
        #[arg(long = "tz", visible_alias = "timezone", value_name = "IANA")]
        tz: Option<String>,
        /// Reconstruction view: referrer + redirect chains and inferred sessions
        /// (the former `chains` command) instead of the unified chronology.
        #[arg(long, group = "mode")]
        chains: bool,
        /// Idle-gap threshold (minutes) for inferring session boundaries in the
        /// `--chains` view.
        #[arg(long, value_name = "MINUTES", default_value_t = DEFAULT_IDLE_GAP_MINUTES)]
        idle_gap: i64,
        /// Entity-graph view: registrable-host nodes with referrer/redirect and
        /// co-occurrence edges (the former `graph` command), as `json` or `dot`.
        #[arg(long, group = "mode", value_name = "FMT", num_args = 0..=1, default_missing_value = "json")]
        graph: Option<GraphFormat>,
        /// Co-occurrence window (seconds) for `--graph` edges (<= 0 disables them).
        #[arg(long, value_name = "SECONDS", default_value_t = browser_forensic_correlate::graph::DEFAULT_COOCCURRENCE_WINDOW_SECS)]
        graph_window: i64,
        /// Output format. Defaults to a human render on a TTY, JSONL when piped.
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        /// Scope to one user (SID or name) — RFC 0001 D9. A non-match errors.
        #[arg(long, value_name = "SID|NAME")]
        user: Option<String>,
        /// Scope to one profile, e.g. `Chrome/Default` (RFC 0001 D9).
        #[arg(long, value_name = "BROWSER/NAME")]
        profile: Option<String>,
        /// Scope to one browser family, e.g. `chrome` (RFC 0001 D9).
        #[arg(long, value_name = "BROWSER")]
        browser: Option<String>,
    },
    /// Reconstruct cached representations consistent with access to a URL, from
    /// browser cache. `PATH` is a cache directory or a whole profile. Writes a
    /// self-contained single-file HTML page, a replayable WARC, or a cached-image
    /// gallery to `--out`. Every artifact carries a provenance manifest of found
    /// vs missing sub-resources: the output shows what the cache STORED, a
    /// *consistent-with* artifact — never a rendering of the page as displayed
    /// (JS/SPA/lazy-loaded/auth-gated content may be absent).
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
    ///
    /// With `--bundle`, write instead a reproducible court/exam BUNDLE to the
    /// `-o <DIR>` directory (RFC 0001 P8 / D10): a self-contained HTML summary
    /// with ranked, court-safe findings, the machine timeline (xlsx + jsonl), the
    /// chain-of-custody manifest (D11), and a SHA-256 sidecar hashing the bundle's
    /// own outputs so it self-verifies with `sha256sum -c SHA256SUMS.txt`.
    Report {
        /// A profile directory or home directory to collect events from.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Report format (single-file modes; ignored with `--bundle`).
        #[arg(long, value_enum, default_value_t = crate::report::ReportFormat::Html)]
        format: crate::report::ReportFormat,
        /// Write a reproducible bundle to the `-o <DIR>` directory instead of a
        /// single file (RFC 0001 P8). Requires `-o <DIR>`.
        #[arg(long)]
        bundle: bool,
        /// Output file for the single-file modes, or (with `--bundle`) the output
        /// DIRECTORY. Single-file modes default to stdout.
        #[arg(long = "out", short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
        /// Render timestamps in this IANA timezone (e.g. `America/New_York`).
        #[arg(long, value_name = "TZ")]
        timezone: Option<String>,
        /// Also write a chain-of-custody manifest (SHA-256/MD5 of every input) here.
        #[arg(long, value_name = "FILE")]
        manifest: Option<PathBuf>,
        /// Scope to one user (SID or name) — RFC 0001 D9. A non-match errors.
        #[arg(long, value_name = "SID|NAME")]
        user: Option<String>,
        /// Scope to one profile, e.g. `Chrome/Default` (RFC 0001 D9).
        #[arg(long, value_name = "BROWSER/NAME")]
        profile: Option<String>,
        /// Scope to one browser family, e.g. `chrome` (RFC 0001 D9).
        #[arg(long, value_name = "BROWSER")]
        browser: Option<String>,
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
    /// Run full triage: discover profiles, parse, check integrity, carve.
    Triage {
        /// Home directory to scan for browser profiles.
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Ingest browser artifacts from a disk image (E01 / raw / dmg). All disk
    /// work (container/partition/filesystem detection and reads) is delegated to
    /// the forensic-vfs fleet; profiles are located across every user and parsed
    /// through the existing readers, each event stamped with image/volume/user
    /// provenance.
    Image {
        /// Path to the disk image (E01 / raw / dmg).
        path: PathBuf,
        /// Optional APFS snapshot transaction id to ingest a historical view of
        /// the volume instead of its live state.
        #[arg(long, value_name = "XID")]
        snapshot: Option<u64>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Print the JSON Schema (draft 2020-12) for the `BrowserEvent` records this
    /// tool emits, derived from the Rust types so it never drifts from the
    /// serialized shape. Feed it to a validator or code generator.
    Schema,
    /// Generate a shell completion script (bash / zsh / fish) to stdout, derived
    /// from the live command tree. Hidden — a setup helper, not a task verb.
    #[command(hide = true)]
    Completions {
        /// The shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// The per-artifact primitives, reachable as `br4n6 artifact <NAME> <PATH>`.
///
/// Naming scheme: each subcommand is the kebab-case of the artifact's canonical
/// name (clap derives `top-sites`, `media-history`, … from the variant names).
/// Two deliberate renames adopt the cleaner forensic name — the login store is
/// `logins` (was `login-data`), and the Chromium `Network Action Predictor` is
/// `network-action-predictor` (was `predictor`). Every variant keeps the exact
/// flags its former flat command had, and routes to the same handler.
#[derive(Subcommand, Debug)]
enum ArtifactKind {
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
    /// Parse browser cookies. Encrypted values are always COUNTED and reported
    /// (never dropped); add `--keys <PATH>` to decrypt them. Cookie plaintext may
    /// show under `--keys` alone (session work); `v20` App-Bound values are
    /// refused, never fabricated (RFC 0001 P6 / D7).
    Cookies {
        /// Path to the cookies artifact file or profile directory.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Decrypt cookie values using key material AUTO-LOCATED **within** this
        /// evidence root and never outside it: the Chromium `Local State`
        /// (DPAPI-wrapped key), Windows DPAPI masterkeys under
        /// `.../Microsoft/Protect/<SID>/`, and — on a live macOS host — the
        /// "… Safe Storage" Keychain item. Usually the profile or evidence root.
        #[arg(long, value_name = "PATH")]
        keys: Option<PathBuf>,
        /// macOS only: the Keychain service holding the "… Safe Storage" secret
        /// (e.g. `Chrome Safe Storage`, `Microsoft Edge Safe Storage`). Refines
        /// `--keys` on a live macOS host.
        #[arg(long, value_name = "SERVICE", default_value = "Chrome Safe Storage")]
        keychain_service: String,
        /// Read the Windows logon password once from stdin (to unwrap the DPAPI
        /// masterkey). NEVER pass a password on argv — it leaks to shell history
        /// and `ps`. Used with `--keys`.
        #[arg(long)]
        password_stdin: bool,
        /// Also write a chain-of-custody manifest here, recording every key file
        /// used (SHA-256, GUID/SID) and how many items each decrypted (D11).
        #[arg(long, value_name = "PATH")]
        manifest: Option<PathBuf>,
    },
    /// Parse browser downloads.
    Downloads(ArtifactArgs),
    /// Parse browser bookmarks.
    Bookmarks(ArtifactArgs),
    /// Parse browser extensions.
    Extensions(ArtifactArgs),
    /// Parse browser login data. Passwords are double-gated (RFC 0001 P6 / D7):
    /// `--keys <PATH>` decrypts using NSS key material auto-located within the
    /// evidence root, and `--reveal-secrets <FILE>` materializes password
    /// plaintext to a FILE only — never the terminal. Usernames show; passwords
    /// render as a placeholder unless written to a file.
    #[command(name = "logins")]
    Logins {
        /// A `logins.json`/`key4.db`/`Login Data` file, or a profile directory.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Decrypt using NSS key material (`key4.db`) AUTO-LOCATED **within** this
        /// evidence root and never outside it. Usually the profile directory.
        #[arg(long, value_name = "PATH")]
        keys: Option<PathBuf>,
        /// Read the Firefox master password once from stdin (empty when none is
        /// set). NEVER pass a password on argv — it leaks to shell history + `ps`.
        #[arg(long)]
        password_stdin: bool,
        /// Materialize decrypted PASSWORD plaintext to this FILE only (never the
        /// terminal — scrollback/tmux/screen-share leak PII). Without it, the
        /// password renders as `[decrypted — write with --reveal-secrets <file>]`.
        #[arg(long, value_name = "FILE")]
        reveal_secrets: Option<PathBuf>,
        /// Also write a chain-of-custody manifest (the key sources used) here.
        #[arg(long, value_name = "PATH")]
        manifest: Option<PathBuf>,
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
    /// Parse browser preferences (Chrome `Preferences` / Firefox `prefs.js`).
    Preferences(ArtifactArgs),
    /// List per-site permission grants (Chrome `Preferences` / Firefox `permissions.sqlite`).
    Permissions(ArtifactArgs),
    /// Surface stored account/payment metadata from Chromium `Web Data`
    /// (cards, tokens, autofill profiles). Values are NEVER decrypted.
    Credentials(ArtifactArgs),
    /// Parse web storage (Local/Session Storage, IndexedDB).
    Storage(ArtifactArgs),
    /// Parse an IE / Edge-Legacy `WebCacheV01.dat` (ESE): history, cookies,
    /// cached content, and DOM storage. `PATH` is the WebCacheV01.dat file.
    Webcache(ArtifactArgs),
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
    #[command(name = "network-action-predictor")]
    NetworkActionPredictor(ArtifactArgs),
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
    // Guarded bare-path convenience (RFC 0001 D3): `br4n6 <PATH>` runs
    // `investigate <PATH>` — but ONLY when the single token is an existing path
    // and not a command name. A token that is both fails with a specific
    // ambiguity diagnostic; anything else falls through to clap unchanged. clap
    // alone cannot disambiguate a subcommand name from a same-named path, so this
    // thin arg-inspection runs before dispatch.
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    match classify_bare_path(&raw_args) {
        BarePath::Ambiguous(token) => {
            anyhow::bail!(
                "Ambiguous: \"{token}\" is both a br4n6 command and a path.\n\
                 Use: br4n6 investigate ./{token}   |   or: br4n6 {token} <args...>"
            );
        }
        BarePath::Investigate(path) => {
            return run_investigate(
                &path,
                crate::investigate::Tier::Standard,
                None,
                None,
                false,
                None,
                None,
                &crate::selectors::Selectors::default(),
            );
        }
        BarePath::Fallthrough => {}
    }

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
        Some(Command::Investigate {
            path,
            quick,
            standard,
            deep,
            format,
            checkpoint,
            restart,
            forced_type,
            manifest,
            user,
            profile,
            browser,
        }) => run_investigate(
            &path,
            tier_from_flags(quick, standard, deep),
            format,
            checkpoint.as_deref(),
            restart,
            forced_type,
            manifest.as_deref(),
            &crate::selectors::Selectors::new(user, profile, browser),
        ),
        Some(Command::Find {
            term,
            path,
            regex,
            literal,
            terms_file,
            iocs,
            from,
            to,
            sources,
            format,
            user,
            profile,
            browser,
        }) => run_find(
            term.as_deref(),
            path.as_deref(),
            regex.as_deref(),
            literal.as_deref(),
            terms_file.as_deref(),
            iocs,
            from.as_deref(),
            to.as_deref(),
            &sources,
            format,
            &crate::selectors::Selectors::new(user, profile, browser),
        ),
        Some(Command::Recover {
            path,
            symbols,
            format,
            user,
            profile,
            browser,
        }) => run_recover(
            &path,
            symbols.as_deref(),
            format,
            &crate::selectors::Selectors::new(user, profile, browser),
        ),
        Some(Command::Artifact { list, kind }) => run_artifact_command(list, kind),
        Some(Command::Timeline {
            path,
            around,
            window,
            tz,
            chains,
            idle_gap,
            graph,
            graph_window,
            format,
            user,
            profile,
            browser,
        }) => run_timeline(
            &path,
            around.as_deref(),
            &window,
            tz.as_deref(),
            chains,
            idle_gap,
            graph,
            graph_window,
            format,
            &crate::selectors::Selectors::new(user, profile, browser),
        ),
        Some(Command::Reconstruct {
            path,
            out,
            url,
            format,
        }) => run_reconstruct(&path, &out, url.as_deref(), format),
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
            bundle,
            output,
            timezone,
            manifest,
            user,
            profile,
            browser,
        }) => run_report(
            &path,
            format,
            bundle,
            output.as_deref(),
            timezone.as_deref(),
            manifest.as_deref(),
            &crate::selectors::Selectors::new(user, profile, browser),
        ),
        Some(Command::Manifest {
            path,
            out,
            timezone,
        }) => run_manifest(&path, out.as_deref(), timezone.as_deref()),
        Some(Command::Profiles { format }) => run_profiles(format),
        Some(Command::Analyze { path, cap }) => run_analyze(&path, cap),
        Some(Command::Integrity(a)) => run_integrity(&a.path, a.format),
        Some(Command::Triage { home, format }) => run_triage(home.as_deref(), format),
        Some(Command::Image {
            path,
            snapshot,
            format,
        }) => run_image(&path, snapshot, format),
        Some(Command::Schema) => run_schema(),
        Some(Command::Completions { shell }) => {
            let mut stdout = std::io::stdout().lock();
            crate::completions::generate(shell, &mut stdout);
            Ok(())
        }
    }
}

/// Resolve the three mutually-exclusive tier flags to a [`Tier`], defaulting to
/// `Standard` (RFC 0001 D2). Clap's arg-group guarantees at most one is set.
fn tier_from_flags(quick: bool, _standard: bool, deep: bool) -> crate::investigate::Tier {
    use crate::investigate::Tier;
    if quick {
        Tier::Quick
    } else if deep {
        Tier::Deep
    } else {
        Tier::Standard
    }
}

/// The profiles an investigation will scan under `path`: the canonical
/// per-user discovery, falling back to a single synthetic profile when `path`
/// is itself a profile directory (the `export`/`report` shape).
fn investigation_profiles(path: &Path) -> Vec<browser_forensic_discovery::DiscoveredProfile> {
    let mut profiles = browser_forensic_discovery::discover_profiles(path);
    if profiles.is_empty() {
        if let Some(family) = profile_family(path) {
            profiles.push(browser_forensic_discovery::DiscoveredProfile {
                browser: family,
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                path: path.to_path_buf(),
                container: None,
            });
        }
    }
    profiles
}

/// The merged report, origin-stamped findings, and interrupt state produced by
/// the per-profile investigation loop.
type ProfileLoopResult = (
    browser_forensic_triage::TriageReport,
    Vec<browser_forensic_core::finding::Finding>,
    Option<Interrupted>,
);

/// A [`ProfileLoopResult`] plus the (selector-scoped) profiles it ran over.
type InvestigationCollection = (
    Vec<browser_forensic_discovery::DiscoveredProfile>,
    browser_forensic_triage::TriageReport,
    Vec<browser_forensic_core::finding::Finding>,
    Option<Interrupted>,
);

/// An empty [`TriageReport`] stamped with the current wall-clock time.
fn empty_report_now() -> browser_forensic_triage::TriageReport {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);
    browser_forensic_triage::TriageReport {
        events: Vec::new(),
        carved: Vec::new(),
        integrity: Vec::new(),
        profiles: Vec::new(),
        generated_at_ns: now_ns,
    }
}

/// Triage one profile fragment at `tier`, reporting progress, and augment it with
/// downloads + installed extensions (Chromium) — artifacts the triage stream
/// omits — by reusing the existing parsers, matching the historic `investigate`
/// event set without changing what `triage`/`report` emit.
fn collect_one_profile(
    profile: &browser_forensic_discovery::DiscoveredProfile,
    tier: crate::investigate::Tier,
    progress: &dyn browser_forensic_triage::TriageProgress,
) -> Result<browser_forensic_triage::TriageReport> {
    let opts = tier.triage_options();
    let mut frag = browser_forensic_triage::triage_profile_with_options_progress(
        &profile.path,
        profile.browser.clone(),
        opts,
        progress,
    )
    .with_context(|| format!("investigating profile {}", profile.path.display()))?;

    if profile.browser == BrowserFamily::Chromium {
        let history = profile.path.join("History");
        if history.is_file() {
            progress.on_unit(&profile.name, "Downloads");
            if let Ok(mut downloads) = browser_forensic_chrome::parse_downloads(&history) {
                frag.events.append(&mut downloads);
            }
        }
        let ext_dir = profile.path.join("Extensions");
        if ext_dir.is_dir() {
            progress.on_unit(&profile.name, "Extensions");
            if let Ok(mut exts) = browser_forensic_chrome::parse_extensions(&ext_dir) {
                frag.events.append(&mut exts);
            }
        }
    }
    Ok(frag)
}

/// How many profile units completed before an investigation was interrupted by
/// Ctrl-C (RFC 0001 D2 / P3b concern 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interrupted {
    /// Profile units fully parsed before the cancellation flag was observed.
    pub done: usize,
    /// Total profile units the run would have parsed.
    pub total: usize,
}

/// The always-present footer for an interrupted run (RFC 0001 D2 / P3b concern
/// 2). Names what was and was not done and how to resume, so partial results are
/// never mistaken for a complete run.
#[must_use]
pub fn interrupted_footer(done: usize, total: usize, path_display: &str) -> String {
    format!(
        "[interrupted] partial results — parsed {done}/{total} profile(s) before Ctrl-C; \
         NOT complete → resume with br4n6 investigate {path_display}"
    )
}

/// Drive the triage pipeline over each profile at `tier`, reporting per-artifact
/// progress and checking `cancel` at each profile boundary (never mid-parse).
/// Returns the merged report and, if the run was interrupted, how far it got.
fn run_profile_loop(
    profiles: &[browser_forensic_discovery::DiscoveredProfile],
    tier: crate::investigate::Tier,
    progress: &dyn crate::progress::InvestigationProgress,
    cancel: &std::sync::atomic::AtomicBool,
    checkpoint: &mut Option<crate::checkpoint::CheckpointSession>,
) -> Result<ProfileLoopResult> {
    use std::sync::atomic::Ordering;

    let total = profiles.len();
    let mut report = empty_report_now();
    // Findings are computed per profile so each carries its origin stamp (D9);
    // concatenated, they equal `findings_from_report` over the merged report.
    let mut findings: Vec<browser_forensic_core::finding::Finding> = Vec::new();
    let mut interrupted = None;

    for (index, profile) in profiles.iter().enumerate() {
        // Check the cancellation flag at the profile boundary — never mid-parse —
        // so a Ctrl-C stops scheduling new work but keeps every completed unit.
        if cancel.load(Ordering::Relaxed) {
            interrupted = Some(Interrupted { done: index, total });
            break;
        }
        let key = unit_key(profile);

        // Resume: reuse a completed unit's persisted fragment instead of
        // re-parsing it, so the merged result equals an uninterrupted run.
        if let Some(unit) = checkpoint
            .as_ref()
            .and_then(|session| session.completed_unit(&key))
        {
            report.events.extend(unit.events.iter().cloned());
            report.integrity.extend(unit.integrity.iter().cloned());
            findings.extend(stamped_profile_findings(
                profile,
                &unit.events,
                &unit.integrity,
            ));
            progress.set_profile(index + 1, total);
            continue;
        }

        progress.set_profile(index, total);
        let frag = collect_one_profile(profile, tier, progress)?;
        // Persist the completed unit's summary-relevant fragment (events +
        // integrity) atomically before merging, so a crash right here still
        // leaves a consistent, resumable checkpoint.
        if let Some(session) = checkpoint.as_mut() {
            session.record(&key, frag.events.clone(), frag.integrity.clone())?;
        }
        // Origin-stamped findings for this profile, from its own fragment.
        findings.extend(crate::selectors::stamp(
            crate::investigate::findings_from_report(&frag),
            profile,
        ));
        let mut frag = frag;
        report.events.append(&mut frag.events);
        report.integrity.append(&mut frag.integrity);
        report.carved.append(&mut frag.carved);
    }
    // Reflect the true completed count (all of them, or how far an interrupt got).
    let done = interrupted.map_or(total, |i| i.done);
    progress.set_profile(done, total);
    progress.finish();

    Ok((report, findings, interrupted))
}

/// Compute the origin-stamped findings for one profile from its events +
/// integrity indicators (RFC 0001 D9). Used on the checkpoint-resume path, where
/// only the persisted fragment (not a full `TriageReport`) is available.
fn stamped_profile_findings(
    profile: &browser_forensic_discovery::DiscoveredProfile,
    events: &[BrowserEvent],
    integrity: &[browser_forensic_integrity::IntegrityIndicator],
) -> Vec<browser_forensic_core::finding::Finding> {
    let report = browser_forensic_triage::TriageReport {
        events: events.to_vec(),
        carved: Vec::new(),
        integrity: integrity.to_vec(),
        profiles: Vec::new(),
        generated_at_ns: 0,
    };
    crate::selectors::stamp(crate::investigate::findings_from_report(&report), profile)
}

/// Stable per-profile checkpoint key: browser family + profile path.
fn unit_key(profile: &browser_forensic_discovery::DiscoveredProfile) -> String {
    format!("{}|{}", profile.browser, profile.path.display())
}

/// Open a resumable checkpoint session when `--checkpoint <PATH>` is given,
/// announcing on stderr whether the run is fresh, resumed, or restarted (a
/// mismatch / corruption never silently resumes). Returns `None` when
/// checkpointing is off. Notices go to stderr so stdout stays byte-clean.
///
/// # Errors
/// Propagates a checkpoint I/O error (e.g. an unreadable checkpoint directory).
fn open_checkpoint(
    evidence: &Path,
    tier: crate::investigate::Tier,
    checkpoint_path: Option<&Path>,
    restart: bool,
) -> Result<Option<crate::checkpoint::CheckpointSession>> {
    let Some(cp_path) = checkpoint_path else {
        return Ok(None);
    };
    let fingerprint = crate::checkpoint::fingerprint(evidence);
    let tier_name = tier_name(tier);
    let (session, resumed) = crate::checkpoint::CheckpointSession::resume_or_new(
        cp_path,
        fingerprint,
        tier_name,
        restart,
    )
    .with_context(|| format!("opening checkpoint {}", cp_path.display()))?;

    match resumed {
        crate::checkpoint::Resumed::Fresh => {}
        crate::checkpoint::Resumed::Resumed {
            completed,
            created_ns,
        } => {
            eprintln!(
                "Resuming: {completed} artifact(s) already complete (checkpoint from {})",
                format_checkpoint_time(created_ns)
            );
        }
        crate::checkpoint::Resumed::Restarted(reason) => {
            eprintln!("[notice] checkpoint not resumed ({reason}); starting a clean run");
        }
    }
    Ok(Some(session))
}

/// The tier's checkpoint tag (checkpoints are tier-specific).
fn tier_name(tier: crate::investigate::Tier) -> &'static str {
    match tier {
        crate::investigate::Tier::Quick => "quick",
        crate::investigate::Tier::Standard => "standard",
        crate::investigate::Tier::Deep => "deep",
    }
}

/// Render a checkpoint creation time (Unix ns) as an RFC 3339 UTC string, or the
/// raw value if it is out of range.
fn format_checkpoint_time(created_ns: i64) -> String {
    chrono::DateTime::from_timestamp(
        created_ns.div_euclid(1_000_000_000),
        (created_ns.rem_euclid(1_000_000_000)) as u32,
    )
    .map_or_else(|| created_ns.to_string(), |dt| dt.to_rfc3339())
}

/// Drive the triage pipeline over each discovered profile at `tier`, reporting
/// per-artifact progress to `progress`, returning the profiles, the merged
/// consolidated report, and (if Ctrl-C was observed) how far the run got. The
/// per-profile loop is the unit boundary the interrupt (P3b concern 2) and
/// checkpoint (concern 3) engines hook into.
fn collect_investigation(
    path: &Path,
    tier: crate::investigate::Tier,
    progress: &dyn crate::progress::InvestigationProgress,
    cancel: &std::sync::atomic::AtomicBool,
    checkpoint: &mut Option<crate::checkpoint::CheckpointSession>,
    selectors: &crate::selectors::Selectors,
) -> Result<InvestigationCollection> {
    // Scope to the selected user/profile/browser (RFC 0001 D9); a non-match is a
    // loud error naming what WAS present, never a silent empty result.
    let profiles = selectors.filter(investigation_profiles(path))?;
    let (report, findings, interrupted) =
        run_profile_loop(&profiles, tier, progress, cancel, checkpoint)?;
    Ok((profiles, report, findings, interrupted))
}

/// The layered detections to show + log for an investigation (RFC 0001 D8).
///
/// With `--type <KIND>` the examiner's forced kind replaces auto-detection (a
/// single record over the top path). Otherwise the top path is detected and, for
/// each discovered profile, its primary history database — so "SQLite" is refined
/// to the concrete artifact by the schema probe, per input.
fn investigation_detections(
    path: &Path,
    profiles: &[browser_forensic_discovery::DiscoveredProfile],
    forced_type: Option<crate::detect::DetectionKind>,
) -> Vec<(PathBuf, crate::detect::Detection)> {
    if let Some(kind) = forced_type {
        return vec![(path.to_path_buf(), crate::detect::forced(kind))];
    }
    let mut out = vec![(path.to_path_buf(), crate::detect::detect(path))];
    for profile in profiles {
        for (name, _family) in PROFILE_HISTORY_DBS {
            let db = profile.path.join(name);
            if db.is_file() {
                out.push((db.clone(), crate::detect::detect(&db)));
            }
        }
    }
    out
}

/// Write a chain-of-custody manifest over `path`'s evidence carrying the
/// per-input detection basis + confidence (RFC 0001 D8/D11).
///
/// # Errors
/// Propagates a manifest serialization or write failure.
fn write_detection_manifest(
    out: &Path,
    path: &Path,
    detections: &[(PathBuf, crate::detect::Detection)],
) -> Result<()> {
    let inputs = browser_forensic_manifest::enumerate_evidence(path);
    let args: Vec<String> = std::env::args().collect();
    let run = browser_forensic_manifest::RunMetadata::capture(
        "br4n6",
        env!("CARGO_PKG_VERSION"),
        &args,
        None,
    );
    let mut manifest = browser_forensic_manifest::build_manifest(&inputs, run);
    manifest.detection_basis = detections
        .iter()
        .map(|(p, det)| crate::detect::to_record(p, det))
        .collect();
    let json = browser_forensic_manifest::to_json(&manifest).context("serializing manifest")?;
    std::fs::write(out, json.as_bytes())
        .with_context(|| format!("writing manifest {}", out.display()))?;
    eprintln!("wrote chain-of-custody manifest to {}", out.display());
    Ok(())
}

/// `br4n6 investigate PATH [--quick|--standard|--deep]` — the RFC 0001 P3a golden
/// path. Runs the bounded triage pipeline at the chosen tier and renders a ranked,
/// court-safe summary (human on a TTY, JSONL of the findings when piped). The
/// human render always ends with the tier's skipped-work footer.
///
/// # Errors
/// Returns a loud error if the path does not exist (a bootstrap failure is never
/// absorbed into an empty result) or the triage pipeline fails.
#[allow(clippy::too_many_arguments)] // one flag per RFC 0001 P3/P7 concern; a struct would obscure the 1:1 CLI mapping
pub fn run_investigate(
    path: &Path,
    tier: crate::investigate::Tier,
    format: Option<OutputFormat>,
    checkpoint_path: Option<&Path>,
    restart: bool,
    forced_type: Option<crate::detect::DetectionKind>,
    manifest_path: Option<&Path>,
    selectors: &crate::selectors::Selectors,
) -> Result<()> {
    use std::io::IsTerminal as _;

    // Bootstrap check: a nonexistent path is a loud error, never a silent empty
    // "clean" summary (which would be indistinguishable from a genuinely empty
    // profile — the worst false-reassurance failure).
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }

    // stderr-only heartbeat, active only on a TTY so pipes/CI stay byte-clean
    // (RFC 0001 P3b concern 1). `NO_COLOR` is honored via `color_enabled`.
    let stderr_is_tty = std::io::stderr().is_terminal();
    let progress = crate::progress::Progress::select(
        stderr_is_tty,
        crate::output::color_enabled(stderr_is_tty),
    );

    // First Ctrl-C sets this flag; the collect loop stops at the next profile
    // boundary and flushes the partial ranked summary (RFC 0001 D2 / P3b concern
    // 2). A second Ctrl-C hard-aborts (see [`install_interrupt_handler`]).
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    install_interrupt_handler(&cancel);

    // Optional resumable checkpoint (RFC 0001 P3b concern 3). Off unless
    // `--checkpoint <PATH>` is given — a read-only tool never writes into evidence
    // by default. The resume decision is announced on stderr so stdout stays clean.
    let mut checkpoint = open_checkpoint(path, tier, checkpoint_path, restart)?;

    let (profiles, _report, findings, interrupted) =
        collect_investigation(path, tier, &progress, &cancel, &mut checkpoint, selectors)?;

    // Layered PATH auto-detection (RFC 0001 D8): show what each input was
    // detected as, with confidence + basis, and — with `--manifest` — record it
    // for court defensibility. `--type` forces the kind (auto-detection skipped).
    let detections = investigation_detections(path, &profiles, forced_type);
    for (_, det) in &detections {
        eprintln!("{}", det.header());
    }
    if let Some(mp) = manifest_path {
        write_detection_manifest(mp, path, &detections)?;
    }

    // Findings are already origin-stamped per profile (D9); rank them for render.
    let findings = crate::investigate::rank_findings(findings);

    let resolved = crate::output::resolve_stdout(format);
    match resolved {
        OutputFormat::Text => {
            let color = crate::output::color_enabled(std::io::stdout().is_terminal());
            print!(
                "{}",
                crate::investigate::render_summary(
                    &profiles,
                    &findings,
                    tier,
                    &path.display().to_string(),
                    color,
                )
            );
            // On a human render the interrupted footer belongs on stdout, with the
            // (partial) summary it qualifies.
            if let Some(i) = interrupted {
                println!(
                    "{}",
                    interrupted_footer(i.done, i.total, &path.display().to_string())
                );
            }
        }
        OutputFormat::Jsonl => {
            for finding in &findings {
                if let Ok(line) = serde_json::to_string(finding) {
                    println!("{line}");
                }
            }
        }
        OutputFormat::Csv => {
            println!("priority,confidence,rule_id,interpretation,source,state,evidence,next");
            for f in &findings {
                println!(
                    "{},{},{},{},{},{},{},{}",
                    csv_field(&f.priority.to_string()),
                    csv_field(&f.confidence.to_string()),
                    csv_field(&f.rule_id),
                    csv_field(&f.interpretation),
                    csv_field(&f.provenance.source.to_string()),
                    csv_field(&f.provenance.state.to_string()),
                    csv_field(&f.evidence),
                    csv_field(f.next.as_deref().unwrap_or("")),
                );
            }
        }
    }

    // A machine render keeps stdout byte-faithful; the interrupt note goes to
    // stderr so the JSONL/CSV stream stays valid.
    if let Some(i) = interrupted {
        if resolved != OutputFormat::Text {
            eprintln!(
                "{}",
                interrupted_footer(i.done, i.total, &path.display().to_string())
            );
        }
        // Exit non-zero-but-clean: partial results already flushed, handles closed.
        anyhow::bail!(
            "interrupted by Ctrl-C after {}/{} profile(s) — partial results flushed; \
             resume with: br4n6 investigate {}",
            i.done,
            i.total,
            path.display()
        );
    }
    Ok(())
}

/// Classify an evidence path into a [`recover::RecoverScope`] (RFC 0001 P5b,
/// resolved-decision #2): a directory is a profile/home; a file is a single
/// SQLite database when it carries the SQLite magic, otherwise a memory image.
/// The examiner makes no submode choice — the scope is read from the path shape.
fn recover_scope_of(path: &Path) -> crate::recover::RecoverScope {
    if path.is_dir() {
        crate::recover::RecoverScope::Profile
    } else if looks_like_sqlite(path) {
        crate::recover::RecoverScope::Database
    } else {
        crate::recover::RecoverScope::MemoryImage
    }
}

/// Whether the first bytes of a file are the SQLite format-3 header magic. A
/// read failure returns `false` (treated as a non-database), never a panic.
fn looks_like_sqlite(path: &Path) -> bool {
    use std::io::Read as _;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0_u8; 16];
    f.read_exact(&mut magic).is_ok() && &magic == b"SQLite format 3\0"
}

/// Recover deleted SQLite/WAL records from a single database via both carve
/// substrates (free pages + WAL), absorbing per-substrate errors so one failing
/// path never suppresses the other. Shared by the profile and single-database
/// recover scopes.
fn carve_db_records(db: &Path) -> Vec<browser_forensic_carve::CarvedRecord> {
    let empty = || browser_forensic_carve::CarveResult {
        records: Vec::new(),
        integrity: Vec::new(),
        stats: browser_forensic_carve::CarveStats::default(),
    };
    let mut records = browser_forensic_carve::carve_sqlite_free_pages(db)
        .unwrap_or_else(|_| empty())
        .records;
    records.extend(
        browser_forensic_carve::recover_from_wal(db)
            .unwrap_or_else(|_| empty())
            .records,
    );
    records
}

/// Candidate Chromium cache directories under a profile (both the modern
/// `Cache/Cache_Data` layout and the flat legacy ones), for orphaned-cache
/// recovery. Only existing directories are returned.
fn candidate_cache_dirs(profile: &Path) -> Vec<PathBuf> {
    ["Cache/Cache_Data", "Cache", "Cache_Data"]
        .iter()
        .map(|rel| profile.join(rel))
        .filter(|p| p.is_dir())
        .collect()
}

/// Gather every recovery [`Finding`](browser_forensic_core::finding::Finding)
/// applicable to a single profile directory: deleted SQLite/WAL records, orphaned
/// cache, recovered domains, deleted bookmarks, and tamper indicators. Each
/// engine is best-effort — a per-engine miss degrades to empty AFTER the path is
/// known-good, never suppressing the others (RFC 0001 fail-loud-on-bootstrap,
/// degrade-to-empty per artifact).
fn recover_profile_findings(profile: &Path) -> Vec<browser_forensic_core::finding::Finding> {
    let mut findings = Vec::new();

    // Deleted SQLite/WAL records from each known history database.
    let mut carved = Vec::new();
    for (name, _family) in PROFILE_HISTORY_DBS {
        let db = profile.join(name);
        if db.is_file() {
            carved.extend(carve_db_records(&db));
        }
    }
    findings.extend(crate::recover::carved_record_findings(&carved));

    // Orphaned / evicted cache entries.
    for cache_dir in candidate_cache_dirs(profile) {
        let events: Vec<BrowserEvent> = browser_forensic_cache::carve_cache_dir(&cache_dir)
            .iter()
            .map(cache_carve_event)
            .collect();
        findings.extend(crate::recover::cache_carve_findings(&events));
    }

    // Domains recovered from network/state artifacts (survive a history clear).
    let domain_events = browser_forensic_triage::collect_recovered_domains(profile);
    findings.extend(crate::recover::recovered_domain_findings(&domain_events));

    // Deleted Firefox bookmarks (backup vs current diff); a missing places.sqlite
    // is not an error here — it just means no bookmark recovery for this profile.
    if let Ok(bookmark_events) = browser_forensic_firefox::recover_deleted_bookmarks(profile) {
        findings.extend(crate::recover::deleted_bookmark_findings(&bookmark_events));
    }

    // Tamper / anti-forensic indicators across the profile's databases.
    let mut indicators = Vec::new();
    gather_profile_tamper_indicators(profile, &mut indicators);
    findings.extend(crate::recover::tamper_findings(&indicators));

    findings
}

/// Gather recovery findings from a single SQLite database: deleted-record carving
/// plus tamper indicators over that one file (no cache/domain/bookmark scope).
fn recover_database_findings(db: &Path) -> Vec<browser_forensic_core::finding::Finding> {
    let mut findings = Vec::new();
    findings.extend(crate::recover::carved_record_findings(&carve_db_records(
        db,
    )));

    let family = browser_forensic_core::detect_browser(db)
        .or_else(|| infer_browser_from_filename(db))
        .unwrap_or(BrowserFamily::Chromium);
    let mut indicators = Vec::new();
    gather_db_tamper_indicators(db, family, &mut indicators);
    findings.extend(crate::recover::tamper_findings(&indicators));
    findings
}

/// Carve browser artifacts from a memory image into recovery findings. Mirrors
/// the structured-carve-then-byte-scan degrade of the former `memory` command: a
/// hard bootstrap failure (unreadable image / no usable profile) is loud, a
/// degradable one falls back to a raw byte-scan (announced on stderr).
///
/// # Errors
/// Propagates a non-degradable memory-carve error or a fallback read error.
fn recover_memory_findings(
    image: &Path,
    symbols: Option<&Path>,
) -> Result<Vec<browser_forensic_core::finding::Finding>> {
    let events = match browser_forensic_memory::carve_memory_image_with_symbols(image, symbols) {
        Ok(events) => {
            let procs = browser_forensic_memory::browser_processes(&events);
            eprintln!(
                "br4n6 recover: structured memory carve — {} event(s) across {} browser \
                 process(es)",
                events.len(),
                procs.len()
            );
            events
        }
        Err(e) if e.is_degradable() => {
            eprintln!(
                "br4n6 recover: {e}; falling back to a raw byte-scan (no process attribution)"
            );
            let bytes = std::fs::read(image)
                .with_context(|| format!("cannot read memory buffer {}", image.display()))?;
            let mut events = browser_forensic_memory::scan_bytes_for_urls(&bytes);
            events.extend(browser_forensic_memory::scan_bytes_for_cookies(&bytes));
            events
        }
        Err(e) => return Err(anyhow::Error::new(e)),
    };
    Ok(crate::recover::memory_findings(&events))
}

/// `br4n6 recover PATH [--symbols ISF] [--format ...]` — the RFC 0001 P5b
/// orchestrator. ONE verb runs ALL applicable recovery over `PATH` and renders a
/// ranked, court-safe summary; the recovery kinds are auto-selected from the
/// path shape (profile dir / single database / memory image), so the examiner
/// makes no submode choice. The human render always ends with the scope's
/// skipped-work footer so absence of a result is never false reassurance.
///
/// # Errors
/// Returns a loud error if the path does not exist (a bootstrap failure is never
/// absorbed into an empty result), or if a memory image cannot be read at all.
pub fn run_recover(
    path: &Path,
    symbols: Option<&Path>,
    format: Option<OutputFormat>,
    selectors: &crate::selectors::Selectors,
) -> Result<()> {
    use std::io::IsTerminal as _;

    // Bootstrap check: a nonexistent path is a loud error, never a silent empty
    // "nothing recovered" summary (indistinguishable from a genuinely clean run).
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }

    let scope = recover_scope_of(path);
    let findings = match scope {
        crate::recover::RecoverScope::Profile => {
            // Every profile beneath a home dir, scoped by the selectors (RFC 0001
            // D9; a non-match errors loudly), each recovered finding stamped with
            // its origin. When discovery classifies nothing and no selector is set,
            // fall back to the path itself as a single (unstamped) profile dir.
            let profiles = selectors.filter(investigation_profiles(path))?;
            let mut findings = Vec::new();
            if profiles.is_empty() {
                findings.extend(recover_profile_findings(path));
            } else {
                for profile in &profiles {
                    findings.extend(crate::selectors::stamp(
                        recover_profile_findings(&profile.path),
                        profile,
                    ));
                }
            }
            findings
        }
        crate::recover::RecoverScope::Database => recover_database_findings(path),
        crate::recover::RecoverScope::MemoryImage => recover_memory_findings(path, symbols)?,
    };
    let findings = crate::recover::rank_findings(findings);

    let resolved = crate::output::resolve_stdout(format);
    let path_display = path.display().to_string();
    match resolved {
        OutputFormat::Text => {
            let color = crate::output::color_enabled(std::io::stdout().is_terminal());
            print!(
                "{}",
                crate::recover::render_summary(&findings, scope, &path_display, color)
            );
        }
        OutputFormat::Jsonl => {
            for finding in &findings {
                if let Ok(line) = serde_json::to_string(finding) {
                    println!("{line}");
                }
            }
        }
        OutputFormat::Csv => {
            println!("priority,confidence,rule_id,interpretation,source,state,evidence,next");
            for f in &findings {
                println!(
                    "{},{},{},{},{},{},{},{}",
                    csv_field(&f.priority.to_string()),
                    csv_field(&f.confidence.to_string()),
                    csv_field(&f.rule_id),
                    csv_field(&f.interpretation),
                    csv_field(&f.provenance.source.to_string()),
                    csv_field(&f.provenance.state.to_string()),
                    csv_field(&f.evidence),
                    csv_field(f.next.as_deref().unwrap_or("")),
                );
            }
        }
    }
    Ok(())
}

/// Install the Ctrl-C (SIGINT) handler: the first interrupt sets `cancel` so the
/// investigation loop stops at the next profile boundary and flushes partial
/// results; a second interrupt hard-aborts (exit 130). Best-effort — if a handler
/// is already installed (e.g. a second call in one process), the existing one
/// stands. Signal registration is the one thin, untestable shell; the flag it
/// sets is what the loop and its tests exercise.
fn install_interrupt_handler(cancel: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::Ordering;
    let cancel = std::sync::Arc::clone(cancel);
    let _ = ctrlc::set_handler(move || {
        if cancel.swap(true, Ordering::SeqCst) {
            // Second Ctrl-C: the operator wants out now.
            std::process::exit(130);
        }
        // First Ctrl-C: flag set; the loop will stop at the next boundary.
    });
}

/// Handle `br4n6 artifact …`: `--list` tabulates the primitives; otherwise the
/// selected primitive routes to its existing handler. With neither, guide the
/// user to `--list` rather than fail silently.
fn run_artifact_command(list: bool, kind: Option<ArtifactKind>) -> Result<()> {
    if list {
        return run_artifact_list();
    }
    match kind {
        Some(k) => dispatch_artifact(k),
        None => anyhow::bail!(
            "no artifact selected — run `br4n6 artifact --list` to see every primitive, \
             or `br4n6 artifact <NAME> <PATH>` to parse one"
        ),
    }
}

/// Route one `artifact` primitive to the same handler its former flat command
/// called. Behavior-preserving: this is a routing move, not a rewrite.
fn dispatch_artifact(kind: ArtifactKind) -> Result<()> {
    match kind {
        ArtifactKind::History {
            path,
            no_collapse,
            search,
            format,
        } => run_history(&path, no_collapse, search.as_deref(), format),
        ArtifactKind::Sessions {
            path,
            search,
            format,
        } => run_sessions(&path, search.as_deref(), format),
        ArtifactKind::Cookies {
            path,
            format,
            keys,
            keychain_service,
            password_stdin,
            manifest,
        } => dispatch_cookies(
            &path,
            format,
            keys.as_deref(),
            &keychain_service,
            password_stdin,
            manifest.as_deref(),
        ),
        ArtifactKind::Downloads(a) => run_artifact(&a.path, ArtifactType::Downloads, a.format),
        ArtifactKind::Bookmarks(a) => run_artifact(&a.path, ArtifactType::Bookmarks, a.format),
        ArtifactKind::Extensions(a) => run_artifact(&a.path, ArtifactType::Extensions, a.format),
        ArtifactKind::Logins {
            path,
            format,
            keys,
            password_stdin,
            reveal_secrets,
            manifest,
        } => dispatch_logins(
            &path,
            format,
            keys.as_deref(),
            password_stdin,
            reveal_secrets.as_deref(),
            manifest.as_deref(),
        ),
        ArtifactKind::Autofill(a) => run_artifact(&a.path, ArtifactType::Autofill, a.format),
        ArtifactKind::Session(a) => run_artifact(&a.path, ArtifactType::Session, a.format),
        ArtifactKind::Cache(a) => run_artifact(&a.path, ArtifactType::Cache, a.format),
        ArtifactKind::Cachestorage(a) => run_cachestorage(&a.path, a.format),
        ArtifactKind::Preferences(a) => run_artifact(&a.path, ArtifactType::Preferences, a.format),
        ArtifactKind::Permissions(a) => run_permissions(&a.path, a.format),
        ArtifactKind::Credentials(a) => run_credentials(&a.path, a.format),
        ArtifactKind::Storage(a) => run_storage(&a.path, a.format),
        ArtifactKind::Webcache(a) => run_webcache(&a.path, a.format),
        ArtifactKind::Indexeddb(a) => run_indexeddb(&a.path, a.format),
        ArtifactKind::Favicons(a) => run_favicons(&a.path, a.format),
        ArtifactKind::TopSites(a) => run_top_sites(&a.path, a.format),
        ArtifactKind::Shortcuts(a) => run_shortcuts(&a.path, a.format),
        ArtifactKind::NetworkActionPredictor(a) => run_predictor(&a.path, a.format),
        ArtifactKind::MediaHistory(a) => run_media_history(&a.path, a.format),
        ArtifactKind::ExtensionCookies(a) => run_extension_cookies(&a.path, a.format),
        ArtifactKind::TypedInput(a) => run_typed_input(&a.path, a.format),
        ArtifactKind::Annotations(a) => run_annotations(&a.path, a.format),
        ArtifactKind::DeletedBookmarks(a) => run_deleted_bookmarks(&a.path, a.format),
    }
}

/// The artifact catalog printed by `br4n6 artifact --list`:
/// `(name, browser family, what it records)`. "What it records" states the
/// artifact as recorded — never that a user deliberately performed the action.
const ARTIFACT_CATALOG: &[(&str, &str, &str)] = &[
    (
        "history",
        "Chromium/Firefox/Safari",
        "URLs visited, with timestamps and transition type",
    ),
    (
        "sessions",
        "Chromium/Firefox",
        "open and recently-closed tabs",
    ),
    (
        "cookies",
        "Chromium/Firefox",
        "cookie names and domains; values decrypted opt-in only",
    ),
    (
        "downloads",
        "Chromium/Firefox",
        "downloaded files: source URL, target path, timing",
    ),
    (
        "bookmarks",
        "Chromium/Firefox",
        "bookmarked URLs and folder structure",
    ),
    (
        "extensions",
        "Chromium/Firefox",
        "installed extensions: id, name, permissions",
    ),
    (
        "logins",
        "Chromium/Firefox",
        "saved login origins/usernames; secrets opt-in only",
    ),
    ("autofill", "Chromium/Firefox", "saved form-field values"),
    (
        "session",
        "Chromium/Firefox",
        "session-store tabs and navigation entries",
    ),
    (
        "cache",
        "Chromium/Firefox/Safari",
        "cached HTTP responses: URL, headers, timing",
    ),
    (
        "cachestorage",
        "Chromium",
        "Service Worker Cache API responses",
    ),
    (
        "preferences",
        "Chromium/Firefox",
        "browser/profile settings",
    ),
    (
        "permissions",
        "Chromium/Firefox",
        "per-site permission grants",
    ),
    (
        "credentials",
        "Chromium",
        "stored account/payment metadata (never decrypted)",
    ),
    (
        "storage",
        "Chromium/Firefox",
        "Local/Session Storage and IndexedDB records",
    ),
    (
        "webcache",
        "IE/Edge-Legacy",
        "history, cookies, cached content, DOM storage (ESE)",
    ),
    (
        "indexeddb",
        "Chromium",
        "IndexedDB database/store names, keys, values",
    ),
    (
        "favicons",
        "Chromium",
        "favicon page_url source (visited URLs)",
    ),
    (
        "top-sites",
        "Chromium",
        "most-visited / frecency-ranked sites",
    ),
    ("shortcuts", "Chromium", "omnibox strings the user typed"),
    (
        "network-action-predictor",
        "Chromium",
        "partial typed strings (autocomplete predictor)",
    ),
    ("media-history", "Chromium", "audio/video playback records"),
    (
        "extension-cookies",
        "Chromium",
        "extension-scoped cookie jar",
    ),
    (
        "typed-input",
        "Firefox",
        "strings typed into the address bar",
    ),
    ("annotations", "Firefox", "page annotations (moz_annos)"),
    (
        "deleted-bookmarks",
        "Firefox",
        "bookmarks in a backup but absent now (consistent with deletion)",
    ),
];

/// Print the artifact catalog as a markdown-clean table (pipe-delimited, no
/// box-drawing, full values — survives paste into Jira/Word/Markdown) via the
/// shared P2 output engine. Columns: NAME, BROWSER, RECORDS.
///
/// # Errors
/// Never fails; returns `Result` for a uniform handler signature.
fn run_artifact_list() -> Result<()> {
    let rows: Vec<Vec<String>> = ARTIFACT_CATALOG
        .iter()
        .map(|(name, family, records)| {
            vec![
                (*name).to_string(),
                (*family).to_string(),
                (*records).to_string(),
            ]
        })
        .collect();
    print!(
        "{}",
        crate::output::markdown_table(&["NAME", "BROWSER", "RECORDS"], &rows)
    );
    Ok(())
}

/// Emit the `BrowserEvent` JSON Schema to stdout as pretty-printed JSON.
///
/// # Errors
/// Propagates a serialization failure (never expected for a derived schema).
pub fn run_schema() -> Result<()> {
    let schema = browser_forensic_core::browser_event_schema();
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(())
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

/// An evidence-source scope for `br4n6 find --source <KIND>` (RFC 0001 P4). The
/// names mirror the provenance `SOURCE` column so one term names one concept
/// across the flag, the table, and JSONL.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum SourceKind {
    History,
    Cache,
    Cookie,
    Download,
    Carved,
    Memory,
    Recovered,
    Extension,
}

impl SourceKind {
    /// The P0 [`EvidenceSource`] this scope selects.
    fn evidence_source(self) -> browser_forensic_core::finding::EvidenceSource {
        use browser_forensic_core::finding::EvidenceSource as E;
        match self {
            Self::History => E::History,
            Self::Cache => E::Cache,
            Self::Cookie => E::Cookie,
            Self::Download => E::Download,
            Self::Carved => E::Carved,
            Self::Memory => E::Memory,
            Self::Recovered => E::Recovered,
            Self::Extension => E::Extension,
        }
    }
}

/// Entity-graph output format for `br4n6 timeline --graph`.
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

/// `br4n6 artifact history` — dump history visits for the auto-detected browser family.
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
    let mut visits = read_history_events(path, no_collapse)?;
    if let Some(needle) = search {
        filter_in_place(&mut visits, needle);
    }
    emit_events(&visits, format);
    Ok(())
}

/// Resolve `PATH` to a concrete history store and parse it into chronological
/// [`BrowserEvent`]s for the auto-detected family (Chromium redirect-collapsed by
/// default). Shared by `artifact history` and the single-file `timeline` path.
///
/// # Errors
/// Returns an actionable error (D10) if the history store cannot be opened or
/// queried — a locked / dirty-WAL / corrupt open is mapped to a recovery
/// suggestion instead of a bare SQLITE_* code, without swallowing the cause.
fn read_history_events(path: &Path, no_collapse: bool) -> Result<Vec<BrowserEvent>> {
    let (family, history) = resolve_history(path)?;
    (|| -> Result<Vec<BrowserEvent>> {
        Ok(match family {
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
        })
    })()
    .map_err(|e| crate::output::actionable_db_error(e, &history))
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

/// Collect a profile/home directory's unified event stream, or a single history
/// file's chronology (RFC 0001 P5a `timeline`). A directory routes through the
/// per-visit-enriched correlation collector; a lone file parses just that history.
///
/// # Errors
/// Propagates the underlying collection / parse error.
fn collect_timeline_events(
    path: &Path,
    selectors: &crate::selectors::Selectors,
) -> Result<Vec<BrowserEvent>> {
    if path.is_dir() {
        return collect_correlation_events(path, selectors);
    }
    // A lone history file: the `urls`-table chronology (matching the historic
    // single-file `timeline`), not the per-visit `visits` table `artifact history`
    // reconstruction needs — so a `visits`-less export still times out cleanly.
    let (family, history) = resolve_history(path)?;
    let mut events = match family {
        Family::Chromium => browser_forensic_chrome::parse_history(&history),
        Family::Firefox => browser_forensic_firefox::parse_history(&history),
        Family::Safari => browser_forensic_safari::parse_history(&history),
    }
    .map_err(|e| crate::output::actionable_db_error(e, &history))?;
    events.sort_by_key(|e| e.timestamp_ns);
    Ok(events)
}

/// Parse a `s`/`m`/`h`/`d`-suffixed duration into nanoseconds (a bare number is
/// seconds). The half-width of the `timeline --around` window.
///
/// # Errors
/// Returns an error on a non-numeric magnitude or an unrecognized unit suffix.
fn parse_duration_ns(s: &str) -> Result<i64> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let magnitude: i64 = num
        .parse()
        .with_context(|| format!("invalid duration magnitude in {s:?}"))?;
    let per_unit_ns: i64 = match unit.trim() {
        "" | "s" => 1_000_000_000,
        "m" => 60 * 1_000_000_000,
        "h" => 3_600 * 1_000_000_000,
        "d" => 86_400 * 1_000_000_000,
        other => anyhow::bail!("unrecognized duration unit {other:?} (want s/m/h/d) in {s:?}"),
    };
    Ok(magnitude.saturating_mul(per_unit_ns))
}

/// Keep only events within `window_ns` on either side of `pivot_ns` (RFC 0001
/// P5a `timeline --around`). Untimed events (`timestamp_ns == 0`) drop out of a
/// pivoted view.
fn retain_around(events: &mut Vec<BrowserEvent>, pivot_ns: i64, window_ns: i64) {
    let lo = pivot_ns.saturating_sub(window_ns);
    let hi = pivot_ns.saturating_add(window_ns);
    events.retain(|e| e.timestamp_ns >= lo && e.timestamp_ns <= hi);
}

/// `br4n6 timeline PATH [--around WHEN --window DUR] [--tz IANA] [--chains |
/// --graph <json|dot>] [--format …]` — the RFC 0001 P5a unified chronology verb.
///
/// The default view is the unified cross-artifact timeline + per-host rollup
/// (formerly `correlate`). `--chains` switches to referrer/redirect/session
/// reconstruction (formerly `chains`); `--graph <json|dot>` emits the entity
/// graph (formerly `graph`). `--around`/`--window` narrow every view to a pivot
/// moment; `--tz` renders timestamps in an IANA zone.
///
/// # Errors
/// Returns a loud error if the path does not exist, a timestamp/duration/timezone
/// is invalid, or event collection fails.
#[allow(clippy::too_many_arguments)] // one arg per timeline flag; a struct would only shuffle them
pub fn run_timeline(
    path: &Path,
    around: Option<&str>,
    window: &str,
    tz: Option<&str>,
    chains: bool,
    idle_gap: i64,
    graph: Option<GraphFormat>,
    graph_window: i64,
    format: Option<OutputFormat>,
    selectors: &crate::selectors::Selectors,
) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    // Validate the selectors up front so EVERY view (default/graph/chains) errors
    // loudly on a non-match, naming what was present (RFC 0001 D9).
    if selectors.is_active() && path.is_dir() {
        selectors.filter(investigation_profiles(path))?;
    }
    let tz = parse_tz(tz)?;
    let around_ns = around.map(parse_timestamp_ns).transpose()?;
    let window_ns = parse_duration_ns(window)?;
    let apply_around = |events: &mut Vec<BrowserEvent>| {
        if let Some(pivot) = around_ns {
            retain_around(events, pivot, window_ns);
        }
    };

    // Entity-graph view (formerly `graph`): timestamps carry no display, so `--tz`
    // does not apply; it renders to stdout (redirect for a file).
    if let Some(graph_format) = graph {
        let mut events = collect_timeline_events(path, selectors)?;
        apply_around(&mut events);
        print!("{}", graph_output(&events, graph_format, graph_window));
        return Ok(());
    }

    let resolved = crate::output::resolve_stdout(format);

    // Reconstruction view (formerly `chains`): referrer/redirect/session-enriched
    // per-visit navigation.
    if chains {
        let mut events = reconstruct_history(path, idle_gap)?;
        apply_around(&mut events);
        emit_events(&events, resolved);
        return Ok(());
    }

    // Default: the unified cross-artifact chronology + per-host rollup.
    let mut events = collect_timeline_events(path, selectors)?;
    apply_around(&mut events);
    print!("{}", correlate_output(&events, resolved, tz));
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

/// Format a Unix-nanoseconds timestamp as RFC 3339, in `tz` when given (the
/// `timeline --tz <IANA>` render), otherwise UTC ([`format_ts`]).
fn format_ts_tz(ns: i64, tz: Option<chrono_tz::Tz>) -> String {
    let Some(tz) = tz else {
        return format_ts(ns);
    };
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = u32::try_from(ns.rem_euclid(1_000_000_000)).unwrap_or(0);
    chrono::DateTime::from_timestamp(secs, nanos).map_or_else(
        || "invalid".to_string(),
        |utc| utc.with_timezone(&tz).to_rfc3339(),
    )
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
// helpers (`triage_summary_lines`, `infer_browser_from_filename`)
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
        // IE / Edge-Legacy consolidate every artifact into WebCacheV01.dat (ESE),
        // not the per-artifact SQLite files this dispatch parses.
        (BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy, _) => {
            anyhow::bail!(
                "IE / Edge-Legacy artifacts live in WebCacheV01.dat (ESE); use `br4n6 artifact webcache PATH`"
            );
        }
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
    let (key4_db, logins_json) = resolve_firefox_profile(path)?;
    decrypt_firefox_logins_with_key4(&key4_db, &logins_json, master_password, include_passwords)
}

/// Decrypt Firefox credentials with an explicit `key4.db` + `logins.json` (the
/// seam the `--keys` UX uses: `key4.db` located within the evidence root, the
/// `logins.json` read from the artifact path). Usernames are always returned; a
/// password only when `include_passwords`.
///
/// # Errors
/// Returns an error when the master password is wrong or a blob cannot be
/// decrypted (never a fabricated value).
pub fn decrypt_firefox_logins_with_key4(
    key4_db: &Path,
    logins_json: &Path,
    master_password: &str,
    include_passwords: bool,
) -> Result<Vec<BrowserEvent>> {
    use browser_forensic_core::{ArtifactKind, BrowserFamily};

    let logins = browser_forensic_decrypt::decrypt_firefox_logins(
        key4_db,
        logins_json,
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
            // The username is shown (D7); it rides the description so it appears
            // on the human/text render, not only in JSONL attrs.
            let desc = format!("{} \u{2014} {}", login.username, login.hostname);
            BrowserEvent::new(
                0,
                BrowserFamily::Firefox,
                ArtifactKind::LoginData,
                &source,
                desc,
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

/// Route `cookies` (RFC 0001 P6 / D7): with `--keys`, auto-locate key material
/// within the evidence root and decrypt; without it, parse plainly and COUNT the
/// encrypted values (reported, never dropped).
fn dispatch_cookies(
    path: &Path,
    format: OutputFormat,
    keys: Option<&Path>,
    keychain_service: &str,
    password_stdin: bool,
    manifest_out: Option<&Path>,
) -> Result<()> {
    match keys {
        Some(root) => run_cookies_decrypt(
            path,
            root,
            keychain_service,
            password_stdin,
            manifest_out,
            format,
        ),
        None => run_cookies_plain(path, format),
    }
}

/// Plain cookie parse: render every cookie, then COUNT the encrypted values and
/// point the examiner at `--keys` (RFC 0001 D7 — counted, never silently dropped).
fn run_cookies_plain(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = parse_cookie_events(path)?;
    events.sort_by_key(|e| e.timestamp_ns);
    let encrypted = events
        .iter()
        .filter(|e| e.attrs.get("encrypted_value").and_then(|v| v.as_str()) == Some("ENCRYPTED"))
        .count();
    print_events(&events, format);
    if encrypted > 0 {
        eprintln!(
            "{encrypted} cookie value(s) encrypted (shown as ENCRYPTED, never dropped) \u{2014} \
             add --keys <PATH> to decrypt"
        );
    }
    Ok(())
}

/// `br4n6 artifact cookies PATH --keys <ROOT>` handler: auto-locate the key within
/// the evidence root, decrypt, stamp per-record provenance, and (optionally) write
/// a manifest recording every key source and what it decrypted.
fn run_cookies_decrypt(
    path: &Path,
    root: &Path,
    keychain_service: &str,
    password_stdin: bool,
    manifest_out: Option<&Path>,
    format: OutputFormat,
) -> Result<()> {
    let password = read_stdin_password(password_stdin)?;
    let mut resolution =
        crate::keys::resolve_chromium_keys(root, password.as_deref(), keychain_service)?;
    // The "Keys:" provenance line goes to stderr so stdout stays a clean record
    // stream; it names exactly what was found and used (D7).
    eprintln!("Keys: {}", resolution.summary);

    let (mut events, method) = match &resolution.key {
        crate::keys::ChromiumKey::Macos(k) => (
            decrypt_chromium_cookies(path, k)?,
            "AES-128-CBC (macOS Keychain)",
        ),
        crate::keys::ChromiumKey::Win(k) => (
            decrypt_chromium_cookies_win(path, k)?,
            "AES-256-GCM (DPAPI)",
        ),
    };
    let decrypted = annotate_cookie_provenance(&mut events, method, &resolution.key_source);
    // Found ≠ decrypted: the key chain was unwrapped (found), and here is how many
    // items it actually decrypted (0 when every value was v20-refused).
    for ks in &mut resolution.audit {
        ks.decrypted_items = decrypted as u64;
    }

    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);

    if let Some(mp) = manifest_out {
        write_keyed_manifest(mp, path, &resolution.audit)?;
        eprintln!("wrote chain-of-custody manifest to {}", mp.display());
    }
    Ok(())
}

/// Stamp each decrypted cookie with machine-readable decryption provenance
/// (`encrypted` + `decryption{method,key_source}`) and return how many rows
/// actually decrypted (a `DECRYPT_FAILED` value stays `encrypted:true`).
fn annotate_cookie_provenance(
    events: &mut [BrowserEvent],
    method: &str,
    key_source: &str,
) -> usize {
    let mut decrypted = 0usize;
    for ev in events.iter_mut() {
        let ok = ev
            .attrs
            .get("value")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.starts_with("DECRYPT_FAILED"));
        if ok {
            decrypted += 1;
        }
        ev.attrs.insert("encrypted".to_string(), json!(!ok));
        ev.attrs.insert(
            "decryption".to_string(),
            json!({ "method": method, "key_source": key_source }),
        );
    }
    decrypted
}

/// Detect the browser family for a cookies path and parse its cookies, mirroring
/// [`run_artifact`]'s detection chain so plain and keyed paths agree.
fn parse_cookie_events(path: &Path) -> Result<Vec<BrowserEvent>> {
    use browser_forensic_core::detect_browser;
    let family = detect_browser(path)
        .or_else(|| infer_browser_from_filename(path))
        .or_else(|| preferences_family(path))
        .with_context(|| format!("cannot determine browser from path: {}", path.display()))?;
    match family {
        BrowserFamily::Chromium => browser_forensic_chrome::parse_cookies(path),
        BrowserFamily::Firefox => browser_forensic_firefox::parse_cookies(path),
        BrowserFamily::Safari => browser_forensic_safari::parse_cookies(path),
        BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy => anyhow::bail!(
            "IE / Edge-Legacy cookies live in WebCacheV01.dat (ESE); use `br4n6 artifact webcache PATH`"
        ),
    }
}

/// Write a chain-of-custody manifest over `evidence` + the key files used,
/// carrying the `--keys` key-source audit (RFC 0001 D7/D11).
fn write_keyed_manifest(
    out: &Path,
    evidence: &Path,
    audit: &[browser_forensic_manifest::KeySource],
) -> Result<()> {
    let mut inputs = vec![evidence.to_path_buf()];
    for ks in audit {
        if let Some(p) = &ks.path {
            inputs.push(PathBuf::from(p));
        }
    }
    let args: Vec<String> = std::env::args().collect();
    let run = browser_forensic_manifest::RunMetadata::capture(
        "br4n6",
        env!("CARGO_PKG_VERSION"),
        &args,
        None,
    );
    let mut manifest = browser_forensic_manifest::build_manifest(&inputs, run);
    manifest.key_sources = audit.to_vec();
    let json = browser_forensic_manifest::to_json(&manifest).context("serializing manifest")?;
    std::fs::write(out, json.as_bytes())
        .with_context(|| format!("writing manifest {}", out.display()))?;
    Ok(())
}

/// Read a single password line from stdin when `enabled` (never from argv — that
/// leaks to shell history + `ps`). Trailing CR/LF is stripped. `None` when the
/// flag is unset (the caller falls back to an empty password, e.g. Windows with a
/// blank logon password or a Firefox profile with no master password).
fn read_stdin_password(enabled: bool) -> Result<Option<String>> {
    use std::io::Read as _;
    if !enabled {
        return Ok(None);
    }
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading password from stdin")?;
    let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
    Ok(Some(trimmed))
}

/// The placeholder shown for a decrypted password on the terminal — the plaintext
/// is materialized to a file via `--reveal-secrets`, never printed (RFC 0001 D7).
const SECRET_PLACEHOLDER: &str = "[decrypted \u{2014} write with --reveal-secrets <file>]";

/// Route `logins` (RFC 0001 P6 / D7): with `--keys`, decrypt via NSS key material
/// located within the evidence root; without it, the plain metadata parser.
fn dispatch_logins(
    path: &Path,
    format: OutputFormat,
    keys: Option<&Path>,
    password_stdin: bool,
    reveal_secrets: Option<&Path>,
    manifest_out: Option<&Path>,
) -> Result<()> {
    match keys {
        Some(root) => run_logins_decrypt(
            path,
            root,
            password_stdin,
            reveal_secrets,
            manifest_out,
            format,
        ),
        None => run_artifact(path, ArtifactType::LoginData, format),
    }
}

/// `br4n6 artifact logins PATH --keys <ROOT>` handler: locate `key4.db` within the
/// evidence root, decrypt, and render. Usernames show; passwords NEVER reach the
/// terminal — they render as a placeholder, and materialize to `--reveal-secrets
/// <FILE>` only.
fn run_logins_decrypt(
    path: &Path,
    root: &Path,
    password_stdin: bool,
    reveal_secrets: Option<&Path>,
    manifest_out: Option<&Path>,
    format: OutputFormat,
) -> Result<()> {
    let master = read_stdin_password(password_stdin)?.unwrap_or_default();
    let (key4_db, mut audit) = crate::keys::locate_firefox_key4(root)?;
    eprintln!(
        "Keys: Firefox NSS key4.db ({}) \u{2192} loaded",
        key4_db.display()
    );
    let logins_json = resolve_firefox_logins_json(path)?;

    // Decrypt password plaintext only when it is bound for a file; otherwise
    // usernames-only, so no plaintext is ever materialized in memory needlessly.
    let want_secrets = reveal_secrets.is_some();
    let mut events =
        decrypt_firefox_logins_with_key4(&key4_db, &logins_json, &master, want_secrets)?;

    // Secrets to file ONLY (never the terminal), then redact the in-memory events
    // so stdout/JSONL can never carry a password.
    let decrypted = if let Some(file) = reveal_secrets {
        let n = write_secrets_file(file, &events)?;
        eprintln!("wrote {n} decrypted secret(s) to {}", file.display());
        n
    } else {
        events.len()
    };
    redact_login_passwords(&mut events);
    for ks in &mut audit {
        ks.decrypted_items = decrypted as u64;
    }

    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);

    if let Some(mp) = manifest_out {
        write_keyed_manifest(mp, &logins_json, &audit)?;
        eprintln!("wrote chain-of-custody manifest to {}", mp.display());
    }
    Ok(())
}

/// Resolve a Firefox `logins.json` from the artifact path (a profile dir, the
/// `logins.json` itself, or a sibling file).
fn resolve_firefox_logins_json(path: &Path) -> Result<PathBuf> {
    let candidate = if path.is_dir() {
        path.join("logins.json")
    } else if path.file_name().and_then(|n| n.to_str()) == Some("logins.json") {
        path.to_path_buf()
    } else {
        path.parent()
            .map_or_else(|| PathBuf::from("logins.json"), |p| p.join("logins.json"))
    };
    if !candidate.exists() {
        anyhow::bail!("no logins.json found at {}", candidate.display());
    }
    Ok(candidate)
}

/// Write decrypted secrets (host, username, password) to a file, one JSON object
/// per line. The FILE is the only place plaintext passwords are ever written.
fn write_secrets_file(file: &Path, events: &[BrowserEvent]) -> Result<usize> {
    let mut out = String::new();
    let mut count = 0usize;
    for ev in events {
        let password = ev.attrs.get("password").and_then(|v| v.as_str());
        // Only rows that actually carry a decrypted password (not the
        // usernames-only placeholder) are materialized.
        let Some(pw) = password.filter(|p| !p.starts_with("(not decrypted")) else {
            continue;
        };
        let record = json!({
            "hostname": ev.attrs.get("hostname"),
            "username": ev.attrs.get("username"),
            "password": pw,
        });
        out.push_str(&record.to_string());
        out.push('\n');
        count += 1;
    }
    std::fs::write(file, out.as_bytes())
        .with_context(|| format!("writing secrets file {}", file.display()))?;
    Ok(count)
}

/// Replace every event's `password` attr with the file-output placeholder so no
/// password plaintext can reach stdout/JSONL (RFC 0001 D7 — terminal is never a
/// secrets sink).
fn redact_login_passwords(events: &mut [BrowserEvent]) {
    for ev in events.iter_mut() {
        if ev.attrs.contains_key("password") {
            ev.attrs
                .insert("password".to_string(), json!(SECRET_PLACEHOLDER));
            // TEXT render shows only the description, so surface the placeholder
            // there too: usernames show, the password reads as the file-output
            // placeholder — never plaintext on the terminal (RFC 0001 D7).
            ev.description = format!("{} {SECRET_PLACEHOLDER}", ev.description);
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

/// Collect a profile/home directory's events, scoped by the user/profile/browser
/// selectors (RFC 0001 D9). With no selector this is exactly
/// [`collect_profile_events`]; with a selector it discovers + filters profiles
/// (a non-match is a loud error naming what WAS present), collects each selected
/// profile's events, and stamps every event with its origin.
///
/// # Errors
/// Propagates a bootstrap failure (nonexistent path), a non-matching selector, or
/// a per-profile collection error.
fn collect_profile_events_scoped(
    path: &Path,
    selectors: &crate::selectors::Selectors,
) -> Result<Vec<BrowserEvent>> {
    if !selectors.is_active() {
        return collect_profile_events(path);
    }
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    let profiles = selectors.filter(investigation_profiles(path))?;
    let mut events = Vec::new();
    for profile in &profiles {
        let report =
            browser_forensic_triage::triage_profile(&profile.path, profile.browser.clone())
                .with_context(|| {
                    format!("collecting events from profile {}", profile.path.display())
                })?;
        let mut frag = report.events;
        for event in &mut frag {
            crate::selectors::stamp_event(event, profile);
        }
        events.append(&mut frag);
    }
    events.sort_by_key(|e| e.timestamp_ns);
    Ok(events)
}

/// The history file inside a profile directory for a given family, if present.
fn history_file_for(profile: &Path, family: BrowserFamily) -> Option<PathBuf> {
    let name = match family {
        BrowserFamily::Chromium => "History",
        BrowserFamily::Firefox => "places.sqlite",
        BrowserFamily::Safari => "History.db",
        BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy => "WebCacheV01.dat",
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
            // No per-visit redirect graph for Safari or the WebCache families.
            BrowserFamily::Safari | BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy => {
                continue
            }
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
fn collect_correlation_events(
    path: &Path,
    selectors: &crate::selectors::Selectors,
) -> Result<Vec<BrowserEvent>> {
    // A scoped run returns only the selected profiles' events (origin-stamped),
    // WITHOUT the path-wide per-visit enrichment — that lever reads every
    // profile's `visits` and would reintroduce out-of-scope data (D9).
    if selectors.is_active() {
        return collect_profile_events_scoped(path, selectors);
    }
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

/// One resolved search term: the string to display and its compiled pattern.
struct TermPat {
    display: String,
    pattern: browser_forensic_search::Pattern,
}

/// Read a term-list file: one term per line, blanks and `#` comments removed.
fn read_terms_file(file: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("reading term list {}", file.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(ToString::to_string)
        .collect())
}

/// The SQLite history databases discovered under `path` (per profile, with a
/// single-profile fallback) — the substrate the bounded carve pass reads.
fn history_dbs(path: &Path) -> Vec<PathBuf> {
    let mut dbs = Vec::new();
    for profile in browser_forensic_discovery::discover_profiles(path) {
        if let Some(hf) = history_file_for(&profile.path, profile.browser.clone()) {
            dbs.push(hf);
        }
    }
    if dbs.is_empty() {
        if let Some(family) = profile_family(path) {
            if let Some(hf) = history_file_for(path, family) {
                dbs.push(hf);
            }
        }
    }
    dbs
}

/// Bounded carve for `find`: recover deleted records from every discovered
/// history DB's free pages and WAL (the same engines `carve` uses) and return a
/// carved hit for each record whose fields match `pattern`. Carved records are
/// stamped `carved`/`carved` — never live or visited (D4).
fn find_carve_hits(
    path: &Path,
    term: &str,
    pattern: &browser_forensic_search::Pattern,
) -> Vec<FindHit> {
    let mut hits = Vec::new();
    for db in history_dbs(path) {
        let mut records = Vec::new();
        if let Ok(r) = browser_forensic_carve::carve_sqlite_free_pages(&db) {
            records.extend(r.records);
        }
        if let Ok(r) = browser_forensic_carve::recover_from_wal(&db) {
            records.extend(r.records);
        }
        for rec in &records {
            let mut matched: Option<String> = None;
            for (key, value) in &rec.fields {
                if let Some(s) = value.as_str() {
                    if pattern.is_match(s) {
                        matched = Some(s.to_string());
                        if key.eq_ignore_ascii_case("url") {
                            break;
                        }
                    }
                }
            }
            if matched.is_none() {
                let serialized = serde_json::to_string(&rec.fields).unwrap_or_default();
                if pattern.is_match(&serialized) {
                    matched = Some(serialized);
                }
            }
            if let Some(value) = matched {
                let provenance =
                    crate::find::provenance_for(&browser_forensic_core::ArtifactKind::Carved);
                let confidence = crate::find::confidence_for(provenance.state);
                let rule_id = crate::find::rule_for(&provenance);
                hits.push(FindHit {
                    term: term.to_string(),
                    confidence,
                    rule_id,
                    provenance,
                    match_value: value,
                    timestamp_ns: 0,
                    browser: None,
                    profile: None,
                    user: None,
                });
            }
        }
    }
    hits
}

/// `br4n6 find <TERM> <PATH>` — the RFC 0001 P4 provenance-first lookup verb.
///
/// Auto-classifies TERM by shape (or takes it from `--regex`/`--term`/
/// `--terms-file`/`@file`), searches across live artifacts, recovered domains,
/// and bounded deleted-record carving, and emits one *provenance-tagged* row per
/// hit — a live visit, a recovered domain, and a carved record stay distinct
/// (D4), never collapsed. TTY renders a markdown-clean table; a pipe emits JSONL
/// carrying every axis. An empty result proves it looked (D10).
///
/// # Errors
/// Returns an error for a missing/ambiguous PATH, an invalid regex or timestamp,
/// an unreadable term list, or a collection failure.
#[allow(clippy::too_many_arguments)]
pub fn run_find(
    term: Option<&str>,
    path: Option<&Path>,
    regex: Option<&str>,
    literal: Option<&str>,
    terms_file: Option<&Path>,
    iocs: bool,
    from: Option<&str>,
    to: Option<&str>,
    sources: &[SourceKind],
    format: Option<OutputFormat>,
    selectors: &crate::selectors::Selectors,
) -> Result<()> {
    use browser_forensic_core::finding::EvidenceSource;
    use browser_forensic_search::{filter_events, EventQuery, Pattern};

    // `--iocs` is a distinct, pattern-free enumeration mode (RFC 0001 P5c): no
    // TERM, no --regex/--term/--terms-file — it lists every candidate entity.
    if iocs {
        if regex.is_some() || literal.is_some() || terms_file.is_some() {
            anyhow::bail!(
                "--iocs enumerates all IOCs; drop --regex/--term/--terms-file (usage: br4n6 find --iocs <PATH>)"
            );
        }
        return run_find_iocs(term, path, from, to, sources, format, selectors);
    }

    // Resolve the PATH: when the term comes from a flag, the single positional is
    // the PATH; otherwise the canonical `find <TERM> <PATH>` two-positional form.
    let flag_mode = regex.is_some() || literal.is_some() || terms_file.is_some();
    let evidence_path: PathBuf = if flag_mode {
        match (term, path) {
            (Some(p), None) => PathBuf::from(p),
            (None, Some(p)) => p.to_path_buf(),
            (Some(_), Some(_)) => anyhow::bail!(
                "with --regex/--term/--terms-file, pass only the PATH (the term comes from the flag)"
            ),
            (None, None) => anyhow::bail!("missing PATH: br4n6 find <PATH> --regex <PAT>"),
        }
    } else {
        match (term, path) {
            (Some(_), Some(p)) => p.to_path_buf(),
            _ => anyhow::bail!(
                "usage: br4n6 find <TERM> <PATH>  (or --regex/--term/--terms-file with <PATH>)"
            ),
        }
    };

    // Build the (display, pattern) term set and the classification announcement.
    let mut terms: Vec<TermPat> = Vec::new();
    let announce: String;
    if let Some(pat) = regex {
        let pattern = Pattern::regex(pat).with_context(|| format!("invalid regex: {pat}"))?;
        announce = format!(
            "Searching with regex /{pat}/ in {} …",
            evidence_path.display()
        );
        terms.push(TermPat {
            display: pat.to_string(),
            pattern,
        });
    } else if let Some(lit) = literal {
        announce = format!(
            "Searching for literal term \"{lit}\" in {} …",
            evidence_path.display()
        );
        terms.push(TermPat {
            display: lit.to_string(),
            pattern: Pattern::substring(lit),
        });
    } else if let Some(file) = terms_file {
        let list = read_terms_file(file)?;
        announce = format!(
            "Searching for {} term(s) from {} in {} …",
            list.len(),
            file.display(),
            evidence_path.display()
        );
        for t in list {
            terms.push(TermPat {
                pattern: Pattern::substring(&t),
                display: t,
            });
        }
    } else {
        let raw = term.unwrap_or_default();
        if let Some(fname) = raw.strip_prefix('@') {
            let file = Path::new(fname);
            let list = read_terms_file(file)?;
            announce = format!(
                "Searching for {} term(s) from {} in {} …",
                list.len(),
                file.display(),
                evidence_path.display()
            );
            for t in list {
                terms.push(TermPat {
                    pattern: Pattern::substring(&t),
                    display: t,
                });
            }
        } else {
            let kind = crate::find::classify_term(raw);
            announce = format!(
                "Searching for {} \"{raw}\" in {} …",
                crate::find::describe_term(&kind),
                evidence_path.display()
            );
            terms.push(TermPat {
                display: raw.to_string(),
                pattern: Pattern::substring(raw),
            });
        }
    }
    if terms.is_empty() {
        anyhow::bail!(
            "no search terms (the @file / --terms-file was empty after removing blanks/comments)"
        );
    }
    eprintln!("{announce}");

    let output_format = crate::output::resolve_stdout(format);
    let from_ns = from.map(parse_timestamp_ns).transpose()?;
    let to_ns = to.map(parse_timestamp_ns).transpose()?;

    // Source scoping (empty = all sources).
    let allowed: Vec<EvidenceSource> = sources.iter().map(|s| s.evidence_source()).collect();
    let source_allowed = |src: &EvidenceSource| allowed.is_empty() || allowed.contains(src);
    let carved_wanted = allowed.is_empty() || allowed.contains(&EvidenceSource::Carved);

    // Live artifacts + recovered domains (triage folds recovered-domain artifacts
    // into the event stream); each hit's provenance is derived from its artifact.
    // Scoped to the selected user/profile/browser (RFC 0001 D9) when set.
    let events = collect_profile_events_scoped(&evidence_path, selectors)?;
    let mut hits: Vec<FindHit> = Vec::new();
    for tp in &terms {
        let query = EventQuery {
            pattern: Some(tp.pattern.clone()),
            fields: Vec::new(),
            from_ns,
            to_ns,
        };
        for e in filter_events(&events, &query) {
            let hit = FindHit::from_event(&tp.display, e);
            if source_allowed(&hit.provenance.source) {
                hits.push(hit);
            }
        }
    }
    // Bounded deleted-record carving.
    if carved_wanted {
        for tp in &terms {
            hits.extend(find_carve_hits(&evidence_path, &tp.display, &tp.pattern));
        }
    }

    emit_find_hits(&hits, output_format);

    if hits.is_empty() {
        let mut searched = vec![
            "live history",
            "downloads",
            "bookmarks",
            "cookies",
            "recovered domains",
        ];
        if carved_wanted {
            searched.push("deleted SQLite records");
        }
        eprintln!(
            "{}",
            crate::output::negative_result(
                &searched,
                &[
                    "encrypted cookies (add --keys)",
                    "memory",
                    "whole-image carving"
                ],
            )
        );
    }
    Ok(())
}

/// `br4n6 find --iocs <PATH>` — pattern-free IOC *enumeration* (RFC 0001 P5c).
///
/// Collects the profile/home events (the same path `find` uses) and enumerates
/// every candidate entity via [`browser_forensic_search::extract_iocs`] — reusing
/// that extractor, never reimplementing it. Each IOC becomes a provenance-tagged
/// [`FindHit`] whose source is its origin event's evidence class but whose
/// user-action claim is `observed-string` (an IOC-shaped string merely appears;
/// it is not a claimed visit/search/download). Scopes with `--from`/`--to` (via
/// the shared time-window filter) and `--source`.
///
/// # Errors
/// Returns an error for a missing PATH, a positional TERM (enumeration takes no
/// query), an invalid timestamp, or a collection failure.
fn run_find_iocs(
    term: Option<&str>,
    path: Option<&Path>,
    from: Option<&str>,
    to: Option<&str>,
    sources: &[SourceKind],
    format: Option<OutputFormat>,
    selectors: &crate::selectors::Selectors,
) -> Result<()> {
    use browser_forensic_core::finding::EvidenceSource;
    use browser_forensic_search::{filter_events, EventQuery};

    // Pattern-free enumeration takes no TERM: the single positional is the PATH.
    let evidence_path: PathBuf = match (term, path) {
        (None, Some(p)) => p.to_path_buf(),
        (Some(p), None) => PathBuf::from(p),
        (Some(_), Some(_)) => anyhow::bail!(
            "--iocs enumerates all IOCs; drop the TERM (usage: br4n6 find --iocs <PATH>)"
        ),
        (None, None) => anyhow::bail!("missing PATH: br4n6 find --iocs <PATH>"),
    };

    let output_format = crate::output::resolve_stdout(format);
    let from_ns = from.map(parse_timestamp_ns).transpose()?;
    let to_ns = to.map(parse_timestamp_ns).transpose()?;

    let allowed: Vec<EvidenceSource> = sources.iter().map(|s| s.evidence_source()).collect();
    let source_allowed = |src: &EvidenceSource| allowed.is_empty() || allowed.contains(src);

    eprintln!("Enumerating IOCs in {} …", evidence_path.display());

    // Scope the events by the time window first, then extract — so an IocMatch's
    // `event_index` indexes the same scoped slice and time scoping matches `find`.
    let events = collect_profile_events_scoped(&evidence_path, selectors)?;
    let query = EventQuery {
        pattern: None,
        fields: Vec::new(),
        from_ns,
        to_ns,
    };
    let scoped: Vec<BrowserEvent> = filter_events(&events, &query)
        .into_iter()
        .cloned()
        .collect();

    let iocs = browser_forensic_search::extract_iocs(&scoped);
    let mut hits: Vec<FindHit> = Vec::new();
    for m in &iocs {
        let Some(event) = scoped.get(m.event_index) else {
            continue;
        };
        let hit = FindHit::from_ioc(m.kind.label(), &m.value, event);
        if source_allowed(&hit.provenance.source) {
            hits.push(hit);
        }
    }

    emit_find_hits(&hits, output_format);

    if hits.is_empty() {
        eprintln!(
            "{}",
            crate::output::negative_result(
                &["live history", "downloads", "bookmarks", "cookies", "cache"],
                &["encrypted values", "deleted/carved records", "memory"],
            )
        );
    }
    Ok(())
}

/// Render `find` hits: a markdown-clean provenance table on a TTY, faithful JSONL
/// (every axis, one object per line) on a pipe, and CSV when forced.
fn emit_find_hits(hits: &[FindHit], format: OutputFormat) {
    match format {
        OutputFormat::Text => {
            if hits.is_empty() {
                return;
            }
            let rows: Vec<Vec<String>> = hits.iter().map(FindHit::row).collect();
            print!("{}", crate::output::markdown_table(&FIND_HEADERS, &rows));
        }
        OutputFormat::Jsonl => {
            for h in hits {
                let mut v = serde_json::to_value(h).unwrap_or_else(|_| json!({}));
                if h.timestamp_ns != 0 {
                    if let Some(map) = v.as_object_mut() {
                        map.insert("timestamp".to_string(), json!(format_ts(h.timestamp_ns)));
                    }
                }
                println!(
                    "{}",
                    serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string())
                );
            }
        }
        OutputFormat::Csv => {
            println!("{}", FIND_HEADERS.join(","));
            for h in hits {
                let row: Vec<String> = h.row().iter().map(|c| csv_escape(c)).collect();
                println!("{}", row.join(","));
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
#[allow(clippy::too_many_arguments)] // one param per RFC 0001 report concern; a 1:1 CLI mapping
pub fn run_report(
    path: &Path,
    format: crate::report::ReportFormat,
    bundle: bool,
    output: Option<&Path>,
    timezone: Option<&str>,
    manifest_out: Option<&Path>,
    selectors: &crate::selectors::Selectors,
) -> Result<()> {
    use std::io::Write as _;

    use crate::report::{self, ReportFormat};

    // `--bundle` writes the reproducible directory deliverable (RFC 0001 P8),
    // not a single file; `-o <DIR>` is then the output directory (required).
    if bundle {
        let dir = output
            .context("--bundle writes a directory: pass -o <DIR> for the reproducible bundle")?;
        return run_report_bundle(path, dir, timezone, selectors);
    }

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

    // Scope the reported events to the selected user/profile/browser (RFC 0001
    // D9), origin-stamped; a non-match errors loudly, naming what was present.
    if selectors.is_active() {
        events = collect_profile_events_scoped(path, selectors)?;
    }

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

/// `br4n6 report --bundle -o <DIR>` — the RFC 0001 P8 reproducible court/exam
/// deliverable. Drives the same standard-tier investigation as `investigate`
/// (so the bundle's ranked findings match the golden path), then hands the
/// events, ranked findings, report meta, and a fully-populated chain-of-custody
/// manifest to [`crate::bundle::write_bundle`], which serializes the HTML
/// summary, the machine timeline (xlsx + jsonl), the manifest, and a SHA-256
/// sidecar hashing them all. Read-only over the evidence.
///
/// # Errors
/// Returns a loud error if the path does not exist (a bootstrap failure is never
/// absorbed into an empty bundle), the timezone is unknown, no recognized
/// evidence is found, or writing any bundle file fails.
fn run_report_bundle(
    path: &Path,
    dir: &Path,
    timezone: Option<&str>,
    selectors: &crate::selectors::Selectors,
) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    let tz = parse_tz(timezone)?;

    // Same bounded standard-tier investigation as the golden path, so the
    // bundle's ranked findings are exactly what `investigate <PATH>` shows.
    // Silent progress (bundle is a one-shot write, not an interactive run); no
    // checkpoint (a read-only tool never writes into evidence unasked).
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let progress = crate::progress::Progress::select(false, false);
    let mut checkpoint = None;
    let tier = crate::investigate::Tier::Standard;
    let (profiles, mut report, findings, _interrupted) =
        collect_investigation(path, tier, &progress, &cancel, &mut checkpoint, selectors)?;
    let findings = crate::investigate::rank_findings(findings);

    let mut events = std::mem::take(&mut report.events);
    events.sort_by_key(|e| e.timestamp_ns);

    // Layered detection basis for every input (RFC 0001 D8), recorded into the
    // manifest for court defensibility.
    let detections = investigation_detections(path, &profiles, None);
    let manifest = build_bundle_manifest(path, tz, &findings, &detections)?;

    let meta = crate::report::ReportMeta {
        case: None,
        examiner: None,
        tool: "br4n6".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timezone: tz.map_or_else(|| "UTC".to_string(), |t| t.name().to_string()),
        generated_at_ns: report.generated_at_ns,
        flags: report_flags(&report),
    };

    let bundle = crate::bundle::Bundle {
        events: &events,
        findings: &findings,
        meta: &meta,
        manifest: &manifest,
        tz,
    };
    let written = crate::bundle::write_bundle(dir, &bundle)?;
    eprintln!(
        "wrote reproducible report bundle to {} ({} events, {} finding(s); files: {})",
        dir.display(),
        events.len(),
        findings.len(),
        written.join(", "),
    );
    Ok(())
}

/// Build the bundle's chain-of-custody manifest with every RFC 0001 D11 audit
/// field populated: hashed inputs, the exact command line (via [`RunMetadata`]),
/// per-input detection basis + confidence (D8), the rule versions that ran, the
/// timezone-conversion rule, the tool/build/schema versions.
///
/// # Errors
/// Returns an error if no recognized evidence is found under `path` or manifest
/// serialization fails.
fn build_bundle_manifest(
    path: &Path,
    tz: Option<chrono_tz::Tz>,
    findings: &[browser_forensic_core::finding::Finding],
    detections: &[(PathBuf, crate::detect::Detection)],
) -> Result<browser_forensic_manifest::Manifest> {
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
    let mut manifest = browser_forensic_manifest::build_manifest(&inputs, run);
    manifest.detection_basis = detections
        .iter()
        .map(|(p, det)| crate::detect::to_record(p, det))
        .collect();
    manifest.rule_versions = crate::bundle::rule_versions_from_findings(findings);
    manifest.tool_version = Some(env!("CARGO_PKG_VERSION").to_string());
    manifest.build_hash = option_env!("VERGEN_GIT_SHA")
        .or(option_env!("GIT_HASH"))
        .map(str::to_string);
    manifest.timezone_rule = Some(crate::bundle::timezone_rule(tz));
    manifest.output_schema_version = Some("browser-forensic/finding/v1".to_string());
    Ok(manifest)
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
        BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy => {
            browser_forensic_webcache::parse_webcache(path)?
        }
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

/// `br4n6 artifact storage PATH` — parse web storage (Local/Session Storage, IndexedDB)
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

/// `br4n6 artifact webcache PATH` — parse an IE / Edge-Legacy `WebCacheV01.dat` (ESE) into
/// a chronological event stream: history visits, cookies, cached content, and
/// DOM storage, each tagged with its browser family and artifact kind. Read-only.
///
/// # Errors
/// Returns an error if the file cannot be opened as an ESE database or its
/// `Containers` table cannot be read (a bootstrap failure, surfaced loud).
pub fn run_webcache(path: &Path, format: OutputFormat) -> Result<()> {
    let mut events = browser_forensic_webcache::parse_webcache(path)
        .with_context(|| format!("parsing WebCache from {}", path.display()))?;
    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, format);
    Ok(())
}

/// `br4n6 artifact cachestorage PATH` — recover Service Worker CacheStorage (Cache API)
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

/// Map a [`RecoveredResource`](browser_forensic_cache::RecoveredResource) to a
/// normalized [`BrowserEvent`], carrying the recovery provenance a live-index hit
/// does not need: `recovered=true`, the carve mechanism, and its recovery quality
/// (full/partial). The note keeps consistent-with framing — a carved entry is a
/// recovered artifact, never asserted to be a deliberate user deletion. Consumed
/// by the `recover` orchestrator's orphaned-cache finding-generator.
fn cache_carve_event(r: &browser_forensic_cache::RecoveredResource) -> BrowserEvent {
    let res = &r.resource;
    let ts = res.response_time_ns.or(res.request_time_ns).unwrap_or(0);
    let mut ev = BrowserEvent::new(
        ts,
        browser_forensic_core::BrowserFamily::Chromium,
        browser_forensic_core::ArtifactKind::Cache,
        res.source_file.display().to_string(),
        res.url.clone(),
    )
    .with_attr("artifact_subtype", json!("cache_carve"))
    .with_attr("recovered", json!(true))
    .with_attr("recovery_mechanism", json!(r.mechanism.as_str()))
    .with_attr("recovery_quality", json!(r.quality.as_str()))
    .with_attr("recovery_note", json!(r.note))
    .with_attr("body_len", json!(res.decoded_body.len()))
    .with_attr("raw_body_len", json!(res.raw_body.len()));
    if let Some(s) = res.http_status {
        ev = ev.with_attr("http_status", json!(s));
    }
    if let Some(ct) = &res.content_type {
        ev = ev.with_attr("content_type", json!(ct));
    }
    if let Some(ce) = &res.content_encoding {
        ev = ev.with_attr("content_encoding", json!(ce));
    }
    if let Some(note) = &res.decode_note {
        ev = ev.with_attr("decode_note", json!(note));
    }
    if let Some(sparse) = &res.sparse_file {
        ev = ev.with_attr("sparse_file", json!(sparse.display().to_string()));
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

    match url {
        Some(target) => println!(
            "Reconstructed cached representations consistent with access to {target} \
             (what the cache STORED, NOT a rendering of the page as displayed; \
             JS/SPA/lazy-loaded/auth-gated content may be absent)."
        ),
        None => println!(
            "Reconstructed cached representations consistent with access \
             (what the cache STORED, NOT a rendering of the page as displayed; \
             JS/SPA/lazy-loaded/auth-gated content may be absent)."
        ),
    }
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

/// `br4n6 artifact indexeddb PATH` — decode a Chromium IndexedDB LevelDB directory
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

/// `br4n6 artifact permissions PATH` — surface per-site permission grants. `PATH` is a
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

/// `br4n6 artifact credentials PATH` — surface stored account/payment metadata from a
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

/// `br4n6 artifact favicons PATH` — parse a Chromium `Favicons` database. Every stored
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

/// `br4n6 artifact top-sites PATH` — parse a Chromium `Top Sites` database (the
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

/// `br4n6 artifact extension-cookies PATH` — parse a Chromium `Extension Cookies` jar
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

/// `br4n6 artifact typed-input PATH` — list strings the user typed into the Firefox
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

/// `br4n6 artifact annotations PATH` — list Firefox page annotations (`moz_annos`).
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

/// `br4n6 artifact deleted-bookmarks PATH` — recover bookmarks present in a Firefox
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

/// `br4n6 artifact media-history PATH` — parse a Chromium `Media History` database:
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

/// `br4n6 artifact network-action-predictor PATH` — parse a Chromium `Network Action Predictor`: the
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

/// `br4n6 artifact shortcuts PATH` — parse a Chromium `Shortcuts` database: the omnibox
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

/// `br4n6 image PATH [--snapshot XID]` — ingest browser artifacts from a disk
/// image, delegating all disk work to the forensic-vfs fleet. Fails loud on any
/// bootstrap problem (unopenable image, no filesystem, no profiles), never a
/// silent empty result.
pub fn run_image(path: &Path, snapshot: Option<u64>, format: OutputFormat) -> Result<()> {
    let events = browser_forensic_image::ingest_image_path(path, snapshot)?;
    match format {
        OutputFormat::Text => {
            println!(
                "Recovered {} browser event(s) from {}",
                events.len(),
                path.display()
            );
            for ev in events.iter().take(50) {
                println!("  {}", fmt::event_to_text(ev));
            }
            if events.len() > 50 {
                println!("  ... and {} more events", events.len() - 50);
            }
        }
        OutputFormat::Jsonl => {
            for ev in &events {
                if let Ok(json) = serde_json::to_string(ev) {
                    println!("{json}");
                }
            }
        }
        OutputFormat::Csv => {
            println!("{}", fmt::TIMELINE_CSV_HEADER);
            for ev in &events {
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
/// / host). `tz` renders the timestamp in an IANA zone when given.
fn correlate_row_text(e: &BrowserEvent, tz: Option<chrono_tz::Tz>) -> String {
    format!(
        "[{ts}] {browser}/{artifact} {host}  {desc}\n",
        ts = format_ts_tz(e.timestamp_ns, tz),
        browser = e.browser,
        artifact = e.artifact,
        host = event_host(e),
        desc = e.description,
    )
}

/// A unified-timeline event as one JSONL object (`record":"event"`). The numeric
/// `timestamp_ns` is always UTC-faithful; the human `timestamp` honors `tz`.
fn correlate_row_json(e: &BrowserEvent, tz: Option<chrono_tz::Tz>) -> String {
    let obj = json!({
        "record": "event",
        "timestamp_ns": e.timestamp_ns,
        "timestamp": format_ts_tz(e.timestamp_ns, tz),
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
fn correlate_row_csv(e: &BrowserEvent, tz: Option<chrono_tz::Tz>) -> String {
    format!(
        "{},{},{},{},{},{},{}\n",
        csv_escape(&format_ts_tz(e.timestamp_ns, tz)),
        csv_escape(&e.browser.to_string()),
        csv_escape(&e.artifact.to_string()),
        csv_escape(&event_host(e)),
        csv_escape(&e.source),
        csv_escape(&e.description),
        csv_escape(&attr_str(e, "url")),
    )
}

/// Render the unified cross-artifact timeline and per-host rollup for
/// `br4n6 timeline` (RFC 0001 P5a; formerly `correlate`). `tz` renders human
/// timestamps in an IANA zone; numeric `timestamp_ns` stays UTC-faithful.
///
/// - `text`: a human timeline section (untimed rows grouped) followed by the
///   per-host rollup.
/// - `jsonl`: a leading `timeline_summary` record, one `event` record per
///   timeline row, then one `host` record per rollup.
/// - `csv`: the unified timeline rows only (one clean schema); use `jsonl`/`text`
///   for the rollup.
#[must_use]
pub fn correlate_output(
    events: &[BrowserEvent],
    format: OutputFormat,
    tz: Option<chrono_tz::Tz>,
) -> String {
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
                out.push_str(&correlate_row_text(e, tz));
            }
            if !tl.untimed.is_empty() {
                out.push_str(&format!("-- untimed ({}) --\n", tl.untimed.len()));
                for e in &tl.untimed {
                    out.push_str(&correlate_row_text(e, tz));
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
                    (Some(f), Some(l)) => {
                        format!("{}..{}", format_ts_tz(f, tz), format_ts_tz(l, tz))
                    }
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
                out.push_str(&correlate_row_json(e, tz));
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
                out.push_str(&correlate_row_csv(e, tz));
            }
        }
    }
    out
}

/// Render the entity graph for `br4n6 timeline --graph` in the requested format.
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
        let out = correlate_output(&events, OutputFormat::Text, None);
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
        let out = correlate_output(&events, OutputFormat::Jsonl, None);
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
        let out = correlate_output(&events, OutputFormat::Csv, None);
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

        let events =
            collect_correlation_events(dir.path(), &crate::selectors::Selectors::default())
                .unwrap();
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
    fn triage_summary_helpers() {
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

    #[test]
    fn run_image_fails_loud_when_engine_unavailable() {
        // Opening a disk image needs the (unpublished) forensic-vfs engine, so
        // `br4n6 image` must fail loud naming the path — never exit 0 / silent.
        let err = format!(
            "{:#}",
            run_image(Path::new("/evidence/case.E01"), None, OutputFormat::Text).unwrap_err()
        );
        assert!(err.contains("/evidence/case.E01"), "names the image: {err}");
        assert!(
            err.contains("forensic-vfs engine"),
            "explains the disk seam: {err}"
        );
    }

    // ---- RFC 0001 P3b concern 2: SIGINT partial flush ----------------------

    /// Build a Chrome profile directory whose `History` carries one executable
    /// download named `exe_name`, so the parsed events are attributable to it.
    fn chrome_profile_with_download(dir: &Path, exe_name: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let history = dir.join("History");
        let conn = rusqlite::Connection::open(&history).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1,'https://example.com','Example',1,13327626000000000);
             INSERT INTO visits VALUES (1,1,13327626000000000,0,0);
             CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT NOT NULL DEFAULT '', start_time INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0, state INTEGER NOT NULL DEFAULT 0, danger_type INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE downloads_url_chains (id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url TEXT NOT NULL);
             INSERT INTO downloads (id,target_path,start_time,total_bytes,state,danger_type) VALUES (1,'/Users/x/Downloads/{exe_name}',13327626000000000,1024,1,0);
             INSERT INTO downloads_url_chains (id,chain_index,url) VALUES (1,0,'https://evil.example/{exe_name}');"
        ))
        .unwrap();
        drop(conn);
    }

    fn discovered_chrome(path: &Path, name: &str) -> browser_forensic_discovery::DiscoveredProfile {
        browser_forensic_discovery::DiscoveredProfile {
            browser: BrowserFamily::Chromium,
            name: name.to_string(),
            path: path.to_path_buf(),
            container: None,
        }
    }

    /// An [`InvestigationProgress`] that trips the cancellation flag the first
    /// time any parse unit is reported, simulating a Ctrl-C landing during the
    /// first profile's work.
    struct CancelOnFirstUnit {
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl browser_forensic_triage::TriageProgress for CancelOnFirstUnit {
        fn on_unit(&self, _profile: &str, _artifact: &str) {
            self.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl crate::progress::InvestigationProgress for CancelOnFirstUnit {
        fn set_profile(&self, _done: usize, _total: usize) {}
        fn finish(&self) {}
    }

    #[test]
    fn interrupted_footer_names_partial_and_resume() {
        let f = interrupted_footer(3, 5, "/ev/case");
        assert!(f.contains("interrupted"), "marks the run interrupted: {f}");
        assert!(
            f.contains('3') && f.contains('5'),
            "names how far it got (3/5): {f}"
        );
        assert!(
            f.to_lowercase().contains("resume") && f.contains("br4n6 investigate /ev/case"),
            "tells the operator how to resume: {f}"
        );
        assert!(
            f.to_lowercase().contains("not complete") || f.to_lowercase().contains("partial"),
            "makes incompleteness explicit: {f}"
        );
    }

    #[test]
    fn run_profile_loop_stops_at_next_boundary_and_flushes_partial() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = dir.path().join("A");
        let b = dir.path().join("B");
        chrome_profile_with_download(&a, "evil1.exe");
        chrome_profile_with_download(&b, "evil2.exe");
        let profiles = vec![discovered_chrome(&a, "A"), discovered_chrome(&b, "B")];

        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress = CancelOnFirstUnit {
            cancel: std::sync::Arc::clone(&cancel),
        };

        let mut no_cp = None;
        let (report, _findings, interrupted) = run_profile_loop(
            &profiles,
            crate::investigate::Tier::Standard,
            &progress,
            &cancel,
            &mut no_cp,
        )
        .expect("loop");

        assert_eq!(
            interrupted,
            Some(Interrupted { done: 1, total: 2 }),
            "stopped at the boundary after the first profile completed"
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("evil1.exe"),
            "the completed first profile's evidence is flushed"
        );
        assert!(
            !json.contains("evil2.exe"),
            "no work from the un-started second profile leaks in"
        );
    }

    // ---- RFC 0001 P3b concern 3: checkpoint / resumability -----------------

    fn findings_json(report: &browser_forensic_triage::TriageReport) -> String {
        let f = crate::investigate::rank_findings(crate::investigate::findings_from_report(report));
        serde_json::to_string(&f).unwrap()
    }

    #[test]
    fn checkpoint_records_completed_unit_on_interrupt() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = dir.path().join("A");
        let b = dir.path().join("B");
        chrome_profile_with_download(&a, "evil1.exe");
        chrome_profile_with_download(&b, "evil2.exe");
        let profiles = vec![discovered_chrome(&a, "A"), discovered_chrome(&b, "B")];

        let cp_path = dir.path().join(".br4n6-checkpoint.json");
        let (session, _) = crate::checkpoint::CheckpointSession::resume_or_new(
            &cp_path,
            crate::checkpoint::fingerprint(dir.path()),
            "standard",
            false,
        )
        .unwrap();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress = CancelOnFirstUnit {
            cancel: std::sync::Arc::clone(&cancel),
        };
        let mut checkpoint = Some(session);
        let (_report, _findings, interrupted) = run_profile_loop(
            &profiles,
            crate::investigate::Tier::Standard,
            &progress,
            &cancel,
            &mut checkpoint,
        )
        .unwrap();
        assert_eq!(interrupted, Some(Interrupted { done: 1, total: 2 }));

        match crate::checkpoint::load(&cp_path) {
            crate::checkpoint::Load::Ok(cp) => {
                assert_eq!(cp.completed.len(), 1, "only the completed unit A recorded");
                assert!(
                    cp.completed[0].key.contains('A'),
                    "the recorded unit is profile A: {}",
                    cp.completed[0].key
                );
            }
            other => panic!("checkpoint should have persisted unit A, got {other:?}"),
        }
    }

    #[test]
    fn resume_equals_uninterrupted() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = dir.path().join("A");
        let b = dir.path().join("B");
        chrome_profile_with_download(&a, "evil1.exe");
        chrome_profile_with_download(&b, "evil2.exe");
        let profiles = vec![discovered_chrome(&a, "A"), discovered_chrome(&b, "B")];
        let inert = crate::progress::Progress::disabled();

        // Uninterrupted baseline (no checkpoint).
        let no_cancel = std::sync::atomic::AtomicBool::new(false);
        let mut no_cp = None;
        let (full, _findings, none) = run_profile_loop(
            &profiles,
            crate::investigate::Tier::Standard,
            &inert,
            &no_cancel,
            &mut no_cp,
        )
        .unwrap();
        assert!(none.is_none());
        let uninterrupted = findings_json(&full);
        assert!(
            uninterrupted.contains("evil1.exe") && uninterrupted.contains("evil2.exe"),
            "baseline sees both downloads"
        );

        // Run 1: interrupt after profile A → checkpoint records unit A. The
        // checkpoint lives OUTSIDE the evidence root: writing it inside would
        // churn the evidence directory's mtime and invalidate its fingerprint.
        let cp_dir = tempfile::TempDir::new().unwrap();
        let cp_path = cp_dir.path().join("run.cp.json");
        let (s1, _) = crate::checkpoint::CheckpointSession::resume_or_new(
            &cp_path,
            crate::checkpoint::fingerprint(dir.path()),
            "standard",
            false,
        )
        .unwrap();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut cp1 = Some(s1);
        let (_r1, _f1, i1) = run_profile_loop(
            &profiles,
            crate::investigate::Tier::Standard,
            &CancelOnFirstUnit {
                cancel: std::sync::Arc::clone(&cancel),
            },
            &cancel,
            &mut cp1,
        )
        .unwrap();
        assert_eq!(i1, Some(Interrupted { done: 1, total: 2 }));

        // Corrupt profile A's History so a *re-parse* of A would yield nothing:
        // a correct resume must reuse the checkpointed fragment, not re-read disk.
        std::fs::write(a.join("History"), b"not a database").unwrap();

        // Run 2: resume → A from checkpoint, B parsed fresh.
        let (s2, resumed) = crate::checkpoint::CheckpointSession::resume_or_new(
            &cp_path,
            crate::checkpoint::fingerprint(dir.path()),
            "standard",
            false,
        )
        .unwrap();
        assert!(
            matches!(
                resumed,
                crate::checkpoint::Resumed::Resumed { completed: 1, .. }
            ),
            "the matching checkpoint resumes its one completed unit: {resumed:?}"
        );
        let no_cancel2 = std::sync::atomic::AtomicBool::new(false);
        let mut cp2 = Some(s2);
        let (r2, _f2, i2) = run_profile_loop(
            &profiles,
            crate::investigate::Tier::Standard,
            &inert,
            &no_cancel2,
            &mut cp2,
        )
        .unwrap();
        assert!(i2.is_none(), "the resumed run completes");
        let resumed_findings = findings_json(&r2);

        assert_eq!(
            resumed_findings, uninterrupted,
            "resumed findings are identical to the uninterrupted run"
        );
    }
}
