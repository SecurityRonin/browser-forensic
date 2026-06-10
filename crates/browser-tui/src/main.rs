//! `br4n6` — the dual-mode (CLI + TUI) browser state-and-history front-end.
//!
//! Chromium MVP (WS-D): discover browsers, dump history visits (redirect-collapsed,
//! WAL-aware, timestamp-normalized) and session state, with local search — in
//! scriptable CLI form or an interactive terminal viewer. With no subcommand,
//! `br4n6` launches the TUI over the default local profile.

mod cli;
mod tui;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use cli::OutputFormat;

/// br4n6 — read-only browser state & history viewer (Chromium MVP).
#[derive(Parser, Debug)]
#[command(name = "br4n6", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List browser profiles discovered on this system.
    Browsers {
        /// Home directory to scan (defaults to the current user's home).
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Dump Chromium history visits (redirect-collapsed by default).
    History {
        /// A `History` file, or a Chromium profile directory containing one.
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
    /// Dump Chromium session state (open / recently-closed tabs).
    Sessions {
        /// A Chromium profile directory, or its `Sessions` directory.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Show only tabs whose URL or title contains this substring.
        #[arg(long, value_name = "TEXT")]
        search: Option<String>,
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
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        None => tui::run_tui(None).map_err(anyhow::Error::from),
        Some(Command::Tui { path }) => tui::run_tui(path).map_err(anyhow::Error::from),
        Some(Command::Browsers { home, format }) => cli::run_browsers(home.as_deref(), format),
        Some(Command::History {
            path,
            no_collapse,
            search,
            format,
        }) => cli::run_history(&path, no_collapse, search.as_deref(), format),
        Some(Command::Sessions {
            path,
            search,
            format,
        }) => cli::run_sessions(&path, search.as_deref(), format),
    };
    if let Err(e) = result {
        eprintln!("br4n6: {e:#}");
        process::exit(1);
    }
}
