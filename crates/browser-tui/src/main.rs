#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! `br4n6` — the dual-mode (CLI + TUI) browser state-and-history front-end.
//!
//! With no subcommand, `br4n6` launches the interactive TUI over the default
//! local profile. With a subcommand it is the scriptable forensic CLI: discover
//! browsers, dump any artifact (history / cookies / downloads / bookmarks /
//! extensions / login-data / autofill / session / cache), analyze rare domains,
//! run integrity checks, carve deleted records, or run a full triage — all with
//! `text`/`jsonl`/`csv` output.
//!
//! The CLI surface and dispatch live in [`browser_tui::cli::run`]; this binary is
//! the thin shell that injects the TUI launcher. The historic `bw` binary
//! (`src/bin/bw.rs`) is the same shell under its documented name.

mod tui;

use std::process;

fn main() {
    if let Err(e) = browser_tui::cli::run(tui::run_tui) {
        eprintln!("br4n6: {e:#}");
        process::exit(1);
    }
}
