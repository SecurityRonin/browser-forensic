#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! `bw` — the historic name for the browser-forensic CLI. It is the exact same
//! dual-mode binary as `br4n6` (same [`browser_tui::cli::run`] dispatch and the
//! same injected TUI launcher); the separate `[[bin]]` keeps the documented
//! `bw <subcommand>` install path and every README example working unchanged.

#[path = "../tui.rs"]
mod tui;

use std::process;

fn main() {
    if let Err(e) = browser_tui::cli::run(tui::run_tui) {
        eprintln!("bw: {e:#}");
        process::exit(1);
    }
}
