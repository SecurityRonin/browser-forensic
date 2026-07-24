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
//! The CLI surface and dispatch live in [`browser_forensic_cli::cli::run`]; this binary is
//! the thin shell that injects the TUI launcher. The historic `bw` binary
//! (`src/bin/bw.rs`) is the same shell under its documented name.

mod tui;

use std::process;
use std::thread;

/// Windows defaults the main-thread stack to 1 MiB, which is not enough for clap
/// to build `br4n6`'s large command tree (the `artifact` namespace plus every
/// verb) — even `br4n6 --help` overflows it there. Run the whole CLI on a worker
/// thread with a generous stack so the tool is usable on Windows and deep
/// artifact/blob decoding keeps headroom. (The same pattern rustc and cargo use
/// for the identical Windows-stack reason.)
const CLI_STACK_SIZE: usize = 32 * 1024 * 1024;

fn main() {
    let worker = thread::Builder::new()
        .name("br4n6".into())
        .stack_size(CLI_STACK_SIZE)
        .spawn(run);

    let exit_code = match worker {
        Ok(handle) => handle.join().unwrap_or(101), // worker panicked (hook already printed)
        Err(e) => {
            eprintln!("br4n6: failed to start worker thread: {e}");
            1
        }
    };
    process::exit(exit_code);
}

/// The real entry point, run on the large-stack worker thread. Returns the
/// process exit code.
fn run() -> i32 {
    match browser_forensic_cli::cli::run(tui::run_tui) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("br4n6: {e:#}");
            1
        }
    }
}
