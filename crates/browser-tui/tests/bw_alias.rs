#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The `bw` binary is a documented entry point (README install line + every CLI
//! example), so `br4n6` also installs under the `bw` name. The two binaries are
//! byte-identical (same `[[bin]]` source); these tests pin that the `bw` alias
//! still serves the historic command surface.

use assert_cmd::Command;

fn bw() -> Command {
    Command::cargo_bin("bw").unwrap()
}

#[test]
fn bw_help_exits_0() {
    bw().arg("--help").assert().success();
}

#[test]
fn bw_history_help_exits_0() {
    bw().args(["history", "--help"]).assert().success();
}

#[test]
fn bw_integrity_help_exits_0() {
    bw().args(["integrity", "--help"]).assert().success();
}

#[test]
fn bw_carve_help_exits_0() {
    bw().args(["carve", "--help"]).assert().success();
}

#[test]
fn bw_triage_help_exits_0() {
    bw().args(["triage", "--help"]).assert().success();
}

#[test]
fn bw_profiles_exits_0() {
    bw().args(["profiles"]).assert().success();
}

#[test]
fn bw_timeline_nonexistent_path_fails() {
    bw().args(["timeline", "/nonexistent/History"]).assert().failure();
}
