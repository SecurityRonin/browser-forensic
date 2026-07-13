#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RFC 0001 Phase P5b clean break (D11): the top-level recovery commands
//! `carve`, `cache-carve`, `recovered-domains`, `tamper-check`, and `memory`
//! are REMOVED — their capability is reachable only through the `recover`
//! orchestrator (and `artifact` for the primitives kept there). No aliases, no
//! shims: invoking a removed name is an unknown-subcommand error.

use assert_cmd::Command;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// Every superseded top-level recovery command now errors as an unrecognized
/// subcommand (clap exits non-zero; the removed name is gone from the surface).
#[test]
fn removed_recovery_commands_error_as_unknown() {
    for removed in [
        "carve",
        "cache-carve",
        "recovered-domains",
        "tamper-check",
        "memory",
    ] {
        let out = br4n6().args([removed, "/tmp/whatever"]).assert().failure();
        let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
        assert!(
            stderr.to_lowercase().contains("unrecognized")
                || stderr.to_lowercase().contains("unexpected"),
            "removed command `{removed}` must error as an unknown subcommand, got: {stderr}"
        );
    }
}

/// The clean break is visible in the top-level help: the removed names no longer
/// appear as commands, and `recover` is the recovery verb that replaces them.
#[test]
fn top_level_help_drops_removed_commands_and_shows_recover() {
    let out = br4n6().arg("--help").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("recover"),
        "top-level help offers the recover verb: {stdout}"
    );
    for gone in ["cache-carve", "recovered-domains", "tamper-check"] {
        assert!(
            !stdout.contains(gone),
            "top-level help still lists removed command `{gone}`: {stdout}"
        );
    }
}

/// `recover --help` remains the discovery surface for every removed capability:
/// it names the recovery kinds so an examiner knows the one verb covers them.
#[test]
fn recover_help_covers_every_removed_capability() {
    let out = br4n6().args(["recover", "--help"]).assert().success();
    let help = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let low = help.to_lowercase();
    // carve → deleted records; cache-carve → cache; recovered-domains → domains;
    // tamper-check → tamper; memory → memory.
    for kind in ["deleted", "cache", "domain", "tamper", "memory"] {
        assert!(
            low.contains(kind),
            "recover --help must cover the `{kind}` capability: {help}"
        );
    }
}
