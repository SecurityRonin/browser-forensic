//! RFC 0001 Phase P8 — shell completions.
//!
//! A hidden `br4n6 completions <bash|zsh|fish>` subcommand emits a completion
//! script to stdout. `clap_complete` derives the script from the same command
//! tree the CLI parses, so it never drifts from the actual verb surface.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use browser_forensic_cli::completions::{generate, Shell};

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

#[test]
fn generate_succeeds_for_every_supported_shell() {
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        let mut buf = Vec::new();
        generate(shell, &mut buf);
        let script = String::from_utf8(buf).unwrap();
        assert!(!script.is_empty(), "{shell} completion is non-empty");
        assert!(
            script.contains("br4n6"),
            "{shell} completion names the binary"
        );
    }
}

#[test]
fn generated_completion_mentions_a_verb() {
    // A smoke check that the script reflects the real surface, not an empty stub.
    let mut buf = Vec::new();
    generate(Shell::Bash, &mut buf);
    let script = String::from_utf8(buf).unwrap();
    assert!(
        script.contains("investigate"),
        "bash completion lists the task-verbs"
    );
}

#[test]
fn completions_subcommand_emits_a_script() {
    for shell in ["bash", "zsh", "fish"] {
        let out = br4n6().args(["completions", shell]).assert().success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        assert!(!stdout.is_empty(), "{shell} script emitted to stdout");
        assert!(stdout.contains("br4n6"), "{shell} script names the binary");
    }
}

#[test]
fn completions_is_hidden_from_top_level_help() {
    let out = br4n6().arg("--help").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains("completions"),
        "the completions helper is hidden from the primary help surface"
    );
}
