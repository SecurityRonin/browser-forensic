//! RFC 0001 Phase P8 — shell completions.
//!
//! `br4n6 completions <SHELL>` writes a completion script to stdout. The script
//! is derived by `clap_complete` from the same [`Cli`](crate::cli::Cli) command
//! tree the binary parses, so completions never drift from the actual verb
//! surface — adding or renaming a verb regenerates a correct script for free.

use std::io::Write;

use clap::CommandFactory as _;
pub use clap_complete::Shell;

use crate::cli::Cli;

/// The binary name completions are generated for (`br4n6`).
pub const BIN: &str = "br4n6";

/// Write a completion script for `shell` to `out`, derived from the live command
/// tree. `bash`, `zsh`, and `fish` are the documented targets; `clap_complete`
/// also covers `elvish` and `powershell` via the same [`Shell`] enum.
pub fn generate(shell: Shell, out: &mut impl Write) {
    clap_complete::generate(shell, &mut Cli::command(), BIN, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shell_yields_a_nonempty_script_naming_the_binary() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let mut buf = Vec::new();
            generate(shell, &mut buf);
            let script = String::from_utf8(buf).expect("utf-8 script");
            assert!(!script.is_empty(), "{shell} script non-empty");
            assert!(script.contains(BIN), "{shell} script names {BIN}");
        }
    }
}
