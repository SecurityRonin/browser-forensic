# 10. One dual-mode binary: scriptable CLI and interactive TUI

## Context

The suite serves two working styles from the same evidence. A pipeline needs a
scriptable, machine-readable CLI; an analyst exploring session state
interactively wants a terminal viewer. Shipping two binaries would fork the
distribution and the parser wiring; folding the interactive render loop into the
CLI library would make the CLI hard to test and couple it to a TUI toolkit.

## Decision

Ship one binary, `br4n6`, that runs in two modes. With a subcommand it runs a
scriptable handler that emits `text` / `jsonl` / `csv`; with no subcommand, or
`br4n6 tui`, it launches an interactive vi-keyed terminal viewer for session
state. The CLI library stays decoupled from the render loop: `run` takes an
injected `launch_tui` callback (a Humble Object seam), so the argument parsing and
every scriptable handler are unit-testable while the irreducible interactive loop
lives in the binary's `main`.

## Consequences

One distribution covers both working styles, over one set of parsers. The
scriptable surface is fully testable; only the thin interactive shell is not. The
injected-callback seam keeps the TUI toolkit dependency out of the library's test
matrix.

## Status

Accepted.
