//! RFC 0001 Phase P2 — the shared output engine (D10).
//!
//! A small, reusable rendering layer that makes CLI output *honest, paste-safe,
//! and pipe-safe*, so every command can adopt it without re-deriving the rules:
//!
//! * **TTY vs pipe auto-format** ([`resolve`]/[`resolve_stdout`]) — a terminal
//!   gets the human render; a pipe gets machine [`OutputFormat::Jsonl`], and the
//!   auto-switch is announced once on stderr ([`PIPE_NOTICE`]) so `tee`/`grep`
//!   users are never surprised by a silent schema change. An explicit `--format`
//!   always wins and never notices.
//! * **Markdown-clean tables** ([`markdown_table`]) — pipe-delimited, no
//!   box-drawing characters, values rendered in full (never ellipsized) and
//!   padded char-safely (never byte-sliced), so a table pastes cleanly into
//!   Jira / Word / Markdown.
//! * **Color as a TTY-only cue** ([`paint`]/[`color_enabled`]) — the severity
//!   *word* is always printed (it survives `tee`); ANSI color is applied only on
//!   a terminal and only when `NO_COLOR` is unset.
//! * **Negative-result discipline** ([`negative_result`]) — an empty search must
//!   prove it looked, naming where it searched and what it skipped.
//! * **Actionable errors** ([`actionable_db_error`]) — a locked / dirty-WAL /
//!   corrupt SQLite open suggests the recovery command instead of a bare
//!   `SQLITE_CORRUPT`, while still surfacing the underlying error.
//!
//! Machine views (`jsonl`/`csv`) stay byte-faithful and round-trippable; the
//! humanization here (tables, color, the notice) is the TTY-facing half of the
//! fleet "render for eyes, preserve for pipes" split.

use std::io::IsTerminal;
use std::path::Path;

use crate::cli::OutputFormat;

/// The one-line stderr notice emitted when output is auto-switched to JSONL on a
/// pipe (D10 — never switch the schema silently).
pub const PIPE_NOTICE: &str = "[notice] piped output → JSONL; use --format text to override";

/// ANSI SGR code for red — a `High` priority cue.
pub const ANSI_RED: &str = "31";
/// ANSI SGR code for yellow — a `Medium` priority cue.
pub const ANSI_YELLOW: &str = "33";
/// ANSI SGR code for cyan — an `Info`/`Low` cue.
pub const ANSI_CYAN: &str = "36";

/// The resolved output decision: which [`OutputFormat`] to render and whether the
/// caller should print the one-line [`PIPE_NOTICE`] on stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    /// The effective format to render.
    pub format: OutputFormat,
    /// True only when the format was auto-selected as JSONL on a pipe.
    pub notice: bool,
}

/// Resolve the effective output format from an optional explicit `--format` and
/// whether stdout is a terminal.
///
/// * An explicit `--format` always wins and never notices.
/// * No `--format` on a TTY renders the human [`OutputFormat::Text`].
/// * No `--format` on a pipe switches to machine [`OutputFormat::Jsonl`] and
///   flags the notice.
#[must_use]
pub fn resolve(explicit: Option<OutputFormat>, stdout_is_tty: bool) -> Resolved {
    match explicit {
        Some(format) => Resolved {
            format,
            notice: false,
        },
        None if stdout_is_tty => Resolved {
            format: OutputFormat::Text,
            notice: false,
        },
        None => Resolved {
            format: OutputFormat::Jsonl,
            notice: true,
        },
    }
}

/// Resolve against the real stdout terminal state and print [`PIPE_NOTICE`] to
/// stderr when the format was auto-selected on a pipe. Returns the effective
/// [`OutputFormat`].
#[must_use]
pub fn resolve_stdout(explicit: Option<OutputFormat>) -> OutputFormat {
    let r = resolve(explicit, std::io::stdout().is_terminal());
    if r.notice {
        eprintln!("{PIPE_NOTICE}");
    }
    r.format
}

/// Character width of a string — code-point count, never byte length, so padding
/// stays correct (and panic-free) on CJK/emoji/accented text.
fn char_width(s: &str) -> usize {
    s.chars().count()
}

/// Pad `cell` on the right with spaces to `width` code points (char-safe).
fn pad_cell(cell: &str, width: usize) -> String {
    let have = char_width(cell);
    let fill = width.saturating_sub(have);
    let mut out = String::with_capacity(cell.len() + fill);
    out.push_str(cell);
    for _ in 0..fill {
        out.push(' ');
    }
    out
}

/// Render a markdown-clean table: `| a | b |` with a `| --- | --- |` rule row.
///
/// No box-drawing characters, so the table survives paste into Jira / Word /
/// Markdown. Column widths are the max code-point width of every cell, so values
/// are shown **in full** — never ellipsized or truncated — and padding is
/// char-safe. Rows shorter than `headers` are padded with empty cells.
#[must_use]
pub fn markdown_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| char_width(h)).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < cols {
                let w = char_width(cell);
                if w > widths[i] {
                    widths[i] = w;
                }
            }
        }
    }

    let mut out = String::new();

    // Header row.
    out.push_str("| ");
    for (i, h) in headers.iter().enumerate() {
        if i > 0 {
            out.push_str(" | ");
        }
        out.push_str(&pad_cell(h, widths[i]));
    }
    out.push_str(" |\n");

    // Markdown rule row (dashes, min 3 so it reads as a rule).
    out.push_str("| ");
    for (i, w) in widths.iter().enumerate() {
        if i > 0 {
            out.push_str(" | ");
        }
        out.push_str(&"-".repeat((*w).max(3)));
    }
    out.push_str(" |\n");

    // Body rows.
    for row in rows {
        out.push_str("| ");
        for (i, w) in widths.iter().enumerate() {
            if i > 0 {
                out.push_str(" | ");
            }
            let cell = row.get(i).map_or("", String::as_str);
            out.push_str(&pad_cell(cell, *w));
        }
        out.push_str(" |\n");
    }

    out
}

/// Pure color decision: color is on only when writing to a terminal **and**
/// `NO_COLOR` is unset. Split out so both [`color_enabled`] and its tests can
/// exercise every combination without racing on a process-global env var.
#[must_use]
pub fn color_enabled_from(stdout_is_tty: bool, no_color_present: bool) -> bool {
    stdout_is_tty && !no_color_present
}

/// Whether ANSI color should be emitted: `stdout_is_tty` **and** `NO_COLOR`
/// unset (D10 — color is a TTY-only cue and `NO_COLOR` is honored).
#[must_use]
pub fn color_enabled(stdout_is_tty: bool) -> bool {
    color_enabled_from(stdout_is_tty, std::env::var_os("NO_COLOR").is_some())
}

/// Wrap `text` in an ANSI SGR color when `enabled`, else return it verbatim.
///
/// The word is always present in the output; color is purely additive, so a
/// severity/priority word survives `tee`, `NO_COLOR`, and a pipe unchanged.
#[must_use]
pub fn paint(text: &str, ansi: &str, enabled: bool) -> String {
    if enabled {
        format!("\u{1b}[{ansi}m{text}\u{1b}[0m")
    } else {
        text.to_string()
    }
}

/// Build the D10 negative-result line: *where it looked and what it skipped*, so
/// an empty result proves it looked. The `skipped` clause is omitted when empty.
///
/// e.g. `no hits in live history/downloads/bookmarks; skipped: encrypted
/// cookies, memory, carving`.
#[must_use]
pub fn negative_result(searched: &[&str], skipped: &[&str]) -> String {
    let mut line = format!("no hits in {}", searched.join("/"));
    if !skipped.is_empty() {
        line.push_str("; skipped: ");
        line.push_str(&skipped.join(", "));
    }
    line
}

/// Whether an error message looks like a SQLite *open/read* failure that a
/// recovery pass could address — a lock, a dirty WAL, or on-disk corruption.
#[must_use]
pub fn is_db_open_failure(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "not a database",
        "is locked",
        "database is locked",
        "malformed",
        "disk image",
        "corrupt",
        "file is encrypted",
        "sqlite_busy",
        "sqlite_notadb",
        "sqlite_corrupt",
    ];
    MARKERS.iter().any(|k| m.contains(k))
}

/// Map a SQLite open/read failure into an *actionable* error that suggests the
/// recovery command, while still surfacing the underlying error (never swallow
/// it). Unrelated errors pass through unchanged.
#[must_use]
pub fn actionable_db_error(err: anyhow::Error, path: &Path) -> anyhow::Error {
    let chain = format!("{err:#}");
    if is_db_open_failure(&chain) {
        anyhow::anyhow!(
            "evidence database at {p} looks locked or corrupt (dirty WAL / not a database) — \
             try recovering deleted and WAL records: br4n6 carve {p}\n(underlying: {chain})",
            p = path.display(),
        )
    } else {
        err
    }
}
