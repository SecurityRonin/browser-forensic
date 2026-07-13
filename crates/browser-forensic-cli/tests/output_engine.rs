#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RFC 0001 Phase P2 — the shared output engine (D10): honest, paste-safe,
//! pipe-safe rendering. These exercise the *pure* library layer of
//! `browser_forensic_cli::output` directly (the binary-driven isatty/notice
//! behaviors live in `output_cli.rs`).

use std::path::Path;

use browser_forensic_cli::cli::OutputFormat;
use browser_forensic_cli::output;

// ---- TTY vs pipe auto-format resolution ----

#[test]
fn explicit_format_is_honored_and_never_notices() {
    for f in [OutputFormat::Text, OutputFormat::Jsonl, OutputFormat::Csv] {
        for tty in [true, false] {
            let r = output::resolve(Some(f), tty);
            assert_eq!(r.format, f, "explicit --format must win");
            assert!(
                !r.notice,
                "explicit --format must never emit the pipe notice"
            );
        }
    }
}

#[test]
fn tty_default_renders_human_text_without_notice() {
    let r = output::resolve(None, true);
    assert_eq!(r.format, OutputFormat::Text);
    assert!(!r.notice, "a TTY never gets the pipe notice");
}

#[test]
fn pipe_default_switches_to_jsonl_and_notices() {
    let r = output::resolve(None, false);
    assert_eq!(
        r.format,
        OutputFormat::Jsonl,
        "a pipe defaults to machine JSONL"
    );
    assert!(r.notice, "a silent schema switch confuses tee/grep users");
}

#[test]
fn pipe_notice_names_jsonl_and_the_text_override() {
    assert!(output::PIPE_NOTICE.contains("JSONL"));
    assert!(output::PIPE_NOTICE.contains("--format text"));
    assert!(output::PIPE_NOTICE.starts_with("[notice]"));
}

// ---- markdown-clean tables ----

const BOX_DRAWING: &[char] = &['┌', '┐', '└', '┘', '│', '─', '├', '┤', '┬', '┴', '┼'];

#[test]
fn markdown_table_has_no_box_drawing_and_uses_pipes() {
    let table = output::markdown_table(
        &["TERM", "SOURCE", "STATE"],
        &[
            vec!["evil.com".into(), "history".into(), "live".into()],
            vec!["evil.com".into(), "carved".into(), "deleted".into()],
        ],
    );
    for c in BOX_DRAWING {
        assert!(
            !table.contains(*c),
            "box-drawing char {c:?} must never appear"
        );
    }
    assert!(table.contains('|'), "markdown tables are pipe-delimited");
    assert!(table.contains("TERM") && table.contains("SOURCE"));
    // A markdown separator rule row (dashes) must be present.
    assert!(
        table.lines().any(|l| l.contains("---")),
        "missing markdown rule row"
    );
}

#[test]
fn markdown_table_never_truncates_a_long_url() {
    let long = "https://evil.example.com/a/very/long/path?with=lots&of=query&params=that-must-not-be-cut#frag";
    let table = output::markdown_table(&["URL"], &[vec![long.into()]]);
    assert!(
        table.contains(long),
        "a full URL must survive verbatim, never ellipsized"
    );
    assert!(!table.contains('…'), "no ellipsis truncation");
}

#[test]
fn markdown_table_is_char_safe_on_multibyte_values() {
    // Byte-slicing this would panic mid-code-point; char-safe padding must not.
    let cjk = "日本語ドメイン.example";
    let table = output::markdown_table(&["ホスト", "状態"], &[vec![cjk.into(), "live".into()]]);
    assert!(table.contains(cjk), "multibyte value preserved in full");
    assert!(table.contains("ホスト"));
}

#[test]
fn markdown_table_pads_short_rows_without_panicking() {
    // A row with fewer cells than headers must not panic and stays aligned.
    let table = output::markdown_table(&["A", "B", "C"], &[vec!["x".into()]]);
    assert!(table.contains('x'));
}

// ---- color as a TTY-only cue; severity word always printed ----

#[test]
fn color_disabled_keeps_the_word_and_strips_ansi() {
    let bare = output::paint("High", output::ANSI_RED, false);
    assert_eq!(bare, "High", "disabled color must be the bare word");
    assert!(!bare.contains('\u{1b}'), "no ANSI escape when color is off");
}

#[test]
fn color_enabled_wraps_the_word_but_keeps_it_readable() {
    let painted = output::paint("High", output::ANSI_RED, true);
    assert!(
        painted.contains("High"),
        "the severity WORD survives even when colored"
    );
    assert!(
        painted.contains('\u{1b}'),
        "an ANSI escape is applied on a TTY"
    );
    assert!(painted.ends_with("\u{1b}[0m"), "color must be reset");
}

#[test]
fn color_gate_is_tty_and_no_color() {
    // is_tty=false is always false; NO_COLOR present disables even on a TTY.
    assert!(!output::color_enabled_from(false, false));
    assert!(!output::color_enabled_from(false, true));
    assert!(
        output::color_enabled_from(true, false),
        "TTY + NO_COLOR unset => color"
    );
    assert!(
        !output::color_enabled_from(true, true),
        "NO_COLOR must be honored"
    );
}

// ---- negative-result discipline ----

#[test]
fn negative_result_states_where_it_looked_and_what_it_skipped() {
    let line = output::negative_result(
        &["live history", "downloads", "bookmarks"],
        &["encrypted cookies", "memory", "carving"],
    );
    assert!(line.starts_with("no hits in "));
    assert!(line.contains("live history/downloads/bookmarks"));
    assert!(line.contains("skipped: encrypted cookies, memory, carving"));
}

#[test]
fn negative_result_omits_skipped_clause_when_nothing_skipped() {
    let line = output::negative_result(&["history"], &[]);
    assert_eq!(line, "no hits in history");
}

// ---- actionable DB-open errors ----

#[test]
fn classifies_lock_and_corruption_as_db_open_failures() {
    assert!(output::is_db_open_failure("file is not a database"));
    assert!(output::is_db_open_failure("database is locked"));
    assert!(output::is_db_open_failure(
        "database disk image is malformed"
    ));
    assert!(!output::is_db_open_failure("No such file or directory"));
}

#[test]
fn actionable_db_error_suggests_recovery_and_keeps_the_underlying() {
    let underlying = anyhow::anyhow!("file is not a database (SQLITE_NOTADB)");
    let mapped = output::actionable_db_error(underlying, Path::new("/ev/History"));
    let msg = format!("{mapped:#}");
    assert!(msg.contains("carve"), "must suggest the recovery command");
    assert!(msg.contains("/ev/History"), "must name the evidence path");
    assert!(
        msg.to_ascii_lowercase().contains("corrupt") || msg.to_ascii_lowercase().contains("lock")
    );
    assert!(
        msg.contains("SQLITE_NOTADB"),
        "must surface the underlying error, not swallow it"
    );
}

#[test]
fn actionable_db_error_passes_unrelated_errors_through_unchanged() {
    let other = anyhow::anyhow!("path does not exist: /nope");
    let mapped = output::actionable_db_error(other, Path::new("/nope"));
    let msg = format!("{mapped:#}");
    assert!(msg.contains("path does not exist"));
    assert!(
        !msg.contains("carve"),
        "unrelated errors must not gain a bogus suggestion"
    );
}
