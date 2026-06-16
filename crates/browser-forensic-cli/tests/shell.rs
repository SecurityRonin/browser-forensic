#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Humble-Object extraction: the decisions pulled out of the `tui.rs` render/event
//! loop — the text-input reducer (shared by the search and glob input prompts) and
//! the effect-outcome → status-string builders that `perform` used to inline. The
//! loop itself (`terminal.draw` / `event::read` / clipboard / fs / open) is the only
//! irreducible shell left.

use browser_forensic_cli::{
    apply_input_key, clipboard_status, export_status, glob_status, open_status, reload_status,
    tagged_status, InputStep,
};
use crossterm::event::KeyCode;

#[test]
fn typing_a_char_edits_the_buffer() {
    let mut buf = String::from("ab");
    assert_eq!(
        apply_input_key(&mut buf, KeyCode::Char('c')),
        InputStep::Edited
    );
    assert_eq!(buf, "abc");
}

#[test]
fn backspace_pops_the_last_char() {
    let mut buf = String::from("abc");
    assert_eq!(
        apply_input_key(&mut buf, KeyCode::Backspace),
        InputStep::Edited
    );
    assert_eq!(buf, "ab");
}

#[test]
fn backspace_on_empty_buffer_is_a_no_op_edit() {
    let mut buf = String::new();
    assert_eq!(
        apply_input_key(&mut buf, KeyCode::Backspace),
        InputStep::Edited
    );
    assert_eq!(buf, "");
}

#[test]
fn enter_accepts() {
    let mut buf = String::from("done");
    assert_eq!(apply_input_key(&mut buf, KeyCode::Enter), InputStep::Accept);
    assert_eq!(buf, "done", "buffer is preserved on accept");
}

#[test]
fn esc_cancels() {
    let mut buf = String::from("nope");
    assert_eq!(apply_input_key(&mut buf, KeyCode::Esc), InputStep::Cancel);
}

#[test]
fn other_keys_are_ignored_without_editing() {
    let mut buf = String::from("x");
    assert_eq!(apply_input_key(&mut buf, KeyCode::Left), InputStep::Ignored);
    assert_eq!(buf, "x");
}

#[test]
fn open_status_reports_success_and_failure() {
    let ok: Result<(), String> = Ok(());
    assert_eq!(open_status("https://x", ok), "opened https://x");
    let err: Result<(), String> = Err("boom".to_string());
    assert_eq!(
        open_status("https://x", err),
        "could not open https://x: boom"
    );
}

#[test]
fn clipboard_status_reports_success_and_failure() {
    let ok: Result<(), String> = Ok(());
    assert_eq!(clipboard_status(ok), "copied to clipboard");
    assert_eq!(
        clipboard_status(Err("no clip".to_string())),
        "clipboard error: no clip"
    );
}

#[test]
fn export_status_reports_both_filenames() {
    let ok: Result<(), String> = Ok(());
    assert_eq!(
        export_status("tab-7", ok),
        "exported tab-7.md and tab-7.json"
    );
    assert_eq!(
        export_status("tab-7", Err("disk full".to_string())),
        "export failed: disk full"
    );
}

#[test]
fn reload_status_reports_success_and_failure() {
    let ok: Result<(), String> = Ok(());
    assert_eq!(reload_status(ok), "reloaded from disk");
    assert_eq!(
        reload_status(Err("missing".to_string())),
        "reload failed: missing"
    );
}

#[test]
fn glob_status_renders_the_live_prompt() {
    assert_eq!(glob_status(true, "git*"), " tag glob: git*");
    assert_eq!(glob_status(false, "ads*"), " untag glob: ads*");
}

#[test]
fn tagged_status_pluralizes_count() {
    assert_eq!(tagged_status(3), "3 tab(s) tagged");
}
