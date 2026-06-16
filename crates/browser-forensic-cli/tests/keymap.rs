#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Milestone 5 — the vi/F-key keymap (a stateful Key → Action mapping).

use browser_forensic_cli::{Action, Keymap};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn ch(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}
fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}
fn code(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

#[test]
fn basic_vi_and_arrows_and_tab() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(ch('j')), Some(Action::Down));
    assert_eq!(km.handle(ch('k')), Some(Action::Up));
    assert_eq!(km.handle(ch('h')), Some(Action::Ascend));
    assert_eq!(km.handle(ch('l')), Some(Action::Descend));
    assert_eq!(km.handle(code(KeyCode::Down)), Some(Action::Down));
    assert_eq!(km.handle(code(KeyCode::Up)), Some(Action::Up));
    assert_eq!(km.handle(code(KeyCode::Left)), Some(Action::Ascend));
    assert_eq!(km.handle(code(KeyCode::Right)), Some(Action::Descend));
    assert_eq!(km.handle(code(KeyCode::Enter)), Some(Action::Descend));
    assert_eq!(km.handle(code(KeyCode::Tab)), Some(Action::SwapPane));
}

#[test]
fn gg_requires_two_keystrokes_and_cancels_on_other_key() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(ch('g')), None, "first g is pending");
    assert_eq!(km.handle(ch('g')), Some(Action::Top), "second g fires Top");

    // A different key after a lone g cancels the pending state.
    assert_eq!(km.handle(ch('g')), None);
    assert_eq!(km.handle(ch('j')), Some(Action::Down), "pending g cleared");
    assert_eq!(km.handle(ch('g')), None);
    assert_eq!(
        km.handle(ch('g')),
        Some(Action::Top),
        "fresh gg works again"
    );
}

#[test]
fn shift_g_is_bottom() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(ch('G')), Some(Action::Bottom));
    // even if the terminal also reports a SHIFT modifier
    assert_eq!(
        km.handle(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT)),
        Some(Action::Bottom)
    );
}

#[test]
fn ctrl_paging() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(ctrl('d')), Some(Action::HalfPageDown));
    assert_eq!(km.handle(ctrl('u')), Some(Action::HalfPageUp));
    assert_eq!(km.handle(ctrl('f')), Some(Action::PageDown));
    assert_eq!(km.handle(ctrl('b')), Some(Action::PageUp));
}

#[test]
fn braces_jump_windows() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(ch('}')), Some(Action::NextWindow));
    assert_eq!(km.handle(ch('{')), Some(Action::PrevWindow));
}

#[test]
fn quit_keys() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(ch('q')), Some(Action::Quit));
    assert_eq!(km.handle(code(KeyCode::F(10))), Some(Action::Quit));
}

#[test]
fn unmapped_key_is_none() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(ch('z')), None);
}
