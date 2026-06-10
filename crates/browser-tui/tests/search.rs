#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Milestone 6 — incremental search across all sources.

use browser_tui::{Action, App, Direction, Keymap};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use snss::{Nav, Source, SourceKind, Tab, Window};

fn tabn(id: i32, url: &str, title: &str) -> Tab {
    Tab {
        id,
        pinned: false,
        current: 0,
        history: vec![Nav {
            index: 0,
            url: url.to_string(),
            title: title.to_string(),
        }],
    }
}

fn sources() -> Vec<Source> {
    vec![
        Source {
            kind: SourceKind::Current,
            path: "S".into(),
            windows: vec![
                Window {
                    id: 1,
                    tabs: vec![
                        tabn(10, "https://github.com/h4x0r", "h4x0r"),
                        tabn(11, "https://example.com", "Example"),
                    ],
                    last_active: None,
                },
                Window {
                    id: 2,
                    tabs: vec![tabn(12, "https://github.com/rust-lang/rust", "Rust")],
                    last_active: None,
                },
            ],
        },
        Source {
            kind: SourceKind::RecentlyClosed,
            path: "T".into(),
            windows: vec![Window {
                id: 0,
                tabs: vec![tabn(20, "https://news.ycombinator.com", "Hacker News")],
                last_active: None,
            }],
        },
    ]
}

fn key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

#[test]
fn set_query_finds_matches_across_sources_and_jumps() {
    let mut app = App::new(sources());
    app.begin_search(Direction::Forward);
    app.set_query("github");
    assert_eq!(app.match_count(), 2, "two github tabs across windows");
    assert_eq!(app.search_query(), Some("github"));
    assert_eq!(app.current_tab().unwrap().id, 10, "jumped to first match");
    assert_eq!(app.current_match(), Some(1));
    assert_eq!(app.depth(), 2, "selection lands at tab level");
}

#[test]
fn search_is_case_insensitive_on_url_and_title() {
    let mut app = App::new(sources());
    app.begin_search(Direction::Forward);
    app.set_query("RUST"); // matches title "Rust" and url rust-lang
    assert_eq!(app.match_count(), 1);
    assert_eq!(app.current_tab().unwrap().id, 12);
}

#[test]
fn next_and_prev_match_cycle_with_wrap() {
    let mut app = App::new(sources());
    app.begin_search(Direction::Forward);
    app.set_query("github");
    assert_eq!(app.current_tab().unwrap().id, 10);
    app.next_match();
    assert_eq!(app.current_tab().unwrap().id, 12);
    app.next_match(); // wraps
    assert_eq!(app.current_tab().unwrap().id, 10);
    app.prev_match(); // wraps back
    assert_eq!(app.current_tab().unwrap().id, 12);
}

#[test]
fn backward_search_starts_at_last_match() {
    let mut app = App::new(sources());
    app.begin_search(Direction::Backward);
    app.set_query("github");
    assert_eq!(app.current_match(), Some(2));
    assert_eq!(app.current_tab().unwrap().id, 12);
}

#[test]
fn no_match_keeps_query_but_zero_count() {
    let mut app = App::new(sources());
    app.begin_search(Direction::Forward);
    app.set_query("zzz-nope");
    assert_eq!(app.match_count(), 0);
    assert_eq!(app.current_match(), None);
    assert_eq!(app.search_query(), Some("zzz-nope"));
}

#[test]
fn clear_search_resets() {
    let mut app = App::new(sources());
    app.begin_search(Direction::Forward);
    app.set_query("github");
    app.clear_search();
    assert_eq!(app.search_query(), None);
    assert_eq!(app.match_count(), 0);
}

#[test]
fn search_hostname_uses_url_under_cursor() {
    let mut app = App::new(sources());
    app.update(Action::Descend); // windows
    app.update(Action::Descend); // tabs of window 1 -> current tab id 10
    app.search_hostname();
    assert_eq!(app.search_query(), Some("github.com"));
    assert_eq!(app.match_count(), 2, "both github.com tabs");
}

#[test]
fn keymap_maps_search_keys() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(key('/')), Some(Action::SearchForward));
    assert_eq!(km.handle(key('?')), Some(Action::SearchBackward));
    assert_eq!(km.handle(key('n')), Some(Action::NextMatch));
    assert_eq!(km.handle(key('N')), Some(Action::PrevMatch));
    assert_eq!(km.handle(key('*')), Some(Action::SearchHostname));
    assert_eq!(
        km.handle(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
        Some(Action::ClearSearch)
    );
}
