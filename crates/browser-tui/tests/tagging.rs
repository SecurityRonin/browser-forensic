#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Milestone 8 — tagging and bulk yank/export.

use browser_tui::{Action, App, Effect, Keymap};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use snss::{Nav, Source, SourceKind, Tab, Window};

fn tab1(id: i32, url: &str) -> Tab {
    Tab {
        id,
        pinned: false,
        current: 0,
        history: vec![Nav {
            index: 0,
            url: url.to_string(),
            title: format!("t{id}"),
        }],
    }
}
fn win(id: i32, tabs: Vec<Tab>) -> Window {
    Window {
        id,
        tabs,
        last_active: None,
    }
}

fn sources() -> Vec<Source> {
    vec![
        Source {
            kind: SourceKind::Current,
            path: "S".into(),
            windows: vec![
                win(
                    1,
                    vec![
                        tab1(10, "https://github.com/h4x0r"),
                        tab1(11, "https://example.com"),
                    ],
                ),
                win(
                    2,
                    vec![tab1(12, "https://github.com/rust-lang/rust/issues")],
                ),
            ],
        },
        Source {
            kind: SourceKind::RecentlyClosed,
            path: "T".into(),
            windows: vec![win(0, vec![tab1(20, "https://news.ycombinator.com")])],
        },
    ]
}

fn key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

#[test]
fn toggle_tag_adds_then_removes_current_tab() {
    let mut app = App::new(sources());
    app.update(Action::Descend); // windows
    app.update(Action::Descend); // tabs -> tab 10
    assert_eq!(app.tag_count(), 0);
    app.update(Action::ToggleTag);
    assert_eq!(app.tag_count(), 1);
    assert!(app.is_tagged((0, 0, 0)));
    app.update(Action::ToggleTag);
    assert_eq!(app.tag_count(), 0);
}

#[test]
fn toggle_tag_above_tab_level_is_noop() {
    let mut app = App::new(sources()); // still at source level
    app.update(Action::ToggleTag);
    assert_eq!(app.tag_count(), 0);
}

#[test]
fn tag_by_glob_tags_matching_tabs() {
    let mut app = App::new(sources());
    app.tag_by_glob("*github.com*");
    assert_eq!(app.tag_count(), 2);
    assert!(app.tagged_urls().iter().all(|u| u.contains("github.com")));
}

#[test]
fn glob_anchors_with_prefix_and_suffix() {
    let mut app = App::new(sources());
    app.tag_by_glob("https://github.com/*/issues");
    assert_eq!(app.tag_count(), 1, "only the .../issues tab");
    assert_eq!(
        app.tagged_urls(),
        vec!["https://github.com/rust-lang/rust/issues"]
    );
}

#[test]
fn untag_by_glob_removes_matching() {
    let mut app = App::new(sources());
    app.tag_by_glob("*"); // tag everything
    assert_eq!(app.tag_count(), 4);
    app.untag_by_glob("*github.com*");
    assert_eq!(app.tag_count(), 2);
}

#[test]
fn tagged_urls_are_in_document_order() {
    let mut app = App::new(sources());
    app.tag_by_glob("*");
    assert_eq!(app.tagged_urls()[0], "https://github.com/h4x0r");
    assert_eq!(app.tagged_urls().len(), 4);
}

#[test]
fn yank_with_tags_joins_all_tagged_urls() {
    let mut app = App::new(sources());
    app.tag_by_glob("*github.com*");
    let Some(Effect::CopyToClipboard(text)) = app.update(Action::YankUrl) else {
        panic!("expected clipboard effect");
    };
    assert_eq!(text.lines().count(), 2);
    assert!(text.contains("https://github.com/h4x0r"));
    assert!(text.contains("https://github.com/rust-lang/rust/issues"));
}

#[test]
fn export_with_tags_exports_all_tagged() {
    let mut app = App::new(sources());
    app.tag_by_glob("*github.com*");
    let Some(Effect::Export(export)) = app.update(Action::Export) else {
        panic!("expected export effect");
    };
    assert!(export.name.contains("tagged"));
    assert!(export.markdown.contains("github.com/h4x0r"));
    assert!(export.json.contains("github.com/rust-lang/rust/issues"));
}

#[test]
fn clear_tags_empties_the_set() {
    let mut app = App::new(sources());
    app.tag_by_glob("*");
    app.clear_tags();
    assert_eq!(app.tag_count(), 0);
}

#[test]
fn keymap_maps_tagging_keys() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(key(' ')), Some(Action::ToggleTag));
    assert_eq!(km.handle(key('+')), Some(Action::TagGlob));
    assert_eq!(km.handle(key('-')), Some(Action::UntagGlob));
}
