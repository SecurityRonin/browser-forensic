#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Milestone 7 — actions: open, yank, export, reload, sort.

use browser_tui::{Action, App, Effect, Keymap, SortMode};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use snss::{Nav, Source, SourceKind, Tab, Window};

fn nav(url: &str, title: &str) -> Nav {
    Nav {
        index: 0,
        url: url.to_string(),
        title: title.to_string(),
    }
}
fn tab1(id: i32, url: &str, title: &str) -> Tab {
    Tab {
        id,
        pinned: false,
        current: 0,
        history: vec![nav(url, title)],
    }
}
fn win(id: i32, tabs: Vec<Tab>) -> Window {
    Window {
        id,
        tabs,
        last_active: None,
    }
}
fn one_tab_app() -> App {
    let sources = vec![Source {
        kind: SourceKind::Current,
        path: "S".into(),
        windows: vec![win(
            1,
            vec![tab1(10, "https://example.com/x", "Example \"quoted\"")],
        )],
    }];
    let mut app = App::new(sources);
    app.update(Action::Descend); // windows
    app.update(Action::Descend); // tabs -> tab 10 in scope
    app
}

fn key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

#[test]
fn open_yields_open_url_effect() {
    let mut app = one_tab_app();
    assert_eq!(
        app.update(Action::Open),
        Some(Effect::OpenUrl("https://example.com/x".into()))
    );
}

#[test]
fn open_above_tab_level_yields_nothing() {
    let mut app = App::new(vec![Source {
        kind: SourceKind::Current,
        path: "S".into(),
        windows: vec![win(1, vec![tab1(10, "https://x", "x")])],
    }]);
    // still at source level
    assert_eq!(app.update(Action::Open), None);
}

#[test]
fn yank_url_and_title_url() {
    let mut app = one_tab_app();
    assert_eq!(
        app.update(Action::YankUrl),
        Some(Effect::CopyToClipboard("https://example.com/x".into()))
    );
    assert_eq!(
        app.update(Action::YankTitleUrl),
        Some(Effect::CopyToClipboard(
            "Example \"quoted\"\nhttps://example.com/x".into()
        ))
    );
}

#[test]
fn reload_yields_reload_effect() {
    let mut app = one_tab_app();
    assert_eq!(app.update(Action::Reload), Some(Effect::Reload));
}

#[test]
fn sort_cycles_through_modes() {
    let mut app = one_tab_app();
    assert_eq!(app.sort(), SortMode::None);
    app.update(Action::Sort);
    assert_eq!(app.sort(), SortMode::Recency);
    app.update(Action::Sort);
    assert_eq!(app.sort(), SortMode::Title);
    app.update(Action::Sort);
    assert_eq!(app.sort(), SortMode::Url);
    app.update(Action::Sort);
    assert_eq!(app.sort(), SortMode::TabCount);
    app.update(Action::Sort);
    assert_eq!(app.sort(), SortMode::Recency, "wraps, never back to None");
}

#[test]
fn sort_by_tab_count_orders_windows() {
    let sources = vec![Source {
        kind: SourceKind::Current,
        path: "S".into(),
        windows: vec![
            win(1, vec![tab1(10, "https://a", "a")]),
            win(2, (0..3).map(|i| tab1(20 + i, "https://b", "b")).collect()),
            win(3, (0..2).map(|i| tab1(30 + i, "https://c", "c")).collect()),
        ],
    }];
    let mut app = App::new(sources);
    while app.sort() != SortMode::TabCount {
        app.update(Action::Sort);
    }
    app.update(Action::Descend); // into windows, now sorted
    let counts: Vec<usize> = app.sources()[0]
        .windows
        .iter()
        .map(|w| w.tabs.len())
        .collect();
    assert_eq!(
        counts,
        vec![3, 2, 1],
        "windows ordered by descending tab count"
    );
}

#[test]
fn sort_by_title_orders_tabs() {
    let sources = vec![Source {
        kind: SourceKind::Current,
        path: "S".into(),
        windows: vec![win(
            1,
            vec![
                tab1(10, "https://b", "Banana"),
                tab1(11, "https://a", "Apple"),
                tab1(12, "https://c", "Cherry"),
            ],
        )],
    }];
    let mut app = App::new(sources);
    while app.sort() != SortMode::Title {
        app.update(Action::Sort);
    }
    let titles: Vec<String> = app.sources()[0].windows[0]
        .tabs
        .iter()
        .map(|t| t.history[0].title.clone())
        .collect();
    assert_eq!(titles, vec!["Apple", "Banana", "Cherry"]);
}

#[test]
fn export_tab_produces_markdown_and_valid_json() {
    let mut app = one_tab_app();
    let Some(Effect::Export(export)) = app.update(Action::Export) else {
        panic!("expected an export effect");
    };
    assert_eq!(export.name, "tab-10");
    assert!(
        export.markdown.contains("https://example.com/x"),
        "md has url"
    );
    assert!(export.markdown.contains("Tab 10"), "md names the tab");
    // The quote in the title must be JSON-escaped, keeping the JSON valid.
    assert!(
        export.json.contains("\\\"quoted\\\""),
        "json escapes quotes: {}",
        export.json
    );
    assert!(export.json.contains("\"url\":\"https://example.com/x\""));
}

#[test]
fn keymap_maps_action_keys() {
    let mut km = Keymap::default();
    assert_eq!(km.handle(key('o')), Some(Action::Open));
    assert_eq!(km.handle(key('y')), Some(Action::YankUrl));
    assert_eq!(km.handle(key('Y')), Some(Action::YankTitleUrl));
    assert_eq!(km.handle(key('e')), Some(Action::Export));
    assert_eq!(km.handle(key('r')), Some(Action::Reload));
    assert_eq!(km.handle(key('s')), Some(Action::Sort));
    assert_eq!(
        km.handle(KeyEvent::new(KeyCode::F(8), KeyModifiers::NONE)),
        Some(Action::Open)
    );
    assert_eq!(
        km.handle(KeyEvent::new(KeyCode::F(4), KeyModifiers::NONE)),
        Some(Action::YankUrl)
    );
    assert_eq!(
        km.handle(KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE)),
        Some(Action::Export)
    );
}
