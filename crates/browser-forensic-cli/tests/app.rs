#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Milestone 4 — the App navigation reducer and a render smoke test.

use browser_forensic_cli::{draw, Action, App, Pane};
use ratatui::{backend::TestBackend, Terminal};
use snss::{Nav, Source, SourceKind, Tab, Window};

fn nav(i: i32, url: &str) -> Nav {
    Nav {
        index: i,
        url: url.to_string(),
        title: format!("title {i}"),
    }
}
fn tab(id: i32, entries: usize) -> Tab {
    Tab {
        id,
        pinned: false,
        current: 0,
        history: (0..entries as i32)
            .map(|i| nav(i, &format!("https://{id}/{i}")))
            .collect(),
    }
}
fn window(id: i32, tabs: Vec<Tab>) -> Window {
    Window {
        id,
        tabs,
        last_active: None,
    }
}

fn sample() -> Vec<Source> {
    vec![
        Source {
            kind: SourceKind::Current,
            path: "Session_1".into(),
            windows: vec![
                window(10, vec![tab(100, 3), tab(101, 1)]),
                window(11, vec![tab(102, 2)]),
            ],
        },
        Source {
            kind: SourceKind::RecentlyClosed,
            path: "Tabs_1".into(),
            windows: vec![window(0, vec![tab(200, 1)])],
        },
    ]
}

#[test]
fn starts_at_source_level() {
    let app = App::new(sample());
    assert_eq!(app.depth(), 0);
    assert_eq!(app.selected_index(), 0);
    assert_eq!(app.active_pane(), Pane::Left);
    assert_eq!(app.level_len(), 2); // two sources
    assert!(!app.should_quit());
}

#[test]
fn down_and_up_are_clamped() {
    let mut app = App::new(sample());
    app.update(Action::Down);
    assert_eq!(app.selected_index(), 1);
    app.update(Action::Down); // already at last source, clamps
    assert_eq!(app.selected_index(), 1);
    app.update(Action::Up);
    assert_eq!(app.selected_index(), 0);
    app.update(Action::Up); // clamps at top
    assert_eq!(app.selected_index(), 0);
}

#[test]
fn descend_and_ascend_walk_the_hierarchy() {
    let mut app = App::new(sample());
    // source 0 -> its windows
    app.update(Action::Descend);
    assert_eq!(app.depth(), 1);
    assert_eq!(app.level_len(), 2); // window 10, 11
    assert_eq!(app.selected_index(), 0, "selection resets on descend");

    // window 1 -> its tabs
    app.update(Action::Down);
    app.update(Action::Descend);
    assert_eq!(app.depth(), 2);
    assert_eq!(app.current_window().unwrap().id, 11);
    assert_eq!(app.level_len(), 1); // window 11 has one tab

    app.update(Action::Ascend);
    assert_eq!(app.depth(), 1);
    app.update(Action::Ascend);
    assert_eq!(app.depth(), 0);
    app.update(Action::Ascend); // clamps at root
    assert_eq!(app.depth(), 0);
}

#[test]
fn descend_into_history_then_stops_at_leaf() {
    let mut app = App::new(sample());
    app.update(Action::Descend); // windows
    app.update(Action::Descend); // tabs of window 10
    app.update(Action::Descend); // history of tab 100
    assert_eq!(app.depth(), 3);
    assert_eq!(app.level_len(), 3); // tab 100 has 3 history entries
    assert_eq!(app.current_nav().unwrap().url, "https://100/0");
    app.update(Action::Descend); // no deeper level
    assert_eq!(app.depth(), 3);
}

#[test]
fn descend_does_nothing_when_no_children() {
    // A source with an empty window: descending into the window has no tabs.
    let sources = vec![Source {
        kind: SourceKind::Current,
        path: "Session_1".into(),
        windows: vec![window(10, vec![])],
    }];
    let mut app = App::new(sources);
    app.update(Action::Descend); // into windows
    assert_eq!(app.depth(), 1);
    app.update(Action::Descend); // window has no tabs -> stays
    assert_eq!(app.depth(), 1);
}

#[test]
fn swap_pane_toggles_and_quit_sets_flag() {
    let mut app = App::new(sample());
    app.update(Action::SwapPane);
    assert_eq!(app.active_pane(), Pane::Right);
    app.update(Action::SwapPane);
    assert_eq!(app.active_pane(), Pane::Left);
    app.update(Action::Quit);
    assert!(app.should_quit());
}

#[test]
fn top_and_bottom_jump_within_level() {
    let mut app = App::new(sample());
    app.update(Action::Descend); // windows (2)
    app.update(Action::Bottom);
    assert_eq!(app.selected_index(), 1);
    app.update(Action::Top);
    assert_eq!(app.selected_index(), 0);
}

#[test]
fn half_and_full_page_move_and_clamp() {
    let big: Vec<Tab> = (0..25).map(|i| tab(1000 + i, 1)).collect();
    let sources = vec![Source {
        kind: SourceKind::Current,
        path: "S".into(),
        windows: vec![window(1, big)],
    }];
    let mut app = App::new(sources);
    app.update(Action::Descend); // windows (1)
    app.update(Action::Descend); // tabs (25)
    app.update(Action::HalfPageDown);
    assert_eq!(app.selected_index(), 10);
    app.update(Action::HalfPageDown);
    assert_eq!(app.selected_index(), 20);
    app.update(Action::PageDown);
    assert_eq!(app.selected_index(), 24, "clamps at last");
    app.update(Action::HalfPageUp);
    assert_eq!(app.selected_index(), 14);
    app.update(Action::PageUp);
    assert_eq!(app.selected_index(), 0, "clamps at top");
}

#[test]
fn next_and_prev_window_jump_and_rescope() {
    let mut app = App::new(sample()); // source 0 has windows 10 and 11
    app.update(Action::Descend); // depth 1 (windows)
    app.update(Action::Descend); // depth 2 (tabs of window 10)
    app.update(Action::Down); // select second tab of window 10
    app.update(Action::NextWindow);
    assert_eq!(app.current_window().unwrap().id, 11);
    assert_eq!(
        app.selected_index(),
        0,
        "tab selection resets for the new window"
    );
    app.update(Action::PrevWindow);
    assert_eq!(app.current_window().unwrap().id, 10);
}

fn buffer_text(app: &App) -> String {
    let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
    term.draw(|f| draw(f, app)).unwrap();
    let buf = term.backend().buffer().clone();
    buf.content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect()
}

#[test]
fn render_shows_source_label_and_a_url() {
    let app = App::new(sample());
    let text = buffer_text(&app);
    assert!(
        text.contains("Current Session"),
        "left pane shows the source label"
    );
}

#[test]
fn render_after_descending_shows_tab_url() {
    let mut app = App::new(sample());
    app.update(Action::Descend); // windows
    app.update(Action::Descend); // tabs
    let text = buffer_text(&app);
    assert!(
        text.contains("https://100/0"),
        "preview shows a tab url, got:\n{text}"
    );
}

/// End-to-end against the real profile when present: discovery → replay → render
/// produces a non-empty frame with the expected chrome. Skips if no profile.
#[test]
fn renders_real_profile_without_panic() {
    let store = match snss::SessionStore::open_default_profile() {
        Ok(s) if !s.sources().is_empty() => s,
        _ => {
            eprintln!("SKIP: no real Brave profile present");
            return;
        }
    };
    let app = App::new(store.sources().to_vec());
    let text = buffer_text(&app);
    assert!(text.contains("Brave Sessions"), "title bar present");
    assert!(text.contains("Current Session"), "current source listed");
}
