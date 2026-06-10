//! The `br4n6` terminal-UI mode: a Midnight-Commander-style, vi-keyed viewer over
//! Chromium session state (open / recently-closed tabs and windows). The pure
//! reducer lives in [`crate::App`]; this module is the side-effecting main loop.
//!
//! Loads sessions from an explicit `Sessions` directory when given, otherwise the
//! default local profile.

use std::io;
use std::path::{Path, PathBuf};
use std::{fs, process};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use snss::SessionStore;

use browser_tui::{draw, Action, App, Effect, Keymap};

/// Open a [`SessionStore`] from an explicit `Sessions` directory or the default
/// local profile.
fn open_store(dir: Option<&Path>) -> Result<SessionStore, snss::SnssError> {
    match dir {
        Some(d) => SessionStore::open_dir(d),
        None => SessionStore::open_default_profile(),
    }
}

/// Run the TUI over the given `Sessions` directory (or the default profile).
///
/// # Errors
/// Returns an [`io::Error`] if terminal I/O fails. A missing/empty store is
/// reported to stderr and exits cleanly (not an error).
pub fn run_tui(dir: Option<PathBuf>) -> io::Result<()> {
    let store = match open_store(dir.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("br4n6: {e}");
            process::exit(1);
        }
    };
    if store.sources().is_empty() {
        eprintln!("br4n6: no session files found.");
        return Ok(());
    }

    let mut app = App::new(store.sources().to_vec());
    let reload_dir = dir;
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app, reload_dir.as_deref());
    ratatui::restore();
    result
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    reload_dir: Option<&Path>,
) -> io::Result<()> {
    let mut keymap = Keymap::default();
    while !app.should_quit() {
        terminal.draw(|f| draw(f, app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if let Some(action) = keymap.handle(key) {
                match action {
                    Action::SearchForward | Action::SearchBackward => {
                        app.update(action);
                        search_input(terminal, app)?;
                    }
                    Action::TagGlob => glob_input(terminal, app, true)?,
                    Action::UntagGlob => glob_input(terminal, app, false)?,
                    other => {
                        if let Some(effect) = app.update(other) {
                            perform(effect, app, reload_dir);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Read a URL glob and tag (or untag) all matching tabs on Enter; Esc cancels.
fn glob_input(terminal: &mut ratatui::DefaultTerminal, app: &mut App, tag: bool) -> io::Result<()> {
    let mut pattern = String::new();
    loop {
        let verb = if tag { "tag" } else { "untag" };
        app.status = format!(" {verb} glob: {pattern}");
        terminal.draw(|f| draw(f, app))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Enter => {
                if tag {
                    app.tag_by_glob(&pattern);
                } else {
                    app.untag_by_glob(&pattern);
                }
                app.status = format!("{} tab(s) tagged", app.tag_count());
                return Ok(());
            }
            KeyCode::Esc => {
                app.status.clear();
                return Ok(());
            }
            KeyCode::Backspace => {
                pattern.pop();
            }
            KeyCode::Char(c) => pattern.push(c),
            _ => {}
        }
    }
}

/// Execute a side effect produced by the reducer and report the outcome in the
/// status bar. Failures are surfaced, never silently swallowed.
fn perform(effect: Effect, app: &mut App, reload_dir: Option<&Path>) {
    match effect {
        Effect::OpenUrl(url) => {
            app.status = match open::that(&url) {
                Ok(()) => format!("opened {url}"),
                Err(e) => format!("could not open {url}: {e}"),
            };
        }
        Effect::CopyToClipboard(text) => {
            app.status = match copy_to_clipboard(&text) {
                Ok(()) => "copied to clipboard".to_string(),
                Err(e) => format!("clipboard error: {e}"),
            };
        }
        Effect::Export(export) => {
            let md = format!("{}.md", export.name);
            let json = format!("{}.json", export.name);
            app.status = match fs::write(&md, &export.markdown)
                .and_then(|()| fs::write(&json, &export.json))
            {
                Ok(()) => format!("exported {md} and {json}"),
                Err(e) => format!("export failed: {e}"),
            };
        }
        Effect::Reload => match open_store(reload_dir) {
            Ok(store) => {
                *app = App::new(store.sources().to_vec());
                app.status = "reloaded from disk".to_string();
            }
            Err(e) => app.status = format!("reload failed: {e}"),
        },
    }
}

fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(text.to_string())?;
    Ok(())
}

/// Drive the incremental-search text input: each keystroke updates the live query
/// and re-runs the search. Enter accepts (keeps the match); Esc cancels (clears).
fn search_input(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> io::Result<()> {
    let mut query = String::new();
    loop {
        terminal.draw(|f| draw(f, app))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Enter => return Ok(()),
            KeyCode::Esc => {
                app.clear_search();
                return Ok(());
            }
            KeyCode::Backspace => {
                query.pop();
                app.set_query(&query);
            }
            KeyCode::Char(c) => {
                query.push(c);
                app.set_query(&query);
            }
            _ => {}
        }
    }
}
