//! `browser_tui` entry point: load the default Brave profile and run the TUI.

use std::io;

use std::fs;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use snss::SessionStore;

use browser_tui::{draw, Action, App, Effect, Keymap};

fn main() -> io::Result<()> {
    let store = match SessionStore::open_default_profile() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("browser_tui: {e}");
            return Ok(());
        }
    };
    if store.sources().is_empty() {
        eprintln!("browser_tui: no Brave session files found.");
        return Ok(());
    }

    let mut app = App::new(store.sources().to_vec());
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> io::Result<()> {
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
                            perform(effect, app);
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
fn perform(effect: Effect, app: &mut App) {
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
        Effect::Reload => match SessionStore::open_default_profile() {
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
