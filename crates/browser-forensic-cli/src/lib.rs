#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! `browser_forensic_cli` — the TUI layer over [`snss`]. The pure application state lives in
//! [`App`] (a testable reducer over [`Action`]s); rendering is a thin function and
//! all side effects are returned as [`Effect`]s for the main loop to execute.

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use snss::{Nav, Source, SourceKind, Tab, Window};

mod render;
pub use render::draw;

pub mod cli;
pub mod export;

/// The outcome of feeding one key to a single-line text prompt (the search and
/// glob input loops). The loop owns the actual `event::read`/`draw`; this maps a
/// key to "what to do with the editor", keeping the decision out of the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputStep {
    /// The buffer changed (a char was pushed/popped); keep reading.
    Edited,
    /// `Enter` — accept the buffer.
    Accept,
    /// `Esc` — cancel the prompt.
    Cancel,
    /// A key with no binding; the buffer is unchanged.
    Ignored,
}

/// Apply one key to a single-line input `buffer`, returning what the prompt loop
/// should do next. `Char` appends, `Backspace` pops, `Enter`/`Esc` finish; any
/// other key is ignored. Pure: the only effect is on the passed-in `buffer`.
pub fn apply_input_key(buffer: &mut String, code: KeyCode) -> InputStep {
    match code {
        KeyCode::Enter => InputStep::Accept,
        KeyCode::Esc => InputStep::Cancel,
        KeyCode::Backspace => {
            buffer.pop();
            InputStep::Edited
        }
        KeyCode::Char(c) => {
            buffer.push(c);
            InputStep::Edited
        }
        _ => InputStep::Ignored,
    }
}

/// Status line after attempting to open a URL in the default browser.
pub fn open_status<E: std::fmt::Display>(url: &str, outcome: Result<(), E>) -> String {
    match outcome {
        Ok(()) => format!("opened {url}"),
        Err(e) => format!("could not open {url}: {e}"),
    }
}

/// Status line after attempting a clipboard copy.
pub fn clipboard_status<E: std::fmt::Display>(outcome: Result<(), E>) -> String {
    match outcome {
        Ok(()) => "copied to clipboard".to_string(),
        Err(e) => format!("clipboard error: {e}"),
    }
}

/// Status line after attempting to write the `<name>.md` + `<name>.json` export.
pub fn export_status<E: std::fmt::Display>(name: &str, outcome: Result<(), E>) -> String {
    match outcome {
        Ok(()) => format!("exported {name}.md and {name}.json"),
        Err(e) => format!("export failed: {e}"),
    }
}

/// Status line after attempting to reload the profile from disk.
pub fn reload_status<E: std::fmt::Display>(outcome: Result<(), E>) -> String {
    match outcome {
        Ok(()) => "reloaded from disk".to_string(),
        Err(e) => format!("reload failed: {e}"),
    }
}

/// The live prompt shown while typing a tag/untag glob.
pub fn glob_status(tag: bool, pattern: &str) -> String {
    let verb = if tag { "tag" } else { "untag" };
    format!(" {verb} glob: {pattern}")
}

/// The status line confirming how many tabs a glob tag/untag affected.
pub fn tagged_status(count: usize) -> String {
    format!("{count} tab(s) tagged")
}

/// How many rows a half-page / full-page jump moves (fixed step; the viewport
/// height is not threaded into the model in v1).
const HALF_PAGE: usize = 10;
const FULL_PAGE: usize = 20;

/// Which of the two Midnight-Commander panes has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    /// The navigator (the hierarchy column).
    Left,
    /// The viewer/preview.
    Right,
}

/// A high-level intent produced by the keymap and applied to [`App`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Move the selection up one row.
    Up,
    /// Move the selection down one row.
    Down,
    /// Descend into the selected item (Source → Window → Tab → history).
    Descend,
    /// Ascend to the parent level.
    Ascend,
    /// Swap the active pane (classic MC `Tab`).
    SwapPane,
    /// Jump to the top of the current list (`gg`).
    Top,
    /// Jump to the bottom of the current list (`G`).
    Bottom,
    /// Move down half a page (`Ctrl-d`).
    HalfPageDown,
    /// Move up half a page (`Ctrl-u`).
    HalfPageUp,
    /// Move down a full page (`Ctrl-f`).
    PageDown,
    /// Move up a full page (`Ctrl-b`).
    PageUp,
    /// Jump to the next window in the current source (`}`).
    NextWindow,
    /// Jump to the previous window in the current source (`{`).
    PrevWindow,
    /// Begin a forward incremental search (`/`).
    SearchForward,
    /// Begin a backward incremental search (`?`).
    SearchBackward,
    /// Jump to the next match (`n`).
    NextMatch,
    /// Jump to the previous match (`N`).
    PrevMatch,
    /// Search for the hostname under the cursor (`*`).
    SearchHostname,
    /// Clear the active search (`Esc`).
    ClearSearch,
    /// Open the URL under the cursor in the default browser (`o`, F8).
    Open,
    /// Copy the URL under the cursor to the clipboard (`y`, F4).
    YankUrl,
    /// Copy the title and URL under the cursor to the clipboard (`Y`).
    YankTitleUrl,
    /// Export the current node to Markdown + JSON (`e`, F5).
    Export,
    /// Reload the profile from disk (`r`).
    Reload,
    /// Cycle the sort mode (`s`).
    Sort,
    /// Tag/untag the tab under the cursor (`Space`).
    ToggleTag,
    /// Tag tabs by URL glob (`+`).
    TagGlob,
    /// Untag tabs by URL glob (`-`).
    UntagGlob,
    /// Quit the application.
    Quit,
}

/// Translates key events into [`Action`]s. Stateful only for the `gg` two-key
/// sequence; everything else is a pure mapping.
#[derive(Debug, Default)]
pub struct Keymap {
    /// Set after a lone `g`, awaiting the second `g` of `gg`.
    pending_g: bool,
}

impl Keymap {
    /// Map a key event to an action, remembering a pending `g` for `gg`.
    pub fn handle(&mut self, key: KeyEvent) -> Option<Action> {
        // Resolve the pending `g`: only a second `g` completes `gg`; any other
        // key cancels it and is then interpreted normally.
        let had_pending_g = self.pending_g;
        self.pending_g = false;
        if had_pending_g
            && key.code == KeyCode::Char('g')
            && !key.modifiers.contains(KeyModifiers::CONTROL)
        {
            return Some(Action::Top);
        }
        // otherwise the pending `g` is cancelled and this key maps normally

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return match key.code {
                KeyCode::Char('d') => Some(Action::HalfPageDown),
                KeyCode::Char('u') => Some(Action::HalfPageUp),
                KeyCode::Char('f') => Some(Action::PageDown),
                KeyCode::Char('b') => Some(Action::PageUp),
                _ => None,
            };
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => Some(Action::Down),
            KeyCode::Char('k') | KeyCode::Up => Some(Action::Up),
            KeyCode::Char('h') | KeyCode::Left => Some(Action::Ascend),
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => Some(Action::Descend),
            KeyCode::Tab => Some(Action::SwapPane),
            KeyCode::Char('g') => {
                self.pending_g = true;
                None
            }
            KeyCode::Char('G') => Some(Action::Bottom),
            KeyCode::Char('}') => Some(Action::NextWindow),
            KeyCode::Char('{') => Some(Action::PrevWindow),
            KeyCode::Char('/') => Some(Action::SearchForward),
            KeyCode::Char('?') => Some(Action::SearchBackward),
            KeyCode::Char('n') => Some(Action::NextMatch),
            KeyCode::Char('N') => Some(Action::PrevMatch),
            KeyCode::Char('*') => Some(Action::SearchHostname),
            KeyCode::Esc => Some(Action::ClearSearch),
            KeyCode::Char('o') | KeyCode::F(8) => Some(Action::Open),
            KeyCode::Char('y') | KeyCode::F(4) => Some(Action::YankUrl),
            KeyCode::Char('Y') => Some(Action::YankTitleUrl),
            KeyCode::Char('e') | KeyCode::F(5) => Some(Action::Export),
            KeyCode::Char('r') => Some(Action::Reload),
            KeyCode::Char('s') => Some(Action::Sort),
            KeyCode::Char(' ') => Some(Action::ToggleTag),
            KeyCode::Char('+') => Some(Action::TagGlob),
            KeyCode::Char('-') => Some(Action::UntagGlob),
            KeyCode::Char('q') | KeyCode::F(10) => Some(Action::Quit),
            _ => None,
        }
    }
}

/// The deepest navigable level (history entries).
const MAX_DEPTH: usize = 3;

/// Search direction for `/` (forward) vs `?` (backward).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `/` — start at the first match.
    Forward,
    /// `?` — start at the last match.
    Backward,
}

/// A tab location in the hierarchy: (source, window, tab) indices.
type TabPath = (usize, usize, usize);

/// A side effect the main loop must perform. The reducer stays pure by returning
/// these instead of touching the clipboard, browser, or filesystem itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Open this URL in the default browser.
    OpenUrl(String),
    /// Put this text on the system clipboard.
    CopyToClipboard(String),
    /// Write this export to disk.
    Export(Export),
    /// Re-read the profile from disk.
    Reload,
}

/// A rendered export of the current node, in both Markdown and JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Suggested base filename (no extension).
    pub name: String,
    /// Human-readable Markdown rendering.
    pub markdown: String,
    /// Machine-readable JSON rendering.
    pub json: String,
}

/// How lists are ordered. Cycled by `s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    /// On-disk order (no reordering).
    None,
    /// Windows by most-recent activity first.
    Recency,
    /// Tabs alphabetically by title.
    Title,
    /// Tabs alphabetically by URL.
    Url,
    /// Windows by descending tab count.
    TabCount,
}

impl SortMode {
    fn label(self) -> &'static str {
        match self {
            SortMode::None => "on-disk",
            SortMode::Recency => "recency",
            SortMode::Title => "title",
            SortMode::Url => "url",
            SortMode::TabCount => "tab-count",
        }
    }
    /// Next mode in the `s` cycle (never returns to `None`).
    fn next(self) -> SortMode {
        match self {
            SortMode::None | SortMode::TabCount => SortMode::Recency,
            SortMode::Recency => SortMode::Title,
            SortMode::Title => SortMode::Url,
            SortMode::Url => SortMode::TabCount,
        }
    }
}

/// Active search state: the query, the matching tab locations in document order,
/// and which match the cursor is on.
#[derive(Debug, Clone)]
struct SearchState {
    query: String,
    dir: Direction,
    matches: Vec<TabPath>,
    current: usize,
}

/// The pure application state. Holds the loaded sources and the navigation
/// cursor; [`App::update`] is the only way state changes.
#[derive(Debug, Clone)]
pub struct App {
    sources: Vec<Source>,
    depth: usize,
    /// Selected row index at each depth (0=sources, 1=windows, 2=tabs, 3=navs).
    selection: [usize; 4],
    active_pane: Pane,
    quit: bool,
    search: Option<SearchState>,
    sort: SortMode,
    /// Tagged tab locations for bulk yank/export.
    tags: BTreeSet<TabPath>,
    /// A transient status-bar message.
    pub status: String,
}

impl App {
    /// Build an app over the given sources, cursor at the top of the source list.
    pub fn new(sources: Vec<Source>) -> Self {
        App {
            sources,
            depth: 0,
            selection: [0; 4],
            active_pane: Pane::Left,
            quit: false,
            search: None,
            sort: SortMode::None,
            tags: BTreeSet::new(),
            status: String::new(),
        }
    }

    /// Apply an action, mutating navigation state. Returns an [`Effect`] for the
    /// main loop to perform (open a URL, copy, export, reload) when one applies.
    pub fn update(&mut self, action: Action) -> Option<Effect> {
        match action {
            Action::Down => {
                let last = self.level_len().saturating_sub(1);
                self.selection[self.depth] = (self.selection[self.depth] + 1).min(last);
            }
            Action::Up => {
                self.selection[self.depth] = self.selection[self.depth].saturating_sub(1);
            }
            Action::Descend => {
                if self.has_children() {
                    self.depth += 1;
                    self.selection[self.depth] = 0;
                }
            }
            Action::Ascend => {
                self.depth = self.depth.saturating_sub(1);
            }
            Action::SwapPane => {
                self.active_pane = match self.active_pane {
                    Pane::Left => Pane::Right,
                    Pane::Right => Pane::Left,
                };
            }
            Action::Top => self.selection[self.depth] = 0,
            Action::Bottom => {
                self.selection[self.depth] = self.level_len().saturating_sub(1);
            }
            Action::HalfPageDown => self.move_by(HALF_PAGE as isize),
            Action::HalfPageUp => self.move_by(-(HALF_PAGE as isize)),
            Action::PageDown => self.move_by(FULL_PAGE as isize),
            Action::PageUp => self.move_by(-(FULL_PAGE as isize)),
            Action::NextWindow => self.jump_window(1),
            Action::PrevWindow => self.jump_window(-1),
            Action::SearchForward => self.begin_search(Direction::Forward),
            Action::SearchBackward => self.begin_search(Direction::Backward),
            Action::NextMatch => self.next_match(),
            Action::PrevMatch => self.prev_match(),
            Action::SearchHostname => self.search_hostname(),
            Action::ClearSearch => self.clear_search(),
            Action::Open => return self.url_under_cursor().map(Effect::OpenUrl),
            Action::YankUrl => {
                // With a tag-set, yank all tagged URLs; otherwise the one under cursor.
                return if self.tags.is_empty() {
                    self.url_under_cursor().map(Effect::CopyToClipboard)
                } else {
                    Some(Effect::CopyToClipboard(self.tagged_urls().join("\n")))
                };
            }
            Action::YankTitleUrl => return self.title_and_url().map(Effect::CopyToClipboard),
            Action::Export => {
                return if self.tags.is_empty() {
                    self.export_current().map(Effect::Export)
                } else {
                    Some(Effect::Export(self.export_tagged()))
                };
            }
            Action::Reload => return Some(Effect::Reload),
            Action::Sort => self.cycle_sort(),
            Action::ToggleTag => self.tag_current(),
            Action::TagGlob | Action::UntagGlob => { /* main drives glob input */ }
            Action::Quit => self.quit = true,
        }
        None
    }

    /// Whether the app has been asked to quit.
    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Current drill depth (0=sources … 3=history).
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The active pane.
    pub fn active_pane(&self) -> Pane {
        self.active_pane
    }

    /// Selected row index at the current depth.
    pub fn selected_index(&self) -> usize {
        self.selection[self.depth]
    }

    /// All loaded sources.
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// The currently selected source (depth ≥ 0).
    pub fn current_source(&self) -> Option<&Source> {
        self.sources.get(self.selection[0])
    }

    /// The currently selected window (depth ≥ 1).
    pub fn current_window(&self) -> Option<&Window> {
        self.current_source()?.windows.get(self.selection[1])
    }

    /// The currently selected tab (depth ≥ 2).
    pub fn current_tab(&self) -> Option<&Tab> {
        self.current_window()?.tabs.get(self.selection[2])
    }

    /// The currently selected history entry (depth = 3).
    pub fn current_nav(&self) -> Option<&Nav> {
        self.current_tab()?.history.get(self.selection[3])
    }

    /// Number of rows at the current depth.
    pub fn level_len(&self) -> usize {
        self.len_at(self.depth)
    }

    /// Number of rows at an arbitrary depth, given the selections above it.
    fn len_at(&self, depth: usize) -> usize {
        match depth {
            0 => self.sources.len(),
            1 => self.current_source().map_or(0, |s| s.windows.len()),
            2 => self.current_window().map_or(0, |w| w.tabs.len()),
            _ => self.current_tab().map_or(0, |t| t.history.len()),
        }
    }

    /// Whether the selected item has children to descend into.
    fn has_children(&self) -> bool {
        self.depth < MAX_DEPTH && self.len_at(self.depth + 1) > 0
    }

    /// Move the current-depth selection by `delta` rows, clamped to the list.
    fn move_by(&mut self, delta: isize) {
        let last = self.level_len().saturating_sub(1) as isize;
        let next = (self.selection[self.depth] as isize + delta).clamp(0, last.max(0));
        self.selection[self.depth] = next as usize;
    }

    /// Jump to the previous/next window in the current source, re-scoping any
    /// deeper selection (tab/history) to the start of the new window.
    fn jump_window(&mut self, delta: isize) {
        let count = self.current_source().map_or(0, |s| s.windows.len());
        if count == 0 {
            return;
        }
        let last = (count - 1) as isize;
        let next = (self.selection[1] as isize + delta).clamp(0, last);
        self.selection[1] = next as usize;
        self.selection[2] = 0;
        self.selection[3] = 0;
    }

    // --- Search (Milestone 6) ------------------------------------------------

    /// Begin an empty incremental search; [`App::set_query`] feeds it text.
    pub fn begin_search(&mut self, dir: Direction) {
        self.search = Some(SearchState {
            query: String::new(),
            dir,
            matches: Vec::new(),
            current: 0,
        });
    }

    /// Set the live query: recompute matches across all sources and jump to the
    /// first (forward) or last (backward) match. Matching is a case-insensitive
    /// substring test over each tab's current URL and title.
    pub fn set_query(&mut self, query: &str) {
        let dir = self.search.as_ref().map_or(Direction::Forward, |s| s.dir);
        let matches = self.find_matches(query);
        let current = match dir {
            Direction::Backward if !matches.is_empty() => matches.len() - 1,
            _ => 0,
        };
        self.search = Some(SearchState {
            query: query.to_string(),
            dir,
            matches,
            current,
        });
        self.jump_to_current_match();
    }

    /// Jump to the next match (wraps).
    pub fn next_match(&mut self) {
        self.step_match(1);
    }

    /// Jump to the previous match (wraps).
    pub fn prev_match(&mut self) {
        self.step_match(-1);
    }

    /// Search for the hostname of the URL under the cursor (`*`).
    pub fn search_hostname(&mut self) {
        let Some(url) = self
            .current_tab()
            .and_then(|t| t.history.get(t.current))
            .map(|n| n.url.clone())
        else {
            return;
        };
        if let Some(host) = host_of(&url) {
            self.begin_search(Direction::Forward);
            self.set_query(host);
        }
    }

    /// Clear any active search.
    pub fn clear_search(&mut self) {
        self.search = None;
    }

    // --- Actions (Milestone 7) ----------------------------------------------

    /// The navigation entry under the cursor: the selected history entry at the
    /// leaf, else the current entry of the tab in scope. `None` above tab level.
    fn entry_under_cursor(&self) -> Option<&Nav> {
        if self.depth < 2 {
            return None;
        }
        if self.depth == MAX_DEPTH {
            self.current_nav()
        } else {
            self.current_tab().and_then(|t| t.history.get(t.current))
        }
    }

    /// The URL under the cursor, if a tab/entry is in scope.
    pub fn url_under_cursor(&self) -> Option<String> {
        self.entry_under_cursor().map(|n| n.url.clone())
    }

    /// "title\nurl" for the entry under the cursor (for `Y`).
    fn title_and_url(&self) -> Option<String> {
        self.entry_under_cursor()
            .map(|n| format!("{}\n{}", n.title, n.url))
    }

    /// The active sort mode.
    pub fn sort(&self) -> SortMode {
        self.sort
    }

    /// Cycle the sort mode and re-order the model; resets the cursor to the top.
    pub fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
        self.apply_sort();
        self.selection = [0; 4];
        self.status = format!("sorted by {}", self.sort.label());
    }

    fn apply_sort(&mut self) {
        match self.sort {
            SortMode::None => {}
            SortMode::Recency => {
                for s in &mut self.sources {
                    // Most-recent first; windows without a timestamp sort last.
                    s.windows.sort_by_key(|w| std::cmp::Reverse(w.last_active));
                }
            }
            SortMode::TabCount => {
                for s in &mut self.sources {
                    s.windows.sort_by_key(|w| std::cmp::Reverse(w.tabs.len()));
                }
            }
            SortMode::Title => self.sort_tabs_by(|n| n.title.to_lowercase()),
            SortMode::Url => self.sort_tabs_by(|n| n.url.to_lowercase()),
        }
    }

    fn sort_tabs_by<K: Ord>(&mut self, key: impl Fn(&Nav) -> K) {
        for source in &mut self.sources {
            for window in &mut source.windows {
                window
                    .tabs
                    .sort_by_key(|t| t.history.get(t.current).map(&key));
            }
        }
    }

    /// Render the node under the cursor to Markdown + JSON. Exports the current
    /// tab's full history when a tab is in scope; otherwise the current window.
    fn export_current(&self) -> Option<Export> {
        let source = self.current_source()?;
        let window = self.current_window()?;
        if let Some(tab) = self.current_tab().filter(|_| self.depth >= 2) {
            return Some(export_tab(source.kind, window.id, tab));
        }
        Some(export_window(source.kind, window))
    }

    // --- Tagging (Milestone 8) ----------------------------------------------

    /// Toggle the tag on the tab under the cursor (only at tab level or deeper).
    pub fn tag_current(&mut self) {
        if self.depth < 2 {
            return;
        }
        let path = (self.selection[0], self.selection[1], self.selection[2]);
        if self.current_tab().is_none() {
            return;
        }
        if !self.tags.insert(path) {
            self.tags.remove(&path);
        }
    }

    /// Tag every tab whose URL matches the glob (`*` wildcards, case-insensitive).
    pub fn tag_by_glob(&mut self, pattern: &str) {
        for path in self.tabs_matching(pattern) {
            self.tags.insert(path);
        }
    }

    /// Untag every tab whose URL matches the glob.
    pub fn untag_by_glob(&mut self, pattern: &str) {
        for path in self.tabs_matching(pattern) {
            self.tags.remove(&path);
        }
    }

    /// Tab locations whose current URL matches the glob.
    fn tabs_matching(&self, pattern: &str) -> Vec<TabPath> {
        let mut out = Vec::new();
        for (si, source) in self.sources.iter().enumerate() {
            for (wi, window) in source.windows.iter().enumerate() {
                for (ti, tab) in window.tabs.iter().enumerate() {
                    if let Some(nav) = tab.history.get(tab.current) {
                        if glob_match(pattern, &nav.url) {
                            out.push((si, wi, ti));
                        }
                    }
                }
            }
        }
        out
    }

    /// Look up a tagged tab by path.
    fn tab_at(&self, (si, wi, ti): TabPath) -> Option<&Tab> {
        self.sources.get(si)?.windows.get(wi)?.tabs.get(ti)
    }

    /// URLs of all tagged tabs, in document order (`BTreeSet` iterates sorted).
    pub fn tagged_urls(&self) -> Vec<String> {
        self.tags
            .iter()
            .filter_map(|&p| self.tab_at(p))
            .filter_map(|t| t.history.get(t.current))
            .map(|n| n.url.clone())
            .collect()
    }

    /// Number of tagged tabs.
    pub fn tag_count(&self) -> usize {
        self.tags.len()
    }

    /// Whether a given tab location is tagged.
    pub fn is_tagged(&self, path: TabPath) -> bool {
        self.tags.contains(&path)
    }

    /// Clear all tags.
    pub fn clear_tags(&mut self) {
        self.tags.clear();
    }

    /// Export all tagged tabs (their current entries) as Markdown + JSON.
    fn export_tagged(&self) -> Export {
        let mut md = format!("# Tagged tabs ({})\n\n", self.tags.len());
        let mut json_tabs = Vec::new();
        for &path in &self.tags {
            let Some(tab) = self.tab_at(path) else {
                continue;
            };
            let Some(nav) = tab.history.get(tab.current) else {
                continue;
            };
            md.push_str(&format!("- [{}]({})\n", nav.title, nav.url));
            json_tabs.push(format!(
                "{{\"id\":{},\"url\":{},\"title\":{}}}",
                tab.id,
                js(&nav.url),
                js(&nav.title)
            ));
        }
        let json = format!("{{\"tagged\":[{}]}}", json_tabs.join(","));
        Export {
            name: format!("tagged-{}", self.tags.len()),
            markdown: md,
            json,
        }
    }

    /// Collect matching tab locations in document order.
    fn find_matches(&self, query: &str) -> Vec<TabPath> {
        let needle = query.to_lowercase();
        let mut out = Vec::new();
        if needle.is_empty() {
            return out;
        }
        for (si, source) in self.sources.iter().enumerate() {
            for (wi, window) in source.windows.iter().enumerate() {
                for (ti, tab) in window.tabs.iter().enumerate() {
                    if let Some(nav) = tab.history.get(tab.current) {
                        if nav.url.to_lowercase().contains(&needle)
                            || nav.title.to_lowercase().contains(&needle)
                        {
                            out.push((si, wi, ti));
                        }
                    }
                }
            }
        }
        out
    }

    /// Move the current-match cursor by `delta` (wrapping) and jump to it.
    fn step_match(&mut self, delta: isize) {
        let Some(search) = self.search.as_mut() else {
            return;
        };
        let n = search.matches.len();
        if n == 0 {
            return;
        }
        let next = (search.current as isize + delta).rem_euclid(n as isize) as usize;
        search.current = next;
        self.jump_to_current_match();
    }

    /// Point the navigation cursor at the current match's tab (depth = tab level).
    fn jump_to_current_match(&mut self) {
        let Some(search) = self.search.as_ref() else {
            return;
        };
        let Some(&(si, wi, ti)) = search.matches.get(search.current) else {
            return;
        };
        self.selection = [si, wi, ti, 0];
        self.depth = 2;
    }

    /// The active query text, if a search is in progress.
    pub fn search_query(&self) -> Option<&str> {
        self.search.as_ref().map(|s| s.query.as_str())
    }

    /// Number of matches for the active search.
    pub fn match_count(&self) -> usize {
        self.search.as_ref().map_or(0, |s| s.matches.len())
    }

    /// 1-based index of the current match, if any matches exist.
    pub fn current_match(&self) -> Option<usize> {
        self.search
            .as_ref()
            .filter(|s| !s.matches.is_empty())
            .map(|s| s.current + 1)
    }

    // --- View model (consumed by the renderer) ------------------------------

    /// Title for the left (navigator) pane at the current depth.
    pub fn left_title(&self) -> String {
        match self.depth {
            0 => "Sources".to_string(),
            1 => format!(
                "Windows · {}",
                self.current_source().map_or("", |s| s.kind.label())
            ),
            2 => format!(
                "Tabs · Window {}",
                self.current_window().map_or(0, |w| w.id)
            ),
            _ => format!("History · Tab {}", self.current_tab().map_or(0, |t| t.id)),
        }
    }

    /// Display rows at a given depth, given the selections above it.
    pub fn rows_at(&self, depth: usize) -> Vec<String> {
        match depth {
            0 => self
                .sources
                .iter()
                .map(|s| format!("{}  ·  {} window(s)", s.kind.label(), s.windows.len()))
                .collect(),
            1 => self
                .current_source()
                .map(|s| {
                    s.windows
                        .iter()
                        .map(|w| format!("Window {}  ·  {} tab(s)", w.id, w.tabs.len()))
                        .collect()
                })
                .unwrap_or_default(),
            2 => self
                .current_window()
                .map(|w| {
                    w.tabs
                        .iter()
                        .enumerate()
                        .map(|(ti, t)| {
                            let tag = if self.is_tagged((self.selection[0], self.selection[1], ti))
                            {
                                '✓'
                            } else {
                                ' '
                            };
                            format!("{tag}{}", format_tab_row(t))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            _ => self
                .current_tab()
                .map(|t| {
                    t.history
                        .iter()
                        .enumerate()
                        .map(|(i, n)| {
                            let cur = if i == t.current { '>' } else { ' ' };
                            format!("{cur} {:>3}  {}", n.index, n.url)
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// Rows at the current depth.
    pub fn left_rows(&self) -> Vec<String> {
        self.rows_at(self.depth)
    }

    /// Title and rows for the right (preview) pane: the selected item's children,
    /// or — at a history leaf — nothing (the detail footer carries the leaf info).
    pub fn right_preview(&self) -> (String, Vec<String>) {
        if self.depth < MAX_DEPTH {
            let title = match self.depth {
                0 => "Windows".to_string(),
                1 => "Tabs".to_string(),
                _ => "History".to_string(),
            };
            (title, self.rows_at(self.depth + 1))
        } else {
            ("History".to_string(), Vec::new())
        }
    }

    /// Key/value detail for the in-focus tab + entry (shown once a tab is in
    /// scope, i.e. depth ≥ 2). Empty at shallower depths.
    pub fn detail_lines(&self) -> Vec<String> {
        if self.depth < 2 {
            return Vec::new();
        }
        let Some(tab) = self.current_tab() else {
            return Vec::new();
        };
        let entry = if self.depth == MAX_DEPTH {
            self.current_nav()
        } else {
            tab.history.get(tab.current)
        };
        vec![
            format!("URL    {}", entry.map_or("", |n| n.url.as_str())),
            format!("Title  {}", entry.map_or("", |n| n.title.as_str())),
            format!(
                "Tab id {} · pinned: {}",
                tab.id,
                if tab.pinned { "yes" } else { "no" }
            ),
        ]
    }

    /// Totals for the title bar: (windows, tabs) across all sources.
    pub fn totals(&self) -> (usize, usize) {
        let windows: usize = self.sources.iter().map(|s| s.windows.len()).sum();
        let tabs: usize = self
            .sources
            .iter()
            .flat_map(|s| &s.windows)
            .map(|w| w.tabs.len())
            .sum();
        (windows, tabs)
    }
}

/// Render a single tab (its full history) to Markdown + JSON.
fn export_tab(kind: SourceKind, window_id: i32, tab: &Tab) -> Export {
    let mut md = format!(
        "# Tab {} ({}, pinned: {})\n\nSource: {} · Window {}\n\n",
        tab.id,
        kind.label(),
        if tab.pinned { "yes" } else { "no" },
        kind.label(),
        window_id
    );
    for (i, n) in tab.history.iter().enumerate() {
        let marker = if i == tab.current { "**→**" } else { "-" };
        md.push_str(&format!("{} [{}]({})\n", marker, n.title, n.url));
    }

    let entries: Vec<String> = tab.history.iter().map(json_nav).collect();
    let json = format!(
        "{{\"source\":{},\"window\":{},\"tab\":{{\"id\":{},\"pinned\":{},\"current\":{},\"history\":[{}]}}}}",
        js(kind.label()),
        window_id,
        tab.id,
        tab.pinned,
        tab.current,
        entries.join(",")
    );
    Export {
        name: format!("tab-{}", tab.id),
        markdown: md,
        json,
    }
}

/// Render a whole window (its tabs' current entries) to Markdown + JSON.
fn export_window(kind: SourceKind, window: &Window) -> Export {
    let mut md = format!(
        "# Window {} ({})\n\n{} tab(s)\n\n",
        window.id,
        kind.label(),
        window.tabs.len()
    );
    let mut tabs_json = Vec::new();
    for tab in &window.tabs {
        let cur = tab.history.get(tab.current);
        let title = cur.map_or("", |n| n.title.as_str());
        let url = cur.map_or("", |n| n.url.as_str());
        let pin = if tab.pinned { "📌 " } else { "" };
        md.push_str(&format!("- {pin}[{title}]({url})\n"));
        tabs_json.push(format!(
            "{{\"id\":{},\"pinned\":{},\"url\":{},\"title\":{}}}",
            tab.id,
            tab.pinned,
            js(url),
            js(title)
        ));
    }
    let json = format!(
        "{{\"source\":{},\"window\":{},\"tabs\":[{}]}}",
        js(kind.label()),
        window.id,
        tabs_json.join(",")
    );
    Export {
        name: format!("window-{}", window.id),
        markdown: md,
        json,
    }
}

/// One navigation entry as a JSON object.
fn json_nav(n: &Nav) -> String {
    format!(
        "{{\"index\":{},\"url\":{},\"title\":{}}}",
        n.index,
        js(&n.url),
        js(&n.title)
    )
}

/// Serialize a string as a JSON string literal (with surrounding quotes),
/// escaping per the JSON spec so titles with quotes/backslashes stay valid.
fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Case-insensitive glob match supporting `*` (any run of characters). A pattern
/// not starting/ending with `*` is anchored at that end. No `?` or character
/// classes — just the wildcard the tag UI advertises.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat = pattern.to_lowercase();
    let txt = text.to_lowercase();
    let parts: Vec<&str> = pat.split('*').collect();
    let n = parts.len();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let anchored_start = i == 0 && !pat.starts_with('*');
        let anchored_end = i == n - 1 && !pat.ends_with('*');
        if anchored_start {
            if !txt[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if anchored_end {
            if !txt[pos..].ends_with(part) {
                return false;
            }
            pos = txt.len();
        } else {
            match txt[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// Extract the hostname from a URL: the text between `://` and the next `/`,
/// `?`, or `#`. Returns `None` for schemes without an authority (e.g. `about:`).
fn host_of(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..end];
    (!host.is_empty()).then_some(host)
}

/// One tab row: a pin marker plus the current entry's URL.
fn format_tab_row(tab: &Tab) -> String {
    let pin = if tab.pinned { "* " } else { "  " };
    let url = tab.history.get(tab.current).map_or("", |n| n.url.as_str());
    format!("{pin}{url}")
}
