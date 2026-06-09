//! Rendering of [`App`] state into a ratatui frame. Pure read-only view: it never
//! mutates state and produces no side effects.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::{App, Pane};

/// Draw the current app state: a title bar, two panes, a detail/status line, and
/// the Midnight-Commander function-key bar.
pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title bar
            Constraint::Min(3),    // panes
            Constraint::Length(1), // status / search
            Constraint::Length(1), // function-key bar
        ])
        .split(area);

    let (windows, tabs) = app.totals();
    let title = format!(" Brave Sessions  ·  {windows} win · {tabs} tabs");
    frame.render_widget(
        Paragraph::new(title).style(Style::default().add_modifier(Modifier::BOLD)),
        rows[0],
    );

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);

    // Left (navigator): rows at the current depth, selection highlighted.
    let left_items: Vec<ListItem> = app.left_rows().into_iter().map(ListItem::new).collect();
    let mut left_state = ListState::default();
    left_state.select(Some(app.selected_index()));
    let left = List::new(left_items)
        .block(pane_block(
            app.left_title(),
            app.active_pane() == Pane::Left,
        ))
        .highlight_symbol("» ")
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(left, panes[0], &mut left_state);

    // Right (preview): the selected item's children, with a detail footer.
    let (right_title, right_rows) = app.right_preview();
    let right_inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(detail_height(app))])
        .split(panes[1]);
    let right_items: Vec<ListItem> = right_rows.into_iter().map(ListItem::new).collect();
    let right =
        List::new(right_items).block(pane_block(right_title, app.active_pane() == Pane::Right));
    frame.render_widget(right, right_inner[0]);

    let detail = app.detail_lines().join("\n");
    if !detail.is_empty() {
        frame.render_widget(
            Paragraph::new(detail).block(Block::default().borders(Borders::ALL)),
            right_inner[1],
        );
    }

    // Status line: live search feedback, else the transient status message.
    let status = match app.search_query() {
        Some(q) => match app.current_match() {
            Some(i) => format!(
                " /{q}    {i}/{} matches  ·  n/N to cycle",
                app.match_count()
            ),
            None => format!(" /{q}    no matches"),
        },
        None if app.tag_count() > 0 => {
            format!(
                " {}    {} tagged · y/e act on tags",
                app.status,
                app.tag_count()
            )
        }
        None => app.status.clone(),
    };
    frame.render_widget(Paragraph::new(status), rows[2]);
    frame.render_widget(
        Paragraph::new(" F1 Help  F3 View  F4 Yank  F5 Export  F7 Search  F8 Open  F10 Quit")
            .style(Style::default().add_modifier(Modifier::REVERSED)),
        rows[3],
    );
}

fn pane_block(title: String, active: bool) -> Block<'static> {
    let style = if active {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(style)
}

fn detail_height(app: &App) -> u16 {
    if app.detail_lines().is_empty() {
        0
    } else {
        5 // 3 lines + top/bottom border
    }
}
