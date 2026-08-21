use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};

use crate::{
    activation,
    model::{ProfileId, Provider},
};

use super::{
    ACCENT, App, ERROR, MODAL_WIDTH, MessageLevel, Overlay, Panel, PendingActivation, Removal,
    WARNING,
    editor::{self, Form, Submission},
    input::FieldValue,
    terminal_safe,
};

pub(super) fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let (required_width, required_height) = app.required_size();
    if area.width < required_width || area.height < required_height {
        draw_small_terminal(
            frame,
            area,
            required_width,
            required_height,
            app.overlay.is_some(),
        );
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    draw_header(frame, rows[0], app);
    draw_tabs(frame, rows[1], app);
    draw_body(frame, rows[2], app);
    draw_footer(frame, rows[3], app);

    match app.overlay.as_ref() {
        Some(Overlay::Help) => draw_help(frame, area),
        Some(Overlay::Activation(pending)) => draw_confirmation(frame, area, pending),
        Some(Overlay::Form(form)) => draw_form(frame, area, form),
        Some(Overlay::Removal(removal)) => draw_removal(frame, area, removal),
        Some(Overlay::SelectionChange(submission)) => {
            draw_selection_change(frame, area, submission);
        }
        None => {}
    }
}

fn draw_small_terminal(
    frame: &mut Frame<'_>,
    area: Rect,
    required_width: u16,
    required_height: u16,
    action_open: bool,
) {
    let text = vec![
        Line::from(Span::styled(
            "ctxlane",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from("Terminal is too small."),
        Line::from(format!(
            "Resize to at least {required_width} x {required_height}."
        )),
        Line::from(if action_open {
            "Writes are disabled. Esc: cancel  Ctrl-C: quit"
        } else {
            "q: quit"
        }),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let active = app
        .state
        .current_context
        .as_ref()
        .map_or_else(|| "none".to_owned(), ToString::to_string);
    let default = app
        .config
        .default_context
        .as_ref()
        .map_or_else(|| "none".to_owned(), ToString::to_string);
    let resolved = match &app.resolution {
        Ok(value) => format!("{} ({})", value.name, value.source.label()),
        Err(_) => "none".to_owned(),
    };
    let title = Line::from(vec![
        Span::styled(
            " ctxlane ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Local account boundary for Claude Code and Codex"),
    ]);
    let status = Line::from(format!(
        " Global: {active}   Default: {default}   Here: {resolved}"
    ));
    frame.render_widget(
        Paragraph::new(vec![title, status]).block(Block::default().borders(Borders::ALL).title(
            format!(
                " {} contexts | {} profiles | {} bindings ",
                app.config.contexts.len(),
                app.config.profiles.len(),
                app.config.bindings.len()
            ),
        )),
        area,
    );
}

fn draw_tabs(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let tabs = Tabs::new(vec!["[1] Contexts", "[2] Profiles", "[3] Bindings"])
        .select(app.panel.index())
        .block(Block::default().borders(Borders::ALL))
        .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
        .divider(" | ");
    frame.render_widget(tabs, area);
}

fn draw_body(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);
    match app.panel {
        Panel::Contexts => draw_contexts(frame, columns[0], columns[1], app),
        Panel::Profiles => draw_profiles(frame, columns[0], columns[1], app),
        Panel::Bindings => draw_bindings(frame, columns[0], columns[1], app),
    }
}

fn draw_contexts(frame: &mut Frame<'_>, list_area: Rect, detail_area: Rect, app: &App) {
    let resolved_name = app.resolution.as_ref().ok().map(|value| &value.name);
    let items = app
        .config
        .contexts
        .keys()
        .map(|name| {
            let mut labels = Vec::new();
            if app.state.current_context.as_ref() == Some(name) {
                labels.push("active");
            }
            if app.config.default_context.as_ref() == Some(name) {
                labels.push("default");
            }
            if resolved_name == Some(name) {
                labels.push("here");
            }
            let suffix = if labels.is_empty() {
                String::new()
            } else {
                format!(" [{}]", labels.join(", "))
            };
            ListItem::new(format!("{name}{suffix}"))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.context_index));
    }
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Contexts "))
        .highlight_symbol("> ")
        .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));
    frame.render_stateful_widget(list, list_area, &mut state);

    let lines = app.selected_context().map_or_else(
        || {
            vec![
                Line::from("No contexts configured."),
                Line::from(""),
                Line::from("Add one with:"),
                Line::from("ctxlane context add <name> ..."),
            ]
        },
        |name| {
            let context = &app.config.contexts[name];
            let mut lines = vec![detail_heading(format!("Context {name}")), Line::from("")];
            append_context_profile(&mut lines, app, "Claude", context.claude.as_ref());
            append_context_profile(&mut lines, app, "Codex", context.codex.as_ref());
            let binding_count = app
                .config
                .bindings
                .iter()
                .filter(|binding| &binding.context == name)
                .count();
            lines.push(Line::from(""));
            lines.push(Line::from(format!("Directory bindings: {binding_count}")));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Credentials are not read or shown in this view.",
                Style::default().fg(Color::DarkGray),
            )));
            lines
        },
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Status "))
            .wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn append_context_profile(
    lines: &mut Vec<Line<'static>>,
    app: &App,
    label: &str,
    id: Option<&ProfileId>,
) {
    match id {
        Some(id) => {
            lines.push(Line::from(format!("{label}: {id}")));
            if let Some(profile) = app.config.profiles.get(id) {
                lines.push(Line::from(format!("  Auth: {}", profile.auth_label())));
                lines.push(Line::from(format!(
                    "  Billing: {}",
                    profile.billing_domain()
                )));
            }
        }
        None => lines.push(Line::from(format!("{label}: not configured"))),
    }
}

fn draw_profiles(frame: &mut Frame<'_>, list_area: Rect, detail_area: Rect, app: &App) {
    let items = app
        .config
        .profiles
        .keys()
        .map(ToString::to_string)
        .map(ListItem::new)
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.profile_index));
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Profiles "))
            .highlight_symbol("> ")
            .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        list_area,
        &mut state,
    );

    let lines = app.selected_profile().map_or_else(
        || vec![Line::from("No profiles configured.")],
        |id| {
            let profile = &app.config.profiles[id];
            let contexts = app
                .config
                .contexts
                .iter()
                .filter(|(_, context)| context.profile(id.provider()) == Some(id))
                .map(|(name, _)| name.to_string())
                .collect::<Vec<_>>();
            vec![
                detail_heading(format!("Profile {id}")),
                Line::from(""),
                Line::from(format!("Provider: {}", profile.provider())),
                Line::from(format!("Auth: {}", profile.auth_label())),
                Line::from(format!("Billing: {}", profile.billing_domain())),
                Line::from(format!(
                    "Used by: {}",
                    if contexts.is_empty() {
                        "no contexts".to_owned()
                    } else {
                        contexts.join(", ")
                    }
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Secret references, account labels, and credentials are hidden.",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Status "))
            .wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn draw_bindings(frame: &mut Frame<'_>, list_area: Rect, detail_area: Rect, app: &App) {
    let items = app
        .config
        .bindings
        .iter()
        .map(|binding| {
            ListItem::new(format!(
                "{} -> {}",
                terminal_safe(&binding.path.display().to_string()),
                binding.context
            ))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.binding_index));
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Bindings "))
            .highlight_symbol("> ")
            .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        list_area,
        &mut state,
    );

    let lines = app.config.bindings.get(app.binding_index).map_or_else(
        || vec![Line::from("No directory bindings configured.")],
        |binding| {
            vec![
                detail_heading("Directory binding"),
                Line::from(""),
                Line::from(format!(
                    "Path: {}",
                    terminal_safe(&binding.path.display().to_string())
                )),
                Line::from(format!("Context: {}", binding.context)),
                Line::from(""),
                Line::from(if app.cwd.starts_with(&binding.path) {
                    "This binding contains the current directory."
                } else {
                    "This binding does not contain the current directory."
                }),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Status "))
            .wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let shortcuts = if area.width < 72 {
        if app.panel == Panel::Contexts {
            " j/k move Enter use a/e/R/d manage ? help q quit "
        } else {
            " j/k move a/e/R/d manage Tab panel ? help q quit "
        }
    } else if app.panel == Panel::Contexts {
        " j/k move Enter use a add e edit R rename d remove ? help q quit "
    } else {
        " j/k move a add e edit R rename d remove Tab panel ? help q quit "
    };
    let content = app.message.as_ref().map_or_else(
        || Line::from(shortcuts),
        |message| {
            let color = match message.level {
                MessageLevel::Info => ACCENT,
                MessageLevel::Warning => WARNING,
                MessageLevel::Error => ERROR,
            };
            Line::from(Span::styled(
                format!(" {} ", message.text),
                Style::default().fg(color),
            ))
        },
    );
    frame.render_widget(
        Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL).title(" Keys "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
    let popup = centered_rect(68, 23, area);
    frame.render_widget(Clear, popup);
    let lines = vec![
        detail_heading("Keyboard shortcuts"),
        Line::from(""),
        Line::from("Up/Down, j/k        Move selection"),
        Line::from("PageUp/PageDown     Move 10 rows"),
        Line::from("Home/End            First or last row"),
        Line::from("Tab, Left/Right     Change panel"),
        Line::from("1 / 2 / 3           Contexts / Profiles / Bindings"),
        Line::from("Enter or u          Activate selected context"),
        Line::from("a / e               Add / edit in current panel"),
        Line::from("R or F2             Rename (binding: edit path)"),
        Line::from("d                   Remove selected item"),
        Line::from("r                   Reload metadata"),
        Line::from("? or h              Open or close this help"),
        Line::from("q or Esc            Quit when no dialog is open"),
        Line::from(""),
        Line::from(Span::styled(
            "The UI never reads secret values or starts a vendor CLI.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from("Press Esc, ?, or h to close."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(ACCENT))
                    .title(" Help "),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_form(frame: &mut Frame<'_>, area: Rect, form: &Form) {
    let height = u16::try_from(form.fields.len())
        .unwrap_or(u16::MAX)
        .saturating_add(9)
        .max(15);
    let popup = centered_rect(MODAL_WIDTH, height, area);
    frame.render_widget(Clear, popup);
    let mut lines = vec![
        detail_heading(form.title()),
        Line::from("Tab/Shift-Tab: field   arrows/Space: choice"),
        Line::from("Enter: validate and save   Esc: cancel"),
        Line::from(""),
    ];
    for (index, field) in form.fields.iter().enumerate() {
        let focused = index == form.focus;
        let marker = if focused { ">" } else { " " };
        let label = truncate_for_terminal(&field.label, 38);
        let value = match &field.value {
            FieldValue::Text(input) => display_text_input(input.value(), input.cursor_column(), 27),
            FieldValue::Choice(choice) => format!("< {} >", choice.value()),
        };
        let style = if focused {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(
            format!("{marker} {label:<38} {value}"),
            style,
        )));
    }
    lines.push(Line::from(""));
    if matches!(form.operation, editor::FormOperation::ProfileAdd) {
        lines.push(Line::from(Span::styled(
            "Credentials are not entered here. Login after the profile is added.",
            Style::default().fg(Color::DarkGray),
        )));
    } else if matches!(form.operation, editor::FormOperation::ProfileEdit { .. }) {
        lines.push(Line::from(Span::styled(
            "Provider, auth, vendor state, WIF route, and credentials stay unchanged.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            terminal_safe(error),
            Style::default().fg(ERROR),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(ACCENT))
                    .title(format!(" {} ", form.title())),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_removal(frame: &mut Frame<'_>, area: Rect, removal: &Removal) {
    let popup = centered_rect(70, 13, area);
    frame.render_widget(Clear, popup);
    let mut lines = vec![
        Line::from(Span::styled(
            "Confirm removal",
            Style::default().fg(WARNING).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(removal.label()),
        Line::from(""),
    ];
    match removal {
        Removal::Context { .. } => {
            lines.push(Line::from(
                "Active or directory-bound contexts are refused.",
            ));
        }
        Removal::Profile { .. } => {
            lines.push(Line::from("Profiles used by a context are refused."));
            lines.push(Line::from(
                "Vendor state stays in place; keyring and remote credentials remain.",
            ));
        }
        Removal::Binding { .. } => {
            lines.push(Line::from(
                "Only the mapping is removed. The directory is unchanged.",
            ));
        }
    }
    lines.extend([
        Line::from(""),
        Line::from("Press y to remove, or n/Esc to cancel."),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(WARNING))
                    .title(" Remove "),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_selection_change(frame: &mut Frame<'_>, area: Rect, submission: &Submission) {
    let popup = centered_rect(MODAL_WIDTH, 17, area);
    frame.render_widget(Clear, popup);
    let mut lines = vec![
        Line::from(Span::styled(
            "Review account selection change",
            Style::default().fg(WARNING).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    if let Submission::ContextEdit {
        name,
        expected,
        replacement,
    } = submission
    {
        lines.push(Line::from(format!("Context: {name}")));
        append_profile_change(
            &mut lines,
            "Claude",
            expected.claude.as_ref(),
            replacement.claude.as_ref(),
        );
        append_profile_change(
            &mut lines,
            "Codex",
            expected.codex.as_ref(),
            replacement.codex.as_ref(),
        );
    }
    lines.extend([
        Line::from(""),
        Line::from("This changes the account used by this context."),
        Line::from("Press y to save, or n/Esc to cancel."),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(WARNING))
                    .title(" Confirm edit "),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn append_profile_change(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    before: Option<&ProfileId>,
    after: Option<&ProfileId>,
) {
    if before != after {
        lines.push(Line::from(format!(
            "{label}: {} -> {}",
            before.map_or("none".to_owned(), ToString::to_string),
            after.map_or("none".to_owned(), ToString::to_string)
        )));
    }
}

fn truncate_for_terminal(value: &str, width: usize) -> String {
    let mut characters = value.chars();
    let mut output = characters.by_ref().take(width).collect::<String>();
    if characters.next().is_some() && width > 1 {
        output.pop();
        output.push('…');
    }
    output
}

fn display_text_input(value: &str, cursor_column: usize, width: usize) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    let start = cursor_column.saturating_sub(width.saturating_sub(1));
    let end = characters.len().min(start.saturating_add(width));
    let mut shown = characters[start..end].iter().collect::<String>();
    if cursor_column == characters.len() && shown.chars().count() < width {
        shown.push('▏');
    } else if cursor_column >= start && cursor_column < end {
        let relative = cursor_column - start;
        let byte = shown
            .char_indices()
            .nth(relative)
            .map_or(shown.len(), |(index, _)| index);
        shown.insert(byte, '▏');
    }
    shown
}

fn draw_confirmation(frame: &mut Frame<'_>, area: Rect, pending: &PendingActivation) {
    let popup = centered_rect(76, 15, area);
    frame.render_widget(Clear, popup);
    let mut lines = vec![
        Line::from(Span::styled(
            "Account profile change",
            Style::default().fg(WARNING).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "Current global context: {}",
            pending.change.previous()
        )),
        Line::from(format!("New global context: {}", pending.change.target())),
    ];
    for (provider, (previous, target)) in [Provider::Claude, Provider::Codex].into_iter().zip(
        pending
            .change
            .previous_profiles()
            .iter()
            .zip(pending.change.target_profiles()),
    ) {
        if previous != target {
            lines.push(Line::from(format!(
                "{provider}: {} -> {}",
                profile_selection_summary(previous.as_ref()),
                profile_selection_summary(target.as_ref())
            )));
        }
    }
    lines.extend([
        Line::from(""),
        Line::from("The selected account or organization may be different."),
        Line::from("Press y to activate, or n/Esc to cancel."),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(WARNING))
                    .title(" Confirm activation "),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn profile_selection_summary(selection: Option<&activation::ProfileSelection>) -> String {
    selection.map_or_else(
        || "none".to_owned(),
        |selection| {
            format!(
                "{} ({}, {})",
                selection.id(),
                selection.auth_label(),
                selection.billing_domain()
            )
        },
    )
}

pub(super) fn profile_route_summary(
    profiles: &[Option<activation::ProfileSelection>; 2],
) -> String {
    [Provider::Claude, Provider::Codex]
        .into_iter()
        .zip(profiles)
        .filter_map(|(provider, profile)| {
            profile
                .as_ref()
                .map(|profile| format!("{provider}={}", profile_selection_summary(Some(profile))))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn detail_heading(value: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(
        value.into(),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))
}

const fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = if width < area.width {
        width
    } else {
        area.width
    };
    let height = if height < area.height {
        height
    } else {
        area.height
    };
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}
