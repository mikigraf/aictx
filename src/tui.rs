use std::{
    io::{self, IsTerminal, Stdout},
    panic::{self, PanicHookInfo},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};

use crate::{
    Error, Result, activation,
    activation::BillingConfirmation,
    config::MetadataStore,
    model::{Config, MutableState, Name, ProfileId, Provider},
    resolver::{ResolvedContext, current_directory, resolve_context},
};

const ACCENT: Color = Color::Cyan;
const WARNING: Color = Color::Yellow;
const ERROR: Color = Color::Red;
const MIN_WIDTH: u16 = 52;
const MIN_HEIGHT: u16 = 14;

/// Open the interactive context browser.
pub fn run(store: &MetadataStore, non_interactive: bool) -> Result<i32> {
    if non_interactive || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(Error::InteractionRequired(
            "interactive mode requires a terminal; use an explicit aictx subcommand in scripts"
                .to_owned(),
        ));
    }

    // Read and validate metadata before changing terminal state. A missing or malformed
    // configuration therefore produces a normal error and is never initialized or replaced.
    let mut app = App::load(store)?;
    let mut signals = TerminationSignals::new().map_err(Error::Terminal)?;
    let _panic_hook = PanicHookGuard::install();
    let mut terminal = TerminalSession::enter().map_err(Error::Terminal)?;
    let loop_result = run_loop(&mut terminal.terminal, &mut app, store, &mut signals);
    let exit_code = app.exit_code;
    let restore_result = terminal.restore();

    match (loop_result, restore_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(Error::Terminal(error)),
        (Ok(()), Ok(())) => Ok(exit_code),
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    store: &MetadataStore,
    signals: &mut TerminationSignals,
) -> Result<()> {
    let mut needs_draw = true;
    while !app.should_quit {
        if needs_draw {
            terminal
                .draw(|frame| draw(frame, app))
                .map_err(Error::Terminal)?;
            needs_draw = false;
        }
        if let Some(exit_code) = signals.pending_exit_code() {
            app.exit_code = exit_code;
            break;
        }
        if !event::poll(Duration::from_millis(100)).map_err(Error::Terminal)? {
            continue;
        }
        match event::read().map_err(Error::Terminal)? {
            Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(app, store, key),
            Event::Resize(_, _)
            | Event::FocusGained
            | Event::FocusLost
            | Event::Mouse(_)
            | Event::Paste(_)
            | Event::Key(_) => {}
        }
        needs_draw = true;
    }
    Ok(())
}

struct TerminationSignals {
    #[cfg(unix)]
    signals: signal_hook::iterator::Signals,
}

impl TerminationSignals {
    fn new() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};

            Ok(Self {
                signals: signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP])?,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    fn pending_exit_code(&mut self) -> Option<i32> {
        #[cfg(unix)]
        {
            use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};

            self.signals.pending().find_map(|signal| match signal {
                SIGINT => Some(128 + SIGINT),
                SIGTERM => Some(128 + SIGTERM),
                SIGHUP => Some(128 + SIGHUP),
                _ => None,
            })
        }

        #[cfg(not(unix))]
        {
            let _ = self;
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Panel {
    Contexts,
    Profiles,
    Bindings,
}

impl Panel {
    const fn next(self) -> Self {
        match self {
            Self::Contexts => Self::Profiles,
            Self::Profiles => Self::Bindings,
            Self::Bindings => Self::Contexts,
        }
    }

    const fn previous(self) -> Self {
        match self {
            Self::Contexts => Self::Bindings,
            Self::Profiles => Self::Contexts,
            Self::Bindings => Self::Profiles,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Contexts => 0,
            Self::Profiles => 1,
            Self::Bindings => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageLevel {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug)]
struct Message {
    level: MessageLevel,
    text: String,
}

#[derive(Clone, Debug)]
struct PendingActivation {
    change: activation::BillingChange,
}

struct App {
    config: Config,
    state: MutableState,
    cwd: PathBuf,
    resolution: std::result::Result<ResolvedContext, String>,
    panel: Panel,
    context_index: usize,
    profile_index: usize,
    binding_index: usize,
    show_help: bool,
    pending_activation: Option<PendingActivation>,
    message: Option<Message>,
    should_quit: bool,
    exit_code: i32,
}

impl App {
    fn load(store: &MetadataStore) -> Result<Self> {
        let (config, state) = store.load_metadata()?;
        let cwd = current_directory()?;
        Ok(Self::from_metadata(config, state, cwd))
    }

    fn from_metadata(config: Config, state: MutableState, cwd: PathBuf) -> Self {
        let resolution = resolve_context(&config, &state, &cwd, None)
            .map_err(|error| terminal_safe(&error.to_string()));
        let context_index = resolution
            .as_ref()
            .ok()
            .and_then(|resolved| {
                config
                    .contexts
                    .keys()
                    .position(|name| name == &resolved.name)
            })
            .unwrap_or(0);
        Self {
            config,
            state,
            cwd,
            resolution,
            panel: Panel::Contexts,
            context_index,
            profile_index: 0,
            binding_index: 0,
            show_help: false,
            pending_activation: None,
            message: None,
            should_quit: false,
            exit_code: 0,
        }
    }

    fn reload(&mut self, store: &MetadataStore) -> Result<()> {
        let selected_context = self.selected_context().cloned();
        let selected_profile = self.selected_profile().cloned();
        let selected_binding = self
            .config
            .bindings
            .get(self.binding_index)
            .map(|binding| binding.path.clone());
        let (config, state) = store.load_metadata()?;
        let cwd = current_directory()?;
        self.config = config;
        self.state = state;
        self.cwd = cwd;
        self.resolution = resolve_context(&self.config, &self.state, &self.cwd, None)
            .map_err(|error| terminal_safe(&error.to_string()));
        self.context_index = selected_context
            .as_ref()
            .and_then(|selected| {
                self.config
                    .contexts
                    .keys()
                    .position(|name| name == selected)
            })
            .unwrap_or(0);
        self.profile_index = selected_profile
            .as_ref()
            .and_then(|selected| self.config.profiles.keys().position(|id| id == selected))
            .unwrap_or(0);
        self.binding_index = selected_binding
            .as_ref()
            .and_then(|selected| {
                self.config
                    .bindings
                    .iter()
                    .position(|binding| &binding.path == selected)
            })
            .unwrap_or(0);
        self.clamp_selections();
        Ok(())
    }

    fn selected_context(&self) -> Option<&Name> {
        self.config.contexts.keys().nth(self.context_index)
    }

    fn selected_profile(&self) -> Option<&ProfileId> {
        self.config.profiles.keys().nth(self.profile_index)
    }

    fn item_count(&self) -> usize {
        match self.panel {
            Panel::Contexts => self.config.contexts.len(),
            Panel::Profiles => self.config.profiles.len(),
            Panel::Bindings => self.config.bindings.len(),
        }
    }

    fn selected_index_mut(&mut self) -> &mut usize {
        match self.panel {
            Panel::Contexts => &mut self.context_index,
            Panel::Profiles => &mut self.profile_index,
            Panel::Bindings => &mut self.binding_index,
        }
    }

    fn move_selection(&mut self, offset: isize) {
        let count = self.item_count();
        if count == 0 {
            *self.selected_index_mut() = 0;
            return;
        }
        let current = *self.selected_index_mut();
        *self.selected_index_mut() = if offset.is_negative() {
            current.saturating_sub(offset.unsigned_abs())
        } else {
            current.saturating_add(offset.unsigned_abs()).min(count - 1)
        };
    }

    fn select_first(&mut self) {
        *self.selected_index_mut() = 0;
    }

    fn select_last(&mut self) {
        *self.selected_index_mut() = self.item_count().saturating_sub(1);
    }

    fn clamp_selections(&mut self) {
        self.context_index = self
            .context_index
            .min(self.config.contexts.len().saturating_sub(1));
        self.profile_index = self
            .profile_index
            .min(self.config.profiles.len().saturating_sub(1));
        self.binding_index = self
            .binding_index
            .min(self.config.bindings.len().saturating_sub(1));
    }

    fn set_message(&mut self, level: MessageLevel, text: impl Into<String>) {
        self.message = Some(Message {
            level,
            text: terminal_safe(&text.into()),
        });
    }
}

fn handle_key(app: &mut App, store: &MetadataStore, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        app.exit_code = 130;
        return;
    }

    if app.pending_activation.is_some() {
        match key.code {
            KeyCode::Char('y' | 'Y') => confirm_activation(app, store),
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                app.pending_activation = None;
                app.set_message(MessageLevel::Info, "Activation cancelled.");
            }
            KeyCode::Char('q') => app.should_quit = true,
            _ => {}
        }
        return;
    }

    if app.show_help {
        match key.code {
            KeyCode::Esc | KeyCode::Char('?' | 'h') => app.show_help = false,
            KeyCode::Char('q') => app.should_quit = true,
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('?' | 'h') => app.show_help = true,
        KeyCode::Tab | KeyCode::Right => app.panel = app.panel.next(),
        KeyCode::BackTab | KeyCode::Left => app.panel = app.panel.previous(),
        KeyCode::Char('1') => app.panel = Panel::Contexts,
        KeyCode::Char('2') => app.panel = Panel::Profiles,
        KeyCode::Char('3') => app.panel = Panel::Bindings,
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
        KeyCode::PageDown => app.move_selection(10),
        KeyCode::PageUp => app.move_selection(-10),
        KeyCode::Home => app.select_first(),
        KeyCode::End => app.select_last(),
        KeyCode::Enter | KeyCode::Char('u') if app.panel == Panel::Contexts => {
            request_activation(app, store);
        }
        KeyCode::Char('r') => match app.reload(store) {
            Ok(()) => app.set_message(MessageLevel::Info, "Metadata reloaded."),
            Err(error) => app.set_message(MessageLevel::Error, error.to_string()),
        },
        _ => {}
    }
}

fn request_activation(app: &mut App, store: &MetadataStore) {
    let Some(target) = app.selected_context().cloned() else {
        app.set_message(
            MessageLevel::Warning,
            "No context is selected. Add one with `aictx context add`.",
        );
        return;
    };
    match activation::required_billing_change(store, &target) {
        Ok(Some(change)) => {
            app.pending_activation = Some(PendingActivation { change });
            app.message = None;
        }
        Ok(None) => {
            let _ = commit_activation(app, store, &target, &BillingConfirmation::None);
        }
        Err(error) => app.set_message(MessageLevel::Error, error.to_string()),
    }
}

fn confirm_activation(app: &mut App, store: &MetadataStore) {
    let Some(pending) = app.pending_activation.take() else {
        return;
    };
    let target = pending.change.target().clone();
    let confirmation = BillingConfirmation::Change(pending.change);
    if matches!(
        commit_activation(app, store, &target, &confirmation),
        Some(Error::InteractionRequired(_))
    ) {
        match activation::required_billing_change(store, &target) {
            Ok(Some(change)) => {
                app.pending_activation = Some(PendingActivation { change });
                app.set_message(
                    MessageLevel::Warning,
                    "Context state changed. Review the billing warning again.",
                );
            }
            Ok(None) => {
                let _ = commit_activation(app, store, &target, &BillingConfirmation::None);
            }
            Err(error) => app.set_message(MessageLevel::Error, error.to_string()),
        }
    }
}

fn commit_activation(
    app: &mut App,
    store: &MetadataStore,
    target: &Name,
    confirmation: &BillingConfirmation,
) -> Option<Error> {
    match activation::activate(store, target, confirmation) {
        Ok(()) => match app.reload(store) {
            Ok(()) => {
                let message = match &app.resolution {
                    Ok(resolved) if &resolved.name != target => format!(
                        "Global active context is {target}; this directory still resolves to {} via {}.",
                        resolved.name,
                        resolved.source.label()
                    ),
                    _ => format!("Active context: {target}"),
                };
                app.set_message(MessageLevel::Info, message);
                None
            }
            Err(error) => {
                app.set_message(
                    MessageLevel::Error,
                    format!("Context changed, but reload failed: {error}"),
                );
                Some(error)
            }
        },
        Err(error) => {
            app.set_message(MessageLevel::Error, error.to_string());
            Some(error)
        }
    }
}

fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        draw_small_terminal(frame, area);
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

    if app.show_help {
        draw_help(frame, area);
    }
    if let Some(pending) = &app.pending_activation {
        draw_confirmation(frame, area, pending);
    }
}

fn draw_small_terminal(frame: &mut Frame<'_>, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "aictx",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from("Terminal is too small."),
        Line::from(format!(
            "Resize to at least {MIN_WIDTH} x {MIN_HEIGHT}. q: quit"
        )),
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
            " aictx ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  secure identity and billing contexts"),
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
                Line::from("aictx context add <name> ..."),
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
            " j/k move  Enter use  ? help  q quit "
        } else {
            " j/k move  Tab panel  ? help  q quit "
        }
    } else if app.panel == Panel::Contexts {
        " j/k: move  Enter/u: use  Tab: panel  r: reload  ?: help  q: quit "
    } else {
        " j/k: move  Tab: panel  r: reload  ?: help  q: quit "
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
    let popup = centered_rect(68, 20, area);
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
        Line::from("r                   Reload metadata"),
        Line::from("? or h              Open or close this help"),
        Line::from("q or Esc            Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "The UI never resolves secrets or starts a vendor CLI.",
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

fn draw_confirmation(frame: &mut Frame<'_>, area: Rect, pending: &PendingActivation) {
    let popup = centered_rect(70, 12, area);
    frame.render_widget(Clear, popup);
    let previous_billing = billing_summary(pending.change.previous_domains());
    let target_billing = billing_summary(pending.change.target_domains());
    let lines = vec![
        Line::from(Span::styled(
            "Billing domain change",
            Style::default().fg(WARNING).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "Current billing context: {}",
            pending.change.previous()
        )),
        Line::from(format!("Current billing: {previous_billing}")),
        Line::from(format!("New global context: {}", pending.change.target())),
        Line::from(format!("New billing: {target_billing}")),
        Line::from(""),
        Line::from("This may charge a different account or organization."),
        Line::from("Press y to activate, or n/Esc to cancel."),
    ];
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

fn billing_summary(domains: [Option<crate::model::BillingDomain>; 2]) -> String {
    let summary = [Provider::Claude, Provider::Codex]
        .into_iter()
        .zip(domains)
        .filter_map(|(provider, domain)| domain.map(|domain| format!("{provider}: {domain}")))
        .collect::<Vec<_>>()
        .join(", ");
    if summary.is_empty() {
        "none".to_owned()
    } else {
        summary
    }
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

fn terminal_safe(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

struct TerminalSetup {
    raw_mode: bool,
    alternate_screen: bool,
    cursor_hidden: bool,
}

impl TerminalSetup {
    fn enter() -> io::Result<Self> {
        let mut setup = Self {
            raw_mode: false,
            alternate_screen: false,
            cursor_hidden: false,
        };
        enable_raw_mode()?;
        setup.raw_mode = true;

        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        setup.alternate_screen = true;
        execute!(stdout, Hide)?;
        setup.cursor_hidden = true;
        Ok(setup)
    }

    fn restore(&mut self) -> io::Result<()> {
        let mut first_error = None;
        let mut stdout = io::stdout();
        if self.cursor_hidden {
            match execute!(stdout, Show) {
                Ok(()) => self.cursor_hidden = false,
                Err(error) => first_error = Some(error),
            }
        }
        if self.alternate_screen {
            match execute!(stdout, LeaveAlternateScreen) {
                Ok(()) => self.alternate_screen = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if self.raw_mode {
            match disable_raw_mode() {
                Ok(()) => self.raw_mode = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for TerminalSetup {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    setup: TerminalSetup,
}

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        let setup = TerminalSetup::enter()?;
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        Ok(Self { terminal, setup })
    }

    fn restore(&mut self) -> io::Result<()> {
        self.setup.restore()
    }
}

type PanicHandler = dyn Fn(&PanicHookInfo<'_>) + Send + Sync + 'static;

struct PanicHookGuard {
    previous: Option<Arc<PanicHandler>>,
}

impl PanicHookGuard {
    fn install() -> Self {
        let previous: Arc<PanicHandler> = Arc::from(panic::take_hook());
        let chained = Arc::clone(&previous);
        panic::set_hook(Box::new(move |information| {
            restore_after_panic();
            chained(information);
        }));
        Self {
            previous: Some(previous),
        }
    }
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let _ = panic::take_hook();
        if let Some(previous) = self.previous.take() {
            panic::set_hook(Box::new(move |information| previous(information)));
        }
    }
}

fn restore_after_panic() {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, Show, LeaveAlternateScreen);
    let _ = disable_raw_mode();
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ratatui::{Terminal, backend::TestBackend};
    use tempfile::TempDir;

    use crate::model::{BillingDomain, Binding, ClaudeAuth, Context, Profile, SCHEMA_VERSION};

    use super::*;

    fn test_app() -> App {
        let work = Name::parse("work").unwrap_or_else(|error| panic!("valid name: {error}"));
        let personal =
            Name::parse("personal").unwrap_or_else(|error| panic!("valid name: {error}"));
        let profile_id: ProfileId = "claude:work"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
        let mut config = Config::default();
        config.profiles.insert(
            profile_id.clone(),
            Profile::Claude {
                billing_domain: BillingDomain::AnthropicApi,
                auth: ClaudeAuth::ApiKey,
                state_dir: PathBuf::from("/tmp/aictx-test-state"),
                secret_ref: Some("keyring://TopSecret/credential".to_owned()),
                account_hint: Some("secret-account@example.test".to_owned()),
                expected_organization: Some("secret-org".to_owned()),
                wif: None,
            },
        );
        config.contexts = BTreeMap::from([
            (
                personal.clone(),
                Context {
                    claude: Some(profile_id.clone()),
                    codex: None,
                },
            ),
            (
                work.clone(),
                Context {
                    claude: Some(profile_id),
                    codex: None,
                },
            ),
        ]);
        config.default_context = Some(personal);
        let state = MutableState {
            version: SCHEMA_VERSION,
            current_context: Some(work),
        };
        App::from_metadata(config, state, std::env::temp_dir())
    }

    fn render_text(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal =
            Terminal::new(backend).unwrap_or_else(|error| panic!("test terminal: {error}"));
        terminal
            .draw(|frame| draw(frame, app))
            .unwrap_or_else(|error| panic!("draw test UI: {error}"));
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>()
    }

    #[test]
    fn tiny_terminal_renders_without_panicking() {
        let text = render_text(&test_app(), 8, 3);
        assert!(!text.is_empty());
    }

    #[test]
    fn profile_view_never_renders_secret_metadata() {
        let mut app = test_app();
        app.panel = Panel::Profiles;
        let text = render_text(&app, 110, 30);
        assert!(text.contains("Profile claude:work"));
        assert!(!text.contains("TopSecret"));
        assert!(!text.contains("secret-account"));
        assert!(!text.contains("secret-org"));
    }

    #[test]
    fn navigation_is_bounded() {
        let mut app = test_app();
        assert_eq!(
            app.selected_context().map(Name::as_str),
            Some("work"),
            "the resolved context should be selected on launch"
        );
        app.move_selection(10);
        assert_eq!(app.context_index, 1);
        app.move_selection(-10);
        assert_eq!(app.context_index, 0);
        app.panel = Panel::Bindings;
        app.move_selection(1);
        assert_eq!(app.binding_index, 0);
    }

    #[test]
    fn header_distinguishes_active_context_from_directory_binding() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let mut app = test_app();
        let personal =
            Name::parse("personal").unwrap_or_else(|error| panic!("valid name: {error}"));
        app.cwd = temporary.path().to_path_buf();
        app.config.bindings.push(Binding {
            path: temporary
                .path()
                .canonicalize()
                .unwrap_or_else(|error| panic!("canonical path: {error}")),
            context: personal,
        });
        app.resolution = resolve_context(&app.config, &app.state, &app.cwd, None)
            .map_err(|error| error.to_string());
        let text = render_text(&app, 120, 30);
        assert!(text.contains("Global: work"));
        assert!(text.contains("Here: personal (directory binding)"));
    }
}
