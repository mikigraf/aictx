use std::{
    io::{self, IsTerminal, Stdout},
    path::PathBuf,
    time::Duration,
};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{Terminal, backend::CrosstermBackend, style::Color};

use crate::{
    Error, Result, activation,
    activation::SelectionConfirmation,
    config::MetadataStore,
    model::{Binding, Config, Context, MutableState, Name, Profile, ProfileId},
    resolver::{ResolvedContext, current_directory, resolve_context},
};

mod editor;
mod input;
mod mutations;
mod render;
mod terminal;

use editor::{Form, FormEvent, Submission};
use mutations::{apply_removal, apply_submission};
use render::{draw, profile_route_summary};
use terminal::{PanicHookGuard, TerminalSession};

const ACCENT: Color = Color::Cyan;
const WARNING: Color = Color::Yellow;
const ERROR: Color = Color::Red;
const MIN_WIDTH: u16 = 52;
const MIN_HEIGHT: u16 = 14;
const MODAL_WIDTH: u16 = 76;

/// Open the interactive account dashboard.
pub fn run(store: &MetadataStore, non_interactive: bool) -> Result<i32> {
    if non_interactive || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(Error::InteractionRequired(
            "interactive mode requires a terminal; use an explicit ctxlane subcommand in scripts"
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
            let area = terminal.size().map_err(Error::Terminal)?;
            app.viewport_width = area.width;
            app.viewport_height = area.height;
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
            Event::Paste(value) => handle_paste(app, &value),
            Event::Resize(_, _)
            | Event::FocusGained
            | Event::FocusLost
            | Event::Mouse(_)
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
    #[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
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
    change: activation::SelectionChange,
}

#[derive(Clone)]
enum Removal {
    Context { name: Name, expected: Context },
    Profile { id: ProfileId, expected: Profile },
    Binding { expected: Binding },
}

impl Removal {
    fn label(&self) -> String {
        match self {
            Self::Context { name, .. } => format!("context {name}"),
            Self::Profile { id, .. } => format!("profile {id}"),
            Self::Binding { expected } => format!(
                "binding {} -> {}",
                terminal_safe(&expected.path.display().to_string()),
                expected.context
            ),
        }
    }
}

#[derive(Clone)]
enum Overlay {
    Help,
    Activation(PendingActivation),
    Form(Form),
    Removal(Removal),
    SelectionChange(Submission),
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
    overlay: Option<Overlay>,
    viewport_width: u16,
    viewport_height: u16,
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
            overlay: None,
            viewport_width: u16::MAX,
            viewport_height: u16::MAX,
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
        self.config = config;
        self.state = state;
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

    fn required_size(&self) -> (u16, u16) {
        match self.overlay.as_ref() {
            Some(Overlay::Help) => (68, 23),
            Some(Overlay::Activation(_) | Overlay::SelectionChange(_)) => (MODAL_WIDTH, 17),
            Some(Overlay::Removal(_)) => (70, 13),
            Some(Overlay::Form(form)) => (
                MODAL_WIDTH,
                u16::try_from(form.fields.len())
                    .unwrap_or(u16::MAX)
                    .saturating_add(9)
                    .max(15),
            ),
            None => (MIN_WIDTH, MIN_HEIGHT),
        }
    }

    fn visible_for_interaction(&self) -> bool {
        let (width, height) = self.required_size();
        self.viewport_width >= width && self.viewport_height >= height
    }
}

fn handle_key(app: &mut App, store: &MetadataStore, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        app.exit_code = 130;
        return;
    }

    if !app.visible_for_interaction() {
        if key.code == KeyCode::Esc && app.overlay.take().is_some() {
            app.set_message(MessageLevel::Info, "Action cancelled.");
        } else if app.overlay.is_none() && key.code == KeyCode::Char('q') {
            app.should_quit = true;
        }
        return;
    }

    if app.overlay.is_some() {
        handle_overlay_key(app, store, key);
        return;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('?' | 'h') => app.overlay = Some(Overlay::Help),
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
        KeyCode::Char('a') => open_add_form(app),
        KeyCode::Char('e') => open_edit_form(app, false),
        KeyCode::Char('R') | KeyCode::F(2) => open_rename_form(app),
        KeyCode::Char('d') => open_removal(app),
        KeyCode::Char('r') => match app.reload(store) {
            Ok(()) => app.set_message(MessageLevel::Info, "Metadata reloaded."),
            Err(error) => app.set_message(MessageLevel::Error, error.to_string()),
        },
        _ => {}
    }
}

fn handle_paste(app: &mut App, value: &str) {
    if !app.visible_for_interaction() {
        return;
    }
    if let Some(Overlay::Form(form)) = app.overlay.as_mut() {
        form.handle_paste(value);
    }
}

fn handle_overlay_key(app: &mut App, store: &MetadataStore, key: KeyEvent) {
    let Some(overlay) = app.overlay.take() else {
        return;
    };
    match overlay {
        Overlay::Help => match key.code {
            KeyCode::Esc | KeyCode::Char('?' | 'h') => {}
            _ => app.overlay = Some(Overlay::Help),
        },
        Overlay::Activation(pending) => match key.code {
            KeyCode::Char('y' | 'Y') => confirm_activation(app, store, pending),
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                app.set_message(MessageLevel::Info, "Activation cancelled.");
            }
            _ => app.overlay = Some(Overlay::Activation(pending)),
        },
        Overlay::Form(mut form) => match form.handle_key(key) {
            FormEvent::Cancel => app.set_message(MessageLevel::Info, "Edit cancelled."),
            FormEvent::Submit => {
                if let Some(submission) = form.submission() {
                    if matches!(
                        &submission,
                        Submission::ContextEdit {
                            expected,
                            replacement,
                            ..
                        } if expected != replacement
                    ) {
                        app.overlay = Some(Overlay::SelectionChange(submission));
                    } else if let Err(error) = apply_submission(app, store, submission) {
                        form.error = Some(error.to_string());
                        app.overlay = Some(Overlay::Form(form));
                    }
                } else {
                    app.overlay = Some(Overlay::Form(form));
                }
            }
            FormEvent::Changed | FormEvent::None => app.overlay = Some(Overlay::Form(form)),
        },
        Overlay::Removal(removal) => match key.code {
            KeyCode::Char('y' | 'Y') => {
                if let Err(error) = apply_removal(app, store, &removal) {
                    app.set_message(MessageLevel::Error, error.to_string());
                }
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                app.set_message(MessageLevel::Info, "Removal cancelled.");
            }
            _ => app.overlay = Some(Overlay::Removal(removal)),
        },
        Overlay::SelectionChange(submission) => match key.code {
            KeyCode::Char('y' | 'Y') => {
                if let Err(error) = apply_submission(app, store, submission.clone()) {
                    app.set_message(MessageLevel::Error, error.to_string());
                    app.overlay = Some(Overlay::SelectionChange(submission));
                }
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                app.set_message(MessageLevel::Info, "Context edit cancelled.");
            }
            _ => app.overlay = Some(Overlay::SelectionChange(submission)),
        },
    }
}

fn open_add_form(app: &mut App) {
    let form = match app.panel {
        Panel::Contexts => Form::context_add(&app.config),
        Panel::Profiles => Form::profile_add(),
        Panel::Bindings => {
            if app.config.contexts.is_empty() {
                app.set_message(
                    MessageLevel::Warning,
                    "Add a context before adding a directory binding.",
                );
                return;
            }
            Form::binding_add(&app.cwd, &app.config)
        }
    };
    app.message = None;
    app.overlay = Some(Overlay::Form(form));
}

fn open_edit_form(app: &mut App, focus_binding_path: bool) {
    let form = match app.panel {
        Panel::Contexts => {
            let Some(name) = app.selected_context().cloned() else {
                app.set_message(MessageLevel::Warning, "No context is selected.");
                return;
            };
            let context = app.config.contexts[&name].clone();
            Form::context_edit(name, context, &app.config)
        }
        Panel::Profiles => {
            let Some(id) = app.selected_profile().cloned() else {
                app.set_message(MessageLevel::Warning, "No profile is selected.");
                return;
            };
            let profile = app.config.profiles[&id].clone();
            Form::profile_edit(id, profile)
        }
        Panel::Bindings => {
            let Some(binding) = app.config.bindings.get(app.binding_index).cloned() else {
                app.set_message(MessageLevel::Warning, "No binding is selected.");
                return;
            };
            Form::binding_edit(
                binding.path,
                binding.context,
                &app.config,
                focus_binding_path,
            )
        }
    };
    app.message = None;
    app.overlay = Some(Overlay::Form(form));
}

fn open_rename_form(app: &mut App) {
    let form = match app.panel {
        Panel::Contexts => {
            let Some(name) = app.selected_context().cloned() else {
                app.set_message(MessageLevel::Warning, "No context is selected.");
                return;
            };
            Form::context_rename(name.clone(), app.config.contexts[&name].clone())
        }
        Panel::Profiles => {
            let Some(id) = app.selected_profile().cloned() else {
                app.set_message(MessageLevel::Warning, "No profile is selected.");
                return;
            };
            Form::profile_rename(id.clone(), app.config.profiles[&id].clone())
        }
        Panel::Bindings => {
            open_edit_form(app, true);
            return;
        }
    };
    app.message = None;
    app.overlay = Some(Overlay::Form(form));
}

fn open_removal(app: &mut App) {
    let removal = match app.panel {
        Panel::Contexts => {
            let Some(name) = app.selected_context().cloned() else {
                app.set_message(MessageLevel::Warning, "No context is selected.");
                return;
            };
            Removal::Context {
                expected: app.config.contexts[&name].clone(),
                name,
            }
        }
        Panel::Profiles => {
            let Some(id) = app.selected_profile().cloned() else {
                app.set_message(MessageLevel::Warning, "No profile is selected.");
                return;
            };
            Removal::Profile {
                expected: app.config.profiles[&id].clone(),
                id,
            }
        }
        Panel::Bindings => {
            let Some(expected) = app.config.bindings.get(app.binding_index).cloned() else {
                app.set_message(MessageLevel::Warning, "No binding is selected.");
                return;
            };
            Removal::Binding { expected }
        }
    };
    app.message = None;
    app.overlay = Some(Overlay::Removal(removal));
}

fn request_activation(app: &mut App, store: &MetadataStore) {
    let Some(target) = app.selected_context().cloned() else {
        app.set_message(
            MessageLevel::Warning,
            "No context is selected. Add one with `ctxlane context add`.",
        );
        return;
    };
    match activation::required_selection_change(store, &target) {
        Ok(Some(change)) => {
            app.overlay = Some(Overlay::Activation(PendingActivation { change }));
            app.message = None;
        }
        Ok(None) => {
            let _ = commit_activation(app, store, &target, &SelectionConfirmation::None);
        }
        Err(error) => app.set_message(MessageLevel::Error, error.to_string()),
    }
}

fn confirm_activation(app: &mut App, store: &MetadataStore, pending: PendingActivation) {
    let target = pending.change.target().clone();
    let confirmation = SelectionConfirmation::Change(pending.change);
    if matches!(
        commit_activation(app, store, &target, &confirmation),
        Some(Error::InteractionRequired(_))
    ) {
        match activation::required_selection_change(store, &target) {
            Ok(Some(change)) => {
                app.overlay = Some(Overlay::Activation(PendingActivation { change }));
                app.set_message(
                    MessageLevel::Warning,
                    "Context or profile state changed. Review the account warning again.",
                );
            }
            Ok(None) => {
                let _ = commit_activation(app, store, &target, &SelectionConfirmation::None);
            }
            Err(error) => app.set_message(MessageLevel::Error, error.to_string()),
        }
    }
}

fn commit_activation(
    app: &mut App,
    store: &MetadataStore,
    target: &Name,
    confirmation: &SelectionConfirmation,
) -> Option<Error> {
    match activation::activate_with_receipt(store, target, confirmation, &app.cwd) {
        Ok(receipt) => match app.reload(store) {
            Ok(()) => {
                let message = if receipt.is_shadowed() {
                    format!(
                        "Global active context: {} [{}]; effective here at commit: {} [{}] ({}). Directory binding takes precedence.",
                        receipt.global_context(),
                        profile_route_summary(receipt.global_profiles()),
                        receipt.effective_context(),
                        profile_route_summary(receipt.effective_profiles()),
                        receipt.source().label()
                    )
                } else {
                    format!(
                        "Global active context: {} [{}]; effective here at commit: {} [{}] ({}).",
                        receipt.global_context(),
                        profile_route_summary(receipt.global_profiles()),
                        receipt.effective_context(),
                        profile_route_summary(receipt.effective_profiles()),
                        receipt.source().label()
                    )
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

#[cfg(test)]
mod tests;
