use std::{
    fmt,
    io::{self, IsTerminal, Read, Write},
    panic::{self, PanicHookInfo},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use secrecy::{ExposeSecret, SecretString};

use crate::{
    Error, Result,
    model::{ProfileId, Provider},
};

const DEFAULT_KEYRING_SERVICE: &str = "ctxlane";
const MAX_SECRET_BYTES: usize = 1024 * 1024;
const INPUT_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const INPUT_DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(20);
const INPUT_DRAIN_DEADLINE: Duration = Duration::from_millis(250);
static KEYRING_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretRef {
    Keyring { service: String, account: String },
}

impl SecretRef {
    #[must_use]
    pub fn default_for(profile_id: &ProfileId) -> Self {
        Self::Keyring {
            service: DEFAULT_KEYRING_SERVICE.to_owned(),
            account: format!(
                "{}-{}-{generation:032x}-{:08x}-{counter:016x}",
                profile_id.provider(),
                profile_id.name(),
                std::process::id(),
                generation = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_nanos()),
                counter = KEYRING_GENERATION.fetch_add(1, Ordering::Relaxed),
            ),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::Keyring { service, account } = self;
        write!(formatter, "keyring://{service}/{account}")
    }
}

impl FromStr for SecretRef {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidInput(
                "secret reference contains a forbidden control character".to_owned(),
            ));
        }

        let rest = value.strip_prefix("keyring://").ok_or_else(|| {
            Error::InvalidInput("secret reference must use `keyring://service/account`".to_owned())
        })?;
        let (service, account) = rest.split_once('/').ok_or_else(|| {
            Error::InvalidInput(
                "keyring reference must have the form `keyring://service/account`".to_owned(),
            )
        })?;
        if service.is_empty() || account.is_empty() || account.contains('/') {
            return Err(Error::InvalidInput(
                "keyring service and account must be non-empty path-safe segments".to_owned(),
            ));
        }
        Ok(Self::Keyring {
            service: service.to_owned(),
            account: account.to_owned(),
        })
    }
}

pub trait SecretProvider {
    fn get(&self, reference: &SecretRef, non_interactive: bool) -> Result<SecretString>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecretManager;

impl SecretManager {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn put(&self, reference: &SecretRef, secret: &SecretString) -> Result<()> {
        enforce_secret_size(secret.expose_secret().len())?;
        let SecretRef::Keyring { service, account } = reference;
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        entry
            .set_password(secret.expose_secret())
            .map_err(|error| Error::CredentialStore(error.to_string()))
    }

    pub fn delete(&self, reference: &SecretRef, non_interactive: bool) -> Result<bool> {
        if non_interactive {
            return Err(Error::InteractionRequired(
                "deleting an OS-keyring credential may require an unlock or consent prompt"
                    .to_owned(),
            ));
        }
        let SecretRef::Keyring { service, account } = reference;
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(Error::CredentialStore(error.to_string())),
        }
    }

    pub fn exists(&self, reference: &SecretRef, non_interactive: bool) -> Result<bool> {
        match self.get(reference, non_interactive) {
            Ok(secret) => {
                drop(secret);
                Ok(true)
            }
            Err(Error::CredentialUnavailable { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

impl SecretProvider for SecretManager {
    fn get(&self, reference: &SecretRef, non_interactive: bool) -> Result<SecretString> {
        if non_interactive {
            return Err(Error::InteractionRequired(
                "OS keyrings can display an unlock or consent prompt; use WIF or vendor OAuth for non-interactive runs"
                    .to_owned(),
            ));
        }
        let SecretRef::Keyring { service, account } = reference;
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        match entry.get_password() {
            Ok(secret) if secret.is_empty() => Err(Error::CredentialUnavailable {
                profile: format!("keyring account {account}"),
                reason: "stored credential is empty".to_owned(),
            }),
            Ok(secret) => {
                enforce_secret_size(secret.len())?;
                Ok(secret.into())
            }
            Err(keyring::Error::NoEntry) => Err(Error::CredentialUnavailable {
                profile: format!("keyring account {account}"),
                reason: "no credential is stored".to_owned(),
            }),
            Err(error) => Err(Error::CredentialStore(error.to_string())),
        }
    }
}

pub fn parse_profile_secret_ref(profile_id: &ProfileId, value: Option<&str>) -> Result<SecretRef> {
    let value = value.ok_or_else(|| Error::CredentialUnavailable {
        profile: profile_id.to_string(),
        reason: "profile has no secret reference".to_owned(),
    })?;
    value.parse()
}

pub fn prompt_secret(label: &str, non_interactive: bool) -> Result<SecretString> {
    if io::stdin().is_terminal() {
        if non_interactive {
            return Err(Error::InteractionRequired(format!(
                "{label} must be supplied on standard input"
            )));
        }
        let secret = rpassword::prompt_password(format!("{label}: "))
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        if secret.is_empty() {
            return Err(Error::InvalidInput("credential cannot be empty".to_owned()));
        }
        enforce_secret_size(secret.len())?;
        return Ok(secret.into());
    }

    let mut secret = read_secret_input(&mut io::stdin())?;
    while matches!(secret.as_bytes().last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    if secret.is_empty() {
        return Err(Error::InvalidInput("credential cannot be empty".to_owned()));
    }
    Ok(secret.into())
}

/// Read and validate a long-lived token created by `claude setup-token`.
pub fn prompt_claude_setup_token(label: &str, non_interactive: bool) -> Result<SecretString> {
    if io::stdin().is_terminal() {
        if non_interactive {
            return Err(Error::InteractionRequired(format!(
                "{label} must be supplied on standard input"
            )));
        }
        return prompt_hidden_claude_setup_token(label);
    }

    let raw = read_secret_input(&mut io::stdin())?;
    let token = normalize_claude_setup_token_paste(&raw)?;
    Ok(token.into())
}

fn read_secret_input(reader: &mut impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::CredentialStore(error.to_string()))?;
    enforce_secret_size(bytes.len())?;
    String::from_utf8(bytes)
        .map_err(|_| Error::InvalidInput("credential must be valid UTF-8".to_owned()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputDecision {
    Continue,
    Finish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromptAction {
    Wait,
    Continue,
    Finish,
    Cancel,
    Interrupt(u8),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum InputState {
    #[default]
    Initial,
    Content,
    TrailingWhitespace,
    ContinuationStart,
    BracketedPaste,
}

#[derive(Default)]
struct ClaudeSetupTokenInput {
    value: String,
    state: InputState,
}

impl ClaudeSetupTokenInput {
    fn push_character(&mut self, character: char) -> Result<()> {
        if matches!(character, ' ' | '\t') {
            return self.push_horizontal_whitespace();
        }
        if character.is_control() || character.is_whitespace() {
            return Err(invalid_claude_setup_token_input());
        }
        match self.state {
            InputState::TrailingWhitespace => Err(Error::InvalidInput(
                "Claude setup token contains whitespace within a token line; nothing was stored"
                    .to_owned(),
            )),
            InputState::BracketedPaste => Err(Error::InvalidInput(
                "extra input followed the Claude setup token; nothing was stored".to_owned(),
            )),
            InputState::Initial | InputState::Content | InputState::ContinuationStart => {
                enforce_secret_size(self.value.len().saturating_add(character.len_utf8()))?;
                self.value.push(character);
                self.state = InputState::Content;
                Ok(())
            }
        }
    }

    fn push_horizontal_whitespace(&mut self) -> Result<()> {
        match self.state {
            InputState::Initial | InputState::ContinuationStart => Ok(()),
            InputState::Content | InputState::TrailingWhitespace => {
                self.state = InputState::TrailingWhitespace;
                Ok(())
            }
            InputState::BracketedPaste => Err(Error::InvalidInput(
                "extra input followed the Claude setup token; nothing was stored".to_owned(),
            )),
        }
    }

    fn push_paste(&mut self, paste: &str) -> Result<()> {
        if !self.value.is_empty() || self.state != InputState::Initial {
            self.state = InputState::BracketedPaste;
            return Err(Error::InvalidInput(
                "paste exactly one complete Claude setup token into an empty prompt".to_owned(),
            ));
        }
        self.state = InputState::BracketedPaste;
        match normalize_claude_setup_token_paste(paste) {
            Ok(token) => {
                self.value = token;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn submit_or_continue(&mut self) -> InputDecision {
        match self.state {
            InputState::BracketedPaste | InputState::ContinuationStart => InputDecision::Finish,
            InputState::Initial | InputState::Content | InputState::TrailingWhitespace => {
                self.state = InputState::ContinuationStart;
                InputDecision::Continue
            }
        }
    }

    fn backspace(&mut self) {
        match self.state {
            InputState::TrailingWhitespace => self.state = InputState::Content,
            InputState::ContinuationStart => {
                self.state = if self.value.is_empty() {
                    InputState::Initial
                } else {
                    InputState::Content
                };
            }
            InputState::Initial => {}
            InputState::Content | InputState::BracketedPaste => {
                self.value.pop();
                self.state = if self.value.is_empty() {
                    InputState::Initial
                } else {
                    InputState::Content
                };
            }
        }
    }

    fn finish(self) -> Result<SecretString> {
        validate_claude_setup_token_input(&self.value)?;
        Ok(self.value.into())
    }
}

struct PromptOutput {
    writer: Box<dyn Write>,
    is_terminal: bool,
}

impl PromptOutput {
    fn open() -> Self {
        let stderr = io::stderr();
        if stderr.is_terminal() {
            return Self {
                writer: Box::new(stderr),
                is_terminal: true,
            };
        }
        let stdout = io::stdout();
        if stdout.is_terminal() {
            return Self {
                writer: Box::new(stdout),
                is_terminal: true,
            };
        }
        Self {
            writer: Box::new(stderr),
            is_terminal: false,
        }
    }
}

impl Write for PromptOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writer.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct HiddenInputGuard {
    output: PromptOutput,
    bracketed_paste_enabled: bool,
    raw_mode_enabled: bool,
    newline_pending: bool,
}

impl HiddenInputGuard {
    fn enter(label: &str) -> Result<Self> {
        #[cfg(unix)]
        use crossterm::event::EnableBracketedPaste;

        let output = PromptOutput::open();
        let completion_instruction = if cfg!(unix) {
            "Press Enter after a protected paste. Otherwise press Enter twice or Ctrl-D."
        } else {
            "Press Enter twice when the full token is pasted."
        };
        // Hide input before making the prompt visible. Otherwise a user who pastes as soon as the
        // prompt is flushed can race raw-mode activation and briefly echo credential bytes.
        crossterm::terminal::enable_raw_mode()
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        let is_terminal = output.is_terminal;
        let mut guard = Self {
            output,
            bracketed_paste_enabled: false,
            raw_mode_enabled: true,
            newline_pending: true,
        };
        #[cfg(unix)]
        if is_terminal {
            // Treat an attempted enable as active until a disable succeeds. An I/O failure can
            // happen after the escape sequence was partially written.
            guard.bracketed_paste_enabled = true;
            if let Err(error) = crossterm::execute!(guard.output, EnableBracketedPaste) {
                return Err(Error::CredentialStore(error.to_string()));
            }
        }
        #[cfg(not(unix))]
        let _ = is_terminal;
        writeln!(
            guard.output,
            "Paste one complete token. Wrapped lines are joined and input stays hidden."
        )
        .and_then(|()| writeln!(guard.output, "{completion_instruction}"))
        .and_then(|()| write!(guard.output, "{label}: "))
        .and_then(|()| guard.output.flush())
        .map_err(|error| Error::CredentialStore(error.to_string()))?;
        Ok(guard)
    }

    fn show_continuation(&mut self) -> Result<()> {
        write!(
            self.output,
            "\r\nContinue pasting, or press Enter again to finish: "
        )
        .and_then(|()| self.output.flush())
        .map_err(|error| Error::CredentialStore(error.to_string()))
    }

    fn restore(&mut self) -> io::Result<()> {
        use crossterm::event::DisableBracketedPaste;

        let mut first_error = None;
        if self.bracketed_paste_enabled {
            match crossterm::execute!(self.output, DisableBracketedPaste) {
                Ok(()) => self.bracketed_paste_enabled = false,
                Err(error) => first_error = Some(error),
            }
        }
        if self.raw_mode_enabled {
            match crossterm::terminal::disable_raw_mode() {
                Ok(()) => self.raw_mode_enabled = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if self.newline_pending {
            match self
                .output
                .write_all(b"\r\n")
                .and_then(|()| self.output.flush())
            {
                Ok(()) => self.newline_pending = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for HiddenInputGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

type PromptPanicHandler = dyn Fn(&PanicHookInfo<'_>) + Send + Sync + 'static;

struct PromptPanicHookGuard {
    previous: Option<Arc<PromptPanicHandler>>,
}

impl PromptPanicHookGuard {
    fn install() -> Self {
        let previous: Arc<PromptPanicHandler> = Arc::from(panic::take_hook());
        let chained = Arc::clone(&previous);
        panic::set_hook(Box::new(move |information| {
            restore_prompt_after_panic();
            chained(information);
        }));
        Self {
            previous: Some(previous),
        }
    }
}

impl Drop for PromptPanicHookGuard {
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

fn restore_prompt_after_panic() {
    #[cfg(unix)]
    {
        use crossterm::event::DisableBracketedPaste;

        let mut stderr = io::stderr();
        if stderr.is_terminal() {
            let _ = crossterm::execute!(stderr, DisableBracketedPaste);
        }
        let mut stdout = io::stdout();
        if stdout.is_terminal() {
            let _ = crossterm::execute!(stdout, DisableBracketedPaste);
        }
    }
    let _ = crossterm::terminal::disable_raw_mode();
}

struct PromptTerminationSignals {
    #[cfg(unix)]
    signals: signal_hook::iterator::Signals,
}

impl PromptTerminationSignals {
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

    fn pending_exit_code(&mut self) -> Option<u8> {
        #[cfg(unix)]
        {
            use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};

            self.signals.pending().find_map(|signal| {
                if matches!(signal, SIGINT | SIGTERM | SIGHUP) {
                    u8::try_from(128 + signal).ok()
                } else {
                    None
                }
            })
        }

        #[cfg(not(unix))]
        {
            let _ = self;
            None
        }
    }
}

fn handle_claude_setup_token_key(
    input: &mut ClaudeSetupTokenInput,
    key: crossterm::event::KeyEvent,
) -> Result<PromptAction> {
    use crossterm::event::{KeyCode, KeyModifiers};

    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Ok(PromptAction::Interrupt(130))
        }
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Ok(PromptAction::Finish)
        }
        KeyCode::Enter => Ok(match input.submit_or_continue() {
            InputDecision::Continue => PromptAction::Continue,
            InputDecision::Finish => PromptAction::Finish,
        }),
        KeyCode::Tab => {
            input.push_horizontal_whitespace()?;
            Ok(PromptAction::Wait)
        }
        KeyCode::Backspace => {
            input.backspace();
            Ok(PromptAction::Wait)
        }
        KeyCode::Esc => Ok(PromptAction::Cancel),
        KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            input.push_character(character)?;
            Ok(PromptAction::Wait)
        }
        _ => Ok(PromptAction::Wait),
    }
}

fn prompt_hidden_claude_setup_token(label: &str) -> Result<SecretString> {
    use crossterm::event::{self, Event, KeyEventKind};

    let mut signals = PromptTerminationSignals::new()
        .map_err(|error| Error::CredentialStore(error.to_string()))?;
    let _panic_hook = PromptPanicHookGuard::install();
    let mut guard = HiddenInputGuard::enter(label)?;
    let mut input = ClaudeSetupTokenInput::default();
    let mut input_error = None;
    let read_result = loop {
        if let Some(exit_code) = signals.pending_exit_code() {
            break Err(Error::Interrupted(exit_code));
        }
        match event::poll(INPUT_EVENT_POLL_INTERVAL) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(Error::CredentialStore(error.to_string())),
        }
        let event = match event::read() {
            Ok(event) => event,
            Err(error) => break Err(Error::CredentialStore(error.to_string())),
        };
        match event {
            Event::Paste(paste) => {
                if let Err(error) = input.push_paste(&paste) {
                    input_error.get_or_insert(error);
                }
            }
            Event::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
                match handle_claude_setup_token_key(&mut input, key) {
                    Ok(PromptAction::Wait) => {}
                    Ok(PromptAction::Continue) => {
                        if let Err(error) = guard.show_continuation() {
                            break Err(error);
                        }
                    }
                    Ok(PromptAction::Finish) => {
                        break if let Some(error) = input_error.take() {
                            Err(error)
                        } else {
                            std::mem::take(&mut input).finish()
                        };
                    }
                    Ok(PromptAction::Cancel) => break Err(Error::Cancelled),
                    Ok(PromptAction::Interrupt(exit_code)) => {
                        break Err(Error::Interrupted(exit_code));
                    }
                    Err(error) => {
                        input_error.get_or_insert(error);
                    }
                }
            }
            _ => {}
        }
    };

    // All normal, validation, parser, and cancellation exits drain queued input and restore the
    // terminal. `HiddenInputGuard::drop` also restores the terminal during unwinding.
    let drain_result = reject_queued_secret_input(&mut signals);
    let restore_result = guard.restore();
    let final_signal = signals.pending_exit_code();
    #[cfg(unix)]
    drop(signals);
    resolve_prompt_result(read_result, drain_result, restore_result, final_signal)
}

fn resolve_prompt_result(
    read_result: Result<SecretString>,
    drain_result: Result<()>,
    restore_result: io::Result<()>,
    final_signal: Option<u8>,
) -> Result<SecretString> {
    let signal = final_signal
        .or_else(|| interrupted_exit_code(&drain_result))
        .or_else(|| interrupted_exit_code(&read_result));
    if let Err(error) = restore_result {
        let context = if let Some(exit_code) = signal {
            format!("operation was interrupted with exit code {exit_code}; ")
        } else if read_result.is_err() || drain_result.is_err() {
            "input was rejected or cancelled; ".to_owned()
        } else {
            String::new()
        };
        return Err(Error::CredentialStore(format!(
            "{context}failed to restore terminal state: {error}"
        )));
    }
    if let Some(exit_code) = signal {
        return Err(Error::Interrupted(exit_code));
    }
    match (read_result, drain_result) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(secret), Ok(())) => Ok(secret),
    }
}

fn interrupted_exit_code<T>(result: &Result<T>) -> Option<u8> {
    match result {
        Err(Error::Interrupted(exit_code)) => Some(*exit_code),
        Ok(_) | Err(_) => None,
    }
}

fn reject_queued_secret_input(signals: &mut PromptTerminationSignals) -> Result<()> {
    use crossterm::event::{self, Event, KeyEventKind};

    let deadline = Instant::now() + INPUT_DRAIN_DEADLINE;
    let mut extra_input = false;
    let mut signal_exit_code = signals.pending_exit_code();
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let wait = INPUT_DRAIN_POLL_INTERVAL.min(deadline.saturating_duration_since(now));
        let event_ready = match event::poll(wait) {
            Ok(event_ready) => event_ready,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => false,
            Err(error) => return Err(Error::CredentialStore(error.to_string())),
        };
        signal_exit_code = signal_exit_code.or_else(|| signals.pending_exit_code());
        if !event_ready {
            continue;
        }
        let queued_event = match event::read() {
            Ok(event) => event,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::CredentialStore(error.to_string())),
        };
        match queued_event {
            Event::Paste(_) => extra_input = true,
            Event::Key(key) if key.kind != KeyEventKind::Release => extra_input = true,
            _ => {}
        }
        signal_exit_code = signal_exit_code.or_else(|| signals.pending_exit_code());
    }
    signal_exit_code = signal_exit_code.or_else(|| signals.pending_exit_code());
    if let Some(exit_code) = signal_exit_code {
        return Err(Error::Interrupted(exit_code));
    }
    if extra_input {
        return Err(Error::InvalidInput(
            "extra input followed the Claude setup token; nothing was stored".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_claude_setup_token_paste(value: &str) -> Result<String> {
    enforce_secret_size(value.len())?;
    let canonical = value.replace("\r\n", "\n").replace('\r', "\n");
    let content = canonical.strip_suffix('\n').unwrap_or(&canonical);
    if content.is_empty() {
        return Err(invalid_claude_setup_token_input());
    }
    if content.ends_with('\n') {
        return Err(Error::InvalidInput(
            "Claude setup token paste contains an ambiguous blank line; nothing was stored"
                .to_owned(),
        ));
    }

    let mut token = String::with_capacity(content.len());
    for line in content.split('\n') {
        let segment = line.trim_matches([' ', '\t']);
        if segment.is_empty() {
            return Err(Error::InvalidInput(
                "Claude setup token paste contains an ambiguous blank line; nothing was stored"
                    .to_owned(),
            ));
        }
        if segment
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(Error::InvalidInput(
                "Claude setup token paste contains whitespace or unsupported characters; nothing was stored"
                    .to_owned(),
            ));
        }
        token.push_str(segment);
    }

    validate_claude_setup_token_input(&token)?;
    Ok(token)
}

fn validate_claude_setup_token_input(value: &str) -> Result<()> {
    enforce_secret_size(value.len())?;
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || looks_like_labeled_or_quoted_token(value)
    {
        return Err(invalid_claude_setup_token_input());
    }
    Ok(())
}

fn looks_like_labeled_or_quoted_token(value: &str) -> bool {
    const WRAPPER_PREFIXES: [&str; 6] = [
        "export ",
        "set ",
        "token:",
        "setup-token:",
        "claude_code_oauth_token=",
        "$env:claude_code_oauth_token=",
    ];

    WRAPPER_PREFIXES.iter().any(|prefix| {
        value
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
    }) || matches!(value.as_bytes().first(), Some(b'\'' | b'"'))
        || matches!(value.as_bytes().last(), Some(b'\'' | b'"'))
}

fn invalid_claude_setup_token_input() -> Error {
    Error::InvalidInput(
        "Claude setup-token input is empty or contains a label, assignment, quote, control character, or ambiguous whitespace; nothing was stored"
            .to_owned(),
    )
}

fn enforce_secret_size(length: usize) -> Result<()> {
    if length > MAX_SECRET_BYTES {
        return Err(Error::PolicyRefused(
            "credential exceeds the 1 MiB safety limit".to_owned(),
        ));
    }
    Ok(())
}

pub fn write_secret_to_stdin(
    stdin: &mut impl Write,
    secret: &SecretString,
    program: &str,
) -> Result<()> {
    stdin
        .write_all(secret.expose_secret().as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .map_err(|_| Error::CredentialPipe {
            program: program.to_owned(),
        })
}

#[must_use]
pub const fn secret_label(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => "Claude credential",
        Provider::Codex => "Codex credential",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_claude_setup_token() -> String {
        format!("opaque-fixture:{}", "Ab9_-xY2~".repeat(6))
    }

    #[test]
    fn parses_only_keyring_references() {
        assert!("keyring://ctxlane/claude-work".parse::<SecretRef>().is_ok());
        // Migration preserves the old service so the existing OS-keyring item
        // remains addressable without reading or copying its value.
        assert!("keyring://aictx/claude-work".parse::<SecretRef>().is_ok());
        assert!("vault://team/ai-token".parse::<SecretRef>().is_err());
        assert!("command://curl/attacker".parse::<SecretRef>().is_err());
        assert!("keyring://missing-account".parse::<SecretRef>().is_err());
    }

    #[test]
    fn debug_never_exposes_secret() {
        let secret: SecretString = "canary-secret".into();
        assert!(!format!("{secret:?}").contains("canary-secret"));
    }

    #[test]
    fn every_secret_source_uses_the_same_size_limit() {
        assert!(enforce_secret_size(MAX_SECRET_BYTES).is_ok());
        assert!(matches!(
            enforce_secret_size(MAX_SECRET_BYTES + 1),
            Err(Error::PolicyRefused(_))
        ));
    }

    #[test]
    fn treats_the_vendor_token_as_opaque_but_rejects_unsafe_wrappers() {
        let marker = "SensitivePayloadMarker";
        for opaque in ["x", "opaque#value+/=:.", "fixture-λ"] {
            validate_claude_setup_token_input(opaque)
                .unwrap_or_else(|error| panic!("rejects opaque vendor token `{opaque}`: {error}"));
        }

        let unsafe_inputs = [
            String::new(),
            format!("{marker} value"),
            format!("{marker}\nvalue"),
            format!("token:{marker}"),
            format!("setup-token:{marker}"),
            format!("CLAUDE_CODE_OAUTH_TOKEN={marker}"),
            format!("$env:CLAUDE_CODE_OAUTH_TOKEN={marker}"),
            format!("export CLAUDE_CODE_OAUTH_TOKEN={marker}"),
            format!("\"{marker}\""),
            format!("'{marker}'"),
            format!("{marker}\u{7f}"),
        ];

        for value in unsafe_inputs {
            let Err(error) = validate_claude_setup_token_input(&value) else {
                panic!("accepted wrapped or ambiguous setup-token input");
            };
            let rendered = error.to_string();
            assert!(!rendered.contains(marker));
            assert!(rendered.contains("Claude setup-token input"));
        }
    }

    #[test]
    fn reassembles_a_wrapped_and_indented_setup_token_paste() {
        let token = synthetic_claude_setup_token();
        let split = token.len() / 2;
        let paste = format!("  {} \r\n\t{}  \n", &token[..split], &token[split..]);

        let normalized = normalize_claude_setup_token_paste(&paste)
            .unwrap_or_else(|error| panic!("normalize synthetic setup token: {error}"));

        assert_eq!(normalized, token);
    }

    #[test]
    fn rejects_labeled_or_ambiguous_setup_token_pastes() {
        let token = synthetic_claude_setup_token();
        let split = token.len() / 2;
        let ambiguous = [
            format!("export CLAUDE_CODE_OAUTH_TOKEN={token}"),
            format!("CLAUDE_CODE_OAUTH_TOKEN={token}"),
            format!("$env:CLAUDE_CODE_OAUTH_TOKEN={token}"),
            format!("token:{token}"),
            format!("setup-token:{token}"),
            format!("\"{token}\""),
            format!("'{token}'"),
            format!("{} {}", &token[..split], &token[split..]),
            format!("{}\n\n{}", &token[..split], &token[split..]),
            format!("{token}\n\n"),
        ];

        for paste in ambiguous {
            let Err(error) = normalize_claude_setup_token_paste(&paste) else {
                panic!("accepted an ambiguous synthetic setup-token paste");
            };
            assert!(!error.to_string().contains(&token));
        }
    }

    #[test]
    fn bracketed_paste_finishes_with_one_enter() {
        let token = synthetic_claude_setup_token();
        let split = token.len() / 2;
        let paste = format!("{}\n  {}\n", &token[..split], &token[split..]);
        let mut input = ClaudeSetupTokenInput::default();

        input
            .push_paste(&paste)
            .unwrap_or_else(|error| panic!("accept protected synthetic paste: {error}"));
        assert_eq!(input.submit_or_continue(), InputDecision::Finish);
        let secret = input
            .finish()
            .unwrap_or_else(|error| panic!("finish protected synthetic paste: {error}"));

        assert_eq!(secret.expose_secret(), &token);
    }

    #[test]
    fn unprotected_wrapped_paste_finishes_on_a_blank_line() {
        let token = synthetic_claude_setup_token();
        let split = token.len() / 2;
        let mut input = ClaudeSetupTokenInput::default();

        for character in token[..split].chars() {
            input
                .push_character(character)
                .unwrap_or_else(|error| panic!("accept first synthetic fragment: {error}"));
        }
        assert_eq!(input.submit_or_continue(), InputDecision::Continue);
        for indentation in [' ', '\t'] {
            input
                .push_character(indentation)
                .unwrap_or_else(|error| panic!("accept continuation indentation: {error}"));
        }
        for character in token[split..].chars() {
            input
                .push_character(character)
                .unwrap_or_else(|error| panic!("accept second synthetic fragment: {error}"));
        }
        assert_eq!(input.submit_or_continue(), InputDecision::Continue);
        assert_eq!(input.submit_or_continue(), InputDecision::Finish);
        let secret = input
            .finish()
            .unwrap_or_else(|error| panic!("finish unprotected synthetic paste: {error}"));

        assert_eq!(secret.expose_secret(), &token);
    }

    #[test]
    fn cancellation_and_interrupt_keys_take_the_restoring_prompt_exit_path() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let mut input = ClaudeSetupTokenInput::default();
        let interrupt = handle_claude_setup_token_key(
            &mut input,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        )
        .unwrap_or_else(|error| panic!("handle interrupt key: {error}"));
        assert_eq!(interrupt, PromptAction::Interrupt(130));

        let cancel = handle_claude_setup_token_key(
            &mut input,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        )
        .unwrap_or_else(|error| panic!("handle cancellation key: {error}"));
        assert_eq!(cancel, PromptAction::Cancel);
    }

    #[test]
    fn signal_during_input_drain_overrides_an_earlier_prompt_error() {
        let result = resolve_prompt_result(
            Err(Error::Cancelled),
            Err(Error::Interrupted(143)),
            Ok(()),
            None,
        );

        assert!(matches!(result, Err(Error::Interrupted(143))));
    }

    #[test]
    fn terminal_restore_failure_is_reported_after_rejected_input() {
        let result = resolve_prompt_result(
            Err(Error::Cancelled),
            Ok(()),
            Err(io::Error::other("synthetic restore failure")),
            None,
        );
        let Err(Error::CredentialStore(message)) = result else {
            panic!("terminal restore failure did not take precedence");
        };

        assert!(message.contains("input was rejected or cancelled"));
        assert!(message.contains("failed to restore terminal state"));
        assert!(message.contains("synthetic restore failure"));
    }

    #[test]
    fn invalid_unprotected_input_stays_open_until_an_explicit_blank_line() {
        let mut input = ClaudeSetupTokenInput::default();
        for character in "opaque-fragment".chars() {
            input
                .push_character(character)
                .unwrap_or_else(|error| panic!("accept opaque fragment: {error}"));
        }
        input
            .push_character(' ')
            .unwrap_or_else(|error| panic!("accept possible line-edge whitespace: {error}"));
        assert!(input.push_character('x').is_err());
        assert_eq!(input.submit_or_continue(), InputDecision::Continue);
        assert_eq!(input.submit_or_continue(), InputDecision::Finish);
    }
}
