use std::{
    io::{self, Stdout},
    panic::{self, PanicHookInfo},
    sync::Arc,
};

use crossterm::{
    cursor::{Hide, Show},
    event::{DisableBracketedPaste, EnableBracketedPaste},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

struct TerminalSetup {
    enabled: u8,
}

const RAW_MODE: u8 = 1 << 0;
const ALTERNATE_SCREEN: u8 = 1 << 1;
const BRACKETED_PASTE: u8 = 1 << 2;
const CURSOR_HIDDEN: u8 = 1 << 3;

impl TerminalSetup {
    fn enter() -> io::Result<Self> {
        let mut setup = Self { enabled: 0 };
        enable_raw_mode()?;
        setup.enabled |= RAW_MODE;

        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        setup.enabled |= ALTERNATE_SCREEN;
        execute!(stdout, EnableBracketedPaste)?;
        setup.enabled |= BRACKETED_PASTE;
        execute!(stdout, Hide)?;
        setup.enabled |= CURSOR_HIDDEN;
        Ok(setup)
    }

    fn restore(&mut self) -> io::Result<()> {
        let mut first_error = None;
        let mut stdout = io::stdout();
        if self.enabled & CURSOR_HIDDEN != 0 {
            match execute!(stdout, Show) {
                Ok(()) => self.enabled &= !CURSOR_HIDDEN,
                Err(error) => first_error = Some(error),
            }
        }
        if self.enabled & BRACKETED_PASTE != 0 {
            match execute!(stdout, DisableBracketedPaste) {
                Ok(()) => self.enabled &= !BRACKETED_PASTE,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if self.enabled & ALTERNATE_SCREEN != 0 {
            match execute!(stdout, LeaveAlternateScreen) {
                Ok(()) => self.enabled &= !ALTERNATE_SCREEN,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if self.enabled & RAW_MODE != 0 {
            match disable_raw_mode() {
                Ok(()) => self.enabled &= !RAW_MODE,
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

pub(super) struct TerminalSession {
    pub(super) terminal: Terminal<CrosstermBackend<Stdout>>,
    setup: TerminalSetup,
}

impl TerminalSession {
    pub(super) fn enter() -> io::Result<Self> {
        let setup = TerminalSetup::enter()?;
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        Ok(Self { terminal, setup })
    }

    pub(super) fn restore(&mut self) -> io::Result<()> {
        self.setup.restore()
    }
}

type PanicHandler = dyn Fn(&PanicHookInfo<'_>) + Send + Sync + 'static;

pub(super) struct PanicHookGuard {
    previous: Option<Arc<PanicHandler>>,
}

impl PanicHookGuard {
    pub(super) fn install() -> Self {
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
    let _ = execute!(stdout, Show, DisableBracketedPaste, LeaveAlternateScreen);
    let _ = disable_raw_mode();
}
