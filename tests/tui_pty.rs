use std::{
    io::{Read, Write},
    path::Path,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use tempfile::TempDir;

use ctxlane::{
    config::{AppPaths, MetadataStore},
    model::ProfileId,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const DASHBOARD_MARKER: &str = "boundary";
const DASHBOARD_FOOTER_MARKER: &str = "quit";
const RELOAD_MESSAGE_MARKER: &str = "Metadata reloaded.";
const SMALL_TERMINAL_MARKER: &str = "Terminal";
const SMALL_TERMINAL_RESIZE_MARKER: &str = "Resize";
const SMALL_TERMINAL_FOOTER_MARKER: &str = "quit";
const MAX_TERMINAL_QUERY_LENGTH: usize = 5;
const SECRET_REF_CANARY: &str = "keyring://pty-canary/never-render-this-secret-ref";
const EDITED_ACCOUNT_LABEL: &str = "visible-smoke-account";
const AUTOMATION_STORE_SENTINEL: &[u8] =
    b"not-a-sqlite-database\nstandalone-dashboard-boundary-canary\n";

type SharedPtyWriter = Arc<Mutex<Box<dyn Write + Send>>>;

#[derive(Default)]
struct TerminalQueryResponder {
    tail: Vec<u8>,
}

impl TerminalQueryResponder {
    fn observe(&mut self, bytes: &[u8]) -> Vec<u8> {
        const RESPONSES: [(&[u8], &[u8]); 4] = [
            (b"\x1b[5n", b"\x1b[0n"),
            (b"\x1b[6n", b"\x1b[1;1R"),
            (b"\x1b[?5n", b"\x1b[?0n"),
            (b"\x1b[?6n", b"\x1b[?1;1R"),
        ];

        let previous_length = self.tail.len();
        self.tail.extend_from_slice(bytes);
        let mut replies = Vec::new();
        for start in 0..self.tail.len() {
            for (query, response) in RESPONSES {
                let end = start.saturating_add(query.len());
                if end > previous_length
                    && self
                        .tail
                        .get(start..end)
                        .is_some_and(|value| value == query)
                {
                    replies.extend_from_slice(response);
                    break;
                }
            }
        }

        let retained_length = self
            .tail
            .len()
            .min(MAX_TERMINAL_QUERY_LENGTH.saturating_sub(1));
        self.tail.rotate_right(retained_length);
        self.tail.truncate(retained_length);
        replies
    }
}

struct ChildGuard {
    child: Box<dyn Child + Send + Sync>,
    reaped: bool,
}

impl ChildGuard {
    fn new(child: Box<dyn Child + Send + Sync>) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<portable_pty::ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn kill_and_reap(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        if self.child.wait().is_ok() {
            self.reaped = true;
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

#[derive(Default)]
struct PtyOutput {
    bytes: Mutex<Vec<u8>>,
    changed: Condvar,
}

impl PtyOutput {
    fn append(&self, bytes: &[u8]) {
        let mut output = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        output.extend_from_slice(bytes);
        self.changed.notify_all();
    }

    fn wait_for(
        &self,
        marker: &str,
        start: usize,
        deadline: Instant,
        action: &str,
    ) -> Result<usize, String> {
        let marker = marker.as_bytes();
        let mut output = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        loop {
            if let Some(position) = output[start..]
                .windows(marker.len())
                .position(|window| window == marker)
            {
                return Ok(start + position + marker.len());
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "timed out waiting for {action}; PTY output:\n{}",
                    String::from_utf8_lossy(&output)
                ));
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_output, _) = self
                .changed
                .wait_timeout(output, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            output = next_output;
        }
    }

    fn snapshot(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

fn write_pty(writer: &SharedPtyWriter, bytes: &[u8]) -> std::io::Result<()> {
    let mut writer = writer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    writer.write_all(bytes)?;
    writer.flush()
}

struct PtyScript<'a> {
    output: &'a PtyOutput,
    writer: &'a SharedPtyWriter,
    offset: usize,
}

impl<'a> PtyScript<'a> {
    const fn new(output: &'a PtyOutput, writer: &'a SharedPtyWriter) -> Self {
        Self {
            output,
            writer,
            offset: 0,
        }
    }

    fn wait_for_result(&mut self, marker: &str, action: &str) -> Result<usize, String> {
        let offset =
            self.output
                .wait_for(marker, self.offset, Instant::now() + TEST_TIMEOUT, action)?;
        self.offset = offset;
        Ok(offset)
    }

    fn wait_for(&mut self, child: &mut ChildGuard, marker: &str, action: &str) -> usize {
        match self.wait_for_result(marker, action) {
            Ok(offset) => offset,
            Err(message) => {
                child.kill_and_reap();
                panic!("{message}");
            }
        }
    }

    fn send(&self, input: &[u8], action: &str) {
        write_pty(self.writer, input).unwrap_or_else(|error| {
            panic!("failed to {action}: {error}");
        });
    }

    fn wait_then_send(
        &mut self,
        child: &mut ChildGuard,
        marker: &str,
        input: &[u8],
        action: &str,
    ) -> usize {
        let offset = self.wait_for(child, marker, action);
        self.send(input, action);
        offset
    }
}

fn initialize(root: &Path) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ctxlane"))
        .arg("--root")
        .arg(root)
        .arg("init")
        .output()
        .unwrap_or_else(|error| panic!("initialize test metadata: {error}"));
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn add_secret_canary_profile(root: &Path) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ctxlane"))
        .arg("--root")
        .arg(root)
        .args([
            "profile",
            "add",
            "claude",
            "sentinel",
            "--auth",
            "api-key",
            "--secret-ref",
            SECRET_REF_CANARY,
        ])
        .output()
        .unwrap_or_else(|error| panic!("add secret canary profile: {error}"));
    assert!(
        output.status.success(),
        "profile setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[derive(Clone, Copy)]
enum PtyJourney<'a> {
    FinalInput(&'a [u8]),
    ProfileCrud,
}

fn run_in_pty(
    root: &Path,
    arguments: &[&str],
    input: &[u8],
    exercise_resize: bool,
) -> (u32, String) {
    let journey = (!input.is_empty()).then_some(PtyJourney::FinalInput(input));
    run_in_pty_journey(root, arguments, journey, exercise_resize, None)
}

fn run_profile_crud_in_pty(root: &Path, current_directory: &Path) -> (u32, String) {
    run_in_pty_journey(
        root,
        &[],
        Some(PtyJourney::ProfileCrud),
        false,
        Some(current_directory),
    )
}

fn run_in_pty_journey(
    root: &Path,
    arguments: &[&str],
    journey: Option<PtyJourney<'_>>,
    exercise_resize: bool,
    current_directory: Option<&Path>,
) -> (u32, String) {
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap_or_else(|error| panic!("open test PTY: {error}"));
    let mut reader = pair
        .master
        .try_clone_reader()
        .unwrap_or_else(|error| panic!("clone PTY reader: {error}"));
    let writer = Arc::new(Mutex::new(
        pair.master
            .take_writer()
            .unwrap_or_else(|error| panic!("take PTY writer: {error}")),
    ));

    let output = Arc::new(PtyOutput::default());
    let reader_output = Arc::clone(&output);
    let responder_writer = Arc::clone(&writer);
    let output_reader = thread::spawn(move || {
        let mut chunk = [0_u8; 4_096];
        let mut responder = TerminalQueryResponder::default();
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    let bytes = &chunk[..count];
                    reader_output.append(bytes);
                    let replies = responder.observe(bytes);
                    if !replies.is_empty() {
                        write_pty(&responder_writer, &replies)
                            .unwrap_or_else(|error| panic!("answer PTY terminal query: {error}"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("read PTY output: {error}"),
            }
        }
    });

    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_ctxlane"));
    command.arg("--root");
    command.arg(root);
    command.args(arguments);
    command.env("TERM", "xterm-256color");
    command.env_remove("NO_COLOR");
    if let Some(current_directory) = current_directory {
        command.cwd(current_directory);
    }
    let mut child = ChildGuard::new(
        pair.slave
            .spawn_command(command)
            .unwrap_or_else(|error| panic!("spawn ctxlane in PTY: {error}")),
    );
    drop(pair.slave);

    if let Some(journey) = journey {
        let mut script = PtyScript::new(output.as_ref(), &writer);
        script.wait_for(&mut child, DASHBOARD_MARKER, "the initial dashboard render");
        script.wait_then_send(
            &mut child,
            DASHBOARD_FOOTER_MARKER,
            b"r",
            "the initial dashboard footer",
        );
        script.wait_for(
            &mut child,
            RELOAD_MESSAGE_MARKER,
            "the event-loop readiness render",
        );
        if exercise_resize {
            pair.master
                .resize(PtySize {
                    rows: 6,
                    cols: 40,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .unwrap_or_else(|error| panic!("shrink PTY: {error}"));
            script.wait_for(
                &mut child,
                SMALL_TERMINAL_MARKER,
                "the undersized-terminal render",
            );
            script.wait_for(
                &mut child,
                SMALL_TERMINAL_RESIZE_MARKER,
                "the undersized-terminal resize instruction",
            );
            script.wait_for(
                &mut child,
                SMALL_TERMINAL_FOOTER_MARKER,
                "the undersized-terminal footer",
            );
            pair.master
                .resize(PtySize {
                    rows: 30,
                    cols: 100,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .unwrap_or_else(|error| panic!("restore PTY size: {error}"));
            script.wait_for(
                &mut child,
                DASHBOARD_MARKER,
                "the restored dashboard render",
            );
            script.wait_for(
                &mut child,
                RELOAD_MESSAGE_MARKER,
                "the restored dashboard status",
            );
        }
        match journey {
            PtyJourney::FinalInput(input) => script.send(input, "write the final PTY input"),
            PtyJourney::ProfileCrud => exercise_profile_crud(&mut script, &mut child, root),
        }
    }

    let exit_deadline = Instant::now() + TEST_TIMEOUT;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll PTY child: {error}"))
        {
            break status;
        }
        if Instant::now() >= exit_deadline {
            child.kill_and_reap();
            panic!("ctxlane PTY session exceeded {TEST_TIMEOUT:?}");
        }
        thread::sleep(Duration::from_millis(20));
    };

    drop(writer);
    drop(pair.master);
    output_reader
        .join()
        .unwrap_or_else(|_| panic!("PTY reader thread panicked"));
    let bytes = output.snapshot();
    (
        status.exit_code(),
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn exercise_profile_crud(script: &mut PtyScript<'_>, child: &mut ChildGuard, root: &Path) {
    let added_id: ProfileId = "claude:smoke"
        .parse()
        .unwrap_or_else(|error| panic!("added profile ID: {error}"));
    let renamed_id: ProfileId = "claude:smoke-renamed"
        .parse()
        .unwrap_or_else(|error| panic!("renamed profile ID: {error}"));
    let store = MetadataStore::new(AppPaths::for_root(root));

    script.send(b"2a", "open the profile add form");
    script.wait_for(child, "Add profile", "the profile add form");
    script.send(b"\tsmoke\r", "submit the profile add form");
    script.wait_for(
        child,
        "Added profile claude:smoke.",
        "the committed profile addition",
    );
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config after profile add: {error}"));
    assert!(config.profiles.contains_key(&added_id));

    script.send(b"e", "open the profile edit form");
    script.wait_for(child, "Edit profile", "the profile edit form");
    script.send(
        format!("{EDITED_ACCOUNT_LABEL}\r").as_bytes(),
        "submit the profile edit form",
    );
    script.wait_for(
        child,
        "Updated profile claude:smoke.",
        "the committed profile edit",
    );
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config after profile edit: {error}"));
    assert_eq!(
        config.profiles[&added_id].account_hint(),
        Some(EDITED_ACCOUNT_LABEL)
    );

    script.send(b"R", "open the profile rename form");
    script.wait_for(child, "Rename profile", "the profile rename form");
    script.send(b"-renamed\r", "submit the profile rename form");
    script.wait_for(
        child,
        "Renamed profile claude:smoke to claude:smoke-renamed.",
        "the committed profile rename",
    );
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config after profile rename: {error}"));
    assert!(!config.profiles.contains_key(&added_id));
    assert_eq!(
        config.profiles[&renamed_id].account_hint(),
        Some(EDITED_ACCOUNT_LABEL)
    );

    script.send(b"d", "open the profile removal confirmation");
    script.wait_for(child, "Confirm removal", "the profile removal confirmation");
    script.send(b"y", "confirm profile removal");
    script.wait_for(
        child,
        "Removed profile claude:smoke-renamed.",
        "the committed profile removal",
    );
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config after profile removal: {error}"));
    assert!(!config.profiles.contains_key(&renamed_id));
    script.send(b"q", "quit after the CRUD journey");
}

fn add_invalid_automation_store_sentinel(root: &Path) -> std::path::PathBuf {
    let automation = root.join("state/automation");
    std::fs::create_dir(&automation)
        .unwrap_or_else(|error| panic!("create automation sentinel directory: {error}"));
    let database = automation.join("lease-store.sqlite3");
    std::fs::write(&database, AUTOMATION_STORE_SENTINEL)
        .unwrap_or_else(|error| panic!("write automation store sentinel: {error}"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&automation, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("secure automation sentinel directory: {error}"));
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("secure automation store sentinel: {error}"));
    }

    database
}

#[test]
fn dashboard_quits_after_resize_and_restores_terminal_state() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    initialize(&root);
    let database = add_invalid_automation_store_sentinel(&root);

    let (code, output) = run_in_pty(&root, &[], b"q", true);
    assert_eq!(code, 0, "PTY output:\n{output}");
    assert!(output.contains("ctxlane"), "dashboard was not rendered");
    assert!(
        output.contains(SMALL_TERMINAL_MARKER),
        "undersized-terminal state was not rendered"
    );
    assert!(
        output.contains("\u{1b}[?1049h"),
        "alternate screen was not entered"
    );
    assert!(
        output.contains("\u{1b}[?1049l"),
        "alternate screen was not restored"
    );
    assert!(output.contains("\u{1b}[?25h"), "cursor was not restored");
    assert!(!output.contains("standalone-dashboard-boundary-canary"));
    assert_eq!(
        std::fs::read(&database)
            .unwrap_or_else(|error| panic!("read automation store sentinel: {error}")),
        AUTOMATION_STORE_SENTINEL
    );
    for suffix in [
        "service.lock",
        "lease-store.sqlite3-journal",
        "lease-store.sqlite3-wal",
        "lease-store.sqlite3-shm",
    ] {
        assert!(
            !database.with_file_name(suffix).exists(),
            "dashboard created automation artifact {suffix}"
        );
    }
}

#[test]
fn terminal_query_responder_handles_fragmented_queries_once() {
    let mut responder = TerminalQueryResponder::default();

    assert!(responder.observe(b"prefix\x1b[").is_empty());
    assert_eq!(responder.observe(b"6n"), b"\x1b[1;1R");
    assert!(responder.observe(b"ordinary output").is_empty());
    assert_eq!(
        responder.observe(b"\x1b[5n\x1b[?6n\x1b[?5n"),
        b"\x1b[0n\x1b[?1;1R\x1b[?0n"
    );
}

#[test]
fn pty_script_cursor_advances_past_each_matching_marker() {
    let output = PtyOutput::default();
    let writer: SharedPtyWriter = Arc::new(Mutex::new(Box::new(std::io::sink())));
    let mut script = PtyScript::new(&output, &writer);

    output.append(b"ready");
    assert_eq!(
        script
            .wait_for_result("ready", "the first marker")
            .unwrap_or_else(|message| panic!("{message}")),
        5
    );

    output.append(b"noise-ready");
    assert_eq!(
        script
            .wait_for_result("ready", "the second marker")
            .unwrap_or_else(|message| panic!("{message}")),
        16,
        "the second wait must not reuse the marker before the script cursor"
    );
}

#[test]
fn dashboard_control_c_exits_130_and_restores_terminal_state() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    initialize(&root);

    let (code, output) = run_in_pty(&root, &[], b"\x03", false);
    assert_eq!(code, 130, "PTY output:\n{output}");
    assert!(output.contains("\u{1b}[?1049l"));
    assert!(output.contains("\u{1b}[?25h"));
}

#[test]
fn dashboard_profile_crud_persists_each_step_without_exposing_secret_metadata() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let current_directory = temporary.path().join("workspace");
    std::fs::create_dir(&current_directory)
        .unwrap_or_else(|error| panic!("create isolated PTY working directory: {error}"));
    initialize(&root);
    add_secret_canary_profile(&root);

    let (code, output) = run_profile_crud_in_pty(&root, &current_directory);
    assert_eq!(code, 0, "PTY output:\n{output}");
    assert!(output.contains("Added profile claude:smoke."));
    assert!(output.contains("Updated profile claude:smoke."));
    assert!(output.contains("Renamed profile claude:smoke to claude:smoke-renamed."));
    assert!(output.contains("Removed profile claude:smoke-renamed."));
    assert!(
        !output.contains(SECRET_REF_CANARY),
        "dashboard exposed a persisted secret reference: {output}"
    );
    assert!(output.contains("\u{1b}[?1049l"));
    assert!(output.contains("\u{1b}[?25h"));
    assert!(output.contains("\u{1b}[?2004l"));

    let store = MetadataStore::new(AppPaths::for_root(root));
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load final CRUD config: {error}"));
    let sentinel: ProfileId = "claude:sentinel"
        .parse()
        .unwrap_or_else(|error| panic!("sentinel profile ID: {error}"));
    assert_eq!(config.profiles.len(), 1);
    assert_eq!(
        config.profiles[&sentinel].secret_ref(),
        Some(SECRET_REF_CANARY)
    );
}

#[test]
fn invalid_interactive_launches_fail_before_raw_terminal_mode() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let missing_root = temporary.path().join("missing");
    let (code, output) = run_in_pty(&missing_root, &[], b"", false);
    assert_eq!(code, 2, "PTY output:\n{output}");
    assert!(output.contains("ctxlane init"));
    assert!(!output.contains("\u{1b}[?1049h"));

    let initialized_root = temporary.path().join("initialized");
    initialize(&initialized_root);
    let (code, output) = run_in_pty(&initialized_root, &["--non-interactive"], b"", false);
    assert_eq!(code, 14, "PTY output:\n{output}");
    assert!(output.contains("interactive mode requires a terminal"));
    assert!(!output.contains("\u{1b}[?1049h"));
}
