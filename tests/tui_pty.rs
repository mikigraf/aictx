use std::{
    io::{Read, Write},
    path::Path,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use tempfile::TempDir;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const DASHBOARD_MARKER: &str = "switcher";
const DASHBOARD_FOOTER_MARKER: &str = "quit";
const RELOAD_MESSAGE_MARKER: &str = "Metadata reloaded.";
const SMALL_TERMINAL_MARKER: &str = "Terminal";
const SMALL_TERMINAL_RESIZE_MARKER: &str = "Resize";
const SMALL_TERMINAL_FOOTER_MARKER: &str = "quit";
const MAX_TERMINAL_QUERY_LENGTH: usize = 5;

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

fn wait_for_output(
    output: &PtyOutput,
    child: &mut ChildGuard,
    marker: &str,
    start: usize,
    deadline: Instant,
    action: &str,
) -> usize {
    output
        .wait_for(marker, start, deadline, action)
        .unwrap_or_else(|message| {
            child.kill_and_reap();
            panic!("{message}");
        })
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

fn run_in_pty(
    root: &Path,
    arguments: &[&str],
    input: &[u8],
    exercise_resize: bool,
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
    let mut child = ChildGuard::new(
        pair.slave
            .spawn_command(command)
            .unwrap_or_else(|error| panic!("spawn ctxlane in PTY: {error}")),
    );
    drop(pair.slave);

    let deadline = Instant::now() + TEST_TIMEOUT;
    if !input.is_empty() {
        let dashboard_header = wait_for_output(
            &output,
            &mut child,
            DASHBOARD_MARKER,
            0,
            deadline,
            "the initial dashboard render",
        );
        let dashboard_footer = wait_for_output(
            &output,
            &mut child,
            DASHBOARD_FOOTER_MARKER,
            dashboard_header,
            deadline,
            "the initial dashboard footer",
        );
        write_pty(&writer, b"r")
            .unwrap_or_else(|error| panic!("write PTY readiness input: {error}"));
        let event_loop_ready = wait_for_output(
            &output,
            &mut child,
            RELOAD_MESSAGE_MARKER,
            dashboard_footer,
            deadline,
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
            let small_marker = wait_for_output(
                &output,
                &mut child,
                SMALL_TERMINAL_MARKER,
                event_loop_ready,
                deadline,
                "the undersized-terminal render",
            );
            let small_resize_instruction = wait_for_output(
                &output,
                &mut child,
                SMALL_TERMINAL_RESIZE_MARKER,
                small_marker,
                deadline,
                "the undersized-terminal resize instruction",
            );
            let small_render = wait_for_output(
                &output,
                &mut child,
                SMALL_TERMINAL_FOOTER_MARKER,
                small_resize_instruction,
                deadline,
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
            let restored_header = wait_for_output(
                &output,
                &mut child,
                DASHBOARD_MARKER,
                small_render,
                deadline,
                "the restored dashboard render",
            );
            wait_for_output(
                &output,
                &mut child,
                RELOAD_MESSAGE_MARKER,
                restored_header,
                deadline,
                "the restored dashboard status",
            );
        }
        write_pty(&writer, input).unwrap_or_else(|error| panic!("write PTY input: {error}"));
    }

    let status = loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll PTY child: {error}"))
        {
            break status;
        }
        if Instant::now() >= deadline {
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

#[test]
fn dashboard_quits_after_resize_and_restores_terminal_state() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    initialize(&root);

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
