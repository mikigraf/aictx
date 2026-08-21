#![cfg(all(unix, feature = "test-fixtures"))]

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use rustix::process::{Pid, Signal, kill_process};
use tempfile::TempDir;

use ctxlane::{
    config::{AppPaths, MetadataStore},
    model::ProfileId,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const BRACKETED_PASTE_ENABLED: &str = "\u{1b}[?2004h";
const BRACKETED_PASTE_DISABLED: &str = "\u{1b}[?2004l";
const REVOCATION_WARNING: &str = "Warning: Claude Code may have created a remote setup token, but ctxlane did not store it. Revoke that token in your Claude account settings (Settings > Claude Code) before retrying.";
const SYNTHETIC_SETUP_TOKEN: &str =
    "opaque-fixture:Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~";

#[derive(Clone, Copy, Debug)]
enum PromptExit {
    Escape,
    Terminate,
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

struct GuidedRun {
    code: u32,
    output: String,
}

fn copy_fake_claude(directory: &Path, name: &str) -> PathBuf {
    let executable = directory.join(name);
    fs::copy(env!("CARGO_BIN_EXE_ctxlane-test-vendor"), &executable)
        .unwrap_or_else(|error| panic!("copy fake Claude executable: {error}"));
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("secure fake Claude executable: {error}"));
    executable
}

fn snapshot(output: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    output
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn capture_output(
    mut reader: Box<dyn Read + Send>,
    output: &Arc<Mutex<Vec<u8>>>,
) -> thread::JoinHandle<()> {
    let reader_output = Arc::clone(output);
    thread::spawn(move || {
        let mut chunk = [0_u8; 4_096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => reader_output
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    })
}

fn wait_for_marker(
    output: &Arc<Mutex<Vec<u8>>>,
    child: &mut ChildGuard,
    marker: &str,
    deadline: Instant,
) {
    loop {
        let bytes = snapshot(output);
        if bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            return;
        }
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll guided PTY child: {error}"))
        {
            panic!(
                "guided PTY child exited with {} before `{marker}`; output:\n{}",
                status.exit_code(),
                String::from_utf8_lossy(&bytes)
            );
        }
        if Instant::now() >= deadline {
            child.kill_and_reap();
            panic!(
                "timed out waiting for `{marker}`; output:\n{}",
                String::from_utf8_lossy(&bytes)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_exit(child: &mut ChildGuard, deadline: Instant) -> portable_pty::ExitStatus {
    loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll guided PTY child: {error}"))
        {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill_and_reap();
            panic!("guided PTY session exceeded {TEST_TIMEOUT:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn run_ok(root: &Path, current_directory: &Path, arguments: &[&str]) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ctxlane"))
        .arg("--root")
        .arg(root)
        .args(arguments)
        .current_dir(current_directory)
        .output()
        .unwrap_or_else(|error| panic!("run ctxlane setup command: {error}"));
    assert!(
        output.status.success(),
        "ctxlane setup command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn configured_profile_state(root: &Path, profile: &str) -> PathBuf {
    let store = MetadataStore::new(AppPaths::for_root(root));
    let profile: ProfileId = profile
        .parse()
        .unwrap_or_else(|error| panic!("parse profile ID: {error}"));
    store
        .load_config()
        .unwrap_or_else(|error| panic!("load profile config: {error}"))
        .profiles
        .get(&profile)
        .unwrap_or_else(|| panic!("missing profile {profile}"))
        .state_dir()
        .to_path_buf()
}

fn run_guided_preflight(root: &Path, current_directory: &Path, fake_claude: &Path) -> GuidedRun {
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap_or_else(|error| panic!("open guided preflight PTY: {error}"));
    let reader = pair
        .master
        .try_clone_reader()
        .unwrap_or_else(|error| panic!("clone guided preflight PTY reader: {error}"));
    let output = Arc::new(Mutex::new(Vec::new()));
    let output_reader = capture_output(reader, &output);
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_ctxlane"));
    command.arg("--root");
    command.arg(root);
    command.arg("--claude-bin");
    command.arg(fake_claude);
    command.arg("init");
    command.arg("--guided");
    command.cwd(current_directory);
    command.env("TERM", "xterm-256color");
    command.env_remove("CI");
    command.env_remove("GITHUB_EVENT_NAME");
    let mut child = ChildGuard::new(
        pair.slave
            .spawn_command(command)
            .unwrap_or_else(|error| panic!("spawn guided preflight in PTY: {error}")),
    );
    drop(pair.slave);
    let status = wait_for_exit(&mut child, Instant::now() + TEST_TIMEOUT);
    drop(pair.master);
    output_reader
        .join()
        .unwrap_or_else(|_| panic!("guided preflight PTY reader thread panicked"));
    GuidedRun {
        code: status.exit_code(),
        output: String::from_utf8_lossy(&snapshot(&output)).into_owned(),
    }
}

#[test]
fn guided_preflight_preserves_malformed_or_incompatible_metadata() {
    let malformed_temporary =
        TempDir::new().unwrap_or_else(|error| panic!("malformed tempdir: {error}"));
    let malformed_root = malformed_temporary.path().join("ctxlane");
    let malformed_worktree = malformed_temporary.path().join("worktree");
    fs::create_dir(&malformed_worktree)
        .unwrap_or_else(|error| panic!("create malformed-test worktree: {error}"));
    let malformed_vendor = copy_fake_claude(malformed_temporary.path(), "claude-malformed-pty");
    run_ok(&malformed_root, &malformed_worktree, &["init"]);
    let malformed_config = malformed_root.join("config/config.toml");
    let malformed = "version = [\n";
    fs::write(&malformed_config, malformed)
        .unwrap_or_else(|error| panic!("write malformed metadata: {error}"));

    let malformed_run =
        run_guided_preflight(&malformed_root, &malformed_worktree, &malformed_vendor);
    assert_eq!(
        malformed_run.code, 2,
        "PTY output:\n{}",
        malformed_run.output
    );
    assert!(
        malformed_run
            .output
            .contains("failed to parse configuration")
            && malformed_run
                .output
                .contains("parser details and input were redacted"),
        "PTY output:\n{}",
        malformed_run.output
    );
    assert_eq!(
        fs::read_to_string(&malformed_config)
            .unwrap_or_else(|error| panic!("read preserved malformed metadata: {error}")),
        malformed
    );
    let malformed_claude_root = malformed_root.join("data/vendor-state/claude");
    assert!(
        !malformed_claude_root.exists()
            || fs::read_dir(&malformed_claude_root)
                .unwrap_or_else(|error| panic!("read malformed-test vendor root: {error}"))
                .next()
                .is_none()
    );

    let incompatible_temporary =
        TempDir::new().unwrap_or_else(|error| panic!("incompatible tempdir: {error}"));
    let incompatible_root = incompatible_temporary.path().join("ctxlane");
    let incompatible_worktree = incompatible_temporary.path().join("worktree");
    fs::create_dir(&incompatible_worktree)
        .unwrap_or_else(|error| panic!("create incompatible-test worktree: {error}"));
    let incompatible_vendor =
        copy_fake_claude(incompatible_temporary.path(), "claude-incompatible-pty");
    run_ok(&incompatible_root, &incompatible_worktree, &["init"]);
    run_ok(
        &incompatible_root,
        &incompatible_worktree,
        &["profile", "add", "claude", "personal", "--auth", "api-key"],
    );
    let incompatible_config = incompatible_root.join("config/config.toml");
    let before = fs::read_to_string(&incompatible_config)
        .unwrap_or_else(|error| panic!("read incompatible profile metadata: {error}"));
    let incompatible_state = configured_profile_state(&incompatible_root, "claude:personal");

    let incompatible_run = run_guided_preflight(
        &incompatible_root,
        &incompatible_worktree,
        &incompatible_vendor,
    );
    assert_eq!(
        incompatible_run.code, 2,
        "PTY output:\n{}",
        incompatible_run.output
    );
    assert!(
        incompatible_run
            .output
            .contains("requires `claude:personal` to use subscription-token authentication")
    );
    assert_eq!(
        fs::read_to_string(&incompatible_config)
            .unwrap_or_else(|error| panic!("read preserved incompatible metadata: {error}")),
        before
    );
    assert!(
        !incompatible_state
            .join("native-vendor-record.json")
            .exists()
    );
}

#[test]
fn guided_vendor_failure_warns_that_the_generated_token_may_need_revocation() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let worktree = temporary.path().join("worktree");
    fs::create_dir(&worktree).unwrap_or_else(|error| panic!("create isolated worktree: {error}"));
    let fake_claude = copy_fake_claude(temporary.path(), "claude-setup-token-exit-23");

    let run = run_guided_preflight(&root, &worktree, &fake_claude);

    assert_eq!(run.code, 23, "PTY output:\n{}", run.output);
    assert!(run.output.contains(REVOCATION_WARNING));
    assert!(!run.output.contains(BRACKETED_PASTE_ENABLED));
    let state_dir = configured_profile_state(&root, "claude:personal");
    let record: serde_json::Value = serde_json::from_slice(
        &fs::read(state_dir.join("native-vendor-record.json"))
            .unwrap_or_else(|error| panic!("read failed setup-token vendor record: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse failed setup-token vendor record: {error}"));
    assert_eq!(record["args"], serde_json::json!(["setup-token"]));
}

#[test]
fn protected_wrapped_paste_succeeds_without_echo_and_restores_the_terminal() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let prompt_harness = copy_fake_claude(temporary.path(), "setup-token-success-harness");
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap_or_else(|error| panic!("open successful setup-token prompt PTY: {error}"));
    let baseline_termios = pair
        .master
        .get_termios()
        .unwrap_or_else(|| panic!("read initial successful prompt terminal settings"));
    let reader = pair
        .master
        .try_clone_reader()
        .unwrap_or_else(|error| panic!("clone successful prompt PTY reader: {error}"));
    let mut writer = pair
        .master
        .take_writer()
        .unwrap_or_else(|error| panic!("take successful prompt PTY writer: {error}"));
    let output = Arc::new(Mutex::new(Vec::new()));
    let output_reader = capture_output(reader, &output);
    let mut command = CommandBuilder::new(&prompt_harness);
    command.arg("prompt-setup-token");
    command.cwd(temporary.path());
    command.env("TERM", "xterm-256color");
    let mut child = ChildGuard::new(
        pair.slave
            .spawn_command(command)
            .unwrap_or_else(|error| panic!("spawn successful setup-token prompt: {error}")),
    );
    let deadline = Instant::now() + TEST_TIMEOUT;
    wait_for_marker(&output, &mut child, BRACKETED_PASTE_ENABLED, deadline);

    let split = SYNTHETIC_SETUP_TOKEN.len() / 2;
    let protected_paste = format!(
        "\u{1b}[200~  {} \r\n\t{}  \n\u{1b}[201~\r",
        &SYNTHETIC_SETUP_TOKEN[..split],
        &SYNTHETIC_SETUP_TOKEN[split..]
    );
    writer
        .write_all(protected_paste.as_bytes())
        .and_then(|()| writer.flush())
        .unwrap_or_else(|error| panic!("write successful protected setup-token paste: {error}"));

    let status = wait_for_exit(&mut child, deadline);
    let restored_termios = pair
        .master
        .get_termios()
        .unwrap_or_else(|| panic!("read successful prompt restored terminal settings"));
    assert_eq!(restored_termios, baseline_termios);
    drop(pair.slave);
    drop(writer);
    drop(pair.master);
    output_reader
        .join()
        .unwrap_or_else(|_| panic!("successful setup-token PTY reader thread panicked"));
    let output = String::from_utf8_lossy(&snapshot(&output)).into_owned();

    assert_eq!(status.exit_code(), 0, "PTY output:\n{output}");
    let raw_enabled = output
        .find(BRACKETED_PASTE_ENABLED)
        .unwrap_or_else(|| panic!("bracketed paste was not enabled; output:\n{output}"));
    let visible_prompt = output
        .find("Paste one complete token")
        .unwrap_or_else(|| panic!("visible prompt was not rendered; output:\n{output}"));
    assert!(raw_enabled < visible_prompt, "PTY output:\n{output}");
    assert!(output.contains("synthetic setup-token accepted"));
    assert!(output.contains(BRACKETED_PASTE_DISABLED));
    assert!(!output.contains(SYNTHETIC_SETUP_TOKEN));
}

#[test]
fn protected_wrapped_paste_rejects_delayed_input_before_the_next_shell() {
    const SHELL_DONE: &str = "CTXLANE_NEXT_SHELL_DRAINED";
    const TERMINAL_RESTORED: &str = "CTXLANE_PROMPT_TERMINAL_RESTORED";

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let sentinel = temporary.path().join("delayed-input-was-executed");
    let prompt_harness = copy_fake_claude(temporary.path(), "setup-token-prompt-harness");
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap_or_else(|error| panic!("open setup-token prompt PTY: {error}"));
    let reader = pair
        .master
        .try_clone_reader()
        .unwrap_or_else(|error| panic!("clone setup-token prompt PTY reader: {error}"));
    let mut writer = pair
        .master
        .take_writer()
        .unwrap_or_else(|error| panic!("take setup-token prompt PTY writer: {error}"));
    let output = Arc::new(Mutex::new(Vec::new()));
    let output_reader = capture_output(reader, &output);
    let deadline = Instant::now() + TEST_TIMEOUT;

    let mut shell_command = CommandBuilder::new("/bin/sh");
    shell_command.arg("-c");
    shell_command.arg(
        "before=$(stty -g)\n\"$CTXLANE_PROMPT_HARNESS\" prompt-setup-token\nstatus=$?\nafter=$(stty -g)\nif [ \"$before\" = \"$after\" ]; then printf 'CTXLANE_PROMPT_TERMINAL_RESTORED\\n'; fi\nprintf 'CTXLANE_PROMPT_STATUS_%s\\n' \"$status\"\nexec /bin/sh -i",
    );
    shell_command.cwd(temporary.path());
    shell_command.env("TERM", "xterm-256color");
    shell_command.env("PS1", "CTXLANE_TEST_SHELL> ");
    shell_command.env("CTXLANE_PROMPT_HARNESS", &prompt_harness);
    let mut shell = ChildGuard::new(
        pair.slave
            .spawn_command(shell_command)
            .unwrap_or_else(|error| panic!("spawn setup-token prompt and next shell: {error}")),
    );
    wait_for_marker(&output, &mut shell, BRACKETED_PASTE_ENABLED, deadline);

    let split = SYNTHETIC_SETUP_TOKEN.len() / 2;
    let protected_paste = format!(
        "\u{1b}[200~  {} \r\n\t{}  \n\u{1b}[201~\r",
        &SYNTHETIC_SETUP_TOKEN[..split],
        &SYNTHETIC_SETUP_TOKEN[split..]
    );
    writer
        .write_all(protected_paste.as_bytes())
        .and_then(|()| writer.flush())
        .unwrap_or_else(|error| panic!("write protected setup-token paste: {error}"));
    thread::sleep(Duration::from_millis(40));
    let delayed = format!("touch {}\r", sentinel.display());
    writer
        .write_all(delayed.as_bytes())
        .and_then(|()| writer.flush())
        .unwrap_or_else(|error| panic!("write delayed sentinel input: {error}"));

    wait_for_marker(&output, &mut shell, TERMINAL_RESTORED, deadline);
    wait_for_marker(&output, &mut shell, "CTXLANE_PROMPT_STATUS_2", deadline);

    let shell_input = format!("printf '{SHELL_DONE}\\n'; exit\r");
    writer
        .write_all(shell_input.as_bytes())
        .and_then(|()| writer.flush())
        .unwrap_or_else(|error| panic!("finish next-shell sentinel check: {error}"));
    let shell_status = wait_for_exit(&mut shell, deadline);

    drop(pair.slave);
    drop(writer);
    drop(pair.master);
    output_reader
        .join()
        .unwrap_or_else(|_| panic!("setup-token PTY reader thread panicked"));
    let output = String::from_utf8_lossy(&snapshot(&output)).into_owned();

    assert_eq!(shell_status.exit_code(), 0, "PTY output:\n{output}");
    assert!(
        output.contains("extra input followed the Claude setup token; nothing was stored"),
        "PTY output:\n{output}"
    );
    assert!(output.contains(BRACKETED_PASTE_ENABLED));
    assert!(output.contains(BRACKETED_PASTE_DISABLED));
    assert!(output.contains(SHELL_DONE), "PTY output:\n{output}");
    assert!(!output.contains(SYNTHETIC_SETUP_TOKEN));
    assert!(!sentinel.exists(), "PTY output:\n{output}");
}

fn run_guided_prompt(exit: PromptExit) -> GuidedRun {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let worktree = temporary.path().join("worktree");
    fs::create_dir(&worktree).unwrap_or_else(|error| panic!("create isolated worktree: {error}"));
    let fake_claude = copy_fake_claude(temporary.path(), "claude-guided-pty");
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap_or_else(|error| panic!("open guided PTY: {error}"));
    let baseline_termios = pair
        .master
        .get_termios()
        .unwrap_or_else(|| panic!("read initial guided PTY terminal settings"));
    let reader = pair
        .master
        .try_clone_reader()
        .unwrap_or_else(|error| panic!("clone guided PTY reader: {error}"));
    let mut writer = pair
        .master
        .take_writer()
        .unwrap_or_else(|error| panic!("take guided PTY writer: {error}"));
    let output = Arc::new(Mutex::new(Vec::new()));
    let output_reader = capture_output(reader, &output);

    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_ctxlane"));
    command.arg("--root");
    command.arg(&root);
    command.arg("--claude-bin");
    command.arg(&fake_claude);
    command.arg("init");
    command.arg("--guided");
    command.cwd(&worktree);
    command.env("TERM", "xterm-256color");
    command.env_remove("CI");
    command.env_remove("GITHUB_EVENT_NAME");
    if matches!(exit, PromptExit::Terminate) {
        // This branch deliberately signals the instrumented CLI. The escape branch still
        // contributes child-process coverage; the signal branch writes only inside the tempdir.
        command.env_remove("LLVM_PROFILE_FILE");
    }
    let mut child = ChildGuard::new(
        pair.slave
            .spawn_command(command)
            .unwrap_or_else(|error| panic!("spawn guided ctxlane in PTY: {error}")),
    );
    let child_process_id = child
        .child
        .process_id()
        .unwrap_or_else(|| panic!("guided PTY child has no process ID"));
    let deadline = Instant::now() + TEST_TIMEOUT;
    wait_for_marker(&output, &mut child, BRACKETED_PASTE_ENABLED, deadline);

    match exit {
        PromptExit::Escape => writer
            .write_all(b"\x1b")
            .and_then(|()| writer.flush())
            .unwrap_or_else(|error| panic!("cancel guided setup-token prompt: {error}")),
        PromptExit::Terminate => {
            let raw_process_id = i32::try_from(child_process_id)
                .unwrap_or_else(|error| panic!("convert guided PTY process ID: {error}"));
            let process_id = Pid::from_raw(raw_process_id)
                .unwrap_or_else(|| panic!("guided PTY process ID was zero"));
            kill_process(process_id, Signal::TERM)
                .unwrap_or_else(|error| panic!("signal guided PTY child: {error}"));
        }
    }

    let status = wait_for_exit(&mut child, deadline);
    let restored_termios = pair
        .master
        .get_termios()
        .unwrap_or_else(|| panic!("read restored guided PTY terminal settings"));
    assert_eq!(
        restored_termios, baseline_termios,
        "guided setup-token prompt did not restore terminal settings after {exit:?}"
    );
    drop(pair.slave);
    drop(writer);
    drop(pair.master);
    output_reader
        .join()
        .unwrap_or_else(|_| panic!("guided PTY reader thread panicked"));
    let output = String::from_utf8_lossy(&snapshot(&output)).into_owned();
    let enabled = output
        .find(BRACKETED_PASTE_ENABLED)
        .unwrap_or_else(|| panic!("bracketed paste was not enabled; output:\n{output}"));
    let disabled = output
        .rfind(BRACKETED_PASTE_DISABLED)
        .unwrap_or_else(|| panic!("bracketed paste was not disabled; output:\n{output}"));
    assert!(
        enabled < disabled,
        "bracketed paste disable preceded enable; output:\n{output}"
    );

    let config = fs::read_to_string(root.join("config/config.toml"))
        .unwrap_or_else(|error| panic!("read guided profile metadata: {error}"));
    assert!(config.contains("[profiles.\"claude:personal\"]"));
    assert!(config.contains("auth = \"subscription-token\""));
    assert!(
        config.contains(&format!("-{child_process_id:08x}-")),
        "guided profile did not receive a generation-specific keyring account: {config}"
    );
    let state_dir = configured_profile_state(&root, "claude:personal");
    let record: serde_json::Value = serde_json::from_slice(
        &fs::read(state_dir.join("native-vendor-record.json"))
            .unwrap_or_else(|error| panic!("read setup-token vendor record: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse setup-token vendor record: {error}"));
    assert_eq!(record["provider"], "claude");
    assert_eq!(record["args"], serde_json::json!(["setup-token"]));

    GuidedRun {
        code: status.exit_code(),
        output,
    }
}

#[test]
fn cancellation_and_termination_restore_the_guided_prompt() {
    for (exit, expected_code, expected_error) in [
        (PromptExit::Escape, 2, "operation cancelled"),
        (PromptExit::Terminate, 143, "operation interrupted"),
    ] {
        let run = run_guided_prompt(exit);
        assert_eq!(run.code, expected_code, "PTY output:\n{}", run.output);
        assert!(
            run.output.contains(expected_error),
            "PTY output:\n{}",
            run.output
        );
        assert!(run.output.contains(REVOCATION_WARNING));
    }
}
