use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};

use tempfile::TempDir;

fn aictx(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aictx"));
    command.arg("--root").arg(root);
    command
}

fn run_ok(command: &mut Command) -> std::process::Output {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("run aictx: {error}"));
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn bare_invocation_refuses_non_terminal_io_without_ansi_output() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let output = aictx(&root)
        .output()
        .unwrap_or_else(|error| panic!("run bare aictx: {error}"));

    assert_eq!(output.status.code(), Some(14));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("interactive mode requires a terminal"));
    assert!(!stderr.contains('\u{1b}'));
    assert!(
        !root.exists(),
        "bare invocation must not initialize metadata"
    );
}

#[test]
fn use_updates_only_mutable_state_and_bindings_take_precedence() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let company = temporary.path().join("company/project");
    fs::create_dir_all(&company).unwrap_or_else(|error| panic!("company directory: {error}"));

    run_ok(aictx(&root).arg("init"));
    run_ok(aictx(&root).args([
        "profile",
        "add",
        "claude",
        "personal",
        "--auth",
        "subscription-token",
        "--secret-ref",
        "keyring://aictx/claude-personal",
    ]));
    run_ok(aictx(&root).args([
        "profile",
        "add",
        "claude",
        "work",
        "--auth",
        "api-key",
        "--secret-ref",
        "keyring://aictx/claude-work",
    ]));
    run_ok(aictx(&root).args(["context", "add", "personal", "--claude", "claude:personal"]));
    run_ok(aictx(&root).args(["context", "add", "work", "--claude", "claude:work"]));

    let config_path = root.join("config/config.toml");
    let config_before =
        fs::read(&config_path).unwrap_or_else(|error| panic!("read config before use: {error}"));
    run_ok(aictx(&root).args(["use", "work", "--yes"]));
    let config_after =
        fs::read(&config_path).unwrap_or_else(|error| panic!("read config after use: {error}"));
    assert_eq!(config_before, config_after, "use must not rewrite config");
    let state = fs::read_to_string(root.join("state/state.toml"))
        .unwrap_or_else(|error| panic!("read state: {error}"));
    assert!(state.contains("current_context = \"work\""));

    run_ok(
        aictx(&root).args([
            "bind",
            company
                .to_str()
                .unwrap_or_else(|| panic!("temporary path should be UTF-8")),
            "personal",
        ]),
    );
    let output = run_ok(aictx(&root).current_dir(&company).arg("current"));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "personal");

    fs::write(
        company.join(".aictx.toml"),
        "secret_command='curl attacker'",
    )
    .unwrap_or_else(|error| panic!("write malicious repo config: {error}"));
    let output = run_ok(aictx(&root).current_dir(&company).arg("current"));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "personal");
}

#[test]
fn provider_auth_combinations_and_access_token_pins_are_validated() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));

    let output = aictx(&root)
        .args(["profile", "add", "claude", "bad", "--auth", "chatgpt-oauth"])
        .output()
        .unwrap_or_else(|error| panic!("run invalid profile command: {error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not valid for Claude"));

    let output = aictx(&root)
        .args([
            "profile",
            "add",
            "codex",
            "automation",
            "--auth",
            "access-token",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run unpinned profile command: {error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("require --workspace"));

    let output = aictx(&root)
        .args([
            "profile",
            "add",
            "codex",
            "api-workspace",
            "--auth",
            "api-key",
            "--secret-ref",
            "keyring://aictx/codex-api-key",
            "--workspace",
            "ws_wrong_mode",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run API-key workspace command: {error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("only with ChatGPT"));
}

#[test]
fn case_folded_profile_add_is_rejected_without_disturbing_existing_state() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));
    run_ok(aictx(&root).args(["profile", "add", "codex", "Work", "--auth", "chatgpt-oauth"]));
    let state_dir = root.join("data/vendor-state/codex/Work");
    let marker = state_dir.join("must-survive");
    fs::write(&marker, "existing state")
        .unwrap_or_else(|error| panic!("write existing state marker: {error}"));

    let output = aictx(&root)
        .args(["profile", "add", "codex", "work", "--auth", "chatgpt-oauth"])
        .output()
        .unwrap_or_else(|error| panic!("run case-folded profile add: {error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("case-insensitive"));
    assert_eq!(
        fs::read_to_string(&marker)
            .unwrap_or_else(|error| panic!("read surviving state marker: {error}")),
        "existing state"
    );

    let state_entries = fs::read_dir(root.join("data/vendor-state/codex"))
        .unwrap_or_else(|error| panic!("read provider state: {error}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("read provider state entry: {error}"))
                .file_name()
        })
        .collect::<Vec<_>>();
    assert_eq!(state_entries, vec![std::ffi::OsString::from("Work")]);
    assert!(root.join("state/profile-locks/codex-work.lock").exists());
}

#[test]
fn billing_domain_changes_require_explicit_non_interactive_confirmation() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));
    run_ok(aictx(&root).args([
        "profile",
        "add",
        "claude",
        "personal",
        "--auth",
        "subscription-token",
        "--secret-ref",
        "keyring://aictx/claude-personal",
    ]));
    run_ok(aictx(&root).args([
        "profile",
        "add",
        "claude",
        "work",
        "--auth",
        "api-key",
        "--secret-ref",
        "keyring://aictx/claude-work",
    ]));
    run_ok(aictx(&root).args(["context", "add", "personal", "--claude", "claude:personal"]));
    run_ok(aictx(&root).args(["context", "add", "work", "--claude", "claude:work"]));

    let output = aictx(&root)
        .args(["--non-interactive", "use", "work"])
        .output()
        .unwrap_or_else(|error| panic!("run unconfirmed use: {error}"));
    assert_eq!(output.status.code(), Some(14));
    assert!(String::from_utf8_lossy(&output.stderr).contains("billing-domain change"));
    let output = run_ok(aictx(&root).arg("current"));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "personal");

    run_ok(aictx(&root).args(["--non-interactive", "use", "work", "--yes"]));
    let output = run_ok(aictx(&root).arg("current"));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "work");
}

#[test]
fn config_schema_rejects_unknown_fields_and_telemetry() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));
    let config_path = root.join("config/config.toml");
    let valid = fs::read_to_string(&config_path)
        .unwrap_or_else(|error| panic!("read generated config: {error}"));

    let unknown = valid.replacen("version = 1\n", "version = 1\nunknown = true\n", 1);
    fs::write(&config_path, unknown)
        .unwrap_or_else(|error| panic!("write config with unknown field: {error}"));
    let output = aictx(&root)
        .args(["profile", "list"])
        .output()
        .unwrap_or_else(|error| panic!("load unknown config: {error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));

    let output = aictx(&root)
        .arg("doctor")
        .output()
        .unwrap_or_else(|error| panic!("diagnose unknown config: {error}"));
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("FAIL metadata"));
    assert!(output.stderr.is_empty());

    let telemetry = valid.replace("telemetry = false", "telemetry = true");
    fs::write(&config_path, telemetry)
        .unwrap_or_else(|error| panic!("write telemetry config: {error}"));
    let output = aictx(&root)
        .args(["profile", "list"])
        .output()
        .unwrap_or_else(|error| panic!("load telemetry config: {error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("telemetry must remain disabled"));
}

#[test]
fn concurrent_metadata_updates_are_serialized_without_lost_writes() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));

    let mut children = Vec::new();
    for index in 0..8 {
        let name = format!("profile-{index}");
        let secret_ref = format!("keyring://aictx/{name}");
        let child = aictx(&root)
            .args([
                "profile",
                "add",
                "claude",
                &name,
                "--auth",
                "api-key",
                "--secret-ref",
                &secret_ref,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn profile add: {error}"));
        children.push(child);
    }
    for child in children {
        let output = child
            .wait_with_output()
            .unwrap_or_else(|error| panic!("wait for profile add: {error}"));
        assert!(
            output.status.success(),
            "concurrent update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = run_ok(aictx(&root).args(["profile", "list"]));
    let listing = String::from_utf8_lossy(&output.stdout);
    for index in 0..8 {
        assert!(listing.contains(&format!("claude:profile-{index}")));
    }
}

#[test]
fn repository_local_layout_override_is_refused_before_initialization() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let project = temporary.path().join("project");
    fs::create_dir_all(project.join(".git"))
        .unwrap_or_else(|error| panic!("create repository marker: {error}"));
    let root = project.join(".aictx");

    let output = aictx(&root)
        .current_dir(&project)
        .arg("init")
        .output()
        .unwrap_or_else(|error| panic!("initialize repository-local layout: {error}"));
    assert_eq!(output.status.code(), Some(15));
    assert!(String::from_utf8_lossy(&output.stderr).contains("current Git worktree"));
    assert!(!root.exists());

    let safe_root = temporary.path().join("safe-aictx");
    let inherited_root = project.join("inherited-aictx");
    run_ok(
        aictx(&safe_root)
            .current_dir(&project)
            .env("AICTX_ROOT", &inherited_root)
            .arg("init"),
    );
    assert!(safe_root.join("config/config.toml").exists());
    assert!(
        !inherited_root.exists(),
        "inherited root controls must be ignored"
    );
}

#[test]
fn recreating_removed_profile_cannot_reuse_old_state_or_default_keyring_item() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));
    run_ok(aictx(&root).args(["profile", "add", "claude", "reusable", "--auth", "api-key"]));

    let config_path = root.join("config/config.toml");
    let before = fs::read_to_string(&config_path)
        .unwrap_or_else(|error| panic!("read first profile config: {error}"));
    let first_reference = before
        .lines()
        .find(|line| line.trim_start().starts_with("secret_ref ="))
        .unwrap_or_else(|| panic!("first secret reference missing"))
        .to_owned();
    let active_state = root.join("data/vendor-state/claude/reusable");
    fs::write(active_state.join("credential-marker"), "old identity")
        .unwrap_or_else(|error| panic!("write old vendor state: {error}"));

    let refused_delete = aictx(&root)
        .args([
            "--non-interactive",
            "profile",
            "remove",
            "claude:reusable",
            "--delete-secret",
        ])
        .output()
        .unwrap_or_else(|error| panic!("remove keyring profile non-interactively: {error}"));
    assert_eq!(refused_delete.status.code(), Some(14));
    assert!(active_state.join("credential-marker").exists());

    run_ok(aictx(&root).args(["profile", "remove", "claude:reusable"]));
    assert!(!active_state.exists());
    let archived = fs::read_dir(root.join("data/vendor-state/claude"))
        .unwrap_or_else(|error| panic!("read vendor-state archive directory: {error}"))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("reusable.retired-"))
        })
        .unwrap_or_else(|| panic!("retired vendor state missing"));
    assert!(archived.join("credential-marker").exists());

    // This is the safe on-disk shape of a process interrupted after its profile
    // metadata was removed but before the managed state directory was retired.
    fs::create_dir(&active_state)
        .unwrap_or_else(|error| panic!("recreate interrupted vendor state: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&active_state, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("secure interrupted vendor state: {error}"));
    }
    fs::write(
        active_state.join("interrupted-marker"),
        "must not be reused",
    )
    .unwrap_or_else(|error| panic!("write interrupted vendor state: {error}"));

    run_ok(aictx(&root).args(["profile", "add", "claude", "reusable", "--auth", "api-key"]));
    let after = fs::read_to_string(&config_path)
        .unwrap_or_else(|error| panic!("read recreated profile config: {error}"));
    let second_reference = after
        .lines()
        .find(|line| line.trim_start().starts_with("secret_ref ="))
        .unwrap_or_else(|| panic!("second secret reference missing"));
    assert_ne!(first_reference, second_reference);
    assert!(!active_state.join("credential-marker").exists());
    assert!(!active_state.join("interrupted-marker").exists());
    let interrupted_archive = fs::read_dir(root.join("data/vendor-state/claude"))
        .unwrap_or_else(|error| panic!("read interrupted state archive directory: {error}"))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("interrupted-marker").exists())
        .unwrap_or_else(|| panic!("interrupted vendor state was not archived"));
    assert!(
        interrupted_archive
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("reusable.retired-"))
    );
}

#[cfg(unix)]
#[test]
fn sensitive_metadata_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));
    for path in [
        root.join("config/config.toml"),
        root.join("state/state.toml"),
        root.join("config/config.lock"),
        root.join("state/metadata.lock"),
        root.join("state/state.lock"),
    ] {
        let mode = fs::metadata(&path)
            .unwrap_or_else(|error| panic!("metadata for {}: {error}", path.display()))
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{} is too permissive", path.display());
    }

    let config_path = root.join("config/config.toml");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|error| panic!("make config insecure: {error}"));
    let output = aictx(&root)
        .args(["profile", "list"])
        .output()
        .unwrap_or_else(|error| panic!("load insecure config: {error}"));
    assert_eq!(output.status.code(), Some(15));
    assert!(String::from_utf8_lossy(&output.stderr).contains("mode 0600"));
}

#[cfg(unix)]
#[test]
fn symlinked_mutable_state_is_refused() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));

    let target = temporary.path().join("attacker-controlled-state.toml");
    fs::write(&target, "version = 1\n")
        .unwrap_or_else(|error| panic!("write symlink target: {error}"));
    let state_path = root.join("state/state.toml");
    fs::remove_file(&state_path).unwrap_or_else(|error| panic!("remove mutable state: {error}"));
    symlink(&target, &state_path).unwrap_or_else(|error| panic!("symlink mutable state: {error}"));

    let output = aictx(&root)
        .arg("current")
        .output()
        .unwrap_or_else(|error| panic!("load symlinked state: {error}"));
    assert_eq!(output.status.code(), Some(15));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing symlinked"));
}
