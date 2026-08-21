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
    let description = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("run aictx: {error}"));
    assert!(
        output.status.success(),
        "command failed: {description}\nstatus: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn copy_aictx_as_vendor(directory: &Path, name: &str) -> std::path::PathBuf {
    let executable = directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_aictx"), &executable)
        .unwrap_or_else(|error| panic!("copy test vendor executable: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("secure test vendor executable: {error}"));
    }
    executable
}

fn add_personal_context(root: &Path) {
    run_ok(aictx(root).arg("init"));
    run_ok(aictx(root).args(["profile", "add", "claude", "personal", "--auth", "api-key"]));
    run_ok(aictx(root).args(["context", "add", "personal", "--claude", "claude:personal"]));
}

#[test]
fn guided_init_rejects_non_interactive_use_before_creating_state() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let output = aictx(&root)
        .args(["--non-interactive", "init", "--guided"])
        .output()
        .unwrap_or_else(|error| panic!("run non-interactive guided init: {error}"));

    assert_eq!(output.status.code(), Some(14));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(
        "guided setup requires terminal input and output for the interactive `claude setup-token` flow"
    ));
    assert!(stderr.contains("without `--non-interactive`"));
    assert!(
        !root.exists(),
        "a rejected guided flow must not create a partial layout"
    );
}

#[test]
fn lifecycle_mutations_before_init_report_not_initialized_without_creating_layout() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");

    for arguments in [
        vec!["profile", "add", "claude", "personal", "--auth", "api-key"],
        vec!["profile", "remove", "claude:personal"],
        vec!["login", "claude:personal"],
        vec!["logout", "claude:personal"],
    ] {
        let output = aictx(&root)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("run pre-initialization command: {error}"));
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("aictx is not initialized"));
        assert!(stderr.contains("aictx init"));
        assert!(!stderr.contains("No such file or directory"));
        assert!(
            !root.exists(),
            "pre-initialization command must not create a partial layout"
        );
    }
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
    let receipt = run_ok(
        aictx(&root)
            .current_dir(&company)
            .args(["use", "work", "--yes"]),
    );
    let receipt = String::from_utf8_lossy(&receipt.stdout);
    assert!(receipt.contains("Global active context: work"));
    assert!(receipt.contains("Global profiles: claude=claude:work (api-key, Anthropic API)"));
    assert!(receipt.contains("Effective here at commit: personal (directory binding)"));
    assert!(receipt.contains(
        "Effective profiles: claude=claude:personal (subscription-token, Claude subscription)"
    ));
    assert!(receipt.contains("directory binding takes precedence"));
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
fn binding_errors_are_actionable_and_deleted_directories_can_be_unbound() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    add_personal_context(&root);

    let binding = temporary.path().join("company/project");
    let missing = aictx(&root)
        .arg("bind")
        .arg(&binding)
        .arg("personal")
        .output()
        .unwrap_or_else(|error| panic!("bind missing directory: {error}"));
    assert_eq!(missing.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(stderr.contains("binding target"));
    assert!(stderr.contains("does not exist; create it first"));
    assert!(!stderr.contains("os error"));

    fs::create_dir_all(&binding)
        .unwrap_or_else(|error| panic!("create directory to bind: {error}"));
    run_ok(aictx(&root).current_dir(temporary.path()).args([
        "bind",
        "company/project",
        "personal",
    ]));
    fs::remove_dir_all(temporary.path().join("company"))
        .unwrap_or_else(|error| panic!("remove bound directory: {error}"));

    let removed = run_ok(
        aictx(&root)
            .current_dir(temporary.path())
            .args(["unbind", "company/project"]),
    );
    assert!(String::from_utf8_lossy(&removed.stdout).contains("Removed binding"));
    let bindings = run_ok(aictx(&root).arg("bindings"));
    assert_eq!(
        String::from_utf8_lossy(&bindings.stdout).trim(),
        "No directory bindings configured."
    );
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
fn subscription_auth_is_provider_neutral_and_persists_vendor_native_modes() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    run_ok(aictx(&root).arg("init"));

    for (provider, name, auth) in [
        ("claude", "canonical", "subscription"),
        ("codex", "canonical", "subscription"),
        ("codex", "personal", "subscription-token"),
        ("codex", "chatgpt-oauth-alias", "chatgpt-oauth"),
    ] {
        run_ok(aictx(&root).args(["profile", "add", provider, name, "--auth", auth]));
    }

    let claude = run_ok(aictx(&root).args(["profile", "show", "claude:canonical"]));
    let claude = String::from_utf8_lossy(&claude.stdout);
    assert!(claude.contains("auth:           subscription-token"));
    assert!(claude.contains("billing:        Claude subscription"));
    assert!(claude.contains("credential:     keyring://"));

    for profile in [
        "codex:canonical",
        "codex:personal",
        "codex:chatgpt-oauth-alias",
    ] {
        let codex = run_ok(aictx(&root).args(["profile", "show", profile]));
        let codex = String::from_utf8_lossy(&codex.stdout);
        assert!(codex.contains("auth:           chatgpt-oauth"));
        assert!(codex.contains("billing:        ChatGPT subscription/workspace"));
        assert!(codex.contains("credential:     vendor/identity-provider managed"));
        assert!(!codex.contains("keyring://"));
    }

    let config = fs::read_to_string(root.join("config/config.toml"))
        .unwrap_or_else(|error| panic!("read provider-native auth config: {error}"));
    assert_eq!(config.matches("auth = \"subscription-token\"").count(), 1);
    assert_eq!(config.matches("auth = \"chatgpt-oauth\"").count(), 3);
    assert!(!config.contains("auth = \"subscription\""));

    let rejected = aictx(&root)
        .args([
            "profile",
            "add",
            "codex",
            "secret-bearing",
            "--auth",
            "subscription-token",
            "--secret-ref",
            "keyring://aictx/must-not-be-used",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run Codex subscription with secret ref: {error}"));
    assert_eq!(rejected.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("credentials must remain vendor-managed")
    );
}

#[test]
fn profile_help_uses_the_provider_neutral_subscription_mode() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let help = run_ok(aictx(&root).args(["profile", "add", "--help"]));
    let help = String::from_utf8_lossy(&help.stdout);

    assert!(help.contains("profile add claude personal --auth subscription"));
    assert!(help.contains("profile add codex work --auth subscription"));
    assert!(help.contains("subscription-token"));
    assert!(help.contains("chatgpt-oauth"));
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
fn account_profile_changes_require_explicit_non_interactive_confirmation() {
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
        "subscription-token",
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
    assert!(String::from_utf8_lossy(&output.stderr).contains("account profile change"));
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

    let json = aictx(&root)
        .args(["doctor", "--json"])
        .output()
        .unwrap_or_else(|error| panic!("diagnose unknown config as JSON: {error}"));
    assert_eq!(json.status.code(), Some(1));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout)
        .unwrap_or_else(|error| panic!("doctor JSON should parse: {error}"));
    assert_eq!(report["ok"], false);
    assert_eq!(report["checks"][0]["level"], "failure");
    assert_eq!(report["checks"][0]["name"], "metadata");

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
fn doctor_fails_readiness_when_a_wif_identity_source_is_missing() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let fake_claude = copy_aictx_as_vendor(temporary.path(), "claude");
    let missing_token = temporary.path().join("missing-identity-token.jwt");
    run_ok(aictx(&root).arg("init"));
    run_ok(
        aictx(&root).args([
            "profile",
            "add",
            "claude",
            "ci",
            "--auth",
            "wif",
            "--organization-id",
            "org_test",
            "--federation-rule-id",
            "rule_test",
            "--service-account-id",
            "service_test",
            "--identity-token-file",
            missing_token
                .to_str()
                .unwrap_or_else(|| panic!("temporary path should be UTF-8")),
        ]),
    );

    let output = aictx(&root)
        .arg("--claude-bin")
        .arg(&fake_claude)
        .args(["doctor", "--provider", "claude"])
        .output()
        .unwrap_or_else(|error| panic!("run doctor with missing WIF source: {error}"));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FAIL"));
    assert!(stdout.contains("claude:ci identity source"));
    assert!(stdout.contains("missing-identity-token.jwt"));
    assert!(!stdout.contains("OS keyring"));

    fs::write(&missing_token, "short-lived-test-identity")
        .unwrap_or_else(|error| panic!("write WIF identity source: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&missing_token, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("secure WIF identity source: {error}"));
    }
    let ready = run_ok(aictx(&root).arg("--claude-bin").arg(&fake_claude).args([
        "doctor",
        "--provider",
        "claude",
        "--json",
    ]));
    let ready: serde_json::Value = serde_json::from_slice(&ready.stdout)
        .unwrap_or_else(|error| panic!("doctor JSON should parse: {error}"));
    assert_eq!(ready["ok"], true);
    let checks = ready["checks"]
        .as_array()
        .unwrap_or_else(|| panic!("doctor checks should be an array"));
    assert!(
        checks.iter().any(|check| {
            check["level"] == "pass" && check["name"] == "claude:ci identity source"
        })
    );
    assert!(
        checks
            .iter()
            .any(|check| { check["level"] == "pass" && check["name"] == "claude:ci credential" })
    );
    assert!(!checks.iter().any(|check| check["name"] == "OS keyring"));
}

#[test]
fn doctor_reports_an_unconfigured_provider_as_not_ready() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let fake_claude = copy_aictx_as_vendor(temporary.path(), "claude");
    run_ok(aictx(&root).arg("init"));

    let output = aictx(&root)
        .arg("--claude-bin")
        .arg(&fake_claude)
        .args(["doctor", "--provider", "claude", "--json"])
        .output()
        .unwrap_or_else(|error| panic!("run unconfigured-provider doctor: {error}"));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("doctor JSON should parse: {error}"));
    assert_eq!(report["ok"], false);
    assert!(report["checks"].as_array().is_some_and(|checks| {
        checks.iter().any(|check| {
            check["level"] == "failure"
                && check["name"] == "claude profiles"
                && check["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("aictx profile add"))
        })
    }));
}

#[cfg(unix)]
#[test]
fn logout_reports_completed_cleanup_and_propagates_vendor_failure() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let fake_codex = temporary.path().join("codex");
    fs::write(&fake_codex, "#!/bin/sh\nexit 0\n")
        .unwrap_or_else(|error| panic!("write successful fake Codex: {error}"));
    fs::set_permissions(&fake_codex, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("secure fake Codex: {error}"));
    run_ok(aictx(&root).arg("init"));
    run_ok(aictx(&root).args([
        "profile",
        "add",
        "codex",
        "personal",
        "--auth",
        "chatgpt-oauth",
    ]));

    let completed = run_ok(
        aictx(&root)
            .arg("--codex-bin")
            .arg(&fake_codex)
            .args(["logout", "codex:personal"]),
    );
    let stdout = String::from_utf8_lossy(&completed.stdout);
    assert!(stdout.contains("Completed local authentication cleanup for codex:personal"));
    assert!(stdout.contains("does not confirm that local credentials existed"));
    assert!(!stdout.contains("Logged out"));

    fs::write(&fake_codex, "#!/bin/sh\nexit 37\n")
        .unwrap_or_else(|error| panic!("write failing fake Codex: {error}"));
    fs::set_permissions(&fake_codex, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("secure failing fake Codex: {error}"));
    let failed = aictx(&root)
        .arg("--codex-bin")
        .arg(&fake_codex)
        .args(["logout", "codex:personal"])
        .output()
        .unwrap_or_else(|error| panic!("run failing Codex logout: {error}"));
    assert_eq!(failed.status.code(), Some(37));
    assert!(failed.stdout.is_empty());
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
fn public_command_surface_supports_a_complete_local_lifecycle() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let project = temporary.path().join("company/project");
    fs::create_dir_all(&project).unwrap_or_else(|error| panic!("create project: {error}"));

    let initialized = run_ok(aictx(&root).arg("init"));
    let initialized_stdout = String::from_utf8_lossy(&initialized.stdout);
    assert!(initialized_stdout.contains("Initialized aictx metadata."));
    assert!(initialized_stdout.contains("Next: add a profile with `aictx profile add --help`."));
    let idempotent = run_ok(aictx(&root).arg("init"));
    assert_eq!(
        String::from_utf8_lossy(&idempotent.stdout).trim(),
        "aictx is already initialized; existing metadata was left unchanged."
    );
    let quiet = run_ok(aictx(&root).args(["--quiet", "init"]));
    assert!(quiet.stdout.is_empty());
    assert!(quiet.stderr.is_empty());

    run_ok(aictx(&root).args([
        "profile",
        "add",
        "claude",
        "personal",
        "--auth",
        "api-key",
        "--account",
        "person@example.test",
        "--organization",
        "organization-private",
    ]));
    run_ok(aictx(&root).args([
        "profile",
        "add",
        "codex",
        "personal",
        "--auth",
        "chatgpt-oauth",
        "--account",
        "codex-user@example.test",
        "--workspace",
        "workspace-private",
    ]));

    let profiles = run_ok(aictx(&root).args(["profile", "list"]));
    let profile_list = String::from_utf8_lossy(&profiles.stdout);
    assert!(profile_list.contains("claude:personal"));
    assert!(profile_list.contains("codex:personal"));
    let shown_profile = run_ok(aictx(&root).args(["profile", "show", "claude:personal"]));
    let shown_profile = String::from_utf8_lossy(&shown_profile.stdout);
    assert!(shown_profile.contains("profile:        claude:personal"));
    assert!(shown_profile.contains("p***@example.test"));
    assert!(!shown_profile.contains("person@example.test"));
    assert!(!shown_profile.contains("organization-private"));

    run_ok(aictx(&root).args([
        "context",
        "add",
        "personal",
        "--claude",
        "claude:personal",
        "--codex",
        "codex:personal",
    ]));
    let contexts = run_ok(aictx(&root).args(["context", "list"]));
    let context_list = String::from_utf8_lossy(&contexts.stdout);
    assert!(context_list.contains("personal"));
    assert!(context_list.contains("claude=claude:personal"));
    assert!(context_list.contains("codex=codex:personal"));
    let shown_context = run_ok(aictx(&root).args(["context", "show", "personal"]));
    assert!(String::from_utf8_lossy(&shown_context.stdout).contains("Context: personal"));

    let status = run_ok(aictx(&root).arg("status"));
    let status = String::from_utf8_lossy(&status.stdout);
    assert!(status.contains("Context: personal (default context)"));
    assert!(status.contains("p***@example.test"));
    assert!(status.contains("c***@example.test"));
    assert!(!status.contains("person@example.test"));
    assert!(!status.contains("codex-user@example.test"));
    assert!(!status.contains("keyring://"));

    let referenced_profile = aictx(&root)
        .args(["profile", "remove", "claude:personal"])
        .output()
        .unwrap_or_else(|error| panic!("remove referenced profile: {error}"));
    assert_eq!(referenced_profile.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&referenced_profile.stderr).contains("still referenced by context")
    );

    run_ok(aictx(&root).arg("bind").arg(&project).arg("personal"));
    let bindings = run_ok(aictx(&root).arg("bindings"));
    let bindings = String::from_utf8_lossy(&bindings.stdout);
    assert!(bindings.contains("personal"));
    assert!(bindings.contains("project"));
    let bound_context = aictx(&root)
        .args(["context", "remove", "personal"])
        .output()
        .unwrap_or_else(|error| panic!("remove bound context: {error}"));
    assert_eq!(bound_context.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bound_context.stderr).contains("directory binding"));
    run_ok(aictx(&root).arg("unbind").arg(&project));
    let no_bindings = run_ok(aictx(&root).arg("bindings"));
    assert_eq!(
        String::from_utf8_lossy(&no_bindings.stdout).trim(),
        "No directory bindings configured."
    );

    for shell in ["bash", "zsh", "fish", "powershell"] {
        let environment = run_ok(aictx(&root).args(["env", "--shell", shell]));
        let environment = String::from_utf8_lossy(&environment.stdout);
        assert!(environment.contains("AICTX_CONTEXT"), "shell={shell}");
        assert!(environment.contains("CLAUDE_CONFIG_DIR"), "shell={shell}");
        assert!(environment.contains("CODEX_HOME"), "shell={shell}");
        assert!(!environment.contains("keyring://"), "shell={shell}");

        let init = run_ok(aictx(&root).args(["shell-init", shell]));
        let init = String::from_utf8_lossy(&init.stdout);
        assert!(init.contains("run claude"), "shell={shell}");
        assert!(init.contains("run codex"), "shell={shell}");
        assert!(init.contains("--root"), "shell={shell}");
    }

    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let completion = run_ok(aictx(&root).args(["completions", shell]));
        let completion = String::from_utf8_lossy(&completion.stdout);
        assert!(!completion.trim().is_empty(), "shell={shell}");
        assert!(completion.contains("aictx"), "shell={shell}");
    }

    run_ok(aictx(&root).args(["context", "remove", "personal"]));
    run_ok(aictx(&root).args(["profile", "remove", "claude:personal"]));
    run_ok(aictx(&root).args(["profile", "remove", "codex:personal"]));
    let no_contexts = run_ok(aictx(&root).args(["context", "list"]));
    assert_eq!(
        String::from_utf8_lossy(&no_contexts.stdout).trim(),
        "No contexts configured."
    );
    let no_profiles = run_ok(aictx(&root).args(["profile", "list"]));
    assert_eq!(
        String::from_utf8_lossy(&no_profiles.stdout).trim(),
        "No profiles configured."
    );
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
