#![cfg(feature = "test-fixtures")]

use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

use aictx::{
    Error, Result,
    config::{AppPaths, MetadataStore, ensure_secure_directory},
    model::{
        BillingDomain, ClaudeAuth, CodexAuth, CodexCredentialStore, Config, Profile, ProfileId,
    },
    runner::{RunOptions, run_profile, vendor_version},
    secret::{SecretProvider, SecretRef},
};
use secrecy::SecretString;
use serde_json::Value;
use tempfile::TempDir;

const RECORD_FILE: &str = "native-vendor-record.json";
const STATIC_SECRET_CANARY: &str = "aictx-native-fixture-static-secret-v1";
const TRUSTED_PUSH_CHILD: &str = "AICTX_NATIVE_VENDOR_TRUSTED_PUSH_CHILD";

fn aictx(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aictx"));
    command.arg("--root").arg(root);
    command.env("CI", "true");
    command.env("GITHUB_EVENT_NAME", "push");
    command
}

fn rerun_as_trusted_push(test_name: &str) -> bool {
    if env::var_os(TRUSTED_PUSH_CHILD).is_some() {
        assert_eq!(
            env::var("GITHUB_EVENT_NAME").unwrap_or_default(),
            "push",
            "trusted-push test child must model a non-PR GitHub event"
        );
        return false;
    }

    let output = Command::new(
        env::current_exe().unwrap_or_else(|error| panic!("resolve current test binary: {error}")),
    )
    .arg("--exact")
    .arg(test_name)
    .arg("--nocapture")
    .env(TRUSTED_PUSH_CHILD, "1")
    .env("CI", "true")
    .env("GITHUB_EVENT_NAME", "push")
    .output()
    .unwrap_or_else(|error| panic!("run {test_name} under trusted push event: {error}"));
    assert!(
        output.status.success(),
        "trusted-push child for {test_name} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

fn run_ok(command: &mut Command) -> Output {
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

fn trusted_vendor(temporary: &TempDir, name: &str) -> PathBuf {
    let suffix = env::consts::EXE_SUFFIX;
    let destination = temporary.path().join(format!("{name}{suffix}"));
    fs::copy(env!("CARGO_BIN_EXE_aictx-test-vendor"), &destination)
        .unwrap_or_else(|error| panic!("copy native vendor fixture: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("make native vendor executable: {error}"));
    }
    destination
}

#[cfg(unix)]
fn shell_path(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "'\\''")
}

fn terminating_version_vendor(temporary: &TempDir) -> PathBuf {
    let target = trusted_vendor(temporary, "claude-version-large-target");

    #[cfg(unix)]
    if env::var_os("LLVM_PROFILE_FILE").is_some() {
        use std::os::unix::fs::PermissionsExt;

        // The output-limit contract intentionally kills this hostile fixture. Keep that child
        // out of cargo-llvm-cov's aggregate so a signal cannot leave a partial raw profile while
        // the calling integration test still records coverage for the production limit path.
        let launcher = temporary.path().join("claude-version-large");
        let ignored_profile = temporary.path().join("terminated-vendor-%p-%m.profraw");
        fs::write(
            &launcher,
            format!(
                "#!/bin/sh\nLLVM_PROFILE_FILE='{}' exec '{}' \"$@\"\n",
                shell_path(&ignored_profile),
                shell_path(&target)
            ),
        )
        .unwrap_or_else(|error| panic!("write coverage-isolated vendor launcher: {error}"));
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("make vendor launcher executable: {error}"));
        return launcher;
    }

    target
}

fn private_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("secure {}: {error}", path.display()));
    }
}

fn record(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read native vendor record {}: {error}", path.display()));
    assert!(!text.contains(STATIC_SECRET_CANARY));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("parse native vendor record: {error}"))
}

#[test]
fn native_version_preflight_rejects_exit_oversize_and_terminal_controls() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    for (name, expected) in [
        ("claude-version-fail", "exited with"),
        ("claude-version-large", "64 KiB output limit"),
        (
            "claude-version-control",
            "returned terminal control characters",
        ),
    ] {
        let executable = if name == "claude-version-large" {
            terminating_version_vendor(&temporary)
        } else {
            trusted_vendor(&temporary, name)
        };
        let mut config = Config::default();
        config.binaries.claude = executable;
        let error = match vendor_version(&config, aictx::model::Provider::Claude) {
            Ok(version) => panic!("{name} unexpectedly reported version {version}"),
            Err(error) => error,
        };
        assert_eq!(error.exit_code(), 16, "{name}: {error}");
        assert!(
            error.to_string().contains(expected),
            "unexpected {name} error: {error}"
        );
    }
}

#[test]
fn native_wif_cli_flow_preserves_arguments_selectors_and_exit_status() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let fake_claude = trusted_vendor(&temporary, "claude");
    let identity_token = temporary.path().join("identity.jwt");
    private_file(&identity_token, "synthetic-identity-token");

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
            identity_token
                .to_str()
                .unwrap_or_else(|| panic!("temporary token path should be UTF-8")),
        ]),
    );

    run_ok(aictx(&root).arg("--claude-bin").arg(&fake_claude).args([
        "--non-interactive",
        "run",
        "--profile",
        "claude:ci",
        "claude",
        "--",
        "native-wif",
        "two words",
        "semi;colon",
    ]));
    let state_dir = root.join("data/vendor-state/claude/ci");
    let captured = record(&state_dir.join(RECORD_FILE));
    assert_eq!(captured["provider"], "claude");
    assert_eq!(
        captured["args"],
        serde_json::json!(["native-wif", "two words", "semi;colon"])
    );
    assert_eq!(captured["anthropic_organization_id"], "org_test");
    assert_eq!(captured["anthropic_federation_rule_id"], "rule_test");
    assert_eq!(
        captured["anthropic_identity_token_file"],
        identity_token.to_string_lossy().as_ref()
    );
    assert_eq!(captured["has_anthropic_api_key"], false);
    assert_eq!(captured["has_openai_api_key"], false);

    let exited = aictx(&root)
        .arg("--claude-bin")
        .arg(&fake_claude)
        .args([
            "--non-interactive",
            "run",
            "--profile",
            "claude:ci",
            "claude",
            "--",
            "exit-23",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run exit propagation contract: {error}"));
    assert_eq!(exited.status.code(), Some(23));
}

#[test]
fn native_codex_oauth_flow_preflights_login_and_isolates_vendor_state() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let fake_codex = trusted_vendor(&temporary, "codex");
    run_ok(aictx(&root).arg("init"));
    run_ok(aictx(&root).args([
        "profile",
        "add",
        "codex",
        "work",
        "--auth",
        "chatgpt-oauth",
        "--workspace",
        "ws_test",
    ]));

    run_ok(aictx(&root).arg("--codex-bin").arg(&fake_codex).args([
        "--non-interactive",
        "run",
        "--profile",
        "codex:work",
        "--trusted-runner",
        "codex",
        "--",
        "native-oauth",
    ]));
    let state_dir = root.join("data/vendor-state/codex/work");
    let record_path = state_dir.join(RECORD_FILE);
    let captured = record(&record_path);
    assert_eq!(captured["provider"], "codex");
    assert_eq!(captured["args"], serde_json::json!(["native-oauth"]));
    assert_eq!(captured["has_openai_api_key"], false);
    let codex_config = fs::read_to_string(state_dir.join("config.toml"))
        .unwrap_or_else(|error| panic!("read generated Codex config: {error}"));
    assert!(codex_config.contains("forced_login_method"));
    assert!(codex_config.contains("forced_chatgpt_workspace_id"));
    assert!(codex_config.contains("shell_environment_policy"));

    let logout = run_ok(
        aictx(&root)
            .arg("--codex-bin")
            .arg(&fake_codex)
            .args(["logout", "codex:work"]),
    );
    let logout = String::from_utf8_lossy(&logout.stdout);
    assert!(logout.contains("Completed local authentication cleanup for codex:work"));
    assert!(logout.contains("does not confirm that local credentials existed"));
    assert!(!logout.contains("Logged out"));

    fs::write(state_dir.join("native-vendor-logout-fail"), b"fail")
        .unwrap_or_else(|error| panic!("write logout-failure marker: {error}"));
    let failed_logout = aictx(&root)
        .arg("--codex-bin")
        .arg(&fake_codex)
        .args(["logout", "codex:work"])
        .output()
        .unwrap_or_else(|error| panic!("run failing logout contract: {error}"));
    assert_eq!(failed_logout.status.code(), Some(37));
    assert!(failed_logout.stdout.is_empty());
    fs::remove_file(state_dir.join("native-vendor-logout-fail"))
        .unwrap_or_else(|error| panic!("remove logout-failure marker: {error}"));

    fs::remove_file(&record_path)
        .unwrap_or_else(|error| panic!("remove prior invocation record: {error}"));
    fs::write(
        state_dir.join("native-vendor-login-unavailable"),
        b"unavailable",
    )
    .unwrap_or_else(|error| panic!("write unavailable-login marker: {error}"));
    let doctor = aictx(&root)
        .arg("--codex-bin")
        .arg(&fake_codex)
        .args([
            "--non-interactive",
            "doctor",
            "--provider",
            "codex",
            "--json",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run unavailable OAuth doctor contract: {error}"));
    assert_eq!(doctor.status.code(), Some(1));
    let doctor: Value = serde_json::from_slice(&doctor.stdout)
        .unwrap_or_else(|error| panic!("parse doctor JSON: {error}"));
    assert_eq!(doctor["ok"], false);
    assert!(doctor["checks"].as_array().is_some_and(|checks| {
        checks
            .iter()
            .any(|check| check["level"] == "failure" && check["name"] == "codex:work credential")
    }));
    let unavailable = aictx(&root)
        .arg("--codex-bin")
        .arg(&fake_codex)
        .args([
            "--non-interactive",
            "run",
            "--profile",
            "codex:work",
            "--trusted-runner",
            "codex",
            "--",
            "must-not-run",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run unavailable OAuth contract: {error}"));
    assert_eq!(unavailable.status.code(), Some(11));
    assert!(!record_path.exists(), "main vendor command must not run");
}

#[test]
fn native_pull_request_policy_refuses_long_lived_profile_before_vendor_execution() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("aictx");
    let fake_codex = trusted_vendor(&temporary, "codex-pr-policy");
    run_ok(aictx(&root).arg("init"));
    run_ok(aictx(&root).args([
        "profile",
        "add",
        "codex",
        "work",
        "--auth",
        "chatgpt-oauth",
        "--workspace",
        "ws_test",
    ]));

    let record_path = root.join("data/vendor-state/codex/work").join(RECORD_FILE);
    for event in ["pull_request", "pull_request_target"] {
        let refused = aictx(&root)
            .arg("--codex-bin")
            .arg(&fake_codex)
            .env("GITHUB_EVENT_NAME", event)
            .args([
                "--non-interactive",
                "run",
                "--profile",
                "codex:work",
                "--trusted-runner",
                "codex",
                "--",
                "must-not-run",
            ])
            .output()
            .unwrap_or_else(|error| panic!("run {event} refusal contract: {error}"));
        assert_eq!(refused.status.code(), Some(15), "event {event}");
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains("credentials are refused in GitHub pull-request workflows"),
            "unexpected refusal for {event}: {}",
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(
            !record_path.exists(),
            "vendor process ran during {event} policy refusal"
        );
    }
}

struct StaticSecret {
    reads: AtomicUsize,
}

impl SecretProvider for StaticSecret {
    fn get(&self, reference: &SecretRef, _non_interactive: bool) -> Result<SecretString> {
        assert_eq!(reference.to_string(), "keyring://aictx/claude-api");
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(SecretString::from(STATIC_SECRET_CANARY))
    }
}

#[test]
fn native_static_claude_preflight_gates_the_main_process() {
    if rerun_as_trusted_push("native_static_claude_preflight_gates_the_main_process") {
        return;
    }

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("aictx"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize metadata: {error}"));
    let fake_claude = trusted_vendor(&temporary, "claude-static");
    let profile_id: ProfileId = "claude:api"
        .parse()
        .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
    let state_dir = paths.profile_state_dir(profile_id.provider(), profile_id.name());
    ensure_secure_directory(&state_dir)
        .unwrap_or_else(|error| panic!("create profile state: {error}"));
    let profile = Profile::Claude {
        billing_domain: BillingDomain::AnthropicApi,
        auth: ClaudeAuth::ApiKey,
        state_dir: state_dir.clone(),
        secret_ref: Some("keyring://aictx/claude-api".to_owned()),
        account_hint: None,
        expected_organization: None,
        wif: None,
    };
    store
        .update_config(|config| {
            config.binaries.claude = fake_claude.clone();
            config.profiles.insert(profile_id.clone(), profile.clone());
            Ok(())
        })
        .unwrap_or_else(|error| panic!("configure static profile: {error}"));
    let config: Config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"));
    let secrets = StaticSecret {
        reads: AtomicUsize::new(0),
    };
    let options = RunOptions {
        cwd: temporary.path().to_path_buf(),
        non_interactive: false,
        trusted_runner: false,
    };

    let code = run_profile(
        &config,
        &paths,
        &profile_id,
        &profile,
        &[OsString::from("native-static"), OsString::from("two words")],
        &secrets,
        &options,
    )
    .unwrap_or_else(|error| panic!("run native static contract: {error}"));
    assert_eq!(code, 0);
    assert_eq!(secrets.reads.load(Ordering::SeqCst), 1);
    let record_path = state_dir.join(RECORD_FILE);
    let captured = record(&record_path);
    assert_eq!(
        captured["args"],
        serde_json::json!(["native-static", "two words"])
    );
    assert_eq!(captured["has_anthropic_api_key"], true);
    assert_eq!(captured["has_claude_oauth_token"], false);
    assert_eq!(captured["has_openai_api_key"], false);
    fs::remove_file(&record_path)
        .unwrap_or_else(|error| panic!("remove successful record: {error}"));

    for (marker, expected) in [
        ("auth-wrong-method", 13),
        ("auth-invalid-json", 16),
        ("auth-oversized", 16),
        ("auth-exit-fail", 13),
    ] {
        let marker_path = state_dir.join(format!("native-vendor-{marker}"));
        fs::write(&marker_path, b"enabled")
            .unwrap_or_else(|error| panic!("write auth marker: {error}"));
        let result = run_profile(
            &config,
            &paths,
            &profile_id,
            &profile,
            &[OsString::from("must-not-run")],
            &secrets,
            &options,
        );
        let error = match result {
            Ok(code) => panic!("auth preflight unexpectedly returned exit {code}"),
            Err(error) => error,
        };
        assert_eq!(error.exit_code(), expected, "marker {marker}: {error}");
        assert!(
            !record_path.exists(),
            "marker {marker} reached main process"
        );
        fs::remove_file(marker_path).unwrap_or_else(|error| panic!("remove auth marker: {error}"));
    }
    assert_eq!(secrets.reads.load(Ordering::SeqCst), 5);
    assert!(matches!(
        run_profile(
            &config,
            &paths,
            &"claude:missing"
                .parse()
                .unwrap_or_else(|error| panic!("valid missing ID: {error}")),
            &profile,
            &[],
            &secrets,
            &options,
        ),
        Err(Error::ProfileNotFound(_))
    ));
}

struct CodexStaticSecret {
    reads: AtomicUsize,
}

impl SecretProvider for CodexStaticSecret {
    fn get(&self, reference: &SecretRef, _non_interactive: bool) -> Result<SecretString> {
        assert_eq!(reference.to_string(), "keyring://aictx/codex-api");
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(SecretString::from(STATIC_SECRET_CANARY))
    }
}

#[test]
fn native_codex_api_key_uses_stdin_login_and_keeps_secret_out_of_main_child() {
    if rerun_as_trusted_push(
        "native_codex_api_key_uses_stdin_login_and_keeps_secret_out_of_main_child",
    ) {
        return;
    }

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("aictx"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize metadata: {error}"));
    let fake_codex = trusted_vendor(&temporary, "codex-static");
    let profile_id: ProfileId = "codex:api"
        .parse()
        .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
    let state_dir = paths.profile_state_dir(profile_id.provider(), profile_id.name());
    ensure_secure_directory(&state_dir)
        .unwrap_or_else(|error| panic!("create profile state: {error}"));
    let profile = Profile::Codex {
        billing_domain: BillingDomain::OpenaiApi,
        auth: CodexAuth::ApiKey,
        state_dir: state_dir.clone(),
        secret_ref: Some("keyring://aictx/codex-api".to_owned()),
        account_hint: None,
        expected_workspace_id: None,
        credential_store: CodexCredentialStore::File,
        trusted_runners_only: false,
    };
    store
        .update_config(|config| {
            config.binaries.codex = fake_codex.clone();
            config.profiles.insert(profile_id.clone(), profile.clone());
            Ok(())
        })
        .unwrap_or_else(|error| panic!("configure static profile: {error}"));
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"));
    let secrets = CodexStaticSecret {
        reads: AtomicUsize::new(0),
    };
    let options = RunOptions {
        cwd: temporary.path().to_path_buf(),
        non_interactive: false,
        trusted_runner: false,
    };

    let code = run_profile(
        &config,
        &paths,
        &profile_id,
        &profile,
        &[OsString::from("native-codex-static")],
        &secrets,
        &options,
    )
    .unwrap_or_else(|error| panic!("run native Codex static contract: {error}"));
    assert_eq!(code, 0);
    assert_eq!(secrets.reads.load(Ordering::SeqCst), 1);
    assert!(
        state_dir
            .join("native-vendor-static-login-present")
            .exists()
    );
    let record_path = state_dir.join(RECORD_FILE);
    let captured = record(&record_path);
    assert_eq!(captured["args"], serde_json::json!(["native-codex-static"]));
    assert_eq!(captured["has_openai_api_key"], false);
    assert_eq!(captured["has_anthropic_api_key"], false);

    fs::remove_file(&record_path)
        .unwrap_or_else(|error| panic!("remove successful record: {error}"));
    fs::write(state_dir.join("native-vendor-static-login-fail"), b"fail")
        .unwrap_or_else(|error| panic!("write static-login failure marker: {error}"));
    let code = run_profile(
        &config,
        &paths,
        &profile_id,
        &profile,
        &[OsString::from("must-not-run")],
        &secrets,
        &options,
    )
    .unwrap_or_else(|error| panic!("run failed-login contract: {error}"));
    assert_eq!(code, 31);
    assert_eq!(secrets.reads.load(Ordering::SeqCst), 2);
    assert!(
        !record_path.exists(),
        "main child ran after failed stdin login"
    );
}
