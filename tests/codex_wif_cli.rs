use std::{
    fs::{self, OpenOptions},
    path::Path,
    process::{Command, Output},
};

use ctxlane::{
    config::{AppPaths, MetadataStore},
    model::{CodexAuth, CodexCredentialStore, Profile, ProfileId},
};
use tempfile::TempDir;

fn ctxlane(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ctxlane"));
    command.arg("--root").arg(root);
    command
}

fn run(command: &mut Command) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("run {command:?}: {error}"))
}

fn run_ok(command: &mut Command) -> Output {
    let output = run(command);
    assert!(
        output.status.success(),
        "command failed ({:?}):\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn valid_wif_args<'a>(token: &'a Path, name: &'a str) -> Vec<std::ffi::OsString> {
    [
        "profile",
        "add",
        "codex",
        name,
        "--auth",
        "wif",
        "--federation-rule-id",
        "idpm_CREDENTIAL_CANARY_RULE",
        "--identity-token-file",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .chain(std::iter::once(token.as_os_str().to_owned()))
    .chain(
        [
            "--workspace",
            "chatgpt-workspace:CREDENTIAL_CANARY_WORKSPACE",
            "--principal",
            "service-account:CREDENTIAL_CANARY_PRINCIPAL",
            "--environment",
            "local-development",
            "--environment",
            "prod+gpu",
            "--workload-label",
            "pool=CREDENTIAL_CANARY_LABEL",
            "--workload-instance-id",
            "controller-01",
            "--workload-display-name",
            "Production-worker:01/@primary",
            "--workload-context-label",
            "pool=trusted",
            "--minimum-codex-version",
            "0.148.0",
        ]
        .into_iter()
        .map(std::ffi::OsString::from),
    )
    .collect()
}

fn init(root: &Path) {
    run_ok(ctxlane(root).arg("init"));
}

fn add_valid(root: &Path, token: &Path, name: &str) {
    run_ok(ctxlane(root).args(valid_wif_args(token, name)));
}

#[test]
fn codex_wif_enrollment_persists_a_closed_redacted_profile() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let token = temporary
        .path()
        .join("identity-source")
        .join("identity.jwt");
    init(&root);
    add_valid(&root, &token, "factory");

    let paths = AppPaths::for_root(&root);
    let config = MetadataStore::new(paths)
        .load_config()
        .unwrap_or_else(|error| panic!("load profile: {error}"));
    let id: ProfileId = "codex:factory"
        .parse()
        .unwrap_or_else(|error| panic!("profile ID: {error}"));
    let Profile::Codex {
        auth,
        expected_workspace_id,
        credential_store,
        trusted_runners_only,
        wif: Some(wif),
        ..
    } = config
        .profiles
        .get(&id)
        .unwrap_or_else(|| panic!("persisted WIF profile"))
    else {
        panic!("Codex WIF shape");
    };
    assert_eq!(*auth, CodexAuth::Wif);
    assert!(expected_workspace_id.is_none());
    assert_eq!(*credential_store, CodexCredentialStore::File);
    assert!(!trusted_runners_only);
    assert_eq!(wif.identity_token_file, token);
    assert_eq!(wif.allowed_environments.len(), 2);
    assert_eq!(wif.allowed_workload_labels.len(), 1);
    assert!(wif.workload_identity_context.is_some());

    let shown = run_ok(ctxlane(&root).args(["profile", "show", "codex:factory"]));
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(shown.contains("native Codex WIF is not qualified"));
    for private in [
        token.display().to_string(),
        "idpm_CREDENTIAL_CANARY_RULE".to_owned(),
        "chatgpt-workspace:CREDENTIAL_CANARY_WORKSPACE".to_owned(),
        "service-account:CREDENTIAL_CANARY_PRINCIPAL".to_owned(),
        "CREDENTIAL_CANARY_LABEL".to_owned(),
        "controller-01".to_owned(),
    ] {
        assert!(!shown.contains(&private), "profile show leaked {private}");
    }

    let credential = run(ctxlane(&root).args(["credential", "check", "codex:factory"]));
    assert_eq!(credential.status.code(), Some(11));
    assert!(String::from_utf8_lossy(&credential.stdout).contains("unavailable"));

    let doctor = run(ctxlane(&root).args(["doctor", "--provider", "codex", "--json"]));
    assert_eq!(doctor.status.code(), Some(1));
    let doctor = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor.contains("native WIF runtime"));
    assert!(doctor.contains("qualification is unavailable"));
    assert!(!doctor.contains(&token.display().to_string()));
    assert!(!doctor.contains("CREDENTIAL_CANARY"));
}

#[test]
fn codex_wif_enrollment_rejects_incomplete_ambiguous_and_repository_bound_input() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let token = temporary
        .path()
        .join("identity-source")
        .join("identity.jwt");
    init(&root);

    for (index, missing_flag) in [
        "--federation-rule-id",
        "--identity-token-file",
        "--workspace",
        "--principal",
        "--environment",
        "--minimum-codex-version",
    ]
    .into_iter()
    .enumerate()
    {
        let mut args = valid_wif_args(&token, &format!("missing{index}"));
        let mut removed = false;
        while let Some(position) = args.iter().position(|value| value == missing_flag) {
            args.remove(position);
            args.remove(position);
            removed = true;
        }
        assert!(removed, "fixture flag {missing_flag}");
        let output = run(ctxlane(&root).args(args));
        assert!(!output.status.success(), "accepted missing {missing_flag}");
    }

    for (name, extra) in [
        (
            "duplicate",
            vec![
                "--workload-label",
                "pool=one",
                "--workload-label",
                "pool=two",
            ],
        ),
        ("badlabel", vec!["--workload-label", "pool/path=value"]),
        ("badenv", vec!["--environment", "prod/eu"]),
        (
            "claudeflag",
            vec!["--organization-id", "org_wrong_provider"],
        ),
    ] {
        let mut args = valid_wif_args(&token, name);
        args.extend(extra.into_iter().map(std::ffi::OsString::from));
        let output = run(ctxlane(&root).args(args));
        assert!(!output.status.success(), "accepted invalid {name} input");
    }

    let project = temporary.path().join("project");
    fs::create_dir_all(project.join(".git"))
        .unwrap_or_else(|error| panic!("create repository marker: {error}"));
    let repository_token = project.join("secrets").join("identity.jwt");
    let output = run(ctxlane(&root).args(valid_wif_args(&repository_token, "repository")));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside Git worktrees"));

    let config = MetadataStore::new(AppPaths::for_root(&root))
        .load_config()
        .unwrap_or_else(|error| panic!("load unchanged config: {error}"));
    assert!(config.profiles.is_empty());
}

#[test]
fn unqualified_codex_wif_public_operations_refuse_before_any_vendor_access() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let token_parent = temporary.path().join("identity-source");
    let token = token_parent.join("identity.jwt");
    init(&root);
    add_valid(&root, &token, "factory");
    run_ok(ctxlane(&root).args(["context", "add", "factory", "--codex", "codex:factory"]));

    let config = MetadataStore::new(AppPaths::for_root(&root))
        .load_config()
        .unwrap_or_else(|error| panic!("load profile: {error}"));
    let id: ProfileId = "codex:factory"
        .parse()
        .unwrap_or_else(|error| panic!("profile ID: {error}"));
    let state_dir = config
        .profiles
        .get(&id)
        .unwrap_or_else(|| panic!("profile"))
        .state_dir()
        .to_path_buf();
    fs::remove_dir_all(&state_dir)
        .unwrap_or_else(|error| panic!("remove prepared vendor state: {error}"));
    fs::create_dir_all(token_parent.join(".git"))
        .unwrap_or_else(|error| panic!("make token location hostile: {error}"));
    let missing_binary = temporary.path().join("missing-codex");

    let operations: Vec<(Vec<std::ffi::OsString>, i32)> = vec![
        (
            vec![
                "--codex-bin".into(),
                missing_binary.as_os_str().to_owned(),
                "run".into(),
                "--profile".into(),
                "codex:factory".into(),
                "codex".into(),
                "--".into(),
                "exec".into(),
                "hello".into(),
            ],
            16,
        ),
        (
            vec![
                "--codex-bin".into(),
                missing_binary.as_os_str().to_owned(),
                "login".into(),
                "codex:factory".into(),
            ],
            16,
        ),
        (
            vec![
                "--codex-bin".into(),
                missing_binary.as_os_str().to_owned(),
                "logout".into(),
                "codex:factory".into(),
            ],
            15,
        ),
        (
            vec![
                "env".into(),
                "--context".into(),
                "factory".into(),
                "--shell".into(),
                "bash".into(),
            ],
            16,
        ),
    ];
    for (arguments, expected_code) in operations {
        let output = run(ctxlane(&root).args(arguments));
        assert_eq!(
            output.status.code(),
            Some(expected_code),
            "unexpected refusal:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("WIF"));
        assert!(!stderr.contains(&token.display().to_string()));
        assert!(!state_dir.exists(), "operation recreated vendor state");
        assert!(
            !missing_binary.exists(),
            "operation touched fake vendor binary"
        );
    }
}

#[test]
fn login_and_logout_honor_the_legacy_exclusive_alias_fence() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let token = temporary
        .path()
        .join("identity-source")
        .join("identity.jwt");
    init(&root);
    add_valid(&root, &token, "factory");
    let paths = AppPaths::for_root(&root);
    let id: ProfileId = "codex:factory"
        .parse()
        .unwrap_or_else(|error| panic!("profile ID: {error}"));
    let alias = OpenOptions::new()
        .read(true)
        .write(true)
        .open(paths.profile_lock(id.provider(), id.name()))
        .unwrap_or_else(|error| panic!("open legacy alias lock: {error}"));
    alias
        .lock_shared()
        .unwrap_or_else(|error| panic!("hold legacy runner lock: {error}"));

    for arguments in [["login", "codex:factory"], ["logout", "codex:factory"]] {
        let output = run(ctxlane(&root).args(arguments));
        assert_eq!(output.status.code(), Some(15));
        assert!(String::from_utf8_lossy(&output.stderr).contains("profile is busy"));
    }
}
