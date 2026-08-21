use std::{path::Path, process::Command};

use ctxlane::Error;
use tempfile::TempDir;

fn ctxlane(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ctxlane"));
    command.arg("--root").arg(root);
    command
}

#[test]
fn exit_codes_remain_stable_by_error_category() {
    let cases = [
        (Error::NotInitialized, 2),
        (Error::ProfileNotFound("claude:missing".to_owned()), 10),
        (
            Error::CredentialUnavailable {
                profile: "claude:work".to_owned(),
                reason: "missing".to_owned(),
            },
            11,
        ),
        (Error::CredentialExpired("codex:work".to_owned()), 12),
        (Error::IdentityMismatch("wrong workspace".to_owned()), 13),
        (Error::InteractionRequired("terminal needed".to_owned()), 14),
        (Error::PolicyRefused("unsafe setting".to_owned()), 15),
        (Error::VendorIncompatible("missing CLI".to_owned()), 16),
        (Error::Interrupted(143), 143),
    ];

    for (error, expected) in cases {
        assert_eq!(error.exit_code(), expected, "wrong exit code for {error}");
    }
}

#[test]
fn recovery_hints_cover_actionable_error_categories() {
    let cases = [
        (Error::NotInitialized, "ctxlane init"),
        (
            Error::ProfileNotFound("claude:missing".to_owned()),
            "ctxlane profile list",
        ),
        (
            Error::ContextNotFound("missing".to_owned()),
            "ctxlane context list",
        ),
        (
            Error::CredentialUnavailable {
                profile: "codex:work".to_owned(),
                reason: "missing".to_owned(),
            },
            "ctxlane login codex:work",
        ),
        (
            Error::InteractionRequired("terminal needed".to_owned()),
            "interactive terminal",
        ),
        (
            Error::PolicyRefused("unsafe setting".to_owned()),
            "Correct the reported unsafe",
        ),
        (
            Error::VendorIncompatible("missing CLI".to_owned()),
            "ctxlane doctor",
        ),
        (
            Error::InvalidConfig("bad metadata".to_owned()),
            "local metadata",
        ),
        (
            Error::CredentialStore("keyring locked".to_owned()),
            "Unlock the OS keyring",
        ),
    ];

    for (error, expected) in cases {
        let hint = error
            .hint()
            .unwrap_or_else(|| panic!("missing hint for {error}"));
        assert!(
            hint.contains(expected),
            "hint for {error:?} did not contain {expected:?}: {hint}"
        );
    }
}

#[test]
fn credential_renderer_uses_only_valid_profile_ids_in_commands() {
    let valid = Error::CredentialUnavailable {
        profile: "codex:work".to_owned(),
        reason: "no credential is stored".to_owned(),
    }
    .render_for_terminal();
    assert!(valid.contains("credential unavailable for codex:work"));
    assert!(valid.contains("`ctxlane login codex:work`"));

    let opaque_handle = "codex-work-opaque-keyring-handle";
    let opaque = Error::CredentialUnavailable {
        profile: format!("keyring account {opaque_handle}"),
        reason: "no credential is stored".to_owned(),
    }
    .render_for_terminal();
    assert!(!opaque.contains(opaque_handle));
    assert!(opaque.contains("ctxlane: credential unavailable: no credential is stored"));
    assert!(opaque.contains("`ctxlane login <provider:name>`"));
}

#[test]
fn terminal_renderer_escapes_control_characters() {
    let rendered = Error::InvalidInput("bad\n\t\u{1b}[31mvalue".to_owned()).render_for_terminal();

    assert!(!rendered.contains('\r'));
    assert!(!rendered.contains('\t'));
    assert!(!rendered.contains('\u{1b}'));
    assert!(rendered.contains(r"bad\n\t\u{1b}[31mvalue"));
    assert_eq!(rendered.lines().count(), 2);
}

#[test]
fn main_prints_one_error_and_one_hint() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let output = ctxlane(&root)
        .args(["profile", "list"])
        .output()
        .unwrap_or_else(|error| panic!("run ctxlane: {error}"));

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)
        .unwrap_or_else(|error| panic!("stderr should be UTF-8: {error}"));
    assert_eq!(stderr.matches("ctxlane:").count(), 1);
    assert_eq!(stderr.matches("Hint:").count(), 1);
    assert!(stderr.contains("ctxlane: ctxlane is not initialized"));
    assert!(stderr.contains("Hint: Run `ctxlane init`"));
}

#[test]
fn main_preserves_missing_resource_exit_code_and_hint() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let init = ctxlane(&root)
        .arg("init")
        .output()
        .unwrap_or_else(|error| panic!("initialize ctxlane: {error}"));
    assert!(init.status.success());

    let output = ctxlane(&root)
        .args(["profile", "show", "claude:missing"])
        .output()
        .unwrap_or_else(|error| panic!("show missing profile: {error}"));
    assert_eq!(output.status.code(), Some(10));
    let stderr = String::from_utf8(output.stderr)
        .unwrap_or_else(|error| panic!("stderr should be UTF-8: {error}"));
    assert!(stderr.contains("profile not found: claude:missing"));
    assert!(stderr.contains("Hint: Run `ctxlane profile list`"));
}

#[test]
fn close_context_and_profile_typos_include_safe_suggestions() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    for arguments in [
        vec!["init"],
        vec!["profile", "add", "claude", "personal", "--auth", "api-key"],
        vec!["context", "add", "personal", "--claude", "claude:personal"],
    ] {
        let output = ctxlane(&root)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("prepare typo contract: {error}"));
        assert!(output.status.success());
    }

    let context = ctxlane(&root)
        .args(["use", "persnal"])
        .output()
        .unwrap_or_else(|error| panic!("run misspelled context: {error}"));
    assert_eq!(context.status.code(), Some(10));
    let context_error = String::from_utf8_lossy(&context.stderr);
    assert!(context_error.contains("did you mean `personal`?"));
    assert!(context_error.contains("ctxlane context list"));

    let profile = ctxlane(&root)
        .args(["profile", "show", "claude:persnal"])
        .output()
        .unwrap_or_else(|error| panic!("run misspelled profile: {error}"));
    assert_eq!(profile.status.code(), Some(10));
    let profile_error = String::from_utf8_lossy(&profile.stderr);
    assert!(profile_error.contains("did you mean `claude:personal`?"));
    assert!(profile_error.contains("ctxlane profile list"));
}

#[test]
fn every_public_help_surface_is_parseable_and_actionable() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let surfaces: &[&[&str]] = &[
        &["--help"],
        &["help"],
        &["init", "--help"],
        &["profile", "--help"],
        &["profile", "add", "--help"],
        &["profile", "list", "--help"],
        &["profile", "show", "--help"],
        &["profile", "remove", "--help"],
        &["context", "--help"],
        &["context", "add", "--help"],
        &["context", "list", "--help"],
        &["context", "show", "--help"],
        &["context", "remove", "--help"],
        &["use", "--help"],
        &["current", "--help"],
        &["login", "--help"],
        &["logout", "--help"],
        &["run", "--help"],
        &["status", "--help"],
        &["bind", "--help"],
        &["unbind", "--help"],
        &["bindings", "--help"],
        &["doctor", "--help"],
        &["credential", "--help"],
        &["credential", "check", "--help"],
        &["env", "--help"],
        &["shell-init", "--help"],
        &["completions", "--help"],
        &["migrate", "--help"],
        &["migrate", "aictx", "--help"],
        &["migrate", "recover", "--help"],
    ];

    for arguments in surfaces {
        let output = ctxlane(&root)
            .args(*arguments)
            .output()
            .unwrap_or_else(|error| panic!("run help surface {arguments:?}: {error}"));
        assert!(
            output.status.success(),
            "help surface {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "help surface {arguments:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Usage:") || arguments == &["help"],
            "help surface {arguments:?} had no usage"
        );
    }

    let init = ctxlane(&root)
        .args(["init", "--help"])
        .output()
        .unwrap_or_else(|error| panic!("run init help: {error}"));
    let init = String::from_utf8_lossy(&init.stdout);
    assert!(init.contains("--guided"));
    assert!(init.contains("claude setup-token"));
    assert!(init.contains("ctxlane run --profile claude:personal"));

    let login = ctxlane(&root)
        .args(["login", "--help"])
        .output()
        .unwrap_or_else(|error| panic!("run login help: {error}"));
    let login = String::from_utf8_lossy(&login.stdout);
    assert!(login.contains("claude:personal"));
    assert!(login.contains("Examples:"));

    let profile_add = ctxlane(&root)
        .args(["profile", "add", "--help"])
        .output()
        .unwrap_or_else(|error| panic!("run profile-add help: {error}"));
    let profile_add = String::from_utf8_lossy(&profile_add.stdout);
    assert!(profile_add.contains("Short local name"));
    assert!(profile_add.contains("Examples:"));

    let context_add = ctxlane(&root)
        .args(["context", "add", "--help"])
        .output()
        .unwrap_or_else(|error| panic!("run context-add help: {error}"));
    let context_add = String::from_utf8_lossy(&context_add.stdout);
    assert!(context_add.contains("Short local context name"));
    assert!(context_add.contains("Claude profile selected"));
    assert!(context_add.contains("Codex profile selected"));
    assert!(context_add.contains("ctxlane context add personal"));

    let bind = ctxlane(&root)
        .args(["bind", "--help"])
        .output()
        .unwrap_or_else(|error| panic!("run bind help: {error}"));
    let bind = String::from_utf8_lossy(&bind.stdout);
    assert!(bind.contains("Existing directory"));
    assert!(bind.contains("Configured context selected"));
    assert!(bind.contains("ctxlane bind . personal"));

    let doctor = ctxlane(&root)
        .args(["doctor", "--help"])
        .output()
        .unwrap_or_else(|error| panic!("run doctor help: {error}"));
    let doctor = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor.contains("Limit vendor binary"));
    assert!(doctor.contains("ctxlane doctor --provider claude"));
    assert!(doctor.contains("ctxlane doctor --provider codex --json"));

    let credential_check = ctxlane(&root)
        .args(["credential", "check", "--help"])
        .output()
        .unwrap_or_else(|error| panic!("run credential-check help: {error}"));
    let credential_check = String::from_utf8_lossy(&credential_check.stdout);
    assert!(credential_check.contains("ctxlane credential check claude:personal"));
    assert!(credential_check.contains("ctxlane credential check --all"));
}
