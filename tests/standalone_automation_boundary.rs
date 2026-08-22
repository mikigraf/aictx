use std::{fs, path::Path, process::Command};

use tempfile::TempDir;

const STORE_SENTINEL: &[u8] = b"not-a-sqlite-database\nstandalone-boundary-canary\n";
const STORE_SENTINEL_CANARY: &str = "standalone-boundary-canary";

fn ctxlane(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ctxlane"));
    command.arg("--root").arg(root);
    command
}

fn run_ok(command: &mut Command) -> std::process::Output {
    let description = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("run ctxlane: {error}"));
    assert!(
        output.status.success(),
        "command failed: {description}\nstatus: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn install_invalid_store_sentinel(root: &Path) -> std::path::PathBuf {
    let automation = root.join("state/automation");
    fs::create_dir(&automation)
        .unwrap_or_else(|error| panic!("create automation sentinel directory: {error}"));
    let database = automation.join("lease-store.sqlite3");
    fs::write(&database, STORE_SENTINEL)
        .unwrap_or_else(|error| panic!("write automation store sentinel: {error}"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&automation, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("secure automation sentinel directory: {error}"));
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("secure automation store sentinel: {error}"));
    }

    database
}

#[test]
fn ordinary_cli_lifecycle_ignores_an_invalid_automation_store_sentinel() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    run_ok(ctxlane(&root).arg("init"));
    let database = install_invalid_store_sentinel(&root);

    run_ok(ctxlane(&root).args([
        "profile",
        "add",
        "codex",
        "personal",
        "--auth",
        "subscription",
    ]));
    run_ok(ctxlane(&root).args(["context", "add", "personal", "--codex", "codex:personal"]));
    run_ok(ctxlane(&root).args(["use", "personal", "--yes"]));

    for arguments in [
        &["profile", "list"][..],
        &["context", "list"][..],
        &["status"][..],
    ] {
        let output = run_ok(ctxlane(&root).args(arguments));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(STORE_SENTINEL_CANARY));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(STORE_SENTINEL_CANARY));
    }

    let doctor = ctxlane(&root)
        .args(["doctor", "--json"])
        .output()
        .unwrap_or_else(|error| panic!("run doctor: {error}"));
    assert_eq!(
        doctor.status.code(),
        Some(1),
        "doctor unexpectedly changed status"
    );
    assert!(doctor.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&doctor.stdout).contains(STORE_SENTINEL_CANARY));

    assert_eq!(
        fs::read(&database).unwrap_or_else(|error| panic!("read store sentinel: {error}")),
        STORE_SENTINEL
    );
    for suffix in [
        "service.lock",
        "lease-store.sqlite3-journal",
        "lease-store.sqlite3-wal",
        "lease-store.sqlite3-shm",
    ] {
        assert!(
            !database.with_file_name(suffix).exists(),
            "ordinary CLI created automation artifact {suffix}"
        );
    }
}
