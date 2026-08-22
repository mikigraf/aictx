use std::{fs, path::Path, process::Command};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use ctxlane::{
    config::{AppPaths, MetadataStore},
    model::ProfileId,
};
use tempfile::TempDir;

const STORE_SENTINEL: &[u8] = b"not-a-sqlite-database\nstandalone-boundary-canary\n";
const STORE_SENTINEL_CANARY: &str = "standalone-boundary-canary";
const AUTHORITY_SENTINEL: &[u8] = b"not-valid-toml\nstandalone-authority-boundary-canary\n";
const AUTHORITY_SENTINEL_CANARY: &str = "standalone-authority-boundary-canary";

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

fn install_invalid_authority_sentinel(root: &Path) -> std::path::PathBuf {
    let authority = root.join("config/automation-authority.toml");
    fs::write(&authority, AUTHORITY_SENTINEL)
        .unwrap_or_else(|error| panic!("write automation authority sentinel: {error}"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&authority, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("secure automation authority sentinel: {error}"));
    }

    authority
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_crash_fence(root: &Path, raw_profile: &str) -> std::path::PathBuf {
    let paths = AppPaths::for_root(root);
    let store = MetadataStore::new(paths);
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config for crash fence: {error}"));
    let profile_id = raw_profile
        .parse::<ProfileId>()
        .unwrap_or_else(|error| panic!("profile ID: {error}"));
    let profile = config
        .profiles
        .get(&profile_id)
        .unwrap_or_else(|| panic!("profile exists"));
    let marker = root.join(format!(
        "state/profile-locks/{}-automation.fence",
        profile.profile_uid()
    ));
    let bytes = format!(
        "format = \"ctxlane-profile-automation-fence\"\nversion = 1\ninstallation_uid = \"{}\"\nprofile_ref = \"{}\"\nprofile_uid = \"{}\"\nfence_id = \"fence_00000000000000000000000000000000\"\n",
        config.installation_uid,
        profile_id,
        profile.profile_uid(),
    );
    fs::write(&marker, bytes).unwrap_or_else(|error| panic!("write crash fence: {error}"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("secure crash fence: {error}"));
    }

    marker
}

#[test]
fn ordinary_cli_lifecycle_ignores_invalid_automation_sentinels() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    run_ok(ctxlane(&root).arg("init"));
    let database = install_invalid_store_sentinel(&root);
    let authority = install_invalid_authority_sentinel(&root);

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
        assert!(!String::from_utf8_lossy(&output.stdout).contains(AUTHORITY_SENTINEL_CANARY));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(AUTHORITY_SENTINEL_CANARY));
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
    assert!(!String::from_utf8_lossy(&doctor.stdout).contains(AUTHORITY_SENTINEL_CANARY));

    assert_eq!(
        fs::read(&database).unwrap_or_else(|error| panic!("read store sentinel: {error}")),
        STORE_SENTINEL
    );
    assert_eq!(
        fs::read(&authority).unwrap_or_else(|error| panic!("read authority sentinel: {error}")),
        AUTHORITY_SENTINEL
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn crash_fence_blocks_profile_resource_use_without_opening_the_lease_store() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    run_ok(ctxlane(&root).arg("init"));
    run_ok(ctxlane(&root).args([
        "profile",
        "add",
        "codex",
        "personal",
        "--auth",
        "subscription",
    ]));
    run_ok(ctxlane(&root).args([
        "profile",
        "add",
        "codex",
        "unrelated",
        "--auth",
        "subscription",
    ]));
    run_ok(ctxlane(&root).args(["context", "add", "personal", "--codex", "codex:personal"]));
    run_ok(ctxlane(&root).args(["context", "add", "unrelated", "--codex", "codex:unrelated"]));
    run_ok(ctxlane(&root).args(["use", "personal", "--yes"]));
    let database = install_invalid_store_sentinel(&root);
    let marker = install_crash_fence(&root, "codex:personal");
    let marker_before = fs::read(&marker).unwrap_or_else(|error| panic!("read marker: {error}"));

    for arguments in [
        &[
            "--non-interactive",
            "run",
            "--profile",
            "codex:personal",
            "codex",
            "--",
            "exec",
        ][..],
        &["--non-interactive", "login", "codex:personal"][..],
        &["--non-interactive", "logout", "codex:personal"][..],
        &["--non-interactive", "credential", "check", "codex:personal"][..],
        &["env", "--context", "personal", "--shell", "bash"][..],
        &["profile", "remove", "codex:personal"][..],
    ] {
        let output = ctxlane(&root)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("run fenced command: {error}"));
        assert_eq!(
            output.status.code(),
            Some(15),
            "unexpected fenced command result for {arguments:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("profile use is refused while automation lease state is unresolved")
        );
    }

    for arguments in [
        &["profile", "list"][..],
        &["profile", "show", "codex:personal"][..],
        &["profile", "show", "codex:unrelated"][..],
        &["status"][..],
        &["use", "personal", "--yes"][..],
        &["env", "--context", "unrelated", "--shell", "bash"][..],
    ] {
        run_ok(ctxlane(&root).args(arguments));
    }
    run_ok(ctxlane(&root).args([
        "profile",
        "add",
        "codex",
        "still-unrelated",
        "--auth",
        "subscription",
    ]));

    let doctor = ctxlane(&root)
        .args(["doctor", "--provider", "codex", "--json"])
        .output()
        .unwrap_or_else(|error| panic!("run doctor: {error}"));
    assert_eq!(doctor.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&doctor.stdout).contains("automation lease state is unresolved")
    );

    assert_eq!(
        fs::read(&marker).unwrap_or_else(|error| panic!("re-read marker: {error}")),
        marker_before
    );
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
        assert!(!database.with_file_name(suffix).exists());
    }
}
