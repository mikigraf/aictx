use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use ctxlane::{
    config::{AppPaths, MetadataStore, ensure_secure_directory},
    migration::migration_journal_path,
    model::{Name, ProfileId, Provider},
};
use serde::Serialize;
use tempfile::TempDir;

fn ctxlane(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ctxlane"));
    command.arg("--root").arg(root);
    command
}

fn run_success(command: &mut Command) -> Output {
    let description = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("run {description}: {error}"));
    assert!(
        output.status.success(),
        "command failed: {description}\nstatus: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct Fixture {
    _temporary: TempDir,
    legacy_root: PathBuf,
    target_root: PathBuf,
    legacy: AppPaths,
    target: AppPaths,
    source_config: Vec<u8>,
    source_state: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let legacy_root = temporary.path().join("aictx-store");
        let target_root = temporary.path().join("ctxlane-store");
        let legacy = AppPaths::for_root(&legacy_root);
        let target = AppPaths::for_root(&target_root);

        run_success(ctxlane(&legacy_root).arg("init"));
        run_success(ctxlane(&legacy_root).args([
            "profile",
            "add",
            "claude",
            "personal",
            "--auth",
            "subscription",
            "--secret-ref",
            "keyring://aictx/preserved-handle",
        ]));
        run_success(ctxlane(&legacy_root).args([
            "profile",
            "add",
            "codex",
            "work",
            "--auth",
            "subscription-token",
        ]));
        run_success(ctxlane(&legacy_root).args([
            "context",
            "add",
            "mixed",
            "--claude",
            "claude:personal",
            "--codex",
            "codex:work",
        ]));
        run_success(ctxlane(&legacy_root).args(["use", "mixed", "--yes"]));

        let personal =
            Name::parse("personal").unwrap_or_else(|error| panic!("parse personal name: {error}"));
        write_private(
            &legacy
                .profile_state_dir(Provider::Claude, &personal)
                .join("session.json"),
            b"claude-session\n",
        );
        let work = Name::parse("work").unwrap_or_else(|error| panic!("parse work name: {error}"));
        let codex_state = legacy.profile_state_dir(Provider::Codex, &work);
        write_private(&codex_state.join("auth.json"), b"codex-session\n");
        write_private(&codex_state.join("active.lock"), b"live-lock\n");

        let source_config = fs::read(&legacy.config_file)
            .unwrap_or_else(|error| panic!("snapshot source config: {error}"));
        let source_state = fs::read(&legacy.state_file)
            .unwrap_or_else(|error| panic!("snapshot source state: {error}"));

        Self {
            _temporary: temporary,
            legacy_root,
            target_root,
            legacy,
            target,
            source_config,
            source_state,
        }
    }

    fn migration_command(&self) -> Command {
        let mut command = ctxlane(&self.target_root);
        command
            .args(["migrate", "aictx", "--from-root"])
            .arg(&self.legacy_root);
        command
    }

    fn recovery_command(&self) -> Command {
        let mut command = ctxlane(&self.target_root);
        command
            .args(["migrate", "recover", "--from-root"])
            .arg(&self.legacy_root);
        command
    }

    fn assert_source_unchanged(&self) {
        assert_eq!(
            fs::read(&self.legacy.config_file)
                .unwrap_or_else(|error| panic!("read source config: {error}")),
            self.source_config
        );
        assert_eq!(
            fs::read(&self.legacy.state_file)
                .unwrap_or_else(|error| panic!("read source state: {error}")),
            self.source_state
        );
        assert_eq!(
            fs::read(
                self.legacy
                    .data_dir
                    .join("vendor-state/codex/work/active.lock")
            )
            .unwrap_or_else(|error| panic!("read source lock: {error}")),
            b"live-lock\n"
        );
    }
}

#[test]
fn dry_run_reports_safe_plan_without_creating_target_state() {
    let fixture = Fixture::new();
    let output = run_success(fixture.migration_command().arg("--dry-run"));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("dry run; no files were changed"));
    assert!(stdout.contains(&fixture.legacy.config_dir.display().to_string()));
    assert!(stdout.contains(&fixture.target.config_dir.display().to_string()));
    assert!(stdout.contains("profiles: 2"));
    assert!(stdout.contains("vendor files: 2"));
    assert!(stdout.contains("vendor directories: 4"));
    assert!(stdout.contains("skipped lock entries: 1"));
    assert!(!stdout.contains("keyring://"));
    assert!(!fixture.target_root.exists());
    assert!(!migration_journal_path(&fixture.target).exists());
    fixture.assert_source_unchanged();
}

#[test]
fn migration_command_copies_state_rewrites_paths_and_preserves_secret_references() {
    let fixture = Fixture::new();
    let source_store = MetadataStore::new(fixture.legacy.clone());
    let source_config = source_store
        .load_config()
        .unwrap_or_else(|error| panic!("load source config: {error}"));
    let claude_id: ProfileId = "claude:personal"
        .parse()
        .unwrap_or_else(|error| panic!("parse Claude profile: {error}"));
    let source_secret_ref = source_config
        .profiles
        .get(&claude_id)
        .and_then(|profile| profile.secret_ref())
        .unwrap_or_else(|| panic!("source secret reference"))
        .to_owned();

    let output = run_success(&mut fixture.migration_command());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Copied the aictx store into the ctxlane layout"));
    assert!(stdout.contains("The old aictx store remains available"));
    assert!(stdout.contains("metadata, vendor state, and credentials were not changed"));
    assert!(!stdout.contains("keyring://"));

    let target_store = MetadataStore::new(fixture.target.clone());
    let (target_config, target_state) = target_store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load migrated metadata: {error}"));
    let target_claude = target_config
        .profiles
        .get(&claude_id)
        .unwrap_or_else(|| panic!("migrated Claude profile"));
    assert_eq!(target_claude.secret_ref(), Some(source_secret_ref.as_str()));
    assert_eq!(
        target_claude.state_dir(),
        fixture.target.data_dir.join("vendor-state/claude/personal")
    );
    assert_eq!(
        target_state
            .current_context
            .as_ref()
            .map(ToString::to_string),
        Some("mixed".to_owned())
    );
    assert_eq!(
        fs::read(
            fixture
                .target
                .data_dir
                .join("vendor-state/claude/personal/session.json")
        )
        .unwrap_or_else(|error| panic!("read migrated vendor state: {error}")),
        b"claude-session\n"
    );
    assert!(
        !fixture
            .target
            .data_dir
            .join("vendor-state/codex/work/active.lock")
            .exists()
    );
    assert!(!migration_journal_path(&fixture.target).exists());
    fixture.assert_source_unchanged();
}

#[test]
fn migration_command_refuses_target_collisions_and_missing_source_root() {
    let collision = Fixture::new();
    ensure_secure_directory(&collision.target.config_dir)
        .unwrap_or_else(|error| panic!("create target collision: {error}"));
    let output = collision
        .migration_command()
        .output()
        .unwrap_or_else(|error| panic!("run colliding migration: {error}"));
    assert_eq!(output.status.code(), Some(15));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("migration never overwrites a target")
    );
    collision.assert_source_unchanged();

    let missing_source = Fixture::new();
    let output = ctxlane(&missing_source.target_root)
        .args(["migrate", "aictx", "--dry-run"])
        .output()
        .unwrap_or_else(|error| panic!("run migration without source root: {error}"));
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`--from-root <ABSOLUTE_PATH>` is required"));
    assert!(!missing_source.target_root.exists());
    missing_source.assert_source_unchanged();

    let invalid_source = Fixture::new();
    let output = ctxlane(&invalid_source.target_root)
        .args([
            "migrate",
            "aictx",
            "--from-root",
            "relative/source",
            "--dry-run",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run migration with relative source root: {error}"));
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`--from-root` must be absolute: relative/source"));
    assert!(!invalid_source.target_root.exists());
    invalid_source.assert_source_unchanged();
}

#[test]
fn recovery_command_rolls_back_owned_partial_state_and_reports_noop_truthfully() {
    let fixture = Fixture::new();
    let transaction_id = "deadbeef-1234";
    let mut targets = [
        fixture.target.config_dir.clone(),
        fixture.target.data_dir.clone(),
        fixture.target.state_dir.clone(),
    ];
    targets.sort();
    let anchors = targets
        .iter()
        .enumerate()
        .map(|(index, target)| RecoveryAnchor {
            target: target.clone(),
            stage: target.with_file_name(format!(
                ".{}.ctxlane-migration-stage-{transaction_id}-{index}",
                target
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or("ctxlane")
            )),
            committed: index == 1,
        })
        .collect::<Vec<_>>();

    for (index, anchor) in anchors.iter().enumerate() {
        let owned = if index == 1 {
            &anchor.target
        } else {
            &anchor.stage
        };
        ensure_secure_directory(owned)
            .unwrap_or_else(|error| panic!("create recovery artifact: {error}"));
        write_private(
            &owned.join(".ctxlane-migration-owner"),
            format!("{transaction_id}\n").as_bytes(),
        );
        write_private(&owned.join("partial-data"), b"partial\n");
    }

    let journal = RecoveryJournal {
        version: 1,
        transaction_id,
        legacy: RecoveryPaths::from(&fixture.legacy),
        target: RecoveryPaths::from(&fixture.target),
        phase: "committing",
        anchors: anchors.clone(),
    };
    let journal_text = toml::to_string_pretty(&journal)
        .unwrap_or_else(|error| panic!("serialize recovery journal: {error}"));
    write_private(
        &migration_journal_path(&fixture.target),
        format!("{journal_text}\n").as_bytes(),
    );

    let output = run_success(&mut fixture.recovery_command());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Rolled back the incomplete"));
    assert!(stdout.contains("Archived committed partial target directories"));
    assert!(stdout.contains("Review these private archives before deleting them"));
    assert!(stdout.contains("old aictx store remains available"));
    assert!(stdout.contains("metadata, vendor state, and credentials were not changed"));
    assert!(!migration_journal_path(&fixture.target).exists());
    for anchor in &anchors {
        assert!(!anchor.target.exists());
        assert!(!anchor.stage.exists());
    }
    let archives = recovery_archives(&fixture.target_root, transaction_id);
    assert_eq!(archives.len(), 1);
    assert_eq!(
        fs::read(archives[0].join("partial-data"))
            .unwrap_or_else(|error| panic!("read archived partial target: {error}")),
        b"partial\n"
    );
    fixture.assert_source_unchanged();

    let output = run_success(&mut fixture.recovery_command());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("No incomplete aictx-to-ctxlane migration was found")
    );
}

fn recovery_archives(root: &Path, transaction_id: &str) -> Vec<PathBuf> {
    let mut archives = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("list recovery archives: {error}"))
        .filter_map(|entry| {
            let entry =
                entry.unwrap_or_else(|error| panic!("read recovery archive entry: {error}"));
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy();
            (path.is_dir()
                && name.contains(".ctxlane-migration-rollback-")
                && name.contains(transaction_id))
            .then_some(path)
        })
        .collect::<Vec<_>>();
    archives.sort();
    archives
}

#[derive(Clone, Serialize)]
struct RecoveryAnchor {
    target: PathBuf,
    stage: PathBuf,
    committed: bool,
}

#[derive(Serialize)]
struct RecoveryJournal<'a> {
    version: u32,
    transaction_id: &'a str,
    legacy: RecoveryPaths,
    target: RecoveryPaths,
    phase: &'a str,
    anchors: Vec<RecoveryAnchor>,
}

#[derive(Serialize)]
struct RecoveryPaths {
    config: PathBuf,
    data: PathBuf,
    state: PathBuf,
}

impl From<&AppPaths> for RecoveryPaths {
    fn from(paths: &AppPaths) -> Self {
        Self {
            config: paths.config_dir.clone(),
            data: paths.data_dir.clone(),
            state: paths.state_dir.clone(),
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = open_private(path);
    file.set_len(0)
        .unwrap_or_else(|error| panic!("truncate {}: {error}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    file.sync_all()
        .unwrap_or_else(|error| panic!("sync {}: {error}", path.display()));
}

fn open_private(path: &Path) -> File {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    options
        .open(path)
        .unwrap_or_else(|error| panic!("open {}: {error}", path.display()))
}
