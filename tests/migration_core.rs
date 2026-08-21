use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aictx::{
    Error,
    config::{AppPaths, MetadataStore, ensure_secure_directory},
    migration::{MigrationPlan, RecoveryOutcome, migration_journal_path, recover_incomplete},
    model::{
        BillingDomain, ClaudeAuth, CodexAuth, CodexCredentialStore, Config, Context, Name, Profile,
        ProfileId,
    },
};
use serde::Serialize;
use tempfile::TempDir;

struct Fixture {
    temporary: TempDir,
    legacy: AppPaths,
    target: AppPaths,
    legacy_config: Vec<u8>,
    legacy_state: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let legacy = AppPaths::for_root(temporary.path().join("aictx"));
        let target = AppPaths::for_root(temporary.path().join("ctxlane"));
        let store = MetadataStore::new(legacy.clone());
        store
            .initialize()
            .unwrap_or_else(|error| panic!("initialize legacy store: {error}"));

        let claude_id: ProfileId = "claude:personal"
            .parse()
            .unwrap_or_else(|error| panic!("parse Claude profile ID: {error}"));
        let codex_id: ProfileId = "codex:work"
            .parse()
            .unwrap_or_else(|error| panic!("parse Codex profile ID: {error}"));
        let context_name =
            Name::parse("mixed").unwrap_or_else(|error| panic!("parse context name: {error}"));
        let binding_path = temporary.path().join("company-project");
        fs::create_dir(&binding_path)
            .unwrap_or_else(|error| panic!("create bound project: {error}"));

        store
            .update_config(|config| {
                config.profiles.insert(
                    claude_id.clone(),
                    Profile::Claude {
                        billing_domain: BillingDomain::ClaudeSubscription,
                        auth: ClaudeAuth::SubscriptionToken,
                        state_dir: legacy.profile_state_dir(claude_id.provider(), claude_id.name()),
                        secret_ref: Some(
                            "keyring://aictx/claude-personal-opaque-handle".to_owned(),
                        ),
                        account_hint: Some("personal@example.test".to_owned()),
                        expected_organization: None,
                        wif: None,
                    },
                );
                config.profiles.insert(
                    codex_id.clone(),
                    Profile::Codex {
                        billing_domain: BillingDomain::ChatgptSubscription,
                        auth: CodexAuth::ChatgptOauth,
                        state_dir: legacy.profile_state_dir(codex_id.provider(), codex_id.name()),
                        secret_ref: None,
                        account_hint: Some("work@example.test".to_owned()),
                        expected_workspace_id: Some("workspace-123".to_owned()),
                        credential_store: CodexCredentialStore::File,
                        trusted_runners_only: false,
                    },
                );
                config.contexts.insert(
                    context_name.clone(),
                    Context {
                        claude: Some(claude_id.clone()),
                        codex: Some(codex_id.clone()),
                    },
                );
                config.default_context = Some(context_name.clone());
                config.bindings.push(aictx::model::Binding {
                    path: binding_path,
                    context: context_name.clone(),
                });
                Ok(())
            })
            .unwrap_or_else(|error| panic!("configure legacy store: {error}"));
        store
            .update_state(|_config, state| {
                state.current_context = Some(context_name);
                Ok(())
            })
            .unwrap_or_else(|error| panic!("configure legacy state: {error}"));

        let claude_state = legacy.profile_state_dir(claude_id.provider(), claude_id.name());
        let codex_state = legacy.profile_state_dir(codex_id.provider(), codex_id.name());
        ensure_secure_directory(&claude_state)
            .unwrap_or_else(|error| panic!("create Claude state: {error}"));
        ensure_secure_directory(&codex_state)
            .unwrap_or_else(|error| panic!("create Codex state: {error}"));
        write_private(&claude_state.join("session.json"), b"claude-session\n");
        write_private(&codex_state.join("auth.json"), b"codex-auth\n");
        write_private(&codex_state.join("active.lock"), b"legacy-lock\n");

        let retired = legacy
            .data_dir
            .join("vendor-state/claude/personal.retired-0001");
        ensure_secure_directory(&retired)
            .unwrap_or_else(|error| panic!("create retired state: {error}"));
        write_private(&retired.join("history.json"), b"retired-history\n");

        let legacy_config = fs::read(&legacy.config_file)
            .unwrap_or_else(|error| panic!("snapshot legacy config: {error}"));
        let legacy_state = fs::read(&legacy.state_file)
            .unwrap_or_else(|error| panic!("snapshot legacy state: {error}"));

        Self {
            temporary,
            legacy,
            target,
            legacy_config,
            legacy_state,
        }
    }

    fn assert_legacy_metadata_unchanged(&self) {
        assert_eq!(
            fs::read(&self.legacy.config_file)
                .unwrap_or_else(|error| panic!("read legacy config: {error}")),
            self.legacy_config
        );
        assert_eq!(
            fs::read(&self.legacy.state_file)
                .unwrap_or_else(|error| panic!("read legacy state: {error}")),
            self.legacy_state
        );
        assert_eq!(
            fs::read(
                self.legacy
                    .data_dir
                    .join("vendor-state/codex/work/active.lock")
            )
            .unwrap_or_else(|error| panic!("read legacy lock: {error}")),
            b"legacy-lock\n"
        );
    }
}

#[test]
fn explicit_migration_copies_state_rewrites_paths_and_preserves_secret_references() {
    let fixture = Fixture::new();

    let plan = MigrationPlan::inspect(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("inspect migration: {error}"));
    assert_eq!(plan.summary().profile_count(), 2);
    assert_eq!(plan.summary().vendor_file_count(), 3);
    assert_eq!(plan.summary().vendor_directory_count(), 5);
    assert_eq!(plan.summary().skipped_lock_count(), 1);
    let debug = format!("{plan:?}");
    assert!(!debug.contains("personal@example.test"));
    assert!(!debug.contains("work@example.test"));
    assert!(!debug.contains("keyring://"));
    assert!(!fixture.target.config_dir.exists());
    assert!(!migration_journal_path(&fixture.target).exists());

    let receipt = plan
        .execute()
        .unwrap_or_else(|error| panic!("execute migration: {error}"));
    assert_eq!(receipt.summary().profile_count(), 2);
    assert_eq!(receipt.summary().vendor_file_count(), 3);
    assert_eq!(receipt.summary().vendor_directory_count(), 5);
    assert_eq!(receipt.summary().skipped_lock_count(), 1);
    assert_eq!(receipt.config_file(), fixture.target.config_file);
    assert_eq!(receipt.state_file(), fixture.target.state_file);
    assert!(!migration_journal_path(&fixture.target).exists());

    // Migration does not carry live lock objects into the new application.
    assert!(!fixture.target.config_dir.join("config.lock").exists());
    assert!(!fixture.target.state_dir.join("metadata.lock").exists());
    assert!(!fixture.target.state_dir.join("state.lock").exists());
    assert!(
        fs::read_dir(fixture.target.state_dir.join("profile-locks"))
            .unwrap_or_else(|error| panic!("read target lock directory: {error}"))
            .next()
            .is_none()
    );
    assert!(
        !fixture
            .target
            .data_dir
            .join("vendor-state/codex/work/active.lock")
            .exists()
    );

    assert_eq!(
        fs::read(
            fixture
                .target
                .data_dir
                .join("vendor-state/claude/personal/session.json")
        )
        .unwrap_or_else(|error| panic!("read migrated Claude state: {error}")),
        b"claude-session\n"
    );
    assert_eq!(
        fs::read(
            fixture
                .target
                .data_dir
                .join("vendor-state/claude/personal.retired-0001/history.json")
        )
        .unwrap_or_else(|error| panic!("read migrated retired state: {error}")),
        b"retired-history\n"
    );

    let target_store = MetadataStore::new(fixture.target.clone());
    let (config, state) = target_store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load migrated metadata: {error}"));
    assert_migrated_profiles(&config, &fixture.target);
    assert_eq!(
        state.current_context.as_ref().map(Name::as_str),
        Some("mixed")
    );
    assert_eq!(
        config.default_context.as_ref().map(Name::as_str),
        Some("mixed")
    );
    assert_eq!(config.bindings.len(), 1);
    fixture.assert_legacy_metadata_unchanged();
}

#[test]
fn planning_and_execution_fail_closed_for_collisions_and_changed_sources() {
    let collision = Fixture::new();
    ensure_secure_directory(&collision.target.config_dir)
        .unwrap_or_else(|error| panic!("create target collision: {error}"));
    let Err(error) = MigrationPlan::inspect(&collision.legacy, &collision.target) else {
        panic!("existing target must be refused");
    };
    assert!(error.to_string().contains("never overwrites a target"));
    collision.assert_legacy_metadata_unchanged();

    let changed = Fixture::new();
    let plan = MigrationPlan::inspect(&changed.legacy, &changed.target)
        .unwrap_or_else(|error| panic!("inspect migration: {error}"));
    write_private(
        &changed
            .legacy
            .data_dir
            .join("vendor-state/claude/personal/session.json"),
        b"changed-after-plan\n",
    );
    let Err(error) = plan.execute() else {
        panic!("changed source must invalidate the plan");
    };
    assert!(matches!(error, Error::ConfigBusy));
    assert!(!changed.target.config_dir.exists());
    assert!(!migration_journal_path(&changed.target).exists());
}

#[test]
fn execution_refuses_a_busy_profile_before_creating_target_state() {
    let fixture = Fixture::new();
    let profile_id: ProfileId = "claude:personal"
        .parse()
        .unwrap_or_else(|error| panic!("parse profile ID: {error}"));
    let lock_path = fixture
        .legacy
        .profile_lock(profile_id.provider(), profile_id.name());
    let lock = open_private(&lock_path);
    lock.try_lock()
        .unwrap_or_else(|error| panic!("hold profile lock: {error}"));

    let plan = MigrationPlan::inspect(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("inspect migration: {error}"));
    let Err(error) = plan.execute() else {
        panic!("busy profile must block migration");
    };
    assert!(error.to_string().contains("profile is busy"));
    assert!(!fixture.target.config_dir.exists());
    assert!(!migration_journal_path(&fixture.target).exists());
    fixture.assert_legacy_metadata_unchanged();
}

#[cfg(unix)]
#[test]
fn planning_refuses_symlinks_in_vendor_state_and_at_the_target() {
    use std::os::unix::fs::symlink;

    let source_link = Fixture::new();
    let outside = source_link.legacy.data_dir.join("outside-session.json");
    write_private(&outside, b"outside\n");
    symlink(
        &outside,
        source_link
            .legacy
            .data_dir
            .join("vendor-state/claude/personal/linked.json"),
    )
    .unwrap_or_else(|error| panic!("create source symlink: {error}"));
    let Err(error) = MigrationPlan::inspect(&source_link.legacy, &source_link.target) else {
        panic!("source symlink must be refused");
    };
    assert!(error.to_string().contains("refusing symlink"));
    assert!(!source_link.target.config_dir.exists());

    let target_link = Fixture::new();
    let outside_directory = target_link.temporary.path().join("outside-target");
    ensure_secure_directory(&outside_directory)
        .unwrap_or_else(|error| panic!("create outside target: {error}"));
    fs::create_dir_all(
        target_link
            .target
            .config_dir
            .parent()
            .unwrap_or_else(|| panic!("target config parent")),
    )
    .unwrap_or_else(|error| panic!("create target parent: {error}"));
    symlink(&outside_directory, &target_link.target.config_dir)
        .unwrap_or_else(|error| panic!("create target symlink: {error}"));
    let Err(error) = MigrationPlan::inspect(&target_link.legacy, &target_link.target) else {
        panic!("target symlink must be refused");
    };
    assert!(error.to_string().contains("already exists as a symlink"));
}

#[cfg(unix)]
#[test]
fn migration_accepts_a_trusted_shared_parent_with_mode_0755() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let shared_parent = fixture
        .target
        .config_dir
        .parent()
        .unwrap_or_else(|| panic!("target config parent"));
    fs::create_dir(shared_parent)
        .unwrap_or_else(|error| panic!("create shared target parent: {error}"));
    fs::set_permissions(shared_parent, fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|error| panic!("set shared target parent mode: {error}"));

    MigrationPlan::inspect(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("inspect under 0755 parent: {error}"))
        .execute()
        .unwrap_or_else(|error| panic!("migrate under 0755 parent: {error}"));

    assert!(fixture.target.config_file.is_file());
    let mode = fs::symlink_metadata(shared_parent)
        .unwrap_or_else(|error| panic!("inspect shared target parent: {error}"))
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn recovery_rolls_back_only_journal_owned_partial_targets() {
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
        anchors,
    };
    let journal_text = toml::to_string_pretty(&journal)
        .unwrap_or_else(|error| panic!("serialize recovery journal: {error}"));
    let journal_path = migration_journal_path(&fixture.target);
    write_private(&journal_path, format!("{journal_text}\n").as_bytes());

    let outcome = recover_incomplete(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("recover partial migration: {error}"));
    assert_eq!(outcome, RecoveryOutcome::RolledBack);
    assert!(!journal_path.exists());
    assert!(targets.iter().all(|target| !target.exists()));
    fixture.assert_legacy_metadata_unchanged();
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

#[derive(Serialize)]
struct RecoveryAnchor {
    target: PathBuf,
    stage: PathBuf,
    committed: bool,
}

fn assert_migrated_profiles(config: &Config, target: &AppPaths) {
    let profiles = config
        .profiles
        .iter()
        .map(|(id, profile)| (id.to_string(), profile))
        .collect::<BTreeMap<_, _>>();
    let claude = profiles
        .get("claude:personal")
        .unwrap_or_else(|| panic!("migrated Claude profile"));
    assert_eq!(
        claude.state_dir(),
        target.data_dir.join("vendor-state/claude/personal")
    );
    assert_eq!(
        claude.secret_ref(),
        Some("keyring://aictx/claude-personal-opaque-handle")
    );
    let codex = profiles
        .get("codex:work")
        .unwrap_or_else(|| panic!("migrated Codex profile"));
    assert_eq!(
        codex.state_dir(),
        target.data_dir.join("vendor-state/codex/work")
    );
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
