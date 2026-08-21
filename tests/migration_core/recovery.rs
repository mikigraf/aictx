use super::*;

#[test]
fn verified_recovery_reconstructs_and_checks_the_complete_target() {
    let intact = Fixture::new();
    MigrationPlan::inspect(&intact.legacy, &intact.target)
        .unwrap_or_else(|error| panic!("inspect intact migration: {error}"))
        .execute()
        .unwrap_or_else(|error| panic!("execute intact migration: {error}"));
    install_recovery_journal(&intact, "verified");
    assert_eq!(
        recover_incomplete(&intact.legacy, &intact.target)
            .unwrap_or_else(|error| panic!("finalize intact migration: {error}")),
        RecoveryOutcome::Finalized
    );

    let corrupted = Fixture::new();
    MigrationPlan::inspect(&corrupted.legacy, &corrupted.target)
        .unwrap_or_else(|error| panic!("inspect corrupt migration: {error}"))
        .execute()
        .unwrap_or_else(|error| panic!("execute corrupt migration: {error}"));
    install_recovery_journal(&corrupted, "verified");
    write_private(
        &corrupted
            .target
            .data_dir
            .join("vendor-state/claude/personal/session.json"),
        b"corrupted\n",
    );
    assert!(recover_incomplete(&corrupted.legacy, &corrupted.target).is_err());
    assert!(migration_journal_path(&corrupted.target).is_file());

    let missing = Fixture::new();
    MigrationPlan::inspect(&missing.legacy, &missing.target)
        .unwrap_or_else(|error| panic!("inspect missing-target migration: {error}"))
        .execute()
        .unwrap_or_else(|error| panic!("execute missing-target migration: {error}"));
    install_recovery_journal(&missing, "verified");
    fs::remove_dir_all(&missing.target.state_dir)
        .unwrap_or_else(|error| panic!("remove committed target anchor: {error}"));
    assert!(recover_incomplete(&missing.legacy, &missing.target).is_err());
    assert!(migration_journal_path(&missing.target).is_file());
}

#[test]
fn old_verified_v1_journal_recovers_then_upgrades_without_the_creating_binary() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let legacy = AppPaths::for_root(temporary.path().join("aictx-v1"));
    let target = AppPaths::for_root(temporary.path().join("ctxlane-v1-target"));
    for directory in [
        &legacy.config_dir,
        &legacy.data_dir,
        &legacy.state_dir,
        &legacy.data_dir.join("vendor-state"),
        &legacy.state_dir.join("profile-locks"),
        &target.config_dir,
        &target.data_dir,
        &target.state_dir,
        &target.data_dir.join("vendor-state"),
        &target.state_dir.join("profile-locks"),
    ] {
        ensure_secure_directory(directory)
            .unwrap_or_else(|error| panic!("create {}: {error}", directory.display()));
    }

    let profile_id: ProfileId = "claude:ci"
        .parse()
        .unwrap_or_else(|error| panic!("profile: {error}"));
    let source_state = legacy.profile_state_dir(profile_id.provider(), profile_id.name());
    let target_state = target.profile_state_dir(profile_id.provider(), profile_id.name());
    let source = legacy_v1_wif_config(profile_id.clone(), source_state);
    let committed = legacy_v1_wif_config(profile_id.clone(), target_state);
    write_private(
        &legacy.config_file,
        format!(
            "{}\n",
            toml::to_string_pretty(&source)
                .unwrap_or_else(|error| panic!("serialize source v1: {error}"))
        )
        .as_bytes(),
    );
    write_private(
        &target.config_file,
        format!(
            "{}\n",
            toml::to_string_pretty(&committed)
                .unwrap_or_else(|error| panic!("serialize target v1: {error}"))
        )
        .as_bytes(),
    );
    let state = ctxlane::model::MutableState::default();
    let state_bytes = format!(
        "{}\n",
        toml::to_string_pretty(&state).unwrap_or_else(|error| panic!("serialize state: {error}"))
    );
    write_private(&legacy.state_file, state_bytes.as_bytes());
    write_private(&target.state_file, state_bytes.as_bytes());
    write_private(&legacy.state_dir.join("metadata.lock"), b"");

    let source_vendor = legacy.data_dir.join("vendor-state/claude/ci");
    let target_vendor = target.data_dir.join("vendor-state/claude/ci");
    ensure_secure_directory(&source_vendor)
        .unwrap_or_else(|error| panic!("create source vendor state: {error}"));
    ensure_secure_directory(&target_vendor)
        .unwrap_or_else(|error| panic!("create target vendor state: {error}"));
    write_private(&source_vendor.join("session.json"), b"legacy-session\n");
    write_private(&target_vendor.join("session.json"), b"legacy-session\n");

    install_old_recovery_journal(&legacy, &target, "verified");
    assert_eq!(
        recover_incomplete(&legacy, &target)
            .unwrap_or_else(|error| panic!("recover old verified journal: {error}")),
        RecoveryOutcome::Finalized
    );
    assert!(!migration_journal_path(&target).exists());
    assert!(
        fs::read_to_string(&target.config_file)
            .unwrap_or_else(|error| panic!("read preserved v1: {error}"))
            .contains("version = 1")
    );

    let (upgraded, state) = MetadataStore::new(target.clone())
        .load_metadata()
        .unwrap_or_else(|error| panic!("upgrade finalized v1 target: {error}"));
    assert_eq!(upgraded.version, ctxlane::model::CONFIG_SCHEMA_VERSION);
    assert_eq!(state.version, ctxlane::model::STATE_SCHEMA_VERSION);
    let profile = upgraded
        .profiles
        .get(&profile_id)
        .unwrap_or_else(|| panic!("upgraded profile"));
    assert_eq!(
        profile.state_dir(),
        target.data_dir.join("vendor-state/claude/ci")
    );
    assert!(!profile.automation().eligible);
}

#[test]
fn new_v1_migration_journal_recovers_with_its_persisted_installation_identity() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let legacy = AppPaths::for_root(temporary.path().join("frozen-v1"));
    let target = AppPaths::for_root(temporary.path().join("current-v2"));
    materialize_frozen_v1_source(&legacy);

    MigrationPlan::inspect(&legacy, &target)
        .unwrap_or_else(|error| panic!("inspect frozen v1: {error}"))
        .execute()
        .unwrap_or_else(|error| panic!("migrate frozen v1: {error}"));
    let before: Config = toml::from_str(
        &fs::read_to_string(&target.config_file)
            .unwrap_or_else(|error| panic!("read migrated v2: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse migrated v2: {error}"));
    assert_eq!(before.version, ctxlane::model::CONFIG_SCHEMA_VERSION);
    assert_eq!(before.profiles.len(), 6);

    install_recovery_journal_for_paths(&legacy, &target, "verified");
    assert_eq!(
        recover_incomplete(&legacy, &target)
            .unwrap_or_else(|error| panic!("recover migrated v1 target: {error}")),
        RecoveryOutcome::Finalized
    );
    let after = MetadataStore::new(target)
        .load_config()
        .unwrap_or_else(|error| panic!("load recovered v2: {error}"));
    assert_eq!(after.installation_uid, before.installation_uid);
    assert_eq!(
        after
            .profiles
            .values()
            .map(Profile::profile_uid)
            .collect::<Vec<_>>(),
        before
            .profiles
            .values()
            .map(Profile::profile_uid)
            .collect::<Vec<_>>()
    );
}

#[test]
fn v2_migration_preserves_renamed_random_state_identity_and_rejects_journal_uid_drift() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let legacy = AppPaths::for_root(temporary.path().join("source-v2"));
    let target = AppPaths::for_root(temporary.path().join("target-v2"));
    let store = MetadataStore::new(legacy.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize source v2: {error}"));
    let receipt = add_profile(
        &store,
        ProfileDraft::Claude {
            name: Name::parse("original").unwrap_or_else(|error| panic!("name: {error}")),
            auth: ClaudeAuth::ApiKey,
            secret_ref: None,
            account_hint: None,
            expected_organization: None,
            wif: None,
        },
    )
    .unwrap_or_else(|error| panic!("add source profile: {error}"));
    let original_id: ProfileId = "claude:original"
        .parse()
        .unwrap_or_else(|error| panic!("original profile: {error}"));
    let expected = store
        .load_config()
        .unwrap_or_else(|error| panic!("load source profile: {error}"))
        .profiles
        .get(&original_id)
        .cloned()
        .unwrap_or_else(|| panic!("source profile"));
    let renamed = Name::parse("renamed").unwrap_or_else(|error| panic!("new name: {error}"));
    rename_profile(&store, &original_id, renamed, &expected)
        .unwrap_or_else(|error| panic!("rename source profile: {error}"));
    let state_leaf = expected
        .state_dir()
        .file_name()
        .unwrap_or_else(|| panic!("state leaf"))
        .to_owned();
    assert_ne!(state_leaf, std::ffi::OsStr::new("renamed"));
    write_private(
        &expected.state_dir().join("session.json"),
        b"random-state\n",
    );

    MigrationPlan::inspect(&legacy, &target)
        .unwrap_or_else(|error| panic!("inspect v2 migration: {error}"))
        .execute()
        .unwrap_or_else(|error| panic!("execute v2 migration: {error}"));
    let migrated_text = fs::read_to_string(&target.config_file)
        .unwrap_or_else(|error| panic!("read migrated v2 config: {error}"));
    let migrated: Config = toml::from_str(&migrated_text)
        .unwrap_or_else(|error| panic!("parse migrated v2 config: {error}"));
    let renamed_id: ProfileId = "claude:renamed"
        .parse()
        .unwrap_or_else(|error| panic!("renamed profile: {error}"));
    let profile = migrated
        .profiles
        .get(&renamed_id)
        .unwrap_or_else(|| panic!("migrated renamed profile"));
    assert_eq!(profile.profile_uid(), &receipt.profile_uid);
    assert_eq!(
        profile.state_dir().file_name(),
        Some(state_leaf.as_os_str())
    );
    assert_eq!(
        profile.state_dir().parent(),
        Some(target.profile_state_root(profile.provider()).as_path())
    );

    install_recovery_journal_for_paths(&legacy, &target, "verified");
    let journal_path = migration_journal_path(&target);
    let journal_text =
        fs::read_to_string(&journal_path).unwrap_or_else(|error| panic!("read journal: {error}"));
    let wrong_uid = "installation_00000000000000000000000001";
    let corrupted = journal_text.replace(migrated.installation_uid.as_str(), wrong_uid);
    assert_ne!(corrupted, journal_text);
    write_private(&journal_path, corrupted.as_bytes());
    assert!(recover_incomplete(&legacy, &target).is_err());
    assert!(journal_path.is_file());

    install_recovery_journal_for_paths(&legacy, &target, "verified");
    assert_eq!(
        recover_incomplete(&legacy, &target)
            .unwrap_or_else(|error| panic!("recover correct v2 journal: {error}")),
        RecoveryOutcome::Finalized
    );
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
        installation_uid: None,
        legacy: RecoveryPaths::from(&fixture.legacy),
        target: RecoveryPaths::from(&fixture.target),
        phase: "committing",
        anchors,
    };
    let journal_text = toml::to_string_pretty(&journal)
        .unwrap_or_else(|error| panic!("serialize recovery journal: {error}"));
    let journal_path = migration_journal_path(&fixture.target);
    write_private(&journal_path, format!("{journal_text}\n").as_bytes());
    let collision = fixture
        .target
        .data_dir
        .with_file_name(".data.ctxlane-migration-rollback-deadbeef-1234-1-0");
    ensure_secure_directory(&collision)
        .unwrap_or_else(|error| panic!("create archive collision: {error}"));
    write_private(&collision.join("sentinel"), b"keep\n");

    let outcome = recover_incomplete(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("recover partial migration: {error}"));
    let RecoveryOutcome::RolledBack { archives } = outcome else {
        panic!("partial migration should be rolled back");
    };
    assert_eq!(archives.len(), 1);
    assert_ne!(archives[0], collision);
    assert_eq!(
        fs::read(collision.join("sentinel"))
            .unwrap_or_else(|error| panic!("read collision sentinel: {error}")),
        b"keep\n"
    );
    assert_eq!(
        fs::read(archives[0].join("partial-data"))
            .unwrap_or_else(|error| panic!("read archived partial target: {error}")),
        b"partial\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::symlink_metadata(&archives[0])
            .unwrap_or_else(|error| panic!("inspect private archive: {error}"))
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
    assert!(!journal_path.exists());
    assert!(targets.iter().all(|target| !target.exists()));
    fixture.assert_legacy_metadata_unchanged();
}

fn install_recovery_journal(fixture: &Fixture, phase: &str) {
    install_recovery_journal_for_paths(&fixture.legacy, &fixture.target, phase);
}

fn install_recovery_journal_for_paths(legacy: &AppPaths, target: &AppPaths, phase: &str) {
    let transaction_id = "deadbeef-9876";
    let mut targets = [
        target.config_dir.clone(),
        target.data_dir.clone(),
        target.state_dir.clone(),
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
            committed: true,
        })
        .collect();
    let config_text = fs::read_to_string(&target.config_file)
        .unwrap_or_else(|error| panic!("read target config for journal: {error}"));
    let config: toml::Value = toml::from_str(&config_text)
        .unwrap_or_else(|error| panic!("parse target config for journal: {error}"));
    let installation_uid = config
        .get("installation_uid")
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("target installation UID"));
    let journal = RecoveryJournal {
        version: 1,
        transaction_id,
        installation_uid: Some(installation_uid.to_owned()),
        legacy: RecoveryPaths::from(legacy),
        target: RecoveryPaths::from(target),
        phase,
        anchors,
    };
    let text = toml::to_string_pretty(&journal)
        .unwrap_or_else(|error| panic!("serialize recovery journal: {error}"));
    write_private(
        &migration_journal_path(target),
        format!("{text}\n").as_bytes(),
    );
}

fn install_old_recovery_journal(legacy: &AppPaths, target: &AppPaths, phase: &str) {
    let transaction_id = "deadbeef-0001";
    let mut targets = [
        target.config_dir.clone(),
        target.data_dir.clone(),
        target.state_dir.clone(),
    ];
    targets.sort();
    let anchors = targets
        .iter()
        .enumerate()
        .map(|(index, anchor_target)| RecoveryAnchor {
            target: anchor_target.clone(),
            stage: anchor_target.with_file_name(format!(
                ".{}.ctxlane-migration-stage-{transaction_id}-{index}",
                anchor_target
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or("ctxlane")
            )),
            committed: true,
        })
        .collect();
    let journal = RecoveryJournal {
        version: 1,
        transaction_id,
        installation_uid: None,
        legacy: RecoveryPaths::from(legacy),
        target: RecoveryPaths::from(target),
        phase,
        anchors,
    };
    let text = toml::to_string_pretty(&journal)
        .unwrap_or_else(|error| panic!("serialize old recovery journal: {error}"));
    write_private(
        &migration_journal_path(target),
        format!("{text}\n").as_bytes(),
    );
}

fn materialize_frozen_v1_source(paths: &AppPaths) {
    paths
        .ensure_layout()
        .unwrap_or_else(|error| panic!("create frozen v1 layout: {error}"));
    let root = paths
        .config_dir
        .parent()
        .unwrap_or_else(|| panic!("explicit source root"));
    let config = include_str!("../fixtures/v0_2_0_schema_v1/config.toml.in")
        .replace("__ROOT__", &toml_path_fragment(root))
        .replace(
            "__CLAUDE_BIN__",
            &toml_path_fragment(&root.join("vendor").join("claude")),
        )
        .replace(
            "__CODEX_BIN__",
            &toml_path_fragment(&root.join("vendor").join("codex")),
        )
        .replace("__TOKEN__", &toml_path_fragment(&root.join("identity.jwt")))
        .replace(
            "__BINDING__",
            &toml_path_fragment(&root.join("company-project")),
        );
    write_private(&paths.config_file, config.as_bytes());
    write_private(
        &paths.state_file,
        include_bytes!("../fixtures/v0_2_0_schema_v1/state.toml"),
    );
    write_private(&paths.state_dir.join("metadata.lock"), b"");
    for relative in ["claude/personal/session.json", "codex/work/auth.json"] {
        let path = paths.data_dir.join("vendor-state").join(relative);
        ensure_secure_directory(
            path.parent()
                .unwrap_or_else(|| panic!("vendor state parent")),
        )
        .unwrap_or_else(|error| panic!("create vendor state: {error}"));
        write_private(&path, format!("{relative}\n").as_bytes());
    }
}

fn toml_path_fragment(path: &Path) -> String {
    path.to_str()
        .unwrap_or_else(|| panic!("fixture path must be UTF-8: {}", path.display()))
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn legacy_v1_wif_config(profile_id: ProfileId, state_dir: PathBuf) -> LegacyConfigV1 {
    LegacyConfigV1 {
        version: 1,
        default_context: None,
        settings: LegacySettingsV1::default(),
        binaries: LegacyBinaryConfigV1::default(),
        profiles: BTreeMap::from([(
            profile_id,
            LegacyProfileV1::Claude {
                billing_domain: BillingDomain::AnthropicApi,
                auth: ClaudeAuth::Wif,
                state_dir,
                secret_ref: None,
                account_hint: Some("ci@example.test".to_owned()),
                expected_organization: Some("org_expected".to_owned()),
                wif: Some(LegacyClaudeWifV1 {
                    organization_id: "org_runtime".to_owned(),
                    federation_rule_id: "rule_runtime".to_owned(),
                    service_account_id: "service_runtime".to_owned(),
                    workspace_id: Some("workspace_runtime".to_owned()),
                    identity_token_file: PathBuf::from(if cfg!(windows) {
                        r"C:\ctxlane\identity.jwt"
                    } else {
                        "/run/ctxlane/identity.jwt"
                    }),
                }),
            },
        )]),
        contexts: BTreeMap::new(),
        bindings: Vec::new(),
    }
}

#[derive(Clone, Serialize)]
struct LegacyConfigV1 {
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_context: Option<Name>,
    settings: LegacySettingsV1,
    binaries: LegacyBinaryConfigV1,
    profiles: BTreeMap<ProfileId, LegacyProfileV1>,
    contexts: BTreeMap<Name, LegacyContextV1>,
    bindings: Vec<LegacyBindingV1>,
}

#[derive(Clone, Serialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
enum LegacyProfileV1 {
    Claude {
        billing_domain: BillingDomain,
        auth: ClaudeAuth,
        state_dir: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        account_hint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_organization: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wif: Option<LegacyClaudeWifV1>,
    },
}

#[derive(Clone, Serialize)]
struct LegacyClaudeWifV1 {
    organization_id: String,
    federation_rule_id: String,
    service_account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_id: Option<String>,
    identity_token_file: PathBuf,
}

#[derive(Clone, Serialize)]
struct LegacyContextV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    claude: Option<ProfileId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    codex: Option<ProfileId>,
}

#[derive(Clone, Serialize)]
struct LegacyBindingV1 {
    path: PathBuf,
    context: Name,
}

#[derive(Clone, Serialize)]
struct LegacySettingsV1 {
    require_billing_confirmation_on_change: bool,
    show_run_banner: bool,
    telemetry: bool,
}

impl Default for LegacySettingsV1 {
    fn default() -> Self {
        Self {
            require_billing_confirmation_on_change: true,
            show_run_banner: true,
            telemetry: false,
        }
    }
}

#[derive(Clone, Serialize)]
struct LegacyBinaryConfigV1 {
    claude: PathBuf,
    codex: PathBuf,
}

impl Default for LegacyBinaryConfigV1 {
    fn default() -> Self {
        Self {
            claude: PathBuf::from("claude"),
            codex: PathBuf::from("codex"),
        }
    }
}

#[derive(Serialize)]
struct RecoveryJournal<'a> {
    version: u32,
    transaction_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    installation_uid: Option<String>,
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
