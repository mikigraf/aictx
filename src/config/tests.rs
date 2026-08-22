use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier},
    thread,
};

use tempfile::TempDir;

use super::*;
use crate::{
    identity::{LEGACY_AICTX, TARGET_CTXLANE},
    model::{
        AutomationPolicy, BillingDomain, ClaudeAuth, CodexAuth, CodexCredentialStore, Context,
        Profile, ProfileId, ProfileUid,
    },
};

fn assert_same_paths(left: &AppPaths, right: &AppPaths) {
    assert_eq!(left.config_dir, right.config_dir);
    assert_eq!(left.data_dir, right.data_dir);
    assert_eq!(left.state_dir, right.state_dir);
    assert_eq!(left.config_file, right.config_file);
    assert_eq!(left.state_file, right.state_file);
    assert_eq!(left.metadata_lock, right.metadata_lock);
    assert_eq!(left.config_lock, right.config_lock);
    assert_eq!(left.state_lock, right.state_lock);
}

fn assert_matches_platform_identity(paths: &AppPaths, identity: AppIdentity) {
    let project = ProjectDirs::from(
        identity.qualifier(),
        identity.organization(),
        identity.application(),
    )
    .unwrap_or_else(|| panic!("platform application directories should be available"));
    let data_dir = project.data_dir().to_path_buf();
    let state_dir = project
        .state_dir()
        .map_or_else(|| data_dir.join("state"), Path::to_path_buf);

    assert_eq!(paths.config_dir, project.config_dir());
    assert_eq!(paths.data_dir, data_dir);
    assert_eq!(paths.state_dir, state_dir);
}

#[test]
fn default_discovery_uses_the_target_application_identity() {
    let current =
        AppPaths::discover(None).unwrap_or_else(|error| panic!("discover current paths: {error}"));
    let target = AppPaths::discover_for(TARGET_CTXLANE, None)
        .unwrap_or_else(|error| panic!("discover target paths: {error}"));

    assert_same_paths(&current, &target);
    assert_matches_platform_identity(&current, TARGET_CTXLANE);
}

#[test]
fn discovery_supports_legacy_and_target_platform_identities() {
    assert_eq!(LEGACY_AICTX.qualifier(), "dev");
    assert_eq!(LEGACY_AICTX.organization(), "Cloudsail");
    assert_eq!(LEGACY_AICTX.application(), "aictx");
    assert_eq!(TARGET_CTXLANE.qualifier(), "dev");
    assert_eq!(TARGET_CTXLANE.organization(), "Cloudsail");
    assert_eq!(TARGET_CTXLANE.application(), "ctxlane");

    let legacy = AppPaths::discover_for(LEGACY_AICTX, None)
        .unwrap_or_else(|error| panic!("discover legacy paths: {error}"));
    let target = AppPaths::discover_for(TARGET_CTXLANE, None)
        .unwrap_or_else(|error| panic!("discover target paths: {error}"));

    assert_matches_platform_identity(&legacy, LEGACY_AICTX);
    assert_matches_platform_identity(&target, TARGET_CTXLANE);
    assert_ne!(legacy.config_dir, target.config_dir);
    assert_ne!(legacy.data_dir, target.data_dir);
    assert_ne!(legacy.state_dir, target.state_dir);
}

#[test]
fn explicit_root_is_independent_of_application_identity() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("explicit-root");
    let legacy = AppPaths::discover_for(LEGACY_AICTX, Some(&root))
        .unwrap_or_else(|error| panic!("discover legacy paths: {error}"));
    let target = AppPaths::discover_for(TARGET_CTXLANE, Some(&root))
        .unwrap_or_else(|error| panic!("discover target paths: {error}"));

    assert_same_paths(&legacy, &target);
    assert_same_paths(&legacy, &AppPaths::for_root(root));
}

#[test]
fn initialize_is_idempotent_and_secure() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths.clone());
    assert!(store.initialize().is_ok());
    assert!(matches!(store.initialize(), Ok(false)));
    assert!(store.load_config().is_ok());
    assert!(paths.config_file.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&paths.config_file)
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
}

#[test]
fn update_revalidates_before_commit() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = MetadataStore::new(AppPaths::for_root(temporary.path().join("ctxlane")));
    assert!(store.initialize().is_ok());
    let result = store.update_config(|config| {
        config.settings.telemetry = true;
        Ok(())
    });
    assert!(result.is_err());
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("config remains readable: {error}"));
    assert!(!config.settings.telemetry);
}

#[test]
fn metadata_store_rejects_non_managed_profile_state_directory() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize: {error}"));
    let mut config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"));
    let name = Name::parse("work").unwrap_or_else(|error| panic!("name: {error}"));
    let profile_id = ProfileId::new(Provider::Codex, name);
    let immutable_uid = ProfileUid::for_state_dir(
        &config.installation_uid,
        profile_id.provider(),
        &paths.config_dir,
    )
    .unwrap_or_else(|error| panic!("profile UID: {error}"));
    config.profiles.insert(
        profile_id,
        Profile::Codex {
            profile_uid: immutable_uid,
            billing_domain: BillingDomain::ChatgptSubscription,
            auth: CodexAuth::ChatgptOauth,
            state_dir: paths.config_dir.clone(),
            secret_ref: None,
            account_hint: None,
            expected_workspace_id: None,
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: false,
            wif: None,
            automation: AutomationPolicy::default(),
        },
    );
    write_toml(&paths.config_file, &config)
        .unwrap_or_else(|error| panic!("write hand-edited config: {error}"));

    let error = match store.load_config() {
        Err(error) => error.to_string(),
        Ok(_) => panic!("non-managed state directory should be rejected"),
    };
    assert!(error.contains("state_dir must be the managed directory"));
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn unsupported_platform_fence_checks_are_zero_filesystem_noops() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("missing-ctxlane");
    let paths = AppPaths::for_root(&root);
    let installation_uid = crate::model::InstallationUid::generate()
        .unwrap_or_else(|error| panic!("installation uid: {error}"));
    let profile_uid = ProfileUid::for_state_dir(
        &installation_uid,
        Provider::Claude,
        &paths
            .profile_state_root(Provider::Claude)
            .join("windows-noop"),
    )
    .unwrap_or_else(|error| panic!("profile uid: {error}"));
    let profile_ref: ProfileId = "claude:windows-noop"
        .parse()
        .unwrap_or_else(|error| panic!("profile ref: {error}"));

    ensure_profile_automation_unfenced(&paths, &profile_uid)
        .unwrap_or_else(|error| panic!("unsupported marker check: {error}"));
    assert!(
        !profile_automation_fence_presence(&paths, &profile_uid)
            .unwrap_or_else(|error| panic!("unsupported marker presence: {error}"))
    );
    assert!(
        prepare_profile_automation_fence(
            &MetadataStore::new(paths.clone()),
            &installation_uid,
            &profile_ref,
            profile_ref.provider(),
            &profile_uid,
        )
        .is_err(),
        "the sealed preparation seam must reject unsupported targets"
    );
    assert_ne!(
        ProfileAutomationResourceMode::Exclusive,
        ProfileAutomationResourceMode::Shared,
        "resource-mode selection must remain explicit on every target"
    );
    assert!(!root.exists());
}

#[test]
fn derived_application_directories_inside_a_repository_are_rejected() {
    let cwd = std::env::current_dir().unwrap_or_else(|error| panic!("current dir: {error}"));
    if !cwd
        .ancestors()
        .any(|ancestor| ancestor.join(".git").exists())
    {
        return;
    }
    let error = match AppPaths::from_dirs(
        cwd.join(".test-config"),
        cwd.join(".test-data"),
        cwd.join(".test-state"),
    ) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("repository-derived application paths should be rejected"),
    };
    assert!(error.contains("must not point inside the current Git worktree"));
}

#[test]
fn explicit_root_rejects_parent_components_before_missing_path_resolution() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary
        .path()
        .join("missing")
        .join("..")
        .join("repository")
        .join(".ctxlane");
    let Err(error) = AppPaths::discover(Some(&root)) else {
        panic!("root containing a parent component should be rejected");
    };
    assert!(error.to_string().contains("must not contain `.` or `..`"));
    assert!(!temporary.path().join("repository/.ctxlane").exists());
}

#[test]
fn concurrent_context_selection_and_removal_preserve_cross_file_invariants() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize: {error}"));

    let profile_id = ProfileId::new(
        Provider::Claude,
        Name::parse("account").unwrap_or_else(|error| panic!("profile name: {error}")),
    );
    let personal =
        Name::parse("personal").unwrap_or_else(|error| panic!("personal context: {error}"));
    let work = Name::parse("work").unwrap_or_else(|error| panic!("work context: {error}"));
    store
        .update_config(|config| {
            let state_dir = paths.profile_state_dir(Provider::Claude, profile_id.name());
            let immutable_uid =
                ProfileUid::for_state_dir(&config.installation_uid, Provider::Claude, &state_dir)?;
            config.profiles.insert(
                profile_id.clone(),
                Profile::Claude {
                    profile_uid: immutable_uid,
                    billing_domain: BillingDomain::AnthropicApi,
                    auth: ClaudeAuth::ApiKey,
                    state_dir,
                    secret_ref: Some("keyring://ctxlane/test-api-key".to_owned()),
                    account_hint: None,
                    expected_organization: None,
                    wif: None,
                    automation: AutomationPolicy::default(),
                },
            );
            let context = Context {
                claude: Some(profile_id.clone()),
                codex: None,
            };
            config.contexts =
                BTreeMap::from([(personal.clone(), context.clone()), (work.clone(), context)]);
            config.default_context = Some(personal.clone());
            Ok(())
        })
        .unwrap_or_else(|error| panic!("seed contexts: {error}"));

    let start = Arc::new(Barrier::new(3));
    let selecting_store = store.clone();
    let selecting_start = Arc::clone(&start);
    let selecting_work = work.clone();
    let selecting = thread::spawn(move || {
        selecting_start.wait();
        selecting_store.update_metadata(|config, state| {
            if !config.contexts.contains_key(&selecting_work) {
                return Err(Error::ContextNotFound(selecting_work.to_string()));
            }
            state.current_context = Some(selecting_work.clone());
            Ok(())
        })
    });

    let removing_store = store.clone();
    let removing_start = Arc::clone(&start);
    let removing_work = work.clone();
    let removing = thread::spawn(move || {
        removing_start.wait();
        removing_store.update_metadata(|config, state| {
            if state.current_context.as_ref() == Some(&removing_work) {
                return Err(Error::InvalidInput("context is active".to_owned()));
            }
            config.contexts.remove(&removing_work);
            Ok(())
        })
    });

    start.wait();
    let _ = selecting
        .join()
        .unwrap_or_else(|_| panic!("selection thread panicked"));
    let _ = removing
        .join()
        .unwrap_or_else(|_| panic!("removal thread panicked"));

    let (config, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load consistent metadata: {error}"));
    assert_eq!(
        config.contexts.contains_key(&work),
        state.current_context.as_ref() == Some(&work),
        "a selected context must not be removed from config"
    );
}

#[test]
fn opposing_lock_requests_use_one_order_and_never_deadlock() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    paths
        .ensure_layout()
        .unwrap_or_else(|error| panic!("layout: {error}"));
    let first = paths.state_dir.join("profile-locks/a.lock");
    let second = paths.state_dir.join("profile-locks/b.lock");
    let start = Arc::new(Barrier::new(2));
    let finish = Arc::new(Barrier::new(2));
    let spawn = |requests: [(PathBuf, bool); 2]| {
        let start = Arc::clone(&start);
        let finish = Arc::clone(&finish);
        thread::spawn(move || {
            start.wait();
            let locks = acquire_ordered_profile_locks(requests);
            let succeeded = locks.is_ok();
            finish.wait();
            drop(locks);
            succeeded
        })
    };
    let forward = spawn([(first.clone(), true), (second.clone(), true)]);
    let reverse = spawn([(second, true), (first, true)]);
    let results = [
        forward
            .join()
            .unwrap_or_else(|_| panic!("forward lock worker panicked")),
        reverse
            .join()
            .unwrap_or_else(|_| panic!("reverse lock worker panicked")),
    ];
    assert_eq!(
        results.into_iter().filter(|succeeded| *succeeded).count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn secure_directory_rejects_a_symlinked_ancestor() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let target = temporary.path().join("target");
    fs::create_dir(&target).unwrap_or_else(|error| panic!("create target: {error}"));
    let linked = temporary.path().join("linked");
    symlink(&target, &linked).unwrap_or_else(|error| panic!("create symlink: {error}"));

    let Err(error) = ensure_secure_directory(&linked.join("sensitive")) else {
        panic!("symlinked ancestor should be rejected");
    };
    assert!(
        error
            .to_string()
            .contains("symlinked security-sensitive path component")
    );
}

#[cfg(unix)]
#[test]
fn sensitive_file_rejects_a_world_writable_ancestor() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let unsafe_directory = temporary.path().join("unsafe");
    fs::create_dir(&unsafe_directory)
        .unwrap_or_else(|error| panic!("create unsafe ancestor: {error}"));
    fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o777))
        .unwrap_or_else(|error| panic!("make ancestor writable: {error}"));
    let sensitive = unsafe_directory.join("state.toml");
    fs::write(&sensitive, "version = 1\n")
        .unwrap_or_else(|error| panic!("write sensitive file: {error}"));
    fs::set_permissions(&sensitive, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("secure sensitive file: {error}"));

    let Err(error) = validate_sensitive_file(&sensitive) else {
        panic!("writable ancestor should be rejected");
    };
    assert!(error.to_string().contains("ancestor"));
    assert!(
        error
            .to_string()
            .contains("writable by group or other users")
    );
}
