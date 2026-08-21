use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;

use ctxlane::{
    Error,
    config::{AppPaths, MetadataStore},
    management::{
        ClaudeProfileEdit, CodexProfileEdit, ProfileDraft, ProfileEdit, ValueEdit, add_binding,
        add_context, add_profile, edit_binding, edit_context, edit_profile, remove_binding,
        remove_context, remove_profile, rename_context, rename_profile,
    },
    model::{
        AutomationPolicy, AutomationRole, CONFIG_SCHEMA_VERSION, ClaudeAuth, CodexAuth,
        CodexCredentialStore, CodexWifConfig, Context, Name, Profile, ProfileId, ProfileUid,
        STATE_SCHEMA_VERSION,
    },
};
use tempfile::TempDir;

fn initialized_store() -> (TempDir, AppPaths, MetadataStore) {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize: {error}"));
    (temporary, paths, store)
}

fn name(value: &str) -> Name {
    Name::parse(value).unwrap_or_else(|error| panic!("valid name: {error}"))
}

fn claude_draft(value: &str) -> ProfileDraft {
    ProfileDraft::Claude {
        name: name(value),
        auth: ClaudeAuth::ApiKey,
        secret_ref: None,
        account_hint: None,
        expected_organization: None,
        wif: None,
    }
}

fn codex_draft(value: &str) -> ProfileDraft {
    ProfileDraft::Codex {
        name: name(value),
        auth: CodexAuth::ChatgptOauth,
        secret_ref: None,
        account_hint: None,
        expected_workspace_id: None,
        credential_store: CodexCredentialStore::File,
        trusted_runners_only: false,
        wif: None,
    }
}

fn profile(store: &MetadataStore, id: &ProfileId) -> Profile {
    store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"))
        .profiles
        .get(id)
        .cloned()
        .unwrap_or_else(|| panic!("missing profile {id}"))
}

#[test]
fn profile_add_allocates_an_immutable_managed_storage_identity() {
    let (_temporary, paths, store) = initialized_store();
    let receipt = add_profile(&store, claude_draft("personal"))
        .unwrap_or_else(|error| panic!("add profile: {error}"));
    let added = profile(&store, &receipt.id);

    let provider_root = paths.profile_state_root(receipt.id.provider());
    assert_eq!(added.state_dir().parent(), Some(provider_root.as_path()));
    assert_ne!(
        added.state_dir(),
        paths.profile_state_dir(receipt.id.provider(), receipt.id.name())
    );
    assert!(added.state_dir().is_dir());
    assert!(added.secret_ref().is_some());

    let duplicate = add_profile(&store, claude_draft("personal"));
    assert!(matches!(duplicate, Err(Error::InvalidInput(_))));
    assert_eq!(
        fs::read_dir(&provider_root)
            .unwrap_or_else(|error| panic!("read provider state root: {error}"))
            .count(),
        1
    );

    let second = add_profile(&store, claude_draft("secondary"))
        .unwrap_or_else(|error| panic!("add second profile: {error}"));
    assert_ne!(added.state_dir(), profile(&store, &second.id).state_dir());
}

#[test]
fn profile_add_leaves_an_unreferenced_legacy_directory_untouched() {
    let (_temporary, paths, store) = initialized_store();
    let legacy = paths.profile_state_dir(ctxlane::model::Provider::Claude, &name("personal"));
    ctxlane::config::ensure_secure_directory(&legacy)
        .unwrap_or_else(|error| panic!("create orphan: {error}"));
    fs::write(legacy.join("orphan-marker"), "old identity")
        .unwrap_or_else(|error| panic!("write orphan marker: {error}"));

    let receipt = add_profile(&store, claude_draft("personal"))
        .unwrap_or_else(|error| panic!("add profile: {error}"));
    assert_eq!(
        fs::read_to_string(legacy.join("orphan-marker"))
            .unwrap_or_else(|error| panic!("read detached marker: {error}")),
        "old identity"
    );
    assert_ne!(profile(&store, &receipt.id).state_dir(), legacy);
}

#[test]
fn profile_add_never_retires_a_legacy_path_owned_by_a_renamed_profile() {
    let (_temporary, paths, store) = initialized_store();
    let old: ProfileId = "claude:old"
        .parse()
        .unwrap_or_else(|error| panic!("old ID: {error}"));
    let legacy = paths.profile_state_dir(old.provider(), old.name());
    ctxlane::config::ensure_secure_directory(&legacy)
        .unwrap_or_else(|error| panic!("create legacy state: {error}"));
    fs::write(legacy.join("live-marker"), "live identity")
        .unwrap_or_else(|error| panic!("write live marker: {error}"));
    store
        .update_config(|config| {
            let profile_uid =
                ProfileUid::for_state_dir(&config.installation_uid, old.provider(), &legacy)?;
            config.profiles.insert(
                old.clone(),
                Profile::Claude {
                    profile_uid,
                    billing_domain: ctxlane::model::BillingDomain::AnthropicApi,
                    auth: ClaudeAuth::ApiKey,
                    state_dir: legacy.clone(),
                    secret_ref: Some("keyring://ctxlane/old-ref".to_owned()),
                    account_hint: None,
                    expected_organization: None,
                    wif: None,
                    automation: AutomationPolicy::default(),
                },
            );
            Ok(())
        })
        .unwrap_or_else(|error| panic!("seed legacy profile: {error}"));
    let snapshot = profile(&store, &old);
    let renamed = rename_profile(&store, &old, name("renamed"), &snapshot)
        .unwrap_or_else(|error| panic!("rename profile: {error}"))
        .id;

    let replacement = add_profile(&store, claude_draft("old"))
        .unwrap_or_else(|error| panic!("reuse old label: {error}"));
    assert_eq!(profile(&store, &renamed).state_dir(), legacy);
    assert_eq!(
        fs::read_to_string(legacy.join("live-marker"))
            .unwrap_or_else(|error| panic!("read live marker: {error}")),
        "live identity"
    );
    assert_ne!(profile(&store, &replacement.id).state_dir(), legacy);
}

#[test]
fn legacy_name_derived_storage_remains_valid_but_external_storage_is_rejected() {
    let (_temporary, paths, store) = initialized_store();
    let legacy_id: ProfileId = "codex:legacy"
        .parse()
        .unwrap_or_else(|error| panic!("profile ID: {error}"));
    store
        .update_config(|config| {
            let state_dir = paths.profile_state_dir(legacy_id.provider(), legacy_id.name());
            let profile_uid = ProfileUid::for_state_dir(
                &config.installation_uid,
                legacy_id.provider(),
                &state_dir,
            )?;
            config.profiles.insert(
                legacy_id.clone(),
                Profile::Codex {
                    profile_uid,
                    billing_domain: ctxlane::model::BillingDomain::ChatgptSubscription,
                    auth: CodexAuth::ChatgptOauth,
                    state_dir,
                    secret_ref: None,
                    account_hint: None,
                    expected_workspace_id: None,
                    credential_store: CodexCredentialStore::File,
                    trusted_runners_only: false,
                    wif: None,
                    automation: AutomationPolicy::default(),
                },
            );
            Ok(())
        })
        .unwrap_or_else(|error| panic!("legacy profile: {error}"));
    assert!(store.load_config().is_ok());

    let result = store.update_config(|config| {
        let value = config
            .profiles
            .get_mut(&legacy_id)
            .ok_or_else(|| Error::ProfileNotFound(legacy_id.to_string()))?;
        match value {
            Profile::Codex { state_dir, .. } | Profile::Claude { state_dir, .. } => {
                *state_dir = paths.data_dir.join("outside-provider-root");
            }
        }
        Ok(())
    });
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
    assert_eq!(
        profile(&store, &legacy_id).state_dir(),
        paths.profile_state_dir(legacy_id.provider(), legacy_id.name())
    );

    let legacy_p_name = paths
        .profile_state_root(legacy_id.provider())
        .join("p-personal");
    store
        .update_config(|config| {
            let profile_uid = ProfileUid::for_state_dir(
                &config.installation_uid,
                legacy_id.provider(),
                &legacy_p_name,
            )?;
            let value = config
                .profiles
                .get_mut(&legacy_id)
                .ok_or_else(|| Error::ProfileNotFound(legacy_id.to_string()))?;
            match value {
                Profile::Codex {
                    profile_uid: current_uid,
                    state_dir,
                    ..
                }
                | Profile::Claude {
                    profile_uid: current_uid,
                    state_dir,
                    ..
                } => {
                    *current_uid = profile_uid;
                    *state_dir = legacy_p_name.clone();
                }
            }
            Ok(())
        })
        .unwrap_or_else(|error| panic!("legacy p-name state: {error}"));
    assert_eq!(profile(&store, &legacy_id).state_dir(), legacy_p_name);

    for invalid_leaf in [
        "ünicode-state".to_owned(),
        "has space".to_owned(),
        ".hidden".to_owned(),
        "x".repeat(65),
    ] {
        let result = store.update_config(|config| {
            let value = config
                .profiles
                .get_mut(&legacy_id)
                .ok_or_else(|| Error::ProfileNotFound(legacy_id.to_string()))?;
            match value {
                Profile::Codex { state_dir, .. } | Profile::Claude { state_dir, .. } => {
                    *state_dir = paths
                        .profile_state_root(legacy_id.provider())
                        .join(&invalid_leaf);
                }
            }
            Ok(())
        });
        assert!(matches!(result, Err(Error::InvalidConfig(_))));
    }
}

#[test]
fn managed_state_directories_reject_ascii_case_aliases() {
    let (_temporary, paths, store) = initialized_store();
    let result = store.update_config(|config| {
        for (profile_name, state_name) in [("first", "Slot"), ("second", "slot")] {
            let id: ProfileId = format!("codex:{profile_name}")
                .parse()
                .unwrap_or_else(|error| panic!("profile ID: {error}"));
            let state_dir = paths
                .profile_state_root(ctxlane::model::Provider::Codex)
                .join(state_name);
            let profile_uid =
                ProfileUid::for_state_dir(&config.installation_uid, id.provider(), &state_dir)?;
            config.profiles.insert(
                id,
                Profile::Codex {
                    profile_uid,
                    billing_domain: ctxlane::model::BillingDomain::ChatgptSubscription,
                    auth: CodexAuth::ChatgptOauth,
                    state_dir,
                    secret_ref: None,
                    account_hint: None,
                    expected_workspace_id: None,
                    credential_store: CodexCredentialStore::File,
                    trusted_runners_only: false,
                    wif: None,
                    automation: AutomationPolicy::default(),
                },
            );
        }
        Ok(())
    });
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"))
            .profiles
            .is_empty()
    );
}

#[test]
fn profile_rename_preserves_state_and_secret_and_rewrites_every_context() {
    let (_temporary, _paths, store) = initialized_store();
    let old = add_profile(&store, claude_draft("work"))
        .unwrap_or_else(|error| panic!("add profile: {error}"))
        .id;
    let before = profile(&store, &old);
    let noop = rename_profile(&store, &old, name("work"), &before)
        .unwrap_or_else(|error| panic!("same-name profile rename: {error}"));
    assert_eq!(noop.id, old);
    let marker = before.state_dir().join("session.json");
    fs::write(&marker, "vendor state")
        .unwrap_or_else(|error| panic!("write state marker: {error}"));
    for context_name in ["one", "two"] {
        add_context(
            &store,
            name(context_name),
            Context {
                claude: Some(old.clone()),
                codex: None,
            },
        )
        .unwrap_or_else(|error| panic!("add context: {error}"));
    }

    let renamed = rename_profile(&store, &old, name("company"), &before)
        .unwrap_or_else(|error| panic!("rename: {error}"))
        .id;
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load renamed config: {error}"));
    let after = config
        .profiles
        .get(&renamed)
        .unwrap_or_else(|| panic!("missing renamed profile"));
    assert!(!config.profiles.contains_key(&old));
    assert_eq!(after.state_dir(), before.state_dir());
    assert_eq!(after.secret_ref(), before.secret_ref());
    assert_eq!(after.profile_uid(), before.profile_uid());
    assert_eq!(after.automation(), before.automation());
    assert_eq!(
        fs::read_to_string(marker).unwrap_or_else(|error| panic!("read marker: {error}")),
        "vendor state"
    );
    assert!(
        config
            .contexts
            .values()
            .all(|context| { context.claude.as_ref() == Some(&renamed) })
    );
}

#[test]
fn profile_rename_rejects_case_folded_collisions_and_stale_snapshots() {
    let (_temporary, _paths, store) = initialized_store();
    let first = add_profile(&store, claude_draft("first"))
        .unwrap_or_else(|error| panic!("add first: {error}"))
        .id;
    let second = add_profile(&store, claude_draft("Work"))
        .unwrap_or_else(|error| panic!("add second: {error}"))
        .id;
    let first_snapshot = profile(&store, &first);
    let collision = rename_profile(&store, &first, name("work"), &first_snapshot);
    assert!(matches!(collision, Err(Error::InvalidInput(_))));

    edit_profile(
        &store,
        &first,
        &first_snapshot,
        ProfileEdit::Claude(ClaudeProfileEdit {
            account_hint: ValueEdit::Set("changed@example.test".to_owned()),
            expected_organization: ValueEdit::Keep,
            automation: None,
        }),
    )
    .unwrap_or_else(|error| panic!("edit profile: {error}"));
    let stale = rename_profile(&store, &first, name("new"), &first_snapshot);
    assert!(matches!(stale, Err(Error::ConfigBusy)));
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"))
            .profiles
            .contains_key(&second)
    );
}

#[test]
fn profile_edit_is_tri_state_and_preserves_route_state_and_secret() {
    let (_temporary, _paths, store) = initialized_store();
    let id = add_profile(
        &store,
        ProfileDraft::Claude {
            name: name("work"),
            auth: ClaudeAuth::ApiKey,
            secret_ref: None,
            account_hint: Some("old@example.test".to_owned()),
            expected_organization: Some("old-org".to_owned()),
            wif: None,
        },
    )
    .unwrap_or_else(|error| panic!("add: {error}"))
    .id;
    let before = profile(&store, &id);

    edit_profile(
        &store,
        &id,
        &before,
        ProfileEdit::Claude(ClaudeProfileEdit {
            account_hint: ValueEdit::Clear,
            expected_organization: ValueEdit::Set("new-org".to_owned()),
            automation: None,
        }),
    )
    .unwrap_or_else(|error| panic!("edit: {error}"));
    let after = profile(&store, &id);
    assert_eq!(after.state_dir(), before.state_dir());
    assert_eq!(after.secret_ref(), before.secret_ref());
    assert_eq!(after.auth_label(), before.auth_label());
    assert_eq!(after.profile_uid(), before.profile_uid());
    assert_eq!(after.automation(), before.automation());
    assert_eq!(after.account_hint(), None);
    assert_eq!(after.expected_organization(), Some("new-org"));

    let stale = edit_profile(
        &store,
        &id,
        &before,
        ProfileEdit::Claude(ClaudeProfileEdit::default()),
    );
    assert!(matches!(stale, Err(Error::ConfigBusy)));
    let wrong_provider = edit_profile(
        &store,
        &id,
        &after,
        ProfileEdit::Codex(CodexProfileEdit::default()),
    );
    assert!(matches!(wrong_provider, Err(Error::InvalidInput(_))));

    let automation = AutomationPolicy {
        eligible: true,
        environments: BTreeSet::from(["local-development".to_owned()]),
        roles: BTreeSet::from([AutomationRole::Implementer]),
        caller_subjects: BTreeSet::from(["caller:local-controller".to_owned()]),
        require_workload_identity: false,
        ..AutomationPolicy::default()
    };
    edit_profile(
        &store,
        &id,
        &after,
        ProfileEdit::Claude(ClaudeProfileEdit {
            account_hint: ValueEdit::Keep,
            expected_organization: ValueEdit::Keep,
            automation: Some(automation.clone()),
        }),
    )
    .unwrap_or_else(|error| panic!("edit automation: {error}"));
    let automated = profile(&store, &id);
    assert_eq!(automated.profile_uid(), before.profile_uid());
    assert_eq!(automated.state_dir(), before.state_dir());
    assert_eq!(automated.secret_ref(), before.secret_ref());
    assert_eq!(automated.automation(), &automation);
}

#[test]
fn invalid_profile_drafts_are_rejected_before_a_state_directory_is_created() {
    let (_temporary, paths, store) = initialized_store();
    let result = add_profile(
        &store,
        ProfileDraft::Claude {
            name: name("broken"),
            auth: ClaudeAuth::Wif,
            secret_ref: None,
            account_hint: None,
            expected_organization: None,
            wif: None,
        },
    );
    assert!(matches!(result, Err(Error::InvalidInput(_))));
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"))
            .profiles
            .is_empty()
    );
    let provider_root = paths.profile_state_root(ctxlane::model::Provider::Claude);
    assert!(
        !provider_root.exists()
            || fs::read_dir(provider_root)
                .unwrap_or_else(|error| panic!("read provider root: {error}"))
                .next()
                .is_none()
    );
}

#[test]
fn profile_edit_is_fenced_by_the_legacy_alias_lock() {
    let (_temporary, paths, store) = initialized_store();
    let id = add_profile(&store, claude_draft("locked-edit"))
        .unwrap_or_else(|error| panic!("add: {error}"))
        .id;
    let expected = profile(&store, &id);
    let alias_path = paths.profile_lock(id.provider(), id.name());
    let legacy_guard = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&alias_path)
        .unwrap_or_else(|error| panic!("open alias lock: {error}"));
    legacy_guard
        .lock_shared()
        .unwrap_or_else(|error| panic!("hold legacy shared lock: {error}"));

    let result = edit_profile(
        &store,
        &id,
        &expected,
        ProfileEdit::Claude(ClaudeProfileEdit {
            account_hint: ValueEdit::Set("changed@example.test".to_owned()),
            expected_organization: ValueEdit::Keep,
            automation: None,
        }),
    );
    assert!(matches!(result, Err(Error::PolicyRefused(_))));
    assert_eq!(profile(&store, &id), expected);
}

#[test]
fn codex_wif_edit_cannot_enable_inapplicable_credential_controls() {
    let (temporary, _paths, store) = initialized_store();
    let id = add_profile(
        &store,
        ProfileDraft::Codex {
            name: name("factory"),
            auth: CodexAuth::Wif,
            secret_ref: None,
            account_hint: None,
            expected_workspace_id: None,
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: false,
            wif: Some(CodexWifConfig {
                federation_rule_id: "idpm_factory".to_owned(),
                identity_token_file: temporary.path().join("identity-source/identity.jwt"),
                expected_workspace: "chatgpt-workspace:factory".to_owned(),
                expected_principal: "service-account:factory".to_owned(),
                allowed_environments: BTreeSet::from(["local-development".to_owned()]),
                allowed_workload_labels: BTreeMap::new(),
                workload_identity_context: None,
                minimum_codex_version: "0.148.0".to_owned(),
            }),
        },
    )
    .unwrap_or_else(|error| panic!("add WIF profile: {error}"))
    .id;
    let expected = profile(&store, &id);
    for edit in [
        CodexProfileEdit {
            credential_store: Some(CodexCredentialStore::Keyring),
            ..CodexProfileEdit::default()
        },
        CodexProfileEdit {
            trusted_runners_only: Some(true),
            ..CodexProfileEdit::default()
        },
        CodexProfileEdit {
            expected_workspace_id: ValueEdit::Set("workspace-bypass".to_owned()),
            ..CodexProfileEdit::default()
        },
    ] {
        let result = edit_profile(&store, &id, &expected, ProfileEdit::Codex(edit));
        assert!(matches!(result, Err(Error::InvalidConfig(_))));
        assert_eq!(profile(&store, &id), expected);
    }
}

#[test]
fn profile_remove_refuses_references_then_detaches_state_without_touching_its_secret() {
    let (_temporary, _paths, store) = initialized_store();
    let id = add_profile(&store, claude_draft("retire"))
        .unwrap_or_else(|error| panic!("add: {error}"))
        .id;
    let expected = profile(&store, &id);
    let secret_ref = expected
        .secret_ref()
        .unwrap_or_else(|| panic!("static profile secret ref"))
        .to_owned();
    let marker = expected.state_dir().join("history.json");
    fs::write(&marker, "history").unwrap_or_else(|error| panic!("write marker: {error}"));
    let context_name = name("uses-profile");
    let context = Context {
        claude: Some(id.clone()),
        codex: None,
    };
    add_context(&store, context_name.clone(), context.clone())
        .unwrap_or_else(|error| panic!("add context: {error}"));
    let referenced = remove_profile(&store, &id, &expected);
    assert!(matches!(referenced, Err(Error::InvalidInput(_))));

    remove_context(&store, &context_name, &context)
        .unwrap_or_else(|error| panic!("remove context: {error}"));
    let receipt = remove_profile(&store, &id, &expected)
        .unwrap_or_else(|error| panic!("remove profile: {error}"));
    let detached = receipt
        .detached_state
        .unwrap_or_else(|| panic!("state should be detached"));
    assert_eq!(detached, expected.state_dir());
    assert!(expected.state_dir().exists());
    assert_eq!(
        fs::read_to_string(detached.join("history.json"))
            .unwrap_or_else(|error| panic!("read detached state: {error}")),
        "history"
    );
    let removed = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"));
    assert!(!removed.profiles.contains_key(&id));
    assert!(
        removed
            .retired_profile_uids
            .contains(expected.profile_uid())
    );
    assert!(secret_ref.starts_with("keyring://"));

    let replacement = add_profile(&store, claude_draft("retire"))
        .unwrap_or_else(|error| panic!("recreate alias: {error}"));
    let replacement_profile = profile(&store, &replacement.id);
    assert_ne!(replacement.profile_uid, *expected.profile_uid());
    assert_ne!(replacement_profile.state_dir(), expected.state_dir());
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load recreated config: {error}"))
            .retired_profile_uids
            .contains(expected.profile_uid())
    );
}

#[path = "management_service/context.rs"]
mod context;
