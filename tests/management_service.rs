use std::fs;

use ctxlane::{
    Error,
    config::{AppPaths, MetadataStore},
    management::{
        ClaudeProfileEdit, CodexProfileEdit, ProfileDraft, ProfileEdit, ValueEdit, add_binding,
        add_context, add_profile, edit_binding, edit_context, edit_profile, remove_binding,
        remove_context, remove_profile, rename_context, rename_profile,
    },
    model::{
        ClaudeAuth, CodexAuth, CodexCredentialStore, Context, Name, Profile, ProfileId,
        SCHEMA_VERSION,
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
            config.profiles.insert(
                old.clone(),
                Profile::Claude {
                    billing_domain: ctxlane::model::BillingDomain::AnthropicApi,
                    auth: ClaudeAuth::ApiKey,
                    state_dir: legacy.clone(),
                    secret_ref: Some("keyring://ctxlane/old-ref".to_owned()),
                    account_hint: None,
                    expected_organization: None,
                    wif: None,
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
            config.profiles.insert(
                legacy_id.clone(),
                Profile::Codex {
                    billing_domain: ctxlane::model::BillingDomain::ChatgptSubscription,
                    auth: CodexAuth::ChatgptOauth,
                    state_dir: paths.profile_state_dir(legacy_id.provider(), legacy_id.name()),
                    secret_ref: None,
                    account_hint: None,
                    expected_workspace_id: None,
                    credential_store: CodexCredentialStore::File,
                    trusted_runners_only: false,
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
            let value = config
                .profiles
                .get_mut(&legacy_id)
                .ok_or_else(|| Error::ProfileNotFound(legacy_id.to_string()))?;
            match value {
                Profile::Codex { state_dir, .. } | Profile::Claude { state_dir, .. } => {
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
            config.profiles.insert(
                id,
                Profile::Codex {
                    billing_domain: ctxlane::model::BillingDomain::ChatgptSubscription,
                    auth: CodexAuth::ChatgptOauth,
                    state_dir: paths
                        .profile_state_root(ctxlane::model::Provider::Codex)
                        .join(state_name),
                    secret_ref: None,
                    account_hint: None,
                    expected_workspace_id: None,
                    credential_store: CodexCredentialStore::File,
                    trusted_runners_only: false,
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
        }),
    )
    .unwrap_or_else(|error| panic!("edit: {error}"));
    let after = profile(&store, &id);
    assert_eq!(after.state_dir(), before.state_dir());
    assert_eq!(after.secret_ref(), before.secret_ref());
    assert_eq!(after.auth_label(), before.auth_label());
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
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
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
    assert!(
        !store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"))
            .profiles
            .contains_key(&id)
    );
    assert!(secret_ref.starts_with("keyring://"));
}

#[test]
fn context_crud_rechecks_snapshots_and_renames_nonactive_references_together() {
    let (temporary, _paths, store) = initialized_store();
    let claude = add_profile(&store, claude_draft("personal"))
        .unwrap_or_else(|error| panic!("add Claude: {error}"))
        .id;
    let codex = add_profile(&store, codex_draft("personal"))
        .unwrap_or_else(|error| panic!("add Codex: {error}"))
        .id;
    let old_name = name("personal");
    let original = Context {
        claude: Some(claude),
        codex: None,
    };
    add_context(&store, old_name.clone(), original.clone())
        .unwrap_or_else(|error| panic!("add context: {error}"));
    let project = temporary.path().join("project");
    fs::create_dir(&project).unwrap_or_else(|error| panic!("create project: {error}"));
    add_binding(&store, &project, old_name.clone())
        .unwrap_or_else(|error| panic!("add binding: {error}"));
    store
        .update_state(|_, state| {
            state.current_context = Some(old_name.clone());
            Ok(())
        })
        .unwrap_or_else(|error| panic!("activate context: {error}"));

    let replacement = Context {
        claude: original.claude.clone(),
        codex: Some(codex),
    };
    edit_context(&store, &old_name, &original, replacement.clone())
        .unwrap_or_else(|error| panic!("edit context: {error}"));
    let stale_edit = edit_context(&store, &old_name, &original, replacement.clone());
    assert!(matches!(stale_edit, Err(Error::ConfigBusy)));

    let noop = rename_context(&store, &old_name, old_name.clone(), &replacement)
        .unwrap_or_else(|error| panic!("same-name rename: {error}"));
    assert_eq!(noop.name, old_name);
    let renamed_name = name("home");
    let active_rename = rename_context(&store, &old_name, renamed_name.clone(), &replacement);
    assert!(matches!(active_rename, Err(Error::InvalidInput(_))));
    let (unchanged_config, unchanged_state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load unchanged metadata: {error}"));
    assert_eq!(unchanged_state.current_context.as_ref(), Some(&old_name));
    assert_eq!(unchanged_config.default_context.as_ref(), Some(&old_name));
    assert_eq!(unchanged_config.bindings[0].context, old_name);

    store
        .update_state(|_, state| {
            state.current_context = None;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("clear active context: {error}"));
    rename_context(&store, &old_name, renamed_name.clone(), &replacement)
        .unwrap_or_else(|error| panic!("rename context: {error}"));
    let (config, metadata_state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load metadata: {error}"));
    assert_eq!(metadata_state.version, SCHEMA_VERSION);
    assert_eq!(metadata_state.current_context, None);
    assert_eq!(config.default_context.as_ref(), Some(&renamed_name));
    assert_eq!(config.bindings[0].context, renamed_name);
    assert_eq!(config.contexts.get(&renamed_name), Some(&replacement));
    assert!(!config.contexts.contains_key(&old_name));
}

#[test]
fn context_remove_refuses_active_and_bound_contexts_and_updates_default() {
    let (temporary, _paths, store) = initialized_store();
    let first_name = name("first");
    let second_name = name("second");
    // Context validation requires real profiles, so seed one through the public service.
    let id = add_profile(&store, claude_draft("account"))
        .unwrap_or_else(|error| panic!("add profile: {error}"))
        .id;
    let first = Context {
        claude: Some(id.clone()),
        codex: None,
    };
    let second = Context {
        claude: Some(id),
        codex: None,
    };
    add_context(&store, first_name.clone(), first.clone())
        .unwrap_or_else(|error| panic!("add first: {error}"));
    add_context(&store, second_name.clone(), second.clone())
        .unwrap_or_else(|error| panic!("add second: {error}"));
    store
        .update_state(|_, state| {
            state.current_context = Some(first_name.clone());
            Ok(())
        })
        .unwrap_or_else(|error| panic!("activate: {error}"));
    assert!(matches!(
        remove_context(&store, &first_name, &first),
        Err(Error::InvalidInput(_))
    ));

    store
        .update_state(|_, state| {
            state.current_context = Some(second_name.clone());
            Ok(())
        })
        .unwrap_or_else(|error| panic!("switch: {error}"));
    let project = temporary.path().join("bound");
    fs::create_dir(&project).unwrap_or_else(|error| panic!("create project: {error}"));
    let binding = add_binding(&store, &project, first_name.clone())
        .unwrap_or_else(|error| panic!("bind: {error}"))
        .binding;
    assert!(matches!(
        remove_context(&store, &first_name, &first),
        Err(Error::InvalidInput(_))
    ));
    remove_binding(&store, &binding).unwrap_or_else(|error| panic!("unbind: {error}"));
    remove_context(&store, &first_name, &first).unwrap_or_else(|error| panic!("remove: {error}"));
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"));
    assert_eq!(config.default_context.as_ref(), Some(&second_name));
}

#[test]
fn binding_crud_is_canonical_stale_safe_and_removes_missing_paths() {
    let (temporary, _paths, store) = initialized_store();
    let id = add_profile(&store, codex_draft("work"))
        .unwrap_or_else(|error| panic!("add profile: {error}"))
        .id;
    let first_context = name("first");
    let second_context = name("second");
    for context_name in [&first_context, &second_context] {
        add_context(
            &store,
            context_name.clone(),
            Context {
                claude: None,
                codex: Some(id.clone()),
            },
        )
        .unwrap_or_else(|error| panic!("add context: {error}"));
    }
    let first_path = temporary.path().join("first path");
    let second_path = temporary.path().join("second path");
    fs::create_dir(&first_path).unwrap_or_else(|error| panic!("create first: {error}"));
    fs::create_dir(&second_path).unwrap_or_else(|error| panic!("create second: {error}"));

    let original = add_binding(&store, &first_path, first_context)
        .unwrap_or_else(|error| panic!("add binding: {error}"))
        .binding;
    assert_eq!(
        original.path,
        first_path
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical path: {error}"))
    );
    assert!(matches!(
        add_binding(&store, &first_path, second_context.clone()),
        Err(Error::InvalidInput(_))
    ));

    let edited = edit_binding(&store, &original, &second_path, second_context)
        .unwrap_or_else(|error| panic!("edit binding: {error}"))
        .binding;
    assert!(matches!(
        edit_binding(&store, &original, &first_path, name("first")),
        Err(Error::ConfigBusy)
    ));
    fs::remove_dir(&second_path).unwrap_or_else(|error| panic!("remove bound path: {error}"));
    remove_binding(&store, &edited).unwrap_or_else(|error| panic!("remove binding: {error}"));
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"))
            .bindings
            .is_empty()
    );
}

#[test]
fn binding_edit_rejects_destination_collisions() {
    let (temporary, _paths, store) = initialized_store();
    let id = add_profile(&store, codex_draft("work"))
        .unwrap_or_else(|error| panic!("add profile: {error}"))
        .id;
    let context_name = name("work");
    add_context(
        &store,
        context_name.clone(),
        Context {
            claude: None,
            codex: Some(id),
        },
    )
    .unwrap_or_else(|error| panic!("add context: {error}"));
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    fs::create_dir(&first).unwrap_or_else(|error| panic!("create first: {error}"));
    fs::create_dir(&second).unwrap_or_else(|error| panic!("create second: {error}"));
    let first_binding = add_binding(&store, &first, context_name.clone())
        .unwrap_or_else(|error| panic!("bind first: {error}"))
        .binding;
    add_binding(&store, &second, context_name.clone())
        .unwrap_or_else(|error| panic!("bind second: {error}"));
    let result = edit_binding(&store, &first_binding, &second, context_name);
    assert!(matches!(result, Err(Error::InvalidInput(_))));
}

#[test]
fn profile_edit_validates_codex_policy_without_mutating_on_failure() {
    let (_temporary, _paths, store) = initialized_store();
    let id = add_profile(
        &store,
        ProfileDraft::Codex {
            name: name("runner"),
            auth: CodexAuth::AccessToken,
            secret_ref: None,
            account_hint: None,
            expected_workspace_id: Some("workspace".to_owned()),
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: true,
        },
    )
    .unwrap_or_else(|error| panic!("add: {error}"))
    .id;
    let before = profile(&store, &id);
    let invalid = edit_profile(
        &store,
        &id,
        &before,
        ProfileEdit::Codex(CodexProfileEdit {
            account_hint: ValueEdit::Keep,
            expected_workspace_id: ValueEdit::Keep,
            credential_store: Some(CodexCredentialStore::Keyring),
            trusted_runners_only: Some(false),
        }),
    );
    assert!(matches!(invalid, Err(Error::InvalidConfig(_))));
    assert_eq!(profile(&store, &id), before);
}

#[test]
fn add_context_rejects_empty_or_missing_profile_routes_without_persisting() {
    let (_temporary, _paths, store) = initialized_store();
    let empty = add_context(
        &store,
        name("empty"),
        Context {
            claude: None,
            codex: None,
        },
    );
    assert!(matches!(empty, Err(Error::InvalidConfig(_))));
    let missing = add_context(
        &store,
        name("missing"),
        Context {
            claude: Some(
                "claude:unknown"
                    .parse()
                    .unwrap_or_else(|error| panic!("profile ID: {error}")),
            ),
            codex: None,
        },
    );
    assert!(matches!(missing, Err(Error::InvalidConfig(_))));
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"))
            .contexts
            .is_empty()
    );
}
