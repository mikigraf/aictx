use super::*;

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
    assert_eq!(metadata_state.version, STATE_SCHEMA_VERSION);
    assert_eq!(config.version, CONFIG_SCHEMA_VERSION);
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
            wif: None,
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
            automation: None,
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
