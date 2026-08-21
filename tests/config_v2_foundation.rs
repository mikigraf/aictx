use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    process::Command,
    sync::{Arc, Barrier},
    thread,
};

use ctxlane::{
    config::{AppPaths, MetadataStore, ensure_secure_directory, write_secure_text},
    management::{ProfileDraft, add_profile, remove_profile},
    model::{
        AutomationPolicy, BillingDomain, CONFIG_SCHEMA_VERSION, ClaudeAuth, CodexAuth,
        CodexCredentialStore, Config, ConfigAuthority, InstallationUid, Name, Profile, ProfileId,
        ProfileUid, Provider, STATE_SCHEMA_VERSION,
    },
};
use tempfile::TempDir;

fn materialize_v1() -> (TempDir, AppPaths, MetadataStore, String) {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let root = temporary.path().join("ctxlane");
    let paths = AppPaths::for_root(&root);
    paths
        .ensure_layout()
        .unwrap_or_else(|error| panic!("layout: {error}"));
    let template = include_str!("fixtures/v0_2_0_schema_v1/config.toml.in");
    let source = template
        .replace("__ROOT__", &toml_path_fragment(&root))
        .replace(
            "__CLAUDE_BIN__",
            &toml_path_fragment(&temporary.path().join("vendor").join("claude")),
        )
        .replace(
            "__CODEX_BIN__",
            &toml_path_fragment(&temporary.path().join("vendor").join("codex")),
        )
        .replace(
            "__TOKEN__",
            &toml_path_fragment(&temporary.path().join("identity.jwt")),
        )
        .replace(
            "__BINDING__",
            &toml_path_fragment(&temporary.path().join("company-project")),
        );
    write_secure_text(&paths.config_file, &source)
        .unwrap_or_else(|error| panic!("write v1 config: {error}"));
    write_secure_text(
        &paths.state_file,
        include_str!("fixtures/v0_2_0_schema_v1/state.toml"),
    )
    .unwrap_or_else(|error| panic!("write v1 state: {error}"));
    let store = MetadataStore::new(paths.clone());
    (temporary, paths, store, source)
}

fn toml_path_fragment(path: &Path) -> String {
    path.to_str()
        .unwrap_or_else(|| panic!("fixture path must be UTF-8: {}", path.display()))
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[test]
fn normal_load_upgrades_frozen_v1_once_while_diagnostics_stay_non_authoritative() {
    let (temporary, paths, store, source) = materialize_v1();
    let state_dir = |provider, name: &str| {
        paths.profile_state_dir(
            provider,
            &Name::parse(name).unwrap_or_else(|error| panic!("fixture state name: {error}")),
        )
    };
    let preserved_state = state_dir(Provider::Claude, "personal");
    ensure_secure_directory(&preserved_state)
        .unwrap_or_else(|error| panic!("create preserved vendor state: {error}"));
    let sentinel = preserved_state.join("session-sentinel.bin");
    write_secure_text(&sentinel, "CREDENTIAL_CANARY_VENDOR_STATE_V1\n")
        .unwrap_or_else(|error| panic!("write vendor-state sentinel: {error}"));
    let missing_state = [
        state_dir(Provider::Claude, "api"),
        state_dir(Provider::Claude, "ci"),
        state_dir(Provider::Codex, "work"),
        state_dir(Provider::Codex, "api"),
        state_dir(Provider::Codex, "ci"),
    ];
    assert!(missing_state.iter().all(|path| !path.exists()));

    let diagnostic = store
        .load_config_for_diagnostics()
        .unwrap_or_else(|error| panic!("diagnostic projection: {error}"));
    assert_eq!(diagnostic.authority(), ConfigAuthority::ProjectedLegacy);
    assert!(!diagnostic.is_authoritative());
    assert!(
        diagnostic
            .profiles
            .values()
            .all(|profile| !profile.automation().eligible)
    );
    assert_eq!(
        fs::read_to_string(&paths.config_file)
            .unwrap_or_else(|error| panic!("read untouched v1: {error}")),
        source
    );

    let (config, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("normal upgrade: {error}"));
    assert_eq!(config.version, CONFIG_SCHEMA_VERSION);
    assert_eq!(state.version, STATE_SCHEMA_VERSION);
    assert!(config.is_authoritative());
    assert!(config.retired_profile_uids.is_empty());
    assert!(
        config
            .profiles
            .values()
            .all(|profile| !profile.automation().eligible)
    );
    let uids = config
        .profiles
        .values()
        .map(|profile| profile.profile_uid().clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(uids.len(), config.profiles.len());
    assert_frozen_v1_semantics(&config, &state, &paths, temporary.path());
    assert_eq!(
        fs::read(&sentinel).unwrap_or_else(|error| panic!("read vendor-state sentinel: {error}")),
        b"CREDENTIAL_CANARY_VENDOR_STATE_V1\n"
    );
    assert!(missing_state.iter().all(|path| !path.exists()));

    let persisted =
        fs::read_to_string(&paths.config_file).unwrap_or_else(|error| panic!("read v2: {error}"));
    assert!(persisted.contains("version = 2"));
    assert!(persisted.contains("installation_uid = \"installation_"));
    assert_eq!(persisted.matches("profile_uid = \"profile_").count(), 6);
    assert!(persisted.matches("[profiles.").count() >= 6);
    assert!(persisted.contains("[profiles.\"claude:personal\".automation]"));
    let persisted_bytes = fs::read(&paths.config_file)
        .unwrap_or_else(|error| panic!("read first persisted v2 bytes: {error}"));

    let again = store
        .load_config()
        .unwrap_or_else(|error| panic!("second load: {error}"));
    assert_eq!(again.installation_uid, config.installation_uid);
    assert_eq!(
        again
            .profiles
            .values()
            .map(Profile::profile_uid)
            .collect::<Vec<_>>(),
        config
            .profiles
            .values()
            .map(Profile::profile_uid)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        fs::read(&paths.config_file)
            .unwrap_or_else(|error| panic!("read second persisted v2 bytes: {error}")),
        persisted_bytes
    );
    assert_eq!(
        fs::read(&sentinel).unwrap_or_else(|error| panic!("reread vendor sentinel: {error}")),
        b"CREDENTIAL_CANARY_VENDOR_STATE_V1\n"
    );
    assert!(missing_state.iter().all(|path| !path.exists()));
}

#[test]
fn active_and_retired_profile_uids_are_disjoint() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = MetadataStore::new(AppPaths::for_root(temporary.path().join("ctxlane")));
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize: {error}"));
    let receipt = add_profile(
        &store,
        ProfileDraft::Claude {
            name: "work"
                .parse()
                .unwrap_or_else(|error| panic!("name: {error}")),
            auth: ClaudeAuth::ApiKey,
            secret_ref: None,
            account_hint: None,
            expected_organization: None,
            wif: None,
        },
    )
    .unwrap_or_else(|error| panic!("add profile: {error}"));
    let result = store.update_config(|config| {
        config
            .retired_profile_uids
            .insert(receipt.profile_uid.clone());
        Ok(())
    });
    assert!(result.is_err());
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load unchanged: {error}"))
            .retired_profile_uids
            .is_empty()
    );
}

#[test]
fn profile_uid_binding_rejects_uid_leaf_tampering_and_case_alias_reuse() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize: {error}"));
    let receipt = add_profile(
        &store,
        ProfileDraft::Claude {
            name: "work"
                .parse()
                .unwrap_or_else(|error| panic!("name: {error}")),
            auth: ClaudeAuth::ApiKey,
            secret_ref: None,
            account_hint: None,
            expected_organization: None,
            wif: None,
        },
    )
    .unwrap_or_else(|error| panic!("add profile: {error}"));
    let expected = store
        .load_config()
        .unwrap_or_else(|error| panic!("load profile: {error}"))
        .profiles
        .get(&receipt.id)
        .cloned()
        .unwrap_or_else(|| panic!("profile"));

    let wrong_uid = ProfileUid::parse("profile_00000000000000000000000001")
        .unwrap_or_else(|error| panic!("wrong UID fixture: {error}"));
    let uid_tamper = store.update_config(|config| {
        set_profile_identity(
            config
                .profiles
                .get_mut(&receipt.id)
                .unwrap_or_else(|| panic!("profile")),
            wrong_uid.clone(),
            expected.state_dir().to_path_buf(),
        );
        Ok(())
    });
    assert!(uid_tamper.is_err());

    let other_state = paths
        .profile_state_root(Provider::Claude)
        .join("different-leaf");
    let leaf_tamper = store.update_config(|config| {
        set_profile_identity(
            config
                .profiles
                .get_mut(&receipt.id)
                .unwrap_or_else(|| panic!("profile")),
            expected.profile_uid().clone(),
            other_state.clone(),
        );
        Ok(())
    });
    assert!(leaf_tamper.is_err());

    remove_profile(&store, &receipt.id, &expected)
        .unwrap_or_else(|error| panic!("remove profile: {error}"));
    let state_leaf = expected
        .state_dir()
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_else(|| panic!("state leaf"));
    let case_alias_state = expected
        .state_dir()
        .parent()
        .unwrap_or_else(|| panic!("state parent"))
        .join(state_leaf.to_ascii_uppercase());
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load retired metadata: {error}"));
    let case_alias_uid = ProfileUid::for_state_dir(
        &config.installation_uid,
        Provider::Claude,
        &case_alias_state,
    )
    .unwrap_or_else(|error| panic!("case alias UID: {error}"));
    assert_eq!(&case_alias_uid, expected.profile_uid());
    let mut resurrected = expected.clone();
    set_profile_identity(&mut resurrected, case_alias_uid, case_alias_state);
    let resurrection = store.update_config(|config| {
        config.profiles.insert(receipt.id.clone(), resurrected);
        Ok(())
    });
    assert!(resurrection.is_err());
}

fn set_profile_identity(
    profile: &mut Profile,
    profile_uid: ProfileUid,
    state_dir: std::path::PathBuf,
) {
    match profile {
        Profile::Claude {
            profile_uid: current_uid,
            state_dir: current_state,
            ..
        }
        | Profile::Codex {
            profile_uid: current_uid,
            state_dir: current_state,
            ..
        } => {
            *current_uid = profile_uid;
            *current_state = state_dir;
        }
    }
}

#[test]
fn malformed_v1_and_v2_config_errors_redact_display_and_debug() {
    for version in [1, 2] {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::for_root(temporary.path().join(format!("ctxlane-{version}")));
        paths
            .ensure_layout()
            .unwrap_or_else(|error| panic!("layout: {error}"));
        let canary = format!("CREDENTIAL_CANARY_CONFIG_V{version}");
        let malformed = format!(
            "version = {version}\naccount_hint = \"{canary}\"\nbroken = [\"unterminated\"\n"
        );
        write_secure_text(&paths.config_file, &malformed)
            .unwrap_or_else(|error| panic!("write malformed: {error}"));
        let Err(error) = MetadataStore::new(paths).load_config() else {
            panic!("malformed config must fail");
        };
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains(&canary));
            assert!(!rendered.contains("unterminated"));
            assert!(rendered.contains("redacted"));
        }
    }
}

#[test]
fn v2_profiles_require_an_explicit_automation_block() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    paths
        .ensure_layout()
        .unwrap_or_else(|error| panic!("layout: {error}"));
    let installation = InstallationUid::parse("installation_00000000000000000000000001")
        .unwrap_or_else(|error| panic!("installation UID: {error}"));
    let state_dir = paths.profile_state_dir(
        Provider::Codex,
        &"personal"
            .parse()
            .unwrap_or_else(|error| panic!("name: {error}")),
    );
    let profile_uid = ProfileUid::for_state_dir(&installation, Provider::Codex, &state_dir)
        .unwrap_or_else(|error| panic!("profile UID: {error}"));
    let text = format!(
        "version = 2\ninstallation_uid = \"{installation}\"\n\n[profiles.\"codex:personal\"]\nprovider = \"codex\"\nprofile_uid = \"{profile_uid}\"\nbilling_domain = \"chatgpt-subscription\"\nauth = \"chatgpt-oauth\"\nstate_dir = \"{}\"\ncredential_store = \"file\"\ntrusted_runners_only = false\n",
        toml_path_fragment(&state_dir)
    );
    write_secure_text(&paths.config_file, &text)
        .unwrap_or_else(|error| panic!("write v2: {error}"));
    assert!(MetadataStore::new(paths).load_config().is_err());
}

#[test]
fn fixture_profile_ids_remain_parseable() {
    for value in [
        "claude:personal",
        "claude:api",
        "claude:ci",
        "codex:work",
        "codex:api",
        "codex:ci",
    ] {
        assert!(value.parse::<ProfileId>().is_ok());
    }
}

#[test]
fn simultaneous_first_v1_loads_publish_one_complete_v2_identity_set() {
    let (_temporary, paths, store, _source) = materialize_v1();
    let workers = 12;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();
    for index in 0..workers {
        let barrier = Arc::clone(&barrier);
        let store = store.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            let result = if index % 2 == 0 {
                store.load_config()
            } else {
                store.update_config(|config| {
                    config.settings.show_run_banner = false;
                    Ok(config.clone())
                })
            };
            match result {
                Ok(config) => Some(config_identity(&config)),
                Err(ctxlane::Error::ConfigBusy) => None,
                Err(error) => panic!("unexpected concurrent upgrade result: {error}"),
            }
        }));
    }

    let successful = handles
        .into_iter()
        .filter_map(|handle| {
            handle
                .join()
                .unwrap_or_else(|_| panic!("upgrade worker panicked"))
        })
        .collect::<Vec<_>>();
    assert!(!successful.is_empty());
    assert!(successful.iter().all(|value| value == &successful[0]));

    let (config, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load final metadata: {error}"));
    assert_eq!(config_identity(&config), successful[0]);
    assert_eq!(config.version, CONFIG_SCHEMA_VERSION);
    assert_eq!(state.version, STATE_SCHEMA_VERSION);
    assert_eq!(config.profiles.len(), 6);
    assert_eq!(
        state.current_context.as_ref().map(ToString::to_string),
        Some("work".to_owned())
    );
    let persisted = fs::read_to_string(&paths.config_file)
        .unwrap_or_else(|error| panic!("read final config: {error}"));
    let parsed: toml::Value =
        toml::from_str(&persisted).unwrap_or_else(|error| panic!("parse final v2: {error}"));
    assert_eq!(
        parsed.get("version").and_then(toml::Value::as_integer),
        Some(2)
    );
}

#[test]
fn doctor_on_frozen_v1_is_stable_and_does_not_persist_projected_uids() {
    let (_temporary, paths, _store, source) = materialize_v1();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ctxlane"))
            .arg("--root")
            .arg(
                paths
                    .config_dir
                    .parent()
                    .unwrap_or_else(|| panic!("explicit root")),
            )
            .args(["doctor", "--provider", "codex", "--json"])
            .output()
            .unwrap_or_else(|error| panic!("run doctor: {error}"))
    };
    let first = run();
    let second = run();
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(second.status.code(), Some(1));
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    let report: serde_json::Value = serde_json::from_slice(&first.stdout)
        .unwrap_or_else(|error| panic!("parse doctor JSON: {error}"));
    assert_eq!(report["ok"], false);
    let rendered = String::from_utf8_lossy(&first.stdout);
    assert!(!rendered.contains("stale"));
    assert!(!rendered.contains("changed while"));
    assert_eq!(
        fs::read_to_string(&paths.config_file)
            .unwrap_or_else(|error| panic!("read unchanged v1 config: {error}")),
        source
    );
}

fn config_identity(config: &Config) -> (String, Vec<(String, String)>) {
    (
        config.installation_uid.to_string(),
        config
            .profiles
            .iter()
            .map(|(id, profile)| (id.to_string(), profile.profile_uid().to_string()))
            .collect(),
    )
}

fn assert_frozen_v1_semantics(
    config: &Config,
    state: &ctxlane::model::MutableState,
    paths: &AppPaths,
    temporary: &Path,
) {
    assert!(!config.settings.require_billing_confirmation_on_change);
    assert!(!config.settings.show_run_banner);
    assert!(!config.settings.telemetry);
    assert_eq!(
        config.binaries.claude,
        temporary.join("vendor").join("claude")
    );
    assert_eq!(
        config.binaries.codex,
        temporary.join("vendor").join("codex")
    );
    assert_eq!(
        config.default_context.as_ref().map(ToString::to_string),
        Some("work".to_owned())
    );
    assert_eq!(
        state.current_context.as_ref().map(ToString::to_string),
        Some("work".to_owned())
    );
    assert_eq!(config.contexts.len(), 2);
    let work = config
        .contexts
        .get(
            &"work"
                .parse()
                .unwrap_or_else(|error| panic!("work: {error}")),
        )
        .unwrap_or_else(|| panic!("work context"));
    assert_eq!(
        work.claude.as_ref().map(ToString::to_string),
        Some("claude:personal".to_owned())
    );
    assert_eq!(
        work.codex.as_ref().map(ToString::to_string),
        Some("codex:work".to_owned())
    );
    let ci = config
        .contexts
        .get(&"ci".parse().unwrap_or_else(|error| panic!("ci: {error}")))
        .unwrap_or_else(|| panic!("ci context"));
    assert_eq!(
        ci.claude.as_ref().map(ToString::to_string),
        Some("claude:ci".to_owned())
    );
    assert_eq!(
        ci.codex.as_ref().map(ToString::to_string),
        Some("codex:ci".to_owned())
    );
    assert_eq!(config.bindings.len(), 1);
    assert_eq!(config.bindings[0].path, temporary.join("company-project"));
    assert_eq!(config.bindings[0].context.to_string(), "work");

    let profile = |id: &str| {
        let id: ProfileId = id
            .parse()
            .unwrap_or_else(|error| panic!("profile ID: {error}"));
        config
            .profiles
            .get(&id)
            .unwrap_or_else(|| panic!("profile {id}"))
    };
    let Profile::Claude {
        billing_domain,
        auth,
        state_dir,
        secret_ref,
        account_hint,
        expected_organization,
        wif,
        automation,
        ..
    } = profile("claude:personal")
    else {
        panic!("Claude personal profile");
    };
    assert_eq!(*billing_domain, BillingDomain::ClaudeSubscription);
    assert_eq!(*auth, ClaudeAuth::SubscriptionToken);
    assert_eq!(
        state_dir,
        &paths.profile_state_root(Provider::Claude).join("personal")
    );
    assert_eq!(
        secret_ref.as_deref(),
        Some("keyring://ctxlane/frozen-claude-personal")
    );
    assert_eq!(account_hint.as_deref(), Some("personal@example.test"));
    assert_eq!(expected_organization.as_deref(), Some("org-personal"));
    assert!(wif.is_none());
    assert_eq!(automation, &AutomationPolicy::default());

    let Profile::Claude {
        billing_domain,
        auth,
        state_dir,
        secret_ref,
        account_hint,
        expected_organization,
        wif,
        automation,
        ..
    } = profile("claude:api")
    else {
        panic!("Claude API profile");
    };
    assert_eq!(*billing_domain, BillingDomain::AnthropicApi);
    assert_eq!(*auth, ClaudeAuth::ApiKey);
    assert_eq!(
        state_dir,
        &paths.profile_state_root(Provider::Claude).join("api")
    );
    assert_eq!(
        secret_ref.as_deref(),
        Some("keyring://ctxlane/frozen-claude-api")
    );
    assert_eq!(account_hint.as_deref(), Some("api@example.test"));
    assert!(expected_organization.is_none());
    assert!(wif.is_none());
    assert_eq!(automation, &AutomationPolicy::default());

    let Profile::Claude {
        billing_domain,
        auth,
        state_dir,
        secret_ref,
        account_hint,
        expected_organization,
        wif: Some(wif),
        automation,
        ..
    } = profile("claude:ci")
    else {
        panic!("Claude WIF profile");
    };
    assert_eq!(*billing_domain, BillingDomain::AnthropicApi);
    assert_eq!(*auth, ClaudeAuth::Wif);
    assert_eq!(
        state_dir,
        &paths.profile_state_root(Provider::Claude).join("ci")
    );
    assert!(secret_ref.is_none());
    assert_eq!(account_hint.as_deref(), Some("ci@example.test"));
    assert_eq!(expected_organization.as_deref(), Some("org-ci"));
    assert_eq!(wif.organization_id, "org-runtime");
    assert_eq!(wif.federation_rule_id, "rule-runtime");
    assert_eq!(wif.service_account_id, "service-runtime");
    assert_eq!(wif.workspace_id.as_deref(), Some("workspace-runtime"));
    assert_eq!(wif.identity_token_file, temporary.join("identity.jwt"));
    assert_eq!(automation, &AutomationPolicy::default());

    assert_codex_profile(
        profile("codex:work"),
        paths,
        "work",
        BillingDomain::ChatgptSubscription,
        CodexAuth::ChatgptOauth,
        None,
        Some("work@example.test"),
        Some("workspace-work"),
        CodexCredentialStore::File,
        false,
    );
    assert_codex_profile(
        profile("codex:api"),
        paths,
        "api",
        BillingDomain::OpenaiApi,
        CodexAuth::ApiKey,
        Some("keyring://ctxlane/frozen-codex-api"),
        Some("openai-api@example.test"),
        None,
        CodexCredentialStore::Keyring,
        false,
    );
    assert_codex_profile(
        profile("codex:ci"),
        paths,
        "ci",
        BillingDomain::ChatgptSubscription,
        CodexAuth::AccessToken,
        Some("keyring://ctxlane/frozen-codex-ci"),
        Some("codex-ci@example.test"),
        Some("workspace-ci"),
        CodexCredentialStore::Auto,
        true,
    );
}

#[allow(clippy::too_many_arguments)]
fn assert_codex_profile(
    profile: &Profile,
    paths: &AppPaths,
    state_leaf: &str,
    expected_billing: BillingDomain,
    expected_auth: CodexAuth,
    expected_secret: Option<&str>,
    expected_hint: Option<&str>,
    expected_workspace: Option<&str>,
    expected_store: CodexCredentialStore,
    expected_trusted: bool,
) {
    let Profile::Codex {
        billing_domain,
        auth,
        state_dir,
        secret_ref,
        account_hint,
        expected_workspace_id,
        credential_store,
        trusted_runners_only,
        wif,
        automation,
        ..
    } = profile
    else {
        panic!("Codex profile");
    };
    assert_eq!(*billing_domain, expected_billing);
    assert_eq!(*auth, expected_auth);
    assert_eq!(
        state_dir,
        &paths.profile_state_root(Provider::Codex).join(state_leaf)
    );
    assert_eq!(secret_ref.as_deref(), expected_secret);
    assert_eq!(account_hint.as_deref(), expected_hint);
    assert_eq!(expected_workspace_id.as_deref(), expected_workspace);
    assert_eq!(*credential_store, expected_store);
    assert_eq!(*trusted_runners_only, expected_trusted);
    assert!(wif.is_none());
    assert_eq!(automation, &AutomationPolicy::default());
}
