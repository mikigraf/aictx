use super::*;

#[test]
fn names_are_path_safe() {
    assert!(Name::parse("work-2").is_ok());
    assert!(Name::parse("../work").is_err());
    assert!(Name::parse("with space").is_err());
    assert!(Name::parse("").is_err());
}

#[test]
fn profile_ids_round_trip() {
    let parsed: ProfileId = "claude:personal".parse().unwrap_or_else(|error| {
        panic!("valid profile ID should parse: {error}");
    });
    assert_eq!(parsed.provider(), Provider::Claude);
    assert_eq!(parsed.name().as_str(), "personal");
    assert_eq!(parsed.to_string(), "claude:personal");
}

#[test]
fn default_config_round_trips() {
    let config = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
    let text = toml::to_string_pretty(&config).unwrap_or_else(|error| {
        panic!("default config should serialize: {error}");
    });
    let decoded: Config = toml::from_str(&text).unwrap_or_else(|error| {
        panic!("default config should deserialize: {error}");
    });
    assert_eq!(decoded, config);
    assert!(decoded.validate().is_ok());
}

#[test]
fn profile_names_and_state_directories_are_ascii_case_fold_unique() {
    let root = std::env::temp_dir().join("ctxlane-model-case-fold-test");
    let profile = |installation_uid: &InstallationUid, state_dir: PathBuf| Profile::Codex {
        profile_uid: ProfileUid::for_state_dir(installation_uid, Provider::Codex, &state_dir)
            .unwrap_or_else(|error| panic!("profile UID: {error}")),
        billing_domain: BillingDomain::ChatgptSubscription,
        auth: CodexAuth::ChatgptOauth,
        state_dir,
        secret_ref: None,
        account_hint: None,
        expected_workspace_id: None,
        credential_store: CodexCredentialStore::File,
        trusted_runners_only: false,
        wif: None,
        automation: AutomationPolicy::default(),
    };

    let mut names = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
    names.profiles.insert(
        ProfileId::new(
            Provider::Codex,
            Name::parse("Work").unwrap_or_else(|error| panic!("name: {error}")),
        ),
        profile(&names.installation_uid, root.join("Work")),
    );
    names.profiles.insert(
        ProfileId::new(
            Provider::Codex,
            Name::parse("work").unwrap_or_else(|error| panic!("name: {error}")),
        ),
        profile(&names.installation_uid, root.join("work-elsewhere")),
    );
    let name_error = match names.validate() {
        Err(error) => error.to_string(),
        Ok(()) => panic!("case-folded profile names should be rejected"),
    };
    assert!(name_error.contains("ASCII case folding"));

    let mut directories = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
    directories.profiles.insert(
        ProfileId::new(
            Provider::Codex,
            Name::parse("first").unwrap_or_else(|error| panic!("name: {error}")),
        ),
        profile(&directories.installation_uid, root.join("VendorState")),
    );
    directories.profiles.insert(
        ProfileId::new(
            Provider::Codex,
            Name::parse("second").unwrap_or_else(|error| panic!("name: {error}")),
        ),
        profile(&directories.installation_uid, root.join("vendorstate")),
    );
    let directory_error = match directories.validate() {
        Err(error) => error.to_string(),
        Ok(()) => panic!("case-folded state directories should be rejected"),
    };
    assert!(directory_error.contains("ASCII-case-fold aliases"));
}

#[test]
fn persisted_metadata_and_paths_reject_control_characters() {
    let root = std::env::temp_dir().join("ctxlane-model-control-test");
    let profile_id = ProfileId::new(
        Provider::Codex,
        Name::parse("work").unwrap_or_else(|error| panic!("name: {error}")),
    );
    let mut config = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
    let state_dir = root.join("state");
    let immutable_uid =
        ProfileUid::for_state_dir(&config.installation_uid, Provider::Codex, &state_dir)
            .unwrap_or_else(|error| panic!("profile UID: {error}"));
    config.profiles.insert(
        profile_id,
        Profile::Codex {
            profile_uid: immutable_uid,
            billing_domain: BillingDomain::ChatgptSubscription,
            auth: CodexAuth::ChatgptOauth,
            state_dir,
            secret_ref: None,
            account_hint: Some("visible\nterminal-control".to_owned()),
            expected_workspace_id: None,
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: false,
            wif: None,
            automation: AutomationPolicy::default(),
        },
    );
    let Err(error) = config.validate() else {
        panic!("control characters in persisted profile metadata should be rejected");
    };
    assert!(error.to_string().contains("control characters"));

    let mut config = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
    config.binaries.codex = root.join("codex\u{1b}[31m");
    let Err(error) = config.validate() else {
        panic!("control characters in persisted paths should be rejected");
    };
    assert!(error.to_string().contains("control characters"));
}
