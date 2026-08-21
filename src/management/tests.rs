use std::fs;

use tempfile::TempDir;

use super::*;

#[test]
fn failed_post_remove_cleanup_restores_metadata_and_allows_retry() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths);
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize: {error}"));
    let receipt = add_profile(
        &store,
        ProfileDraft::Claude {
            name: Name::parse("work").unwrap_or_else(|error| panic!("name: {error}")),
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
        .unwrap_or_else(|| panic!("profile exists"));
    let marker = expected.state_dir().join("session.json");
    fs::write(&marker, "still here").unwrap_or_else(|error| panic!("write state marker: {error}"));

    let failed = remove_profile_with(&store, &receipt.id, &expected, |_| {
        Err::<(), _>(Error::CredentialStore(
            "injected cleanup failure".to_owned(),
        ))
    });
    assert!(matches!(failed, Err(Error::CredentialStore(_))));
    let restored = store
        .load_config()
        .unwrap_or_else(|error| panic!("load restored profile: {error}"));
    assert_eq!(restored.profiles.get(&receipt.id), Some(&expected));
    assert!(
        !restored
            .retired_profile_uids
            .contains(expected.profile_uid())
    );
    assert_eq!(
        fs::read_to_string(&marker).unwrap_or_else(|error| panic!("read state marker: {error}")),
        "still here"
    );

    let removed = remove_profile(&store, &receipt.id, &expected)
        .unwrap_or_else(|error| panic!("retry removal: {error}"));
    assert_eq!(
        removed.detached_state.as_deref(),
        Some(expected.state_dir())
    );
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load retired profile: {error}"))
            .retired_profile_uids
            .contains(expected.profile_uid())
    );
}
