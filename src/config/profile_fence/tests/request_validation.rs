use super::*;

#[test]
fn untrusted_request_aliases_are_refused_without_poisoning_a_valid_fence() {
    let fixture = fixture();
    let fence = prepare(&fixture);
    let marker = fixture
        .paths
        .profile_automation_fence(fixture.profile.profile_uid());

    let missing: ProfileId = "claude:missing"
        .parse()
        .unwrap_or_else(|error| panic!("missing profile ref: {error}"));
    assert_eq!(
        validate_profile_automation_fence_profile(
            &fixture.store,
            &fixture.installation_uid,
            &missing,
            missing.provider(),
            fixture.profile.profile_uid(),
            &fence,
        )
        .unwrap_or_else(|error| panic!("missing request decision: {error}")),
        Some(ProfileFenceRefusal::ProfileNotFound)
    );

    let foreign: ProfileId = "codex:missing"
        .parse()
        .unwrap_or_else(|error| panic!("foreign profile ref: {error}"));
    assert_eq!(
        validate_profile_automation_fence_profile(
            &fixture.store,
            &fixture.installation_uid,
            &foreign,
            foreign.provider(),
            fixture.profile.profile_uid(),
            &fence,
        )
        .unwrap_or_else(|error| panic!("cross-provider request decision: {error}")),
        Some(ProfileFenceRefusal::ProfileNotFound)
    );
    assert_eq!(
        validate_profile_automation_fence_profile(
            &fixture.store,
            &fixture.installation_uid,
            &fixture.profile_id,
            Provider::Codex,
            fixture.profile.profile_uid(),
            &fence,
        )
        .unwrap_or_else(|error| panic!("provider-mismatch request decision: {error}")),
        Some(ProfileFenceRefusal::ProviderMismatch)
    );

    assert!(marker.exists(), "request refusals must retain the marker");
    assert_eq!(
        validate_profile_automation_fence_profile(
            &fixture.store,
            &fixture.installation_uid,
            &fixture.profile_id,
            fixture.profile_id.provider(),
            fixture.profile.profile_uid(),
            &fence,
        )
        .unwrap_or_else(|error| panic!("valid request after refusals: {error}")),
        None,
        "terminal refusals must not poison the retained fence"
    );
    fence
        .validate_binding(&fixture.installation_uid, fixture.profile.profile_uid())
        .unwrap_or_else(|error| panic!("valid fence survived refusals: {error}"));
    upgrade(fence)
        .clear()
        .unwrap_or_else(|error| panic!("clear valid fence: {error}"));
}

#[test]
fn marker_representative_drift_from_authoritative_current_ref_is_hard() {
    let fixture = fixture();
    let fence = prepare(&fixture);
    let replacement = ProfileId::new(
        fixture.profile_id.provider(),
        Name::parse("renamed").unwrap_or_else(|error| panic!("replacement name: {error}")),
    );

    fixture
        .store
        .update_config(|config| {
            let profile = config
                .profiles
                .remove(&fixture.profile_id)
                .ok_or(Error::ConfigBusy)?;
            config.profiles.insert(replacement.clone(), profile);
            Ok(())
        })
        .unwrap_or_else(|error| panic!("inject legacy metadata drift: {error}"));

    assert!(
        validate_profile_automation_fence_profile(
            &fixture.store,
            &fixture.installation_uid,
            &replacement,
            replacement.provider(),
            fixture.profile.profile_uid(),
            &fence,
        )
        .is_err(),
        "a marker bound to the former alias must not authorize the current alias"
    );
    assert!(
        fixture
            .paths
            .profile_automation_fence(fixture.profile.profile_uid())
            .exists(),
        "hard current-binding drift must leave the marker for recovery"
    );

    upgrade(fence)
        .clear()
        .unwrap_or_else(|error| panic!("clear drifted marker under recovery authority: {error}"));
}
