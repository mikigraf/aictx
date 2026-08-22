use super::*;

fn profile_ref(value: &str) -> ProfileId {
    value
        .parse()
        .unwrap_or_else(|error| panic!("profile ref `{value}`: {error}"))
}

fn rename_current(fixture: &Fixture, name: &str) -> ProfileId {
    rename_profile(
        &fixture.store,
        &fixture.profile_id,
        Name::parse(name).unwrap_or_else(|error| panic!("current profile name: {error}")),
        &fixture.profile,
    )
    .unwrap_or_else(|error| panic!("rename current profile: {error}"))
    .id
}

fn prepare_recovery(fixture: &Fixture, historical: &ProfileId) -> ProfileAutomationFenceGuard {
    match prepare_profile_automation_recovery_fence(
        &fixture.store,
        &fixture.installation_uid,
        historical,
        historical.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("prepare recovery fence: {error}"))
    {
        ProfileAutomationRecoveryFencePreparation::Prepared(guard) => guard,
        ProfileAutomationRecoveryFencePreparation::Busy => {
            panic!("recovery aliases should be available")
        }
        ProfileAutomationRecoveryFencePreparation::CleanupBusy(_) => {
            panic!("new recovery fence should not need a cleanup retry")
        }
        ProfileAutomationRecoveryFencePreparation::CleanupDeferred(error) => {
            panic!("new recovery fence should be safe: {error}")
        }
    }
}

fn assert_alias_shared_busy(fixture: &Fixture, profile_ref: &ProfileId) {
    let path = fixture
        .paths
        .profile_lock(profile_ref.provider(), profile_ref.name());
    assert!(
        acquire_profile_lock(&path, false).is_err(),
        "legacy alias {profile_ref} must remain exclusively retained"
    );
}

fn assert_alias_shared_available(fixture: &Fixture, profile_ref: &ProfileId) {
    let path = fixture
        .paths
        .profile_lock(profile_ref.provider(), profile_ref.name());
    assert!(
        acquire_profile_lock(&path, false).is_ok(),
        "legacy alias {profile_ref} should be released after clear"
    );
}

#[test]
fn recovery_fence_retains_historical_current_and_extended_aliases() {
    let fixture = fixture();
    let current = rename_current(&fixture, "current");
    let historical_a = profile_ref("claude:historical-a");
    let historical_b = profile_ref("claude:historical-b");

    let guard = prepare_recovery(&fixture, &historical_a);
    assert_eq!(guard.binding.profile_ref, historical_a);
    assert_alias_shared_busy(&fixture, &historical_a);
    assert_alias_shared_busy(&fixture, &current);
    guard
        .validate_recovery_binding(
            &fixture.installation_uid,
            &current,
            current.provider(),
            fixture.profile.profile_uid(),
        )
        .unwrap_or_else(|error| panic!("current alias membership: {error}"));

    let guard = match extend_profile_automation_recovery_fence_alias(
        &fixture.store,
        &fixture.installation_uid,
        &historical_b,
        historical_b.provider(),
        fixture.profile.profile_uid(),
        guard,
    )
    .unwrap_or_else(|error| panic!("extend recovery aliases: {error}"))
    {
        ProfileAutomationFenceAliasExtension::Extended(guard) => guard,
        ProfileAutomationFenceAliasExtension::Busy(_) => panic!("historical B is available"),
        ProfileAutomationFenceAliasExtension::CleanupDeferred(error) => {
            panic!("same-provider alias extension should be safe: {error}")
        }
    };
    for profile_ref in [&historical_a, &historical_b, &current] {
        assert_alias_shared_busy(&fixture, profile_ref);
        guard
            .validate_recovery_binding(
                &fixture.installation_uid,
                profile_ref,
                profile_ref.provider(),
                fixture.profile.profile_uid(),
            )
            .unwrap_or_else(|error| panic!("retained alias membership: {error}"));
    }

    upgrade(guard)
        .clear()
        .unwrap_or_else(|error| panic!("clear expanded fence: {error}"));
    for profile_ref in [&historical_a, &historical_b, &current] {
        assert_alias_shared_available(&fixture, profile_ref);
    }
}

#[test]
fn startup_recovery_reacquires_representative_and_current_aliases() {
    let fixture = fixture();
    let current = rename_current(&fixture, "current");
    let historical = profile_ref("claude:historical");
    drop(prepare_recovery(&fixture, &historical));

    let guard = recover_one(&fixture);
    assert_eq!(guard.binding.profile_ref, historical);
    assert_alias_shared_busy(&fixture, &historical);
    assert_alias_shared_busy(&fixture, &current);
    guard
        .validate_recovery_binding(
            &fixture.installation_uid,
            &current,
            current.provider(),
            fixture.profile.profile_uid(),
        )
        .unwrap_or_else(|error| panic!("startup current alias membership: {error}"));
    upgrade(guard)
        .clear()
        .unwrap_or_else(|error| panic!("clear startup-recovered fence: {error}"));
}

#[test]
fn contended_alias_extension_is_retryable_without_automation_state() {
    let fixture = fixture();
    let current = rename_current(&fixture, "current");
    let historical_a = profile_ref("claude:historical-a");
    let historical_b = profile_ref("claude:historical-b");
    let guard = prepare_recovery(&fixture, &historical_a);
    let alias_b_path = fixture
        .paths
        .profile_lock(historical_b.provider(), historical_b.name());
    let opposing = acquire_profile_lock(&alias_b_path, false)
        .unwrap_or_else(|error| panic!("opposing historical alias: {error}"));

    let guard = match extend_profile_automation_recovery_fence_alias(
        &fixture.store,
        &fixture.installation_uid,
        &historical_b,
        historical_b.provider(),
        fixture.profile.profile_uid(),
        guard,
    )
    .unwrap_or_else(|error| panic!("contended alias extension: {error}"))
    {
        ProfileAutomationFenceAliasExtension::Busy(guard) => guard,
        ProfileAutomationFenceAliasExtension::Extended(_) => {
            panic!("opposing alias-shared lock must make extension busy")
        }
        ProfileAutomationFenceAliasExtension::CleanupDeferred(error) => {
            panic!("ordinary alias contention must remain retryable: {error}")
        }
    };
    assert_alias_shared_busy(&fixture, &historical_a);
    assert_alias_shared_busy(&fixture, &current);
    assert!(
        !fixture.paths.automation_state_dir().exists(),
        "config-only recovery preparation must not open the lease store"
    );

    drop(opposing);
    let guard = match extend_profile_automation_recovery_fence_alias(
        &fixture.store,
        &fixture.installation_uid,
        &historical_b,
        historical_b.provider(),
        fixture.profile.profile_uid(),
        guard,
    )
    .unwrap_or_else(|error| panic!("retry alias extension: {error}"))
    {
        ProfileAutomationFenceAliasExtension::Extended(guard) => guard,
        ProfileAutomationFenceAliasExtension::Busy(_) => panic!("released alias stayed busy"),
        ProfileAutomationFenceAliasExtension::CleanupDeferred(error) => {
            panic!("retryable alias became unsafe: {error}")
        }
    };
    assert_alias_shared_busy(&fixture, &historical_b);
    upgrade(guard)
        .clear()
        .unwrap_or_else(|error| panic!("clear retried alias fence: {error}"));
}

#[test]
fn cross_provider_alias_extension_fails_closed_without_extending() {
    let fixture = fixture();
    let current = rename_current(&fixture, "current");
    let historical = profile_ref("claude:historical");
    let guard = prepare_recovery(&fixture, &historical);
    let foreign = profile_ref("codex:foreign-history");

    let holder = match extend_profile_automation_recovery_fence_alias(
        &fixture.store,
        &fixture.installation_uid,
        &foreign,
        Provider::Codex,
        fixture.profile.profile_uid(),
        guard,
    )
    .unwrap_or_else(|error| panic!("cross-provider extension decision: {error}"))
    {
        ProfileAutomationFenceAliasExtension::CleanupDeferred(failure) => failure.into_parts().1,
        ProfileAutomationFenceAliasExtension::Busy(_) => {
            panic!("provider mismatch is not ordinary lock contention")
        }
        ProfileAutomationFenceAliasExtension::Extended(_) => {
            panic!("one UID fence must never combine providers")
        }
    };
    assert_alias_shared_busy(&fixture, &historical);
    assert_alias_shared_busy(&fixture, &current);
    assert_alias_shared_available(&fixture, &foreign);
    assert!(
        fixture
            .paths
            .profile_automation_fence(fixture.profile.profile_uid())
            .exists()
    );

    drop(holder);
    clear_recovered(&fixture);
}
