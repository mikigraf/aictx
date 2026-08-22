use super::super::fault;
use super::*;

fn retain_failure(failure: ProfileAutomationFenceFailure) -> ProfileAutomationDeferredFenceGuard {
    failure.into_parts().1
}

fn marker_path(fixture: &Fixture) -> std::path::PathBuf {
    fixture
        .paths
        .profile_automation_fence(fixture.profile.profile_uid())
}

fn assert_alias_shared_busy(fixture: &Fixture, profile_ref: &ProfileId) {
    let path = fixture
        .paths
        .profile_lock(profile_ref.provider(), profile_ref.name());
    assert!(
        acquire_profile_lock(&path, false).is_err(),
        "retained fence state must exclude legacy alias-shared users"
    );
}

fn assert_lifecycle_shared_busy(fixture: &Fixture) {
    let path = fixture
        .paths
        .profile_lifecycle_lock(fixture.profile.profile_uid());
    assert!(
        acquire_profile_lock(&path, false).is_err(),
        "retained exclusive lifecycle state must exclude lifecycle-shared users"
    );
}

fn assert_lifecycle_exclusive_busy(fixture: &Fixture) {
    let path = fixture
        .paths
        .profile_lifecycle_lock(fixture.profile.profile_uid());
    assert!(
        acquire_profile_lock(&path, true).is_err(),
        "retained lifecycle state must exclude lifecycle-exclusive users"
    );
}

#[test]
fn post_create_validation_failure_retains_alias_and_lifecycle_exclusion() {
    let fixture = fixture();
    fault::inject(fault::Point::PostCreateValidation);
    let decision = prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile_id.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("injected preparation: {error}"));
    let holder = match decision {
        ProfileAutomationFencePreparation::CleanupDeferred(failure) => retain_failure(failure),
        _ => panic!("post-create validation must defer cleanup"),
    };

    assert!(marker_path(&fixture).exists());
    assert_alias_shared_busy(&fixture, &fixture.profile_id);
    assert_lifecycle_shared_busy(&fixture);
    drop(holder);
    clear_recovered(&fixture);
}

#[test]
fn recovery_preparation_validation_failure_retains_every_alias() {
    let fixture = fixture();
    let historical: ProfileId = "claude:historical"
        .parse()
        .unwrap_or_else(|error| panic!("historical profile ref: {error}"));
    fault::inject(fault::Point::RecoveryPreparationValidation);
    let decision = prepare_profile_automation_recovery_fence(
        &fixture.store,
        &fixture.installation_uid,
        &historical,
        historical.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("injected recovery preparation: {error}"));
    let holder = match decision {
        ProfileAutomationRecoveryFencePreparation::CleanupDeferred(failure) => {
            retain_failure(failure)
        }
        _ => panic!("recovery validation must defer cleanup"),
    };

    assert!(marker_path(&fixture).exists());
    assert_alias_shared_busy(&fixture, &historical);
    assert_alias_shared_busy(&fixture, &fixture.profile_id);
    assert_lifecycle_shared_busy(&fixture);
    drop(holder);
    clear_recovered(&fixture);
}

#[test]
fn upgrade_validation_failure_retains_exclusive_interlocks() {
    let fixture = fixture();
    let fence = prepare(&fixture);
    fault::inject(fault::Point::UpgradeValidation);
    let holder = match fence.try_upgrade_for_clear() {
        ProfileAutomationFenceUpgrade::CleanupDeferred(failure) => retain_failure(failure),
        _ => panic!("upgrade validation must defer cleanup"),
    };

    assert!(marker_path(&fixture).exists());
    assert_alias_shared_busy(&fixture, &fixture.profile_id);
    assert_lifecycle_shared_busy(&fixture);
    drop(holder);
    clear_recovered(&fixture);
}

#[test]
fn downgrade_validation_failure_retains_alias_and_lifecycle_state() {
    let fixture = fixture();
    let clear = upgrade(prepare(&fixture));
    fault::inject(fault::Point::DowngradeValidation);
    let holder = match clear.downgrade() {
        ProfileAutomationFenceDowngrade::CleanupDeferred(failure) => retain_failure(failure),
        _ => panic!("downgrade validation must defer cleanup"),
    };

    assert!(marker_path(&fixture).exists());
    assert_alias_shared_busy(&fixture, &fixture.profile_id);
    assert_lifecycle_exclusive_busy(&fixture);
    drop(holder);
    clear_recovered(&fixture);
}

#[test]
fn clear_validation_failure_retains_marker_alias_and_lifecycle() {
    let fixture = fixture();
    let clear = upgrade(prepare(&fixture));
    fault::inject(fault::Point::ClearValidation);
    let holder = retain_failure(
        clear
            .clear()
            .err()
            .unwrap_or_else(|| panic!("clear validation fault must fail")),
    );

    assert!(marker_path(&fixture).exists());
    assert_alias_shared_busy(&fixture, &fixture.profile_id);
    assert_lifecycle_shared_busy(&fixture);
    drop(holder);
    clear_recovered(&fixture);
}

#[test]
fn parent_sync_failure_retains_exclusion_after_marker_unlink() {
    let fixture = fixture();
    let clear = upgrade(prepare(&fixture));
    fault::inject(fault::Point::ClearParentSync);
    let holder = retain_failure(
        clear
            .clear()
            .err()
            .unwrap_or_else(|| panic!("parent sync fault must fail")),
    );

    assert!(
        !marker_path(&fixture).exists(),
        "the injected failure occurs after the exact marker unlink"
    );
    assert_alias_shared_busy(&fixture, &fixture.profile_id);
    assert_lifecycle_shared_busy(&fixture);
    drop(holder);

    let alias = fixture
        .paths
        .profile_lock(fixture.profile_id.provider(), fixture.profile_id.name());
    assert!(acquire_profile_lock(&alias, false).is_ok());
    let lifecycle = fixture
        .paths
        .profile_lifecycle_lock(fixture.profile.profile_uid());
    assert!(acquire_profile_lock(&lifecycle, false).is_ok());
    assert!(
        recover_profile_automation_fences(&fixture.paths, &fixture.installation_uid)
            .unwrap_or_else(|error| panic!("empty recovery after unlink: {error}"))
            .is_empty()
    );
}
