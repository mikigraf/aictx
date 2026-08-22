use std::{sync::mpsc, thread, time::Duration};

use super::*;
use crate::{
    Error,
    config::acquire_profile_lock,
    management::{ClaudeProfileEdit, ProfileEdit, ValueEdit, edit_profile},
    runner::{RunOptions, run_profile},
    secret::SecretManager,
};

fn acquire_resource(
    fixture: &Fixture,
    fence: &ProfileAutomationFenceGuard,
    mode: ProfileAutomationResourceMode,
) -> ProfileAutomationResourceAcquisition {
    acquire_profile_automation_resource(
        &fixture.paths,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile.profile_uid(),
        mode,
        fence,
    )
    .unwrap_or_else(|error| panic!("acquire {mode:?} resource: {error}"))
}

fn acquired_resource(
    fixture: &Fixture,
    fence: &ProfileAutomationFenceGuard,
    mode: ProfileAutomationResourceMode,
) -> ProfileAutomationResourceGuard {
    match acquire_resource(fixture, fence, mode) {
        ProfileAutomationResourceAcquisition::Acquired(guard) => guard,
        ProfileAutomationResourceAcquisition::Busy => {
            panic!("{mode:?} resource should be available")
        }
    }
}

#[test]
fn resource_modes_enforce_shared_and_exclusive_lock_semantics() {
    let fixture = fixture();
    let fence = prepare(&fixture);
    let first_shared = acquired_resource(&fixture, &fence, ProfileAutomationResourceMode::Shared);
    let second_shared = acquired_resource(&fixture, &fence, ProfileAutomationResourceMode::Shared);
    first_shared
        .validate_binding(
            &fixture.installation_uid,
            fixture.profile.profile_uid(),
            ProfileAutomationResourceMode::Shared,
        )
        .unwrap_or_else(|error| panic!("validate shared resource: {error}"));
    assert!(matches!(
        acquire_resource(&fixture, &fence, ProfileAutomationResourceMode::Exclusive),
        ProfileAutomationResourceAcquisition::Busy
    ));
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_resource_lock(fixture.profile.profile_uid()),
            true,
        )
        .is_err(),
        "ordinary exclusive profile use must conflict with automation shared use"
    );
    drop((first_shared, second_shared));

    let exclusive = acquired_resource(&fixture, &fence, ProfileAutomationResourceMode::Exclusive);
    for mode in [
        ProfileAutomationResourceMode::Shared,
        ProfileAutomationResourceMode::Exclusive,
    ] {
        assert!(matches!(
            acquire_resource(&fixture, &fence, mode),
            ProfileAutomationResourceAcquisition::Busy
        ));
    }
    drop(exclusive);
    drop(fence);
    clear_recovered(&fixture);
}

#[test]
fn terminal_missing_profile_refusal_does_not_depend_on_alias_availability() {
    let fixture = fixture();
    let missing: ProfileId = "claude:missing"
        .parse()
        .unwrap_or_else(|error| panic!("missing profile ref: {error}"));
    let stale_runner = acquire_profile_lock(
        &fixture
            .paths
            .profile_lock(missing.provider(), missing.name()),
        false,
    )
    .unwrap_or_else(|error| panic!("stale runner alias lock: {error}"));
    let lifecycle = fixture
        .paths
        .profile_lifecycle_lock(fixture.profile.profile_uid());
    assert!(!lifecycle.exists());

    let decision = prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &missing,
        missing.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("missing profile decision: {error}"));
    assert!(matches!(
        decision,
        ProfileAutomationFencePreparation::Refused(ProfileFenceRefusal::ProfileNotFound)
    ));
    assert!(
        !lifecycle.exists(),
        "terminal identity refusal must not create an arbitrary UID lock or fence"
    );
    drop(stale_runner);
}

#[test]
fn fence_preparation_reports_typed_busy_without_publishing_a_marker() {
    let fixture = fixture();
    let alias = acquire_profile_lock(
        &fixture
            .paths
            .profile_lock(fixture.profile_id.provider(), fixture.profile_id.name()),
        false,
    )
    .unwrap_or_else(|error| panic!("ordinary alias lock: {error}"));

    let decision = prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile_id.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("busy fence decision: {error}"));
    assert!(matches!(decision, ProfileAutomationFencePreparation::Busy));
    assert!(
        !fixture
            .paths
            .profile_automation_fence(fixture.profile.profile_uid())
            .exists()
    );

    drop(alias);
    let fence = prepare(&fixture);
    drop(fence);
    clear_recovered(&fixture);
}

#[test]
fn recovery_fence_preparation_reports_typed_busy_and_retries() {
    let fixture = fixture();
    let alias = acquire_profile_lock(
        &fixture
            .paths
            .profile_lock(fixture.profile_id.provider(), fixture.profile_id.name()),
        false,
    )
    .unwrap_or_else(|error| panic!("ordinary alias lock: {error}"));

    let decision = prepare_profile_automation_recovery_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile_id.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("busy recovery fence decision: {error}"));
    assert!(matches!(
        decision,
        ProfileAutomationRecoveryFencePreparation::Busy
    ));
    assert!(
        !fixture
            .paths
            .profile_automation_fence(fixture.profile.profile_uid())
            .exists()
    );

    drop(alias);
    let fence = match prepare_profile_automation_recovery_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile_id.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("retry recovery fence: {error}"))
    {
        ProfileAutomationRecoveryFencePreparation::Prepared(guard) => guard,
        ProfileAutomationRecoveryFencePreparation::Busy => panic!("released alias stayed busy"),
        ProfileAutomationRecoveryFencePreparation::CleanupBusy(_) => {
            panic!("retry recovery fence hit cleanup contention")
        }
        ProfileAutomationRecoveryFencePreparation::CleanupDeferred(error) => {
            panic!("retry recovery fence deferred: {error}")
        }
    };
    upgrade(fence)
        .clear()
        .unwrap_or_else(|error| panic!("clear recovery fence: {error}"));
}

#[test]
fn live_fence_makes_run_and_edit_return_without_waiting_for_release() {
    let fixture = fixture();
    let mut fence = Some(prepare(&fixture));
    let prompt = Duration::from_secs(2);

    let (edit_sender, edit_receiver) = mpsc::channel();
    let edit_store = fixture.store.clone();
    let edit_id = fixture.profile_id.clone();
    let edit_profile_snapshot = fixture.profile.clone();
    let edit_thread = thread::spawn(move || {
        let result = edit_profile(
            &edit_store,
            &edit_id,
            &edit_profile_snapshot,
            ProfileEdit::Claude(ClaudeProfileEdit {
                account_hint: ValueEdit::Set("must-not-land".to_owned()),
                ..ClaudeProfileEdit::default()
            }),
        );
        let _ = edit_sender.send(matches!(result, Err(Error::PolicyRefused(_))));
    });
    let edit_refused = match edit_receiver.recv_timeout(prompt) {
        Ok(refused) => refused,
        Err(error) => {
            drop(fence.take());
            let _ = edit_thread.join();
            panic!("live-fenced edit did not return promptly: {error}");
        }
    };
    edit_thread
        .join()
        .unwrap_or_else(|_| panic!("live-fenced edit thread panicked"));
    assert!(edit_refused);

    let config = fixture
        .store
        .load_config()
        .unwrap_or_else(|error| panic!("load config for run: {error}"));
    let (run_sender, run_receiver) = mpsc::channel();
    let run_paths = fixture.paths.clone();
    let run_id = fixture.profile_id.clone();
    let run_profile_snapshot = fixture.profile.clone();
    let run_cwd = fixture.paths.data_dir.clone();
    let run_thread = thread::spawn(move || {
        let result = run_profile(
            &config,
            &run_paths,
            &run_id,
            &run_profile_snapshot,
            &[],
            &SecretManager::new(),
            &RunOptions {
                cwd: run_cwd,
                non_interactive: true,
                trusted_runner: true,
            },
        );
        let _ = run_sender.send(matches!(result, Err(Error::PolicyRefused(_))));
    });
    let run_refused = match run_receiver.recv_timeout(prompt) {
        Ok(refused) => refused,
        Err(error) => {
            drop(fence.take());
            let _ = run_thread.join();
            panic!("live-fenced run did not return promptly: {error}");
        }
    };
    run_thread
        .join()
        .unwrap_or_else(|_| panic!("live-fenced run thread panicked"));
    assert!(run_refused);

    let unchanged = fixture
        .store
        .load_config()
        .unwrap_or_else(|error| panic!("load unchanged config: {error}"));
    assert_eq!(
        unchanged.profiles.get(&fixture.profile_id),
        Some(&fixture.profile),
        "an operation refused for live-fence contention must not execute later"
    );
    drop(fence.take());
    clear_recovered(&fixture);
}
