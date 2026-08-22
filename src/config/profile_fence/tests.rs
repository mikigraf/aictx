#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{FileExt, MetadataExt, PermissionsExt, symlink},
};

#[cfg(target_os = "linux")]
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use tempfile::TempDir;

use super::marker::encode_marker;
use super::*;
use crate::{
    config::acquire_profile_lock,
    management::{
        ClaudeProfileEdit, ProfileDraft, ProfileEdit, add_profile, edit_profile, remove_profile,
        rename_profile,
    },
    model::{ClaudeAuth, Name, Profile},
};

mod aliases;
mod contention;
mod deferred;
mod request_validation;

struct Fixture {
    _temporary: TempDir,
    paths: AppPaths,
    store: MetadataStore,
    installation_uid: InstallationUid,
    profile_id: ProfileId,
    profile: Profile,
}

fn fixture() -> Fixture {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize: {error}"));
    let receipt = add_profile(
        &store,
        ProfileDraft::Claude {
            name: Name::parse("work").unwrap_or_else(|error| panic!("profile name: {error}")),
            auth: ClaudeAuth::ApiKey,
            secret_ref: None,
            account_hint: None,
            expected_organization: None,
            wif: None,
        },
    )
    .unwrap_or_else(|error| panic!("add profile: {error}"));
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"));
    let profile = config
        .profiles
        .get(&receipt.id)
        .cloned()
        .unwrap_or_else(|| panic!("new profile exists"));
    Fixture {
        _temporary: temporary,
        paths,
        store,
        installation_uid: config.installation_uid,
        profile_id: receipt.id,
        profile,
    }
}

fn prepare(fixture: &Fixture) -> ProfileAutomationFenceGuard {
    match prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile_id.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("prepare fence: {error}"))
    {
        ProfileAutomationFencePreparation::Prepared(guard) => guard,
        ProfileAutomationFencePreparation::Refused(_) => {
            panic!("current profile should produce a fence")
        }
        ProfileAutomationFencePreparation::Busy => panic!("current profile should not be busy"),
        ProfileAutomationFencePreparation::CleanupBusy(_) => {
            panic!("new profile fence unexpectedly hit cleanup contention")
        }
        ProfileAutomationFencePreparation::CleanupDeferred(error) => {
            panic!("new profile fence unexpectedly needs recovery: {error}")
        }
    }
}

fn upgrade(guard: ProfileAutomationFenceGuard) -> ProfileAutomationFenceClearGuard {
    match guard.try_upgrade_for_clear() {
        ProfileAutomationFenceUpgrade::Exclusive(guard) => guard,
        ProfileAutomationFenceUpgrade::Busy(_) => {
            panic!("exclusive conversion should not be busy")
        }
        ProfileAutomationFenceUpgrade::CleanupDeferred(error) => {
            panic!("exclusive conversion should succeed: {error}")
        }
    }
}

fn upgrade_busy(guard: ProfileAutomationFenceBusyGuard) -> ProfileAutomationFenceClearGuard {
    match guard.try_upgrade_for_clear() {
        ProfileAutomationFenceUpgrade::Exclusive(guard) => guard,
        ProfileAutomationFenceUpgrade::Busy(_) => {
            panic!("released lifecycle contention stayed busy")
        }
        ProfileAutomationFenceUpgrade::CleanupDeferred(error) => {
            panic!("retryable lifecycle contention became unsafe: {error}")
        }
    }
}

fn recover_one(fixture: &Fixture) -> ProfileAutomationFenceGuard {
    let mut recovered =
        recover_profile_automation_fences(&fixture.paths, &fixture.installation_uid)
            .unwrap_or_else(|error| panic!("recover fences: {error}"));
    assert_eq!(recovered.len(), 1);
    recovered
        .remove(fixture.profile.profile_uid())
        .unwrap_or_else(|| panic!("profile fence was recovered"))
}

fn clear_recovered(fixture: &Fixture) {
    upgrade(recover_one(fixture))
        .clear()
        .unwrap_or_else(|error| panic!("clear recovered fence: {error}"));
}

#[test]
fn zero_marker_recovery_does_not_require_metadata_config() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    paths
        .ensure_layout()
        .unwrap_or_else(|error| panic!("initialize layout: {error}"));
    let installation_uid =
        InstallationUid::generate().unwrap_or_else(|error| panic!("installation UID: {error}"));

    let recovered = recover_profile_automation_fences(&paths, &installation_uid)
        .unwrap_or_else(|error| panic!("empty recovery scan: {error}"));
    assert!(recovered.is_empty());
    assert!(!paths.config_file.exists());
}

#[test]
fn preparation_publishes_a_private_durable_cloexec_marker_and_resource_lock() {
    let fixture = fixture();
    let fence = prepare(&fixture);
    let marker = fixture
        .paths
        .profile_automation_fence(fixture.profile.profile_uid());
    let metadata =
        fs::symlink_metadata(&marker).unwrap_or_else(|error| panic!("marker metadata: {error}"));
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    let fd_flags = rustix::io::fcntl_getfd(&fence.binding.marker)
        .unwrap_or_else(|error| panic!("marker fd flags: {error}"));
    assert!(fd_flags.contains(rustix::io::FdFlags::CLOEXEC));
    fence
        .validate_binding(&fixture.installation_uid, fixture.profile.profile_uid())
        .unwrap_or_else(|error| panic!("validate fence: {error}"));

    let resource = match acquire_profile_automation_resource(
        &fixture.paths,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile.profile_uid(),
        ProfileAutomationResourceMode::Exclusive,
        &fence,
    )
    .unwrap_or_else(|error| panic!("acquire resource: {error}"))
    {
        ProfileAutomationResourceAcquisition::Acquired(resource) => resource,
        ProfileAutomationResourceAcquisition::Busy => panic!("resource should be available"),
    };
    resource
        .validate_binding(
            &fixture.installation_uid,
            fixture.profile.profile_uid(),
            ProfileAutomationResourceMode::Exclusive,
        )
        .unwrap_or_else(|error| panic!("validate resource: {error}"));
    assert!(
        resource
            .validate_binding(
                &fixture.installation_uid,
                fixture.profile.profile_uid(),
                ProfileAutomationResourceMode::Shared,
            )
            .is_err(),
        "the resource capability must bind its acquisition mode"
    );
    assert!(
        matches!(
            acquire_profile_automation_resource(
                &fixture.paths,
                &fixture.installation_uid,
                &fixture.profile_id,
                fixture.profile.profile_uid(),
                ProfileAutomationResourceMode::Exclusive,
                &fence,
            )
            .unwrap_or_else(|error| panic!("contended resource decision: {error}")),
            ProfileAutomationResourceAcquisition::Busy
        ),
        "one process-local resource guard must not prove shared-home isolation"
    );
    drop(resource);
    assert!(matches!(
        acquire_profile_automation_resource(
            &fixture.paths,
            &fixture.installation_uid,
            &fixture.profile_id,
            fixture.profile.profile_uid(),
            ProfileAutomationResourceMode::Exclusive,
            &fence,
        )
        .unwrap_or_else(|error| panic!("reacquire resource: {error}")),
        ProfileAutomationResourceAcquisition::Acquired(_)
    ));

    drop(fence);
    assert!(
        marker.exists(),
        "dropping the guard must not clear durability"
    );
    clear_recovered(&fixture);
    assert!(!marker.exists());
}

#[test]
fn an_existing_marker_is_recovery_only_and_is_never_adopted_by_prepare() {
    let fixture = fixture();
    drop(prepare(&fixture));
    let decision = prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile_id.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("existing marker decision: {error}"));
    let ProfileAutomationFencePreparation::CleanupDeferred(failure) = decision else {
        panic!("an existing marker must require recovery");
    };
    drop(failure);
    clear_recovered(&fixture);
}

#[test]
fn fence_retains_the_legacy_alias_exclusive_across_unresolved_state() {
    let fixture = fixture();
    let alias_path = fixture
        .paths
        .profile_lock(fixture.profile_id.provider(), fixture.profile_id.name());
    let old_runner = acquire_profile_lock(&alias_path, false)
        .unwrap_or_else(|error| panic!("simulate old runner: {error}"));
    let decision = prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile_id.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("pre-upgrade runner contention: {error}"));
    assert!(
        matches!(decision, ProfileAutomationFencePreparation::Busy),
        "automation must drain a pre-upgrade alias-shared runner"
    );
    assert!(
        !fixture
            .paths
            .profile_automation_fence(fixture.profile.profile_uid())
            .exists()
    );
    drop(old_runner);

    let fence = prepare(&fixture);
    assert!(
        acquire_profile_lock(&alias_path, false).is_err(),
        "the durable fence guard must retain alias-exclusive"
    );
    drop(fence);
    clear_recovered(&fixture);
}

#[test]
fn pre_marker_requested_recovery_can_fence_a_historical_profile_ref() {
    let fixture = fixture();
    let historical: ProfileId = "claude:historical"
        .parse()
        .unwrap_or_else(|error| panic!("historical profile ref: {error}"));
    let guard = match prepare_profile_automation_recovery_fence(
        &fixture.store,
        &fixture.installation_uid,
        &historical,
        historical.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("prepare historical recovery fence: {error}"))
    {
        ProfileAutomationRecoveryFencePreparation::Prepared(guard) => guard,
        ProfileAutomationRecoveryFencePreparation::Busy => {
            panic!("recovery profile should not be busy")
        }
        ProfileAutomationRecoveryFencePreparation::CleanupBusy(_) => {
            panic!("historical recovery fence unexpectedly hit cleanup contention")
        }
        ProfileAutomationRecoveryFencePreparation::CleanupDeferred(error) => {
            panic!("historical recovery fence unexpectedly deferred: {error}")
        }
    };
    assert!(
        profile_automation_fence_presence(&fixture.paths, fixture.profile.profile_uid())
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );
    guard
        .validate_recovery_binding(
            &fixture.installation_uid,
            &historical,
            historical.provider(),
            fixture.profile.profile_uid(),
        )
        .unwrap_or_else(|error| panic!("historical binding: {error}"));
    assert!(
        guard
            .validate_recovery_binding(
                &fixture.installation_uid,
                &historical,
                Provider::Codex,
                fixture.profile.profile_uid(),
            )
            .is_err(),
        "persisted provider mismatch must not borrow a recovered capability"
    );
    assert_eq!(
        validate_profile_automation_fence_profile(
            &fixture.store,
            &fixture.installation_uid,
            &historical,
            historical.provider(),
            fixture.profile.profile_uid(),
            &guard,
        )
        .unwrap_or_else(|error| panic!("historical currentness decision: {error}")),
        Some(ProfileFenceRefusal::ProfileNotFound)
    );
    assert!(
        validate_profile_automation_fence_profile(
            &fixture.store,
            &fixture.installation_uid,
            &fixture.profile_id,
            fixture.profile_id.provider(),
            fixture.profile.profile_uid(),
            &guard,
        )
        .is_err(),
        "a recovered old alias must never authorize the renamed current alias"
    );
    assert!(
        acquire_profile_automation_resource(
            &fixture.paths,
            &fixture.installation_uid,
            &fixture.profile_id,
            fixture.profile.profile_uid(),
            ProfileAutomationResourceMode::Exclusive,
            &guard,
        )
        .is_err()
    );
    drop(guard);
    clear_recovered(&fixture);
}

#[test]
fn terminal_identity_refusals_create_no_marker() {
    let fixture = fixture();
    let marker = fixture
        .paths
        .profile_automation_fence(fixture.profile.profile_uid());
    let missing: ProfileId = "claude:missing"
        .parse()
        .unwrap_or_else(|error| panic!("missing profile ref: {error}"));
    let missing_result = prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &missing,
        missing.provider(),
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("missing profile decision: {error}"));
    assert!(matches!(
        missing_result,
        ProfileAutomationFencePreparation::Refused(ProfileFenceRefusal::ProfileNotFound)
    ));
    assert!(!marker.exists());

    let provider_result = prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        Provider::Codex,
        fixture.profile.profile_uid(),
    )
    .unwrap_or_else(|error| panic!("provider decision: {error}"));
    assert!(matches!(
        provider_result,
        ProfileAutomationFencePreparation::Refused(ProfileFenceRefusal::ProviderMismatch)
    ));
    assert!(!marker.exists());

    let other_uid = ProfileUid::for_state_dir(
        &fixture.installation_uid,
        fixture.profile_id.provider(),
        &fixture
            .paths
            .profile_state_root(fixture.profile_id.provider())
            .join("other"),
    )
    .unwrap_or_else(|error| panic!("other profile uid: {error}"));
    let uid_result = prepare_profile_automation_fence(
        &fixture.store,
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile_id.provider(),
        &other_uid,
    )
    .unwrap_or_else(|error| panic!("UID decision: {error}"));
    assert!(matches!(
        uid_result,
        ProfileAutomationFencePreparation::Refused(ProfileFenceRefusal::ProfileNotFound)
    ));
    assert!(!fixture.paths.profile_automation_fence(&other_uid).exists());

    let other_installation = InstallationUid::generate()
        .unwrap_or_else(|error| panic!("other installation UID: {error}"));
    assert!(
        prepare_profile_automation_fence(
            &fixture.store,
            &other_installation,
            &fixture.profile_id,
            fixture.profile_id.provider(),
            fixture.profile.profile_uid(),
        )
        .is_err()
    );
    assert!(!marker.exists());
}

#[test]
fn contended_upgrade_is_retryable_and_leaves_the_marker() {
    let fixture = fixture();
    let fence = prepare(&fixture);
    let marker = fixture
        .paths
        .profile_automation_fence(fixture.profile.profile_uid());
    let opposing_shared = acquire_profile_lock(
        &fixture
            .paths
            .profile_lifecycle_lock(fixture.profile.profile_uid()),
        false,
    )
    .unwrap_or_else(|error| panic!("opposing shared lifecycle guard: {error}"));
    let busy = match fence.try_upgrade_for_clear() {
        ProfileAutomationFenceUpgrade::Busy(guard) => guard,
        ProfileAutomationFenceUpgrade::CleanupDeferred(error) => {
            panic!("ordinary lifecycle contention must remain retryable: {error}")
        }
        ProfileAutomationFenceUpgrade::Exclusive(_) => {
            panic!("opposing shared lifecycle lock must prevent exclusive conversion")
        }
    };
    assert!(marker.exists());
    let alias_path = fixture
        .paths
        .profile_lock(fixture.profile_id.provider(), fixture.profile_id.name());
    assert!(acquire_profile_lock(&alias_path, false).is_err());
    drop(opposing_shared);
    upgrade_busy(busy)
        .clear()
        .unwrap_or_else(|error| panic!("clear retried fence: {error}"));
    assert!(!marker.exists());
}

#[test]
fn successful_downgrade_retains_shared_lifecycle_exclusion() {
    let fixture = fixture();
    let clear = upgrade(prepare(&fixture));
    let fence = match clear.downgrade() {
        ProfileAutomationFenceDowngrade::Shared(guard) => guard,
        ProfileAutomationFenceDowngrade::Busy(_) => panic!("downgrade should not be busy"),
        ProfileAutomationFenceDowngrade::CleanupDeferred(error) => {
            panic!("downgrade should succeed: {error}")
        }
    };
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_lifecycle_lock(fixture.profile.profile_uid()),
            true,
        )
        .is_err(),
        "downgraded guard must still exclude metadata mutation"
    );
    drop(fence);
    clear_recovered(&fixture);
}

#[test]
fn in_place_fence_id_tampering_invalidates_the_live_capability() {
    let fixture = fixture();
    let fence = prepare(&fixture);
    let marker = fixture
        .paths
        .profile_automation_fence(fixture.profile.profile_uid());
    let bytes = fs::read(&marker).unwrap_or_else(|error| panic!("read marker: {error}"));
    let last_hex = bytes
        .len()
        .checked_sub(3)
        .unwrap_or_else(|| panic!("marker contains a fence id"));
    let replacement = if bytes[last_hex] == b'a' { b'b' } else { b'a' };
    let writable = OpenOptions::new()
        .write(true)
        .open(&marker)
        .unwrap_or_else(|error| panic!("open marker for injected tamper: {error}"));
    assert_eq!(
        writable
            .write_at(&[replacement], u64::try_from(last_hex).unwrap_or(u64::MAX))
            .unwrap_or_else(|error| panic!("tamper marker: {error}")),
        1
    );
    writable
        .sync_all()
        .unwrap_or_else(|error| panic!("sync tamper: {error}"));

    assert!(
        fence
            .validate_binding(&fixture.installation_uid, fixture.profile.profile_uid())
            .is_err()
    );
    assert!(
        acquire_profile_automation_resource(
            &fixture.paths,
            &fixture.installation_uid,
            &fixture.profile_id,
            fixture.profile.profile_uid(),
            ProfileAutomationResourceMode::Exclusive,
            &fence,
        )
        .is_err()
    );
    assert!(matches!(
        fence.try_upgrade_for_clear(),
        ProfileAutomationFenceUpgrade::CleanupDeferred(_)
    ));
    assert!(marker.exists());

    // Recovery binds the now-durable bytes as a new orphan capability; only
    // an explicit zero-blocker recovery clear may remove it.
    clear_recovered(&fixture);
}

#[test]
fn unsafe_existing_markers_fail_closed_without_mutating_link_targets() {
    let fixture = fixture();
    let marker = fixture
        .paths
        .profile_automation_fence(fixture.profile.profile_uid());
    let target = marker
        .parent()
        .unwrap_or_else(|| panic!("marker has parent"))
        .join("external-target");
    fs::write(&target, b"do not change").unwrap_or_else(|error| panic!("write target: {error}"));
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("secure target: {error}"));

    symlink(&target, &marker).unwrap_or_else(|error| panic!("symlink marker: {error}"));
    assert!(matches!(
        prepare_profile_automation_fence(
            &fixture.store,
            &fixture.installation_uid,
            &fixture.profile_id,
            fixture.profile_id.provider(),
            fixture.profile.profile_uid(),
        )
        .unwrap_or_else(|error| panic!("symlink marker decision: {error}")),
        ProfileAutomationFencePreparation::CleanupDeferred(_)
    ));
    assert!(recover_profile_automation_fences(&fixture.paths, &fixture.installation_uid).is_err());
    assert_eq!(
        fs::read(&target).unwrap_or_else(|error| panic!("read symlink target: {error}")),
        b"do not change"
    );
    fs::remove_file(&marker).unwrap_or_else(|error| panic!("remove symlink: {error}"));

    fs::hard_link(&target, &marker).unwrap_or_else(|error| panic!("hard-link marker: {error}"));
    assert!(recover_profile_automation_fences(&fixture.paths, &fixture.installation_uid).is_err());
    assert_eq!(
        fs::read(&target).unwrap_or_else(|error| panic!("read hard-link target: {error}")),
        b"do not change"
    );
    assert_eq!(
        fs::metadata(&target)
            .unwrap_or_else(|error| panic!("target metadata: {error}"))
            .nlink(),
        2
    );
    fs::remove_file(&marker).unwrap_or_else(|error| panic!("remove hard link: {error}"));

    let bytes = encode_marker(
        &fixture.installation_uid,
        &fixture.profile_id,
        fixture.profile.profile_uid(),
        "fence_00000000000000000000000000000000",
    );
    fs::write(&marker, &bytes).unwrap_or_else(|error| panic!("write marker: {error}"));
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|error| panic!("set unsafe marker mode: {error}"));
    assert!(recover_profile_automation_fences(&fixture.paths, &fixture.installation_uid).is_err());
    assert_eq!(
        fs::metadata(&marker)
            .unwrap_or_else(|error| panic!("marker metadata: {error}"))
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    assert_eq!(
        fs::read(&marker).unwrap_or_else(|error| panic!("read unsafe marker: {error}")),
        bytes
    );
}

#[test]
fn recovery_rejects_duplicate_legacy_alias_bindings_across_uids() {
    let fixture = fixture();
    drop(prepare(&fixture));
    let other_uid = ProfileUid::for_state_dir(
        &fixture.installation_uid,
        fixture.profile_id.provider(),
        &fixture
            .paths
            .profile_state_root(fixture.profile_id.provider())
            .join("duplicate-alias"),
    )
    .unwrap_or_else(|error| panic!("other profile uid: {error}"));
    let duplicate = fixture.paths.profile_automation_fence(&other_uid);
    let bytes = encode_marker(
        &fixture.installation_uid,
        &fixture.profile_id,
        &other_uid,
        "fence_11111111111111111111111111111111",
    );
    fs::write(&duplicate, bytes)
        .unwrap_or_else(|error| panic!("write duplicate alias marker: {error}"));
    fs::set_permissions(&duplicate, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("secure duplicate marker: {error}"));

    let error = recover_profile_automation_fences(&fixture.paths, &fixture.installation_uid)
        .err()
        .unwrap_or_else(|| panic!("duplicate alias binding must fail recovery"));
    assert!(error.to_string().contains("multiple UIDs"));
    let alias = fixture
        .paths
        .profile_lock(fixture.profile_id.provider(), fixture.profile_id.name());
    assert!(
        acquire_profile_lock(&alias, true).is_ok(),
        "duplicate graph must be rejected before retaining its alias lock"
    );
}

#[test]
fn recovery_rejects_noncanonical_marker_like_names() {
    let fixture = fixture();
    let marker_like = fixture
        .paths
        .state_dir
        .join("profile-locks/invalid-automation.fence");
    fs::write(&marker_like, b"not a marker")
        .unwrap_or_else(|error| panic!("write marker-like object: {error}"));
    fs::set_permissions(&marker_like, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("secure marker-like object: {error}"));

    assert!(
        recover_profile_automation_fences(&fixture.paths, &fixture.installation_uid).is_err(),
        "startup recovery must not silently ignore a non-canonical marker name"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn recovery_rejects_non_utf8_marker_like_names() {
    const MARKER_SUFFIX: &[u8] = b"-automation.fence";
    let fixture = fixture();
    let marker_like = fixture
        .paths
        .state_dir
        .join("profile-locks")
        .join(OsString::from_vec(
            [b"invalid-".as_slice(), &[0xff], MARKER_SUFFIX].concat(),
        ));
    fs::write(&marker_like, b"not a marker")
        .unwrap_or_else(|error| panic!("write marker-like object: {error}"));
    fs::set_permissions(&marker_like, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("secure marker-like object: {error}"));

    assert!(
        recover_profile_automation_fences(&fixture.paths, &fixture.installation_uid).is_err(),
        "startup recovery must not silently ignore a malformed marker-like name"
    );
}

#[test]
fn crashed_marker_refuses_metadata_mutation_without_opening_automation_state() {
    let fixture = fixture();
    drop(prepare(&fixture));
    assert!(!fixture.paths.automation_state_dir().exists());

    let edit = edit_profile(
        &fixture.store,
        &fixture.profile_id,
        &fixture.profile,
        ProfileEdit::Claude(ClaudeProfileEdit::default()),
    );
    assert!(matches!(edit, Err(Error::PolicyRefused(_))));
    let rename = rename_profile(
        &fixture.store,
        &fixture.profile_id,
        Name::parse("renamed").unwrap_or_else(|error| panic!("new name: {error}")),
        &fixture.profile,
    );
    assert!(matches!(rename, Err(Error::PolicyRefused(_))));
    let same_name = rename_profile(
        &fixture.store,
        &fixture.profile_id,
        fixture.profile_id.name().clone(),
        &fixture.profile,
    );
    assert!(matches!(same_name, Err(Error::PolicyRefused(_))));
    let removal = remove_profile(&fixture.store, &fixture.profile_id, &fixture.profile);
    assert!(matches!(removal, Err(Error::PolicyRefused(_))));

    let config = fixture
        .store
        .load_config()
        .unwrap_or_else(|error| panic!("load unchanged config: {error}"));
    assert_eq!(
        config.profiles.get(&fixture.profile_id),
        Some(&fixture.profile)
    );
    assert!(!fixture.paths.automation_state_dir().exists());
    clear_recovered(&fixture);
}
