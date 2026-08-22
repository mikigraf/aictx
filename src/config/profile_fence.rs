// Keep the sealed service-side capability surface source-compatible on
// unsupported targets; only the ordinary zero-filesystem check is exercised.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(dead_code, unused_imports)
)]

use crate::{
    Error, Result,
    model::{Config, InstallationUid, ProfileId, ProfileUid, Provider},
};

use super::storage::ProfileLockConversion;
use super::{AppPaths, MetadataStore, ProfileLockGuard};

mod alias;
#[cfg(test)]
mod fault;
mod locks;
mod marker;
mod recovery;
mod resource;
pub(crate) use alias::{
    ProfileAutomationFenceAliasExtension, extend_profile_automation_recovery_fence_alias,
};
use locks::{FenceLockAcquisition, FenceLocks, RetainedProfileAliases, try_acquire_fence_locks};
use marker::{FenceBinding, sync_marker_parent, unlink_exact_marker, validate_marker};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use marker::{NewMarkerFailure, create_new_marker, marker_presence};
pub(crate) use recovery::recover_profile_automation_fences;
pub(crate) use resource::{
    ProfileAutomationResourceAcquisition, ProfileAutomationResourceGuard,
    ProfileAutomationResourceMode, acquire_profile_automation_resource,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileFenceRefusal {
    ProfileNotFound,
    ProviderMismatch,
}

// The service deliberately redacts cleanup causes at its boundary; retaining
// them here keeps direct callers and focused fault tests diagnostic.
#[allow(dead_code)]
pub(crate) enum ProfileAutomationFencePreparation {
    Prepared(ProfileAutomationFenceGuard),
    Refused(ProfileFenceRefusal),
    Busy,
    CleanupBusy(ProfileAutomationFenceBusyGuard),
    CleanupDeferred(ProfileAutomationFenceFailure),
}

#[allow(dead_code)]
pub(crate) enum ProfileAutomationRecoveryFencePreparation {
    Prepared(ProfileAutomationFenceGuard),
    Busy,
    CleanupBusy(ProfileAutomationFenceBusyGuard),
    CleanupDeferred(ProfileAutomationFenceFailure),
}

/// Result of consuming a shared fence guard for a non-blocking exclusive
/// lifecycle conversion. `Busy` retains a complete retry capability;
/// `CleanupDeferred` retains opaque alias exclusion and all available state
/// until restart recovery resolves the ambiguity.
#[allow(dead_code)]
pub(crate) enum ProfileAutomationFenceUpgrade {
    Exclusive(ProfileAutomationFenceClearGuard),
    Busy(ProfileAutomationFenceBusyGuard),
    CleanupDeferred(ProfileAutomationFenceFailure),
}

/// Result of consuming an exclusive clear guard after a zero-blocker proof
/// found another blocker. Contention remains retryable; hard failure retains
/// opaque exclusion instead of silently dropping the live-service interlock.
#[allow(dead_code)]
pub(crate) enum ProfileAutomationFenceDowngrade {
    Shared(ProfileAutomationFenceGuard),
    Busy(ProfileAutomationFenceBusyGuard),
    CleanupDeferred(ProfileAutomationFenceFailure),
}

/// Opaque post-marker ownership for expected lifecycle contention. This
/// complete binding may retry the exclusive conversion without exposing its
/// lock, descriptor, or marker path.
pub(crate) struct ProfileAutomationFenceBusyGuard {
    binding: FenceBinding,
    legacy_aliases: RetainedProfileAliases,
    lifecycle: ProfileLockGuard,
}

/// Opaque fail-closed ownership retained by a surviving store after any
/// post-marker uncertainty. It exposes neither paths nor descriptors and
/// never authorizes profile use or marker removal.
pub(crate) struct ProfileAutomationDeferredFenceGuard {
    _legacy_aliases: RetainedProfileAliases,
    _lifecycle: Option<ProfileLockGuard>,
    _binding: Option<FenceBinding>,
}

pub(crate) struct ProfileAutomationFenceFailure {
    error: Error,
    guard: ProfileAutomationDeferredFenceGuard,
}

impl ProfileAutomationFenceFailure {
    pub(crate) fn into_parts(self) -> (Error, ProfileAutomationDeferredFenceGuard) {
        (self.error, self.guard)
    }
}

impl std::fmt::Display for ProfileAutomationFenceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

/// Opaque proof that a durable marker exists while this process retains the
/// matching shared lifecycle lock. Dropping this guard never removes the
/// marker; only the explicit recovery/zero-blocker clear state may do that.
pub(crate) struct ProfileAutomationFenceGuard {
    binding: FenceBinding,
    legacy_aliases: RetainedProfileAliases,
    lifecycle: ProfileLockGuard,
}

/// Exclusive lifecycle state used while the store proves that no durable
/// blocker remains. Clear failures retain both alias and lifecycle exclusion,
/// including the parent-sync window after the marker has been unlinked.
pub(crate) struct ProfileAutomationFenceClearGuard {
    binding: FenceBinding,
    legacy_aliases: RetainedProfileAliases,
    lifecycle: ProfileLockGuard,
}

impl ProfileAutomationFenceGuard {
    pub(crate) fn validate_binding(
        &self,
        installation_uid: &InstallationUid,
        profile_uid: &ProfileUid,
    ) -> Result<()> {
        if &self.binding.installation_uid != installation_uid
            || &self.binding.profile_uid != profile_uid
        {
            return Err(Error::PolicyRefused(
                "automation profile fence binding does not match the requested identity".to_owned(),
            ));
        }
        validate_marker(&self.binding)
    }

    pub(crate) fn validate_recovery_binding(
        &self,
        installation_uid: &InstallationUid,
        profile_ref: &ProfileId,
        provider: Provider,
        profile_uid: &ProfileUid,
    ) -> Result<()> {
        self.validate_binding(installation_uid, profile_uid)?;
        if profile_ref.provider() != provider
            || self.binding.profile_ref.provider() != provider
            || !self.legacy_aliases.contains(profile_ref)
        {
            return Err(Error::PolicyRefused(
                "automation profile fence does not match the persisted profile identity".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_current_binding(
        &self,
        installation_uid: &InstallationUid,
        profile_ref: &ProfileId,
        profile_uid: &ProfileUid,
    ) -> Result<()> {
        self.validate_binding(installation_uid, profile_uid)?;
        if &self.binding.profile_ref != profile_ref {
            return Err(Error::PolicyRefused(
                "automation profile fence requires recovery before the profile alias can change"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Consume the shared guard and attempt an exclusive conversion. Expected
    /// contention returns a retryable opaque holder; ambiguity returns a hard
    /// deferred holder. Both retain the legacy alias exclusion.
    pub(crate) fn try_upgrade_for_clear(self) -> ProfileAutomationFenceUpgrade {
        let Self {
            binding,
            legacy_aliases,
            lifecycle,
        } = self;
        try_upgrade_fence(binding, legacy_aliases, lifecycle)
    }

    pub(crate) fn defer(self) -> ProfileAutomationDeferredFenceGuard {
        deferred_guard(
            self.legacy_aliases,
            Some(self.lifecycle),
            Some(self.binding),
        )
    }
}

impl ProfileAutomationFenceBusyGuard {
    pub(crate) fn try_upgrade_for_clear(self) -> ProfileAutomationFenceUpgrade {
        try_upgrade_fence(self.binding, self.legacy_aliases, self.lifecycle)
    }
}

fn try_upgrade_fence(
    binding: FenceBinding,
    legacy_aliases: RetainedProfileAliases,
    lifecycle: ProfileLockGuard,
) -> ProfileAutomationFenceUpgrade {
    let lifecycle = match lifecycle.try_upgrade_to_exclusive(&binding.lifecycle_path) {
        ProfileLockConversion::Converted(lifecycle) => lifecycle,
        ProfileLockConversion::Busy(lifecycle) => {
            return ProfileAutomationFenceUpgrade::Busy(busy_guard(
                binding,
                legacy_aliases,
                lifecycle,
            ));
        }
        ProfileLockConversion::Failed(lifecycle, error) => {
            return ProfileAutomationFenceUpgrade::CleanupDeferred(deferred_failure(
                error,
                legacy_aliases,
                Some(lifecycle),
                Some(binding),
            ));
        }
    };
    #[cfg(test)]
    if fault::take(fault::Point::UpgradeValidation) {
        return ProfileAutomationFenceUpgrade::CleanupDeferred(deferred_failure(
            unsafe_fence(),
            legacy_aliases,
            Some(lifecycle),
            Some(binding),
        ));
    }
    if let Err(error) = validate_marker(&binding) {
        return ProfileAutomationFenceUpgrade::CleanupDeferred(deferred_failure(
            error,
            legacy_aliases,
            Some(lifecycle),
            Some(binding),
        ));
    }
    ProfileAutomationFenceUpgrade::Exclusive(ProfileAutomationFenceClearGuard {
        binding,
        legacy_aliases,
        lifecycle,
    })
}

impl ProfileAutomationFenceClearGuard {
    /// Keep the durable fence after a zero-blocker check found another user.
    /// Conversion contention remains retryable and all hard failures retain
    /// an opaque alias holder.
    pub(crate) fn downgrade(self) -> ProfileAutomationFenceDowngrade {
        let Self {
            binding,
            legacy_aliases,
            lifecycle,
        } = self;
        let lifecycle = match lifecycle.downgrade_to_shared(&binding.lifecycle_path) {
            ProfileLockConversion::Converted(lifecycle) => lifecycle,
            ProfileLockConversion::Busy(lifecycle) => {
                return ProfileAutomationFenceDowngrade::Busy(busy_guard(
                    binding,
                    legacy_aliases,
                    lifecycle,
                ));
            }
            ProfileLockConversion::Failed(lifecycle, error) => {
                return ProfileAutomationFenceDowngrade::CleanupDeferred(deferred_failure(
                    error,
                    legacy_aliases,
                    Some(lifecycle),
                    Some(binding),
                ));
            }
        };
        #[cfg(test)]
        if fault::take(fault::Point::DowngradeValidation) {
            return ProfileAutomationFenceDowngrade::CleanupDeferred(deferred_failure(
                unsafe_fence(),
                legacy_aliases,
                Some(lifecycle),
                Some(binding),
            ));
        }
        if let Err(error) = validate_marker(&binding) {
            return ProfileAutomationFenceDowngrade::CleanupDeferred(deferred_failure(
                error,
                legacy_aliases,
                Some(lifecycle),
                Some(binding),
            ));
        }
        ProfileAutomationFenceDowngrade::Shared(ProfileAutomationFenceGuard {
            binding,
            legacy_aliases,
            lifecycle,
        })
    }

    /// Remove the exact marker represented by this guard. The caller must have
    /// committed a same-profile zero-blocker proof while retaining this guard.
    #[allow(clippy::result_large_err)] // The Err must retain opaque lock ownership.
    pub(crate) fn clear(self) -> std::result::Result<(), ProfileAutomationFenceFailure> {
        #[cfg(test)]
        if fault::take(fault::Point::ClearValidation) {
            return Err(self.into_failure(unsafe_fence()));
        }
        if let Err(error) = validate_marker(&self.binding) {
            return Err(self.into_failure(error));
        }
        if let Err(error) = unlink_exact_marker(&self.binding) {
            return Err(self.into_failure(error));
        }
        #[cfg(test)]
        if fault::take(fault::Point::ClearParentSync) {
            return Err(self.into_failure(unsafe_fence()));
        }
        if let Err(error) = sync_marker_parent(&self.binding.marker_path) {
            return Err(self.into_failure(error));
        }
        Ok(())
    }

    pub(crate) fn defer(self) -> ProfileAutomationDeferredFenceGuard {
        deferred_guard(
            self.legacy_aliases,
            Some(self.lifecycle),
            Some(self.binding),
        )
    }

    fn into_failure(self, error: Error) -> ProfileAutomationFenceFailure {
        ProfileAutomationFenceFailure {
            error,
            guard: self.defer(),
        }
    }
}

fn busy_guard(
    binding: FenceBinding,
    legacy_aliases: RetainedProfileAliases,
    lifecycle: ProfileLockGuard,
) -> ProfileAutomationFenceBusyGuard {
    ProfileAutomationFenceBusyGuard {
        binding,
        legacy_aliases,
        lifecycle,
    }
}

fn deferred_guard(
    legacy_aliases: RetainedProfileAliases,
    lifecycle: Option<ProfileLockGuard>,
    binding: Option<FenceBinding>,
) -> ProfileAutomationDeferredFenceGuard {
    ProfileAutomationDeferredFenceGuard {
        _legacy_aliases: legacy_aliases,
        _lifecycle: lifecycle,
        _binding: binding,
    }
}

fn deferred_failure(
    error: Error,
    legacy_aliases: RetainedProfileAliases,
    lifecycle: Option<ProfileLockGuard>,
    binding: Option<FenceBinding>,
) -> ProfileAutomationFenceFailure {
    ProfileAutomationFenceFailure {
        error,
        guard: deferred_guard(legacy_aliases, lifecycle, binding),
    }
}

/// Resolve an exact current profile under its immutable lifecycle lock and,
/// only when it matches, publish the durable marker before returning a shared
/// lifecycle guard. A terminal identity refusal creates no marker.
pub(crate) fn prepare_profile_automation_fence(
    store: &MetadataStore,
    installation_uid: &InstallationUid,
    profile_ref: &ProfileId,
    provider: Provider,
    profile_uid: &ProfileUid,
) -> Result<ProfileAutomationFencePreparation> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (store, installation_uid, profile_ref, provider, profile_uid);
        Err(unsupported())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let paths = store.paths();
        let config = store.load_config()?;
        if let Some(refusal) = current_profile_refusal(
            &config,
            installation_uid,
            profile_ref,
            provider,
            profile_uid,
        )? {
            return Ok(ProfileAutomationFencePreparation::Refused(refusal));
        }
        let FenceLocks {
            aliases: legacy_aliases,
            lifecycle_path,
            lifecycle,
        } = match try_acquire_fence_locks(paths, [profile_ref.clone()], profile_uid, true)? {
            FenceLockAcquisition::Acquired(locks) => locks,
            FenceLockAcquisition::Busy => {
                return Ok(ProfileAutomationFencePreparation::Busy);
            }
        };
        let config = store.load_config()?;
        if let Some(refusal) = current_profile_refusal(
            &config,
            installation_uid,
            profile_ref,
            provider,
            profile_uid,
        )? {
            return Ok(ProfileAutomationFencePreparation::Refused(refusal));
        }

        let marker_path = paths.profile_automation_fence(profile_uid);
        let opened =
            match create_new_marker(&marker_path, installation_uid, profile_ref, profile_uid) {
                Ok(opened) => opened,
                Err(NewMarkerFailure::Outer(error)) => return Err(error),
                Err(NewMarkerFailure::CleanupDeferred(error)) => {
                    return Ok(ProfileAutomationFencePreparation::CleanupDeferred(
                        deferred_failure(error, legacy_aliases, Some(lifecycle), None),
                    ));
                }
            };
        let binding = FenceBinding {
            installation_uid: installation_uid.clone(),
            profile_ref: profile_ref.clone(),
            profile_uid: profile_uid.clone(),
            fence_id: opened.fence_id,
            marker_bytes: opened.bytes,
            marker_snapshot: opened.snapshot,
            marker: opened.file,
            marker_path,
            lifecycle_path: lifecycle_path.clone(),
        };
        #[cfg(test)]
        if fault::take(fault::Point::PostCreateValidation) {
            return Ok(ProfileAutomationFencePreparation::CleanupDeferred(
                deferred_failure(
                    unsafe_fence(),
                    legacy_aliases,
                    Some(lifecycle),
                    Some(binding),
                ),
            ));
        }
        let lifecycle = match lifecycle.downgrade_to_shared(&lifecycle_path) {
            ProfileLockConversion::Converted(lifecycle) => lifecycle,
            ProfileLockConversion::Busy(lifecycle) => {
                return Ok(ProfileAutomationFencePreparation::CleanupBusy(busy_guard(
                    binding,
                    legacy_aliases,
                    lifecycle,
                )));
            }
            ProfileLockConversion::Failed(lifecycle, error) => {
                return Ok(ProfileAutomationFencePreparation::CleanupDeferred(
                    deferred_failure(error, legacy_aliases, Some(lifecycle), Some(binding)),
                ));
            }
        };
        if let Err(error) = validate_marker(&binding) {
            return Ok(ProfileAutomationFencePreparation::CleanupDeferred(
                deferred_failure(error, legacy_aliases, Some(lifecycle), Some(binding)),
            ));
        }
        Ok(ProfileAutomationFencePreparation::Prepared(
            ProfileAutomationFenceGuard {
                binding,
                legacy_aliases,
                lifecycle,
            },
        ))
    }
}

/// Fence a durable pre-marker REQUESTED row before recovery terminalizes it.
/// Historical profile metadata may no longer be current, so this validates
/// the persisted provider/ref binding and installation. A current profile is
/// optional, but its same-provider alias is retained when it maps to this UID.
pub(crate) fn prepare_profile_automation_recovery_fence(
    store: &MetadataStore,
    installation_uid: &InstallationUid,
    profile_ref: &ProfileId,
    provider: Provider,
    profile_uid: &ProfileUid,
) -> Result<ProfileAutomationRecoveryFencePreparation> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (store, installation_uid, profile_ref, provider, profile_uid);
        Err(unsupported())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if profile_ref.provider() != provider {
            return Err(Error::PolicyRefused(
                "persisted automation profile provider and reference do not match".to_owned(),
            ));
        }
        let paths = store.paths();
        let config = store.load_config()?;
        if &config.installation_uid != installation_uid {
            return Err(Error::PolicyRefused(
                "automation store identity no longer matches the metadata installation".to_owned(),
            ));
        }
        let current_profile_ref = current_profile_ref_for_uid(&config, profile_uid)?;
        if current_profile_ref
            .as_ref()
            .is_some_and(|current| current.provider() != provider)
        {
            return Err(unsafe_fence());
        }
        let mut profile_refs = vec![profile_ref.clone()];
        if let Some(current) = &current_profile_ref
            && current != profile_ref
        {
            profile_refs.push(current.clone());
        }
        let FenceLocks {
            aliases: legacy_aliases,
            lifecycle_path,
            lifecycle,
        } = match try_acquire_fence_locks(paths, profile_refs, profile_uid, true)? {
            FenceLockAcquisition::Acquired(locks) => locks,
            FenceLockAcquisition::Busy => {
                return Ok(ProfileAutomationRecoveryFencePreparation::Busy);
            }
        };
        let current = store.load_config()?;
        if &current.installation_uid != installation_uid {
            return Err(Error::PolicyRefused(
                "automation store identity no longer matches the metadata installation".to_owned(),
            ));
        }
        if current_profile_ref_for_uid(&current, profile_uid)? != current_profile_ref {
            return Err(Error::ConfigBusy);
        }
        let marker_path = paths.profile_automation_fence(profile_uid);
        let opened =
            match create_new_marker(&marker_path, installation_uid, profile_ref, profile_uid) {
                Ok(opened) => opened,
                Err(NewMarkerFailure::Outer(error)) => return Err(error),
                Err(NewMarkerFailure::CleanupDeferred(error)) => {
                    return Ok(ProfileAutomationRecoveryFencePreparation::CleanupDeferred(
                        deferred_failure(error, legacy_aliases, Some(lifecycle), None),
                    ));
                }
            };
        let binding = FenceBinding {
            installation_uid: installation_uid.clone(),
            profile_ref: profile_ref.clone(),
            profile_uid: profile_uid.clone(),
            fence_id: opened.fence_id,
            marker_bytes: opened.bytes,
            marker_snapshot: opened.snapshot,
            marker: opened.file,
            marker_path,
            lifecycle_path: lifecycle_path.clone(),
        };
        #[cfg(test)]
        if fault::take(fault::Point::RecoveryPreparationValidation) {
            return Ok(ProfileAutomationRecoveryFencePreparation::CleanupDeferred(
                deferred_failure(
                    unsafe_fence(),
                    legacy_aliases,
                    Some(lifecycle),
                    Some(binding),
                ),
            ));
        }
        let lifecycle = match lifecycle.downgrade_to_shared(&lifecycle_path) {
            ProfileLockConversion::Converted(lifecycle) => lifecycle,
            ProfileLockConversion::Busy(lifecycle) => {
                return Ok(ProfileAutomationRecoveryFencePreparation::CleanupBusy(
                    busy_guard(binding, legacy_aliases, lifecycle),
                ));
            }
            ProfileLockConversion::Failed(lifecycle, error) => {
                return Ok(ProfileAutomationRecoveryFencePreparation::CleanupDeferred(
                    deferred_failure(error, legacy_aliases, Some(lifecycle), Some(binding)),
                ));
            }
        };
        if let Err(error) = validate_marker(&binding) {
            return Ok(ProfileAutomationRecoveryFencePreparation::CleanupDeferred(
                deferred_failure(error, legacy_aliases, Some(lifecycle), Some(binding)),
            ));
        }
        Ok(ProfileAutomationRecoveryFencePreparation::Prepared(
            ProfileAutomationFenceGuard {
                binding,
                legacy_aliases,
                lifecycle,
            },
        ))
    }
}

/// Revalidate another unseen request for a UID whose durable fence is already
/// represented in the service registry. The borrowed guard keeps lifecycle
/// metadata immutable throughout the authoritative config read. Untrusted
/// aliases are classified before the exact current-alias capability check, so
/// a terminal refusal cannot poison an otherwise valid retained fence.
pub(crate) fn validate_profile_automation_fence_profile(
    store: &MetadataStore,
    installation_uid: &InstallationUid,
    profile_ref: &ProfileId,
    provider: Provider,
    profile_uid: &ProfileUid,
    fence: &ProfileAutomationFenceGuard,
) -> Result<Option<ProfileFenceRefusal>> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            store,
            installation_uid,
            profile_ref,
            provider,
            profile_uid,
            fence,
        );
        Err(unsupported())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        fence.validate_binding(installation_uid, profile_uid)?;
        let config = store.load_config()?;
        let refusal = current_profile_refusal(
            &config,
            installation_uid,
            profile_ref,
            provider,
            profile_uid,
        )?;
        if refusal.is_some() {
            return Ok(refusal);
        }
        fence.validate_current_binding(installation_uid, profile_ref, profile_uid)?;
        Ok(None)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_profile_refusal(
    config: &Config,
    installation_uid: &InstallationUid,
    profile_ref: &ProfileId,
    provider: Provider,
    profile_uid: &ProfileUid,
) -> Result<Option<ProfileFenceRefusal>> {
    if &config.installation_uid != installation_uid {
        return Err(Error::PolicyRefused(
            "automation store identity no longer matches the metadata installation".to_owned(),
        ));
    }
    if profile_ref.provider() != provider {
        return Ok(Some(ProfileFenceRefusal::ProviderMismatch));
    }
    let Some(profile) = config.profiles.get(profile_ref) else {
        return Ok(Some(ProfileFenceRefusal::ProfileNotFound));
    };
    if profile.provider() != provider {
        Ok(Some(ProfileFenceRefusal::ProviderMismatch))
    } else if profile.profile_uid() != profile_uid {
        Ok(Some(ProfileFenceRefusal::ProfileNotFound))
    } else {
        Ok(None)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_profile_ref_for_uid(
    config: &Config,
    profile_uid: &ProfileUid,
) -> Result<Option<ProfileId>> {
    let mut matches = config
        .profiles
        .iter()
        .filter(|(_, profile)| profile.profile_uid() == profile_uid)
        .map(|(profile_ref, _)| profile_ref.clone());
    let current = matches.next();
    if matches.next().is_some() {
        return Err(unsafe_fence());
    }
    Ok(current)
}

/// Ordinary metadata management checks only the deterministic marker pathname.
/// It never opens the marker, automation directory, service lock, or lease DB.
/// Any object at that pathname is conservatively treated as a live/recovery
/// fence; only the sealed recovery path may validate and remove one.
// Unsupported targets intentionally preserve the shared Result API while
// performing no filesystem access.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(clippy::unnecessary_wraps)
)]
pub(crate) fn ensure_profile_automation_unfenced(
    paths: &AppPaths,
    profile_uid: &ProfileUid,
) -> Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (paths, profile_uid);
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match profile_automation_fence_presence(paths, profile_uid) {
            Ok(false) => Ok(()),
            Ok(true) | Err(_) => Err(active_fence()),
        }
    }
}

// Unsupported targets intentionally preserve the shared Result API while
// performing no filesystem access.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(clippy::unnecessary_wraps)
)]
pub(crate) fn profile_automation_fence_presence(
    paths: &AppPaths,
    profile_uid: &ProfileUid,
) -> Result<bool> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (paths, profile_uid);
        Ok(false)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        marker_presence(&paths.profile_automation_fence(profile_uid))
    }
}

fn active_fence() -> Error {
    Error::PolicyRefused(
        "profile use is refused while automation lease state is unresolved".to_owned(),
    )
}

fn unsafe_fence() -> Error {
    Error::PolicyRefused("automation profile fence is invalid or unsafe".to_owned())
}

fn orphan_fence() -> Error {
    Error::PolicyRefused(
        "an unreconciled automation profile fence requires explicit recovery".to_owned(),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unsupported() -> Error {
    Error::PolicyRefused("automation profile fencing is unsupported on this platform".to_owned())
}

#[cfg(test)]
mod tests;
