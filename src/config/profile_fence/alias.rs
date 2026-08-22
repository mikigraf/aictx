#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::BTreeMap;

use crate::{
    Error, Result,
    model::{InstallationUid, ProfileId, ProfileUid, Provider},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::current_profile_ref_for_uid;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::marker::validate_marker;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use super::unsupported;
use super::{
    MetadataStore, ProfileAutomationFenceFailure, ProfileAutomationFenceGuard, deferred_failure,
    unsafe_fence,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::config::storage::{ProfileLockAcquisition, try_acquire_profile_lock};

pub(crate) enum ProfileAutomationFenceAliasExtension {
    Extended(ProfileAutomationFenceGuard),
    Busy(ProfileAutomationFenceGuard),
    CleanupDeferred(ProfileAutomationFenceFailure),
}

// The outer error channel preserves unsupported-target/API parity; supported
// post-marker failures intentionally carry their retained holder in the enum.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn extend_profile_automation_recovery_fence_alias(
    store: &MetadataStore,
    installation_uid: &InstallationUid,
    profile_ref: &ProfileId,
    provider: Provider,
    profile_uid: &ProfileUid,
    guard: ProfileAutomationFenceGuard,
) -> Result<ProfileAutomationFenceAliasExtension> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            store,
            installation_uid,
            profile_ref,
            provider,
            profile_uid,
            guard,
        );
        Err(unsupported())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let ProfileAutomationFenceGuard {
            binding,
            mut legacy_aliases,
            lifecycle,
        } = guard;
        if &binding.installation_uid != installation_uid
            || &binding.profile_uid != profile_uid
            || profile_ref.provider() != provider
            || binding.profile_ref.provider() != provider
        {
            return Ok(hard_failure(
                unsafe_fence(),
                binding,
                legacy_aliases,
                lifecycle,
            ));
        }
        if let Err(error) = validate_marker(&binding) {
            return Ok(hard_failure(error, binding, legacy_aliases, lifecycle));
        }

        let before = match store.load_config() {
            Ok(config) => config,
            Err(error) => {
                return Ok(hard_failure(error, binding, legacy_aliases, lifecycle));
            }
        };
        if &before.installation_uid != installation_uid {
            return Ok(hard_failure(
                unsafe_fence(),
                binding,
                legacy_aliases,
                lifecycle,
            ));
        }
        let current = match current_profile_ref_for_uid(&before, profile_uid) {
            Ok(current) => current,
            Err(error) => {
                return Ok(hard_failure(error, binding, legacy_aliases, lifecycle));
            }
        };
        if current
            .as_ref()
            .is_some_and(|current| current.provider() != provider)
        {
            return Ok(hard_failure(
                unsafe_fence(),
                binding,
                legacy_aliases,
                lifecycle,
            ));
        }

        let paths = store.paths();
        let mut missing = BTreeMap::new();
        for candidate in std::iter::once(profile_ref.clone()).chain(current.clone()) {
            if !legacy_aliases.contains(&candidate) {
                let path = paths.profile_lock(candidate.provider(), candidate.name());
                if missing.insert(path, candidate).is_some() {
                    return Ok(hard_failure(
                        unsafe_fence(),
                        binding,
                        legacy_aliases,
                        lifecycle,
                    ));
                }
            }
        }
        for (path, candidate) in missing {
            match try_acquire_profile_lock(&path, true) {
                Ok(ProfileLockAcquisition::Acquired(alias)) => {
                    legacy_aliases.guards.insert(candidate, alias);
                }
                Ok(ProfileLockAcquisition::Busy) => {
                    return Ok(ProfileAutomationFenceAliasExtension::Busy(
                        ProfileAutomationFenceGuard {
                            binding,
                            legacy_aliases,
                            lifecycle,
                        },
                    ));
                }
                Err(error) => {
                    return Ok(hard_failure(error, binding, legacy_aliases, lifecycle));
                }
            }
        }

        let after = match store.load_config() {
            Ok(config) => config,
            Err(error) => {
                return Ok(hard_failure(error, binding, legacy_aliases, lifecycle));
            }
        };
        let after_current = match current_profile_ref_for_uid(&after, profile_uid) {
            Ok(current) => current,
            Err(error) => {
                return Ok(hard_failure(error, binding, legacy_aliases, lifecycle));
            }
        };
        if &after.installation_uid != installation_uid
            || after_current
                .as_ref()
                .is_some_and(|current| current.provider() != provider)
            || after_current != current
        {
            return Ok(hard_failure(
                unsafe_fence(),
                binding,
                legacy_aliases,
                lifecycle,
            ));
        }
        if let Err(error) = validate_marker(&binding) {
            return Ok(hard_failure(error, binding, legacy_aliases, lifecycle));
        }
        Ok(ProfileAutomationFenceAliasExtension::Extended(
            ProfileAutomationFenceGuard {
                binding,
                legacy_aliases,
                lifecycle,
            },
        ))
    }
}

fn hard_failure(
    error: Error,
    binding: super::marker::FenceBinding,
    legacy_aliases: super::locks::RetainedProfileAliases,
    lifecycle: crate::config::ProfileLockGuard,
) -> ProfileAutomationFenceAliasExtension {
    ProfileAutomationFenceAliasExtension::CleanupDeferred(deferred_failure(
        error,
        legacy_aliases,
        Some(lifecycle),
        Some(binding),
    ))
}
