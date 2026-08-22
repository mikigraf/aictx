use crate::{
    Error, Result,
    model::{InstallationUid, ProfileId, ProfileUid},
};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use super::unsupported;
use super::{AppPaths, ProfileAutomationFenceGuard, ProfileLockGuard};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::config::storage::{ProfileLockAcquisition, try_acquire_profile_lock};

/// Policy-bound mutable-home compatibility guard for one activating lease.
pub(crate) struct ProfileAutomationResourceGuard {
    installation_uid: InstallationUid,
    profile_uid: ProfileUid,
    mode: ProfileAutomationResourceMode,
    _resource: ProfileLockGuard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileAutomationResourceMode {
    Exclusive,
    Shared,
}

pub(crate) enum ProfileAutomationResourceAcquisition {
    Acquired(ProfileAutomationResourceGuard),
    Busy,
}

impl ProfileAutomationResourceGuard {
    pub(crate) fn validate_binding(
        &self,
        installation_uid: &InstallationUid,
        profile_uid: &ProfileUid,
        expected_mode: ProfileAutomationResourceMode,
    ) -> Result<()> {
        if &self.installation_uid != installation_uid
            || &self.profile_uid != profile_uid
            || self.mode != expected_mode
        {
            return Err(Error::PolicyRefused(
                "automation profile resource binding does not match the requested identity or mode"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn acquire_profile_automation_resource(
    paths: &AppPaths,
    installation_uid: &InstallationUid,
    profile_ref: &ProfileId,
    profile_uid: &ProfileUid,
    mode: ProfileAutomationResourceMode,
    fence: &ProfileAutomationFenceGuard,
) -> Result<ProfileAutomationResourceAcquisition> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            paths,
            installation_uid,
            profile_ref,
            profile_uid,
            mode,
            fence,
        );
        Err(unsupported())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        fence.validate_current_binding(installation_uid, profile_ref, profile_uid)?;
        let exclusive = mode == ProfileAutomationResourceMode::Exclusive;
        match try_acquire_profile_lock(&paths.profile_resource_lock(profile_uid), exclusive)? {
            ProfileLockAcquisition::Acquired(resource) => Ok(
                ProfileAutomationResourceAcquisition::Acquired(ProfileAutomationResourceGuard {
                    installation_uid: installation_uid.clone(),
                    profile_uid: profile_uid.clone(),
                    mode,
                    _resource: resource,
                }),
            ),
            ProfileLockAcquisition::Busy => Ok(ProfileAutomationResourceAcquisition::Busy),
        }
    }
}
