// Signatures intentionally mirror the supported typestate API even though an
// unsupported target can never construct either private store value.
#![allow(clippy::unused_self)]

use crate::{
    automation::{
        contracts::{
            CallerSubject, HostIdentity, IdentityLeaseRequest, LeaseId, LeaseReasonCode,
            UtcTimestamp,
        },
        lease::{ClockSample, LeaseControl, LeaseResolution, ServiceClockGeneration},
        policy::EffectivePolicy,
    },
    config::AppPaths,
    model::InstallationUid,
};

use super::{
    AuthenticatedRequestControl, BeginAcquireResult, CapacityReleaseResult, CommittedMutation,
    PruneResult, RecoveryMutationResult, RecoveryPage, RecoveryPageRequest, StoreError,
};

pub(crate) struct RecoveringStore {
    _private: (),
}
pub(crate) struct ReadyStore {
    _private: (),
}

impl RecoveringStore {
    pub(crate) fn open(
        _paths: &AppPaths,
        _installation_uid: &InstallationUid,
        _now: &UtcTimestamp,
    ) -> Result<Self, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    #[must_use]
    pub(crate) const fn service_clock_generation(&self) -> ServiceClockGeneration {
        ServiceClockGeneration::from_value(0)
    }

    pub(crate) fn into_ready(self, _now: &UtcTimestamp) -> Result<ReadyStore, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(crate) fn recovery_candidates(
        &self,
        _page: &RecoveryPageRequest,
    ) -> Result<RecoveryPage, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(crate) fn recovered_profile_fences(&self) -> Vec<crate::model::ProfileUid> {
        Vec::new()
    }

    pub(crate) fn clear_orphan_profile_fence(
        &mut self,
        _profile_uid: &crate::model::ProfileUid,
    ) -> Result<bool, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn terminalize_prior_generation(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _now: &UtcTimestamp,
    ) -> Result<RecoveryMutationResult, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
}

impl ReadyStore {
    #[must_use]
    pub(crate) const fn service_clock_generation(&self) -> ServiceClockGeneration {
        ServiceClockGeneration::from_value(0)
    }

    pub(in crate::automation::store) fn begin_acquire(
        &mut self,
        _request: &IdentityLeaseRequest,
        _caller: &CallerSubject,
        _host: &HostIdentity,
        _issuance_clock: &ClockSample,
    ) -> Result<BeginAcquireResult, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn refuse_requested(
        &mut self,
        _control: &AuthenticatedRequestControl<'_>,
        _refusal: super::lifecycle_types::NonCapacityRefusal,
        _now: &UtcTimestamp,
    ) -> Result<CommittedMutation<()>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn activate_requested(
        &mut self,
        _control: &AuthenticatedRequestControl<'_>,
        _policy: &EffectivePolicy,
        _resolution: LeaseResolution,
        _now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn begin_renewal(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _control: &LeaseControl<'_>,
        _policy: &EffectivePolicy,
        _now: &ClockSample,
    ) -> Result<CommittedMutation<crate::automation::contracts::FencingGeneration>, StoreError>
    {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn acknowledge_renewal(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _control: &LeaseControl<'_>,
        _now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn close_lease(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _control: &LeaseControl<'_>,
        _reason: LeaseReasonCode,
        _now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn revoke_authenticated(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _control: &LeaseControl<'_>,
        _now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn revoke_by_service(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _reason: LeaseReasonCode,
        _now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn mark_error(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _reason: LeaseReasonCode,
        _now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn enforce_expiration(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _now: &ClockSample,
    ) -> Result<CommittedMutation<bool>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn release_terminal_capacity(
        &mut self,
        _lease_id: &LeaseId,
        _expected_row_version: u64,
        _now: &UtcTimestamp,
    ) -> Result<CapacityReleaseResult, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(crate) fn retry_profile_fence_cleanup(
        &mut self,
        _profile_uid: &crate::model::ProfileUid,
    ) -> Result<bool, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(in crate::automation::store) fn prune_retained(
        &mut self,
        _now: &UtcTimestamp,
    ) -> Result<PruneResult, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn unsupported_open_does_not_touch_the_filesystem() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let untouched = temporary.path().join("must-not-exist");
        let paths = AppPaths::for_root(untouched.clone());
        let installation =
            InstallationUid::generate().unwrap_or_else(|error| panic!("installation uid: {error}"));
        let now = "2026-08-22T10:00:00Z"
            .parse::<UtcTimestamp>()
            .unwrap_or_else(|error| panic!("timestamp: {error:?}"));

        assert!(matches!(
            RecoveringStore::open(&paths, &installation, &now),
            Err(StoreError::UnsupportedPlatform)
        ));
        assert!(!untouched.exists());
    }
}
