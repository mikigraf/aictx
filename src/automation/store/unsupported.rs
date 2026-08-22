// Signatures intentionally mirror the supported typestate API even though an
// unsupported target can never construct either private store value.
#![allow(clippy::unused_self)]

use crate::{
    automation::{
        contracts::{CallerSubject, HostIdentity, IdentityLeaseRequest, RefusalCode, UtcTimestamp},
        lease::{ClockSample, ServiceClockGeneration},
    },
    config::AppPaths,
    model::InstallationUid,
};

use super::{BeginAcquireResult, StoreError};

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
}

impl ReadyStore {
    #[must_use]
    pub(crate) const fn service_clock_generation(&self) -> ServiceClockGeneration {
        ServiceClockGeneration::from_value(0)
    }

    pub(crate) fn begin_acquire(
        &mut self,
        _request: &IdentityLeaseRequest,
        _caller: &CallerSubject,
        _host: &HostIdentity,
        _issuance_clock: &ClockSample,
    ) -> Result<BeginAcquireResult, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }

    pub(crate) fn refuse_requested(
        &mut self,
        _lease_id: &crate::automation::contracts::LeaseId,
        _refusal_code: RefusalCode,
        _now: &UtcTimestamp,
    ) -> Result<(), StoreError> {
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
