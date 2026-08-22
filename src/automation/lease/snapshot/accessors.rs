use crate::automation::{
    contracts::{
        CallerSubject, FencingGeneration, HostIdentity, LeaseId, ProfileRef, ProfileUid, Provider,
        Sha256Digest, UtcTimestamp,
    },
    lease::{
        LeaseResolution, LeaseSnapshot, MonotonicMoment, PersistedLeaseState,
        PersistedResolvedAuthority,
    },
};

impl PersistedResolvedAuthority {
    #[must_use]
    pub(crate) const fn resolution(&self) -> &LeaseResolution {
        &self.resolution
    }

    #[must_use]
    pub(crate) const fn effective_policy_digest(&self) -> Sha256Digest {
        self.effective_policy_digest
    }

    #[must_use]
    pub(crate) const fn fencing_generation(&self) -> FencingGeneration {
        self.fencing_generation
    }

    #[must_use]
    pub(crate) const fn expires_at(&self) -> &UtcTimestamp {
        &self.expires_at
    }

    #[must_use]
    pub(crate) const fn maximum_expires_at(&self) -> &UtcTimestamp {
        &self.maximum_expires_at
    }

    #[must_use]
    pub(crate) const fn interval_anchor_wall(&self) -> &UtcTimestamp {
        &self.interval_anchor_wall
    }

    #[must_use]
    pub(crate) const fn interval_anchor_monotonic(&self) -> MonotonicMoment {
        self.interval_anchor_monotonic
    }

    #[must_use]
    pub(crate) const fn monotonic_deadline(&self) -> MonotonicMoment {
        self.monotonic_deadline
    }

    #[must_use]
    pub(crate) const fn monotonic_maximum_deadline(&self) -> MonotonicMoment {
        self.monotonic_maximum_deadline
    }
}

impl LeaseSnapshot {
    #[must_use]
    pub(crate) const fn lease_id(&self) -> &LeaseId {
        &self.binding.lease_id
    }

    #[must_use]
    pub(crate) const fn caller_subject(&self) -> &CallerSubject {
        &self.binding.caller_subject
    }

    #[must_use]
    pub(crate) const fn host_identity(&self) -> &HostIdentity {
        &self.binding.host_identity
    }

    #[must_use]
    pub(crate) const fn profile_uid(&self) -> &ProfileUid {
        &self.binding.profile_uid
    }

    #[must_use]
    pub(crate) const fn profile_ref(&self) -> &ProfileRef {
        &self.binding.profile_ref
    }

    #[must_use]
    pub(crate) const fn provider(&self) -> Provider {
        self.binding.provider
    }

    #[must_use]
    pub(crate) const fn persisted_state(&self) -> &PersistedLeaseState {
        &self.state
    }
}
