use crate::automation::{
    contracts::{FencingGeneration, LeaseId, LeaseStatus},
    policy::EffectivePolicy,
};

use super::{
    ClockSample, Lease, LeaseDomainError, LeaseResolution, LeaseState, ResolvedAuthority,
    add_seconds, deadline_reached, earlier, validate_resolution, wall_nanoseconds_between,
};

pub(crate) struct PreparedActivation {
    lease_id: LeaseId,
    authority: ResolvedAuthority,
}

impl Lease {
    pub(crate) fn prepare_activation(
        &mut self,
        policy: &EffectivePolicy,
        resolution: &LeaseResolution,
        now: &ClockSample,
    ) -> Result<PreparedActivation, LeaseDomainError> {
        self.require_status(LeaseStatus::Requested)?;
        self.observe_activation_clock(now)?;
        self.validate_policy_binding(policy)?;
        if policy.requested_ttl_seconds != self.binding.initial_requested_ttl_seconds {
            return Err(LeaseDomainError::PolicyBindingMismatch);
        }
        validate_resolution(self.binding.provider, policy, resolution)?;
        let maximum_by_session = add_seconds(self.issued_at(), policy.maximum_session_seconds)?;
        let maximum_expires_at = earlier(&policy.signed_expires_at, &maximum_by_session).clone();
        let expires_at = add_seconds(self.issued_at(), policy.requested_ttl_seconds)?;
        if maximum_expires_at.is_before(&expires_at) || !self.issued_at().is_before(&expires_at) {
            return Err(LeaseDomainError::SessionLimitReached);
        }
        let maximum_runtime = wall_nanoseconds_between(self.issued_at(), &maximum_expires_at)?;
        let monotonic_maximum_deadline = self
            .issuance_clock
            .monotonic
            .checked_add_nanoseconds(maximum_runtime)
            .ok_or(LeaseDomainError::ClockOverflow)?;
        let monotonic_deadline = self
            .issuance_clock
            .monotonic
            .checked_add_seconds(policy.requested_ttl_seconds)
            .ok_or(LeaseDomainError::ClockOverflow)?;
        if monotonic_deadline > monotonic_maximum_deadline
            || deadline_reached(now, &expires_at, monotonic_deadline)
            || deadline_reached(now, &maximum_expires_at, monotonic_maximum_deadline)
        {
            return Err(LeaseDomainError::SessionLimitReached);
        }
        Ok(PreparedActivation {
            lease_id: self.binding.lease_id.clone(),
            authority: ResolvedAuthority {
                resolution: resolution.clone(),
                effective_policy_digest: policy.digest(),
                fencing_generation: FencingGeneration::from_value(1)
                    .map_err(|_| LeaseDomainError::GenerationExhausted)?,
                expires_at,
                maximum_expires_at,
                interval_anchor_wall: self.issuance_clock.wall.clone(),
                interval_anchor_monotonic: self.issuance_clock.monotonic,
                monotonic_deadline,
                monotonic_maximum_deadline,
            },
        })
    }

    pub(crate) fn activate_prepared(
        &mut self,
        prepared: PreparedActivation,
    ) -> Result<(), LeaseDomainError> {
        self.require_status(LeaseStatus::Requested)?;
        if self.binding.lease_id != prepared.lease_id {
            return Err(LeaseDomainError::PolicyBindingMismatch);
        }
        self.state = LeaseState::Active(prepared.authority);
        Ok(())
    }

    // The public domain boundary owns the caller's resolved authority evidence.
    #[allow(clippy::needless_pass_by_value)]
    pub fn activate(
        &mut self,
        policy: &EffectivePolicy,
        resolution: LeaseResolution,
        now: &ClockSample,
    ) -> Result<(), LeaseDomainError> {
        let prepared = self.prepare_activation(policy, &resolution, now)?;
        self.activate_prepared(prepared)
    }
}
