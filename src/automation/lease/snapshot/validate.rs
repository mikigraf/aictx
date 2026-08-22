use crate::automation::contracts::{
    AgentRole, IsolationClassification, LeaseReasonCode, LeaseStatus, UtcTimestamp,
};

use super::{
    ClockSample, LeaseBinding, LeaseDomainError, MonotonicMoment, PersistedResolvedAuthority,
};

pub(super) fn validate_authority(
    authority: &PersistedResolvedAuthority,
    binding: &LeaseBinding,
    issuance_clock: &ClockSample,
    high_water: MonotonicMoment,
) -> Result<(), LeaseDomainError> {
    let issued_at = &issuance_clock.wall;
    let issued_monotonic = issuance_clock.monotonic;
    let resolution = &authority.resolution;
    if !resolution.workspace_ref.matches_provider(binding.provider)
        || !resolution.auth_mode.supports_provider(binding.provider)
        || resolution.isolation == IsolationClassification::Unproven
        || (resolution.isolation == IsolationClassification::CopiedCredentialDevelopment
            && binding.environment.as_str() != "local-development"
            && binding.role != AgentRole::PrReviewer)
        || !issued_at.is_before(&authority.expires_at)
        || authority
            .maximum_expires_at
            .is_before(&authority.expires_at)
        || binding
            .signed_authorization_expires_at
            .is_before(&authority.maximum_expires_at)
        || authority.monotonic_deadline <= issued_monotonic
        || authority.monotonic_maximum_deadline < authority.monotonic_deadline
        || authority.interval_anchor_monotonic < issued_monotonic
        || authority.interval_anchor_monotonic > high_water
        || (authority.fencing_generation.get() == 1
            && (&authority.interval_anchor_wall != issued_at
                || authority.interval_anchor_monotonic != issued_monotonic))
    {
        return Err(LeaseDomainError::InvalidSnapshot);
    }
    let interval_nanos = validate_deadline_pair(
        &authority.interval_anchor_wall,
        authority.interval_anchor_monotonic,
        &authority.expires_at,
        authority.monotonic_deadline,
    )?;
    let maximum_nanos = validate_deadline_pair(
        issued_at,
        issued_monotonic,
        &authority.maximum_expires_at,
        authority.monotonic_maximum_deadline,
    )?;
    let requested_nanos = seconds_as_nanoseconds(binding.initial_requested_ttl_seconds)?;
    let signed_ttl_nanos = seconds_as_nanoseconds(binding.signed_maximum_ttl_seconds)?;
    let signed_session_nanos = seconds_as_nanoseconds(binding.signed_maximum_session_seconds)?;
    if requested_nanos > signed_ttl_nanos
        || signed_ttl_nanos > signed_session_nanos
        || interval_nanos > signed_ttl_nanos
        || maximum_nanos > signed_session_nanos
        || (authority.fencing_generation.get() == 1 && interval_nanos != requested_nanos)
    {
        return Err(LeaseDomainError::InvalidSnapshot);
    }
    Ok(())
}

fn seconds_as_nanoseconds(seconds: u64) -> Result<u128, LeaseDomainError> {
    u128::from(seconds)
        .checked_mul(1_000_000_000)
        .ok_or(LeaseDomainError::InvalidSnapshot)
}

fn validate_deadline_pair(
    anchor_wall: &UtcTimestamp,
    anchor_monotonic: MonotonicMoment,
    deadline_wall: &UtcTimestamp,
    deadline_monotonic: MonotonicMoment,
) -> Result<u128, LeaseDomainError> {
    let wall_delta = super::super::wall_nanoseconds_between(anchor_wall, deadline_wall)
        .map_err(|_| LeaseDomainError::InvalidSnapshot)?;
    let monotonic_delta = deadline_monotonic
        .as_nanoseconds()
        .checked_sub(anchor_monotonic.as_nanoseconds())
        .ok_or(LeaseDomainError::InvalidSnapshot)?;
    if wall_delta == monotonic_delta {
        Ok(wall_delta)
    } else {
        Err(LeaseDomainError::InvalidSnapshot)
    }
}

pub(super) fn validate_acknowledgement_pair(
    authority: &PersistedResolvedAuthority,
    acknowledgement_wall: &UtcTimestamp,
    acknowledgement_monotonic: MonotonicMoment,
) -> Result<(), LeaseDomainError> {
    const ACK_TIMEOUT_NANOS: u128 = 30_000_000_000;
    validate_deadline_pair(
        &authority.interval_anchor_wall,
        authority.interval_anchor_monotonic,
        acknowledgement_wall,
        acknowledgement_monotonic,
    )?;
    let interval = super::super::wall_nanoseconds_between(
        &authority.interval_anchor_wall,
        &authority.expires_at,
    )
    .map_err(|_| LeaseDomainError::InvalidSnapshot)?;
    let acknowledgement = super::super::wall_nanoseconds_between(
        &authority.interval_anchor_wall,
        acknowledgement_wall,
    )
    .map_err(|_| LeaseDomainError::InvalidSnapshot)?;
    if acknowledgement == interval.min(ACK_TIMEOUT_NANOS) {
        Ok(())
    } else {
        Err(LeaseDomainError::InvalidSnapshot)
    }
}

pub(super) fn validate_live_high_water(
    authority: &PersistedResolvedAuthority,
    high_water: MonotonicMoment,
) -> Result<(), LeaseDomainError> {
    if high_water >= authority.monotonic_deadline
        || high_water >= authority.monotonic_maximum_deadline
    {
        Err(LeaseDomainError::InvalidSnapshot)
    } else {
        Ok(())
    }
}

pub(super) fn require_reason(
    status: LeaseStatus,
    reason: LeaseReasonCode,
) -> Result<(), LeaseDomainError> {
    let valid = match status {
        LeaseStatus::Closed => matches!(
            reason,
            LeaseReasonCode::Completed | LeaseReasonCode::WorkerFailed
        ),
        LeaseStatus::Revoked => super::super::revocation_reason(reason),
        LeaseStatus::Expired => matches!(
            reason,
            LeaseReasonCode::LeaseExpired | LeaseReasonCode::MaximumLifetimeReached
        ),
        LeaseStatus::Error => matches!(
            reason,
            LeaseReasonCode::ProcessUnverifiable
                | LeaseReasonCode::ServiceRecovery
                | LeaseReasonCode::InternalError
        ),
        LeaseStatus::Requested
        | LeaseStatus::Active
        | LeaseStatus::Renewing
        | LeaseStatus::Refused => false,
    };
    if valid {
        Ok(())
    } else {
        Err(LeaseDomainError::InvalidSnapshot)
    }
}
