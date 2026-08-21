//! Pure identity-lease lifecycle and fencing domain.
//!
//! The types here perform no persistence, locking, process management, or
//! ambient profile resolution. Wall time is retained for audit attribution;
//! caller-supplied monotonic moments are the rollback-resistant runtime gate.

use super::{
    contracts::{
        AgentRole, AutomationAuthMode, AutomationErrorCode, AutomationOperation, EnvironmentName,
        ExecutionHandle, FencingGeneration, HostIdentity, IsolationClassification, LeaseReasonCode,
        LeaseStatus, PrincipalRef, Provider, RefusalCode, RunId, Sha256Digest, TenantId,
        UtcTimestamp, WorkerIdentity, WorkspaceRef,
    },
    policy::EffectivePolicy,
};

mod clock;
mod replay;
pub use clock::{ClockSample, MonotonicMoment};
use clock::{add_seconds, deadline_reached, earlier, wall_nanoseconds_between};
pub use replay::{LeaseBinding, ReplayBinding, ReplayDisposition};

pub const RENEWAL_ACK_TIMEOUT_SECONDS: u64 = 30;

/// Runtime-resolved identity. Every field is non-secret and safe for public
/// lease attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseResolution {
    pub execution_handle: ExecutionHandle,
    pub worker_identity: Option<WorkerIdentity>,
    pub principal_ref: PrincipalRef,
    pub workspace_ref: WorkspaceRef,
    pub auth_mode: AutomationAuthMode,
    pub isolation: IsolationClassification,
}

/// Control-plane binding checked by renewal, closure, and execution gates.
pub struct LeaseControl<'a> {
    pub tenant_id: &'a TenantId,
    pub run_id: &'a RunId,
    pub role: AgentRole,
    pub host_identity: &'a HostIdentity,
    pub fencing_generation: FencingGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedAuthority {
    resolution: LeaseResolution,
    effective_policy_digest: Sha256Digest,
    fencing_generation: FencingGeneration,
    expires_at: UtcTimestamp,
    maximum_expires_at: UtcTimestamp,
    monotonic_deadline: MonotonicMoment,
    monotonic_maximum_deadline: MonotonicMoment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseState {
    Requested,
    Active(ResolvedAuthority),
    Renewing {
        authority: ResolvedAuthority,
        acknowledgement_deadline: UtcTimestamp,
        monotonic_acknowledgement_deadline: MonotonicMoment,
    },
    Error {
        authority: ResolvedAuthority,
        reason: LeaseReasonCode,
    },
    Closed {
        authority: ResolvedAuthority,
        reason: LeaseReasonCode,
    },
    Revoked {
        authority: ResolvedAuthority,
        reason: LeaseReasonCode,
    },
    Expired {
        authority: ResolvedAuthority,
        reason: LeaseReasonCode,
    },
    Refused(RefusalCode),
}

impl LeaseState {
    const fn status(&self) -> LeaseStatus {
        match self {
            Self::Requested => LeaseStatus::Requested,
            Self::Active(_) => LeaseStatus::Active,
            Self::Renewing { .. } => LeaseStatus::Renewing,
            Self::Error { .. } => LeaseStatus::Error,
            Self::Closed { .. } => LeaseStatus::Closed,
            Self::Revoked { .. } => LeaseStatus::Revoked,
            Self::Expired { .. } => LeaseStatus::Expired,
            Self::Refused(_) => LeaseStatus::Refused,
        }
    }

    const fn authority(&self) -> Option<&ResolvedAuthority> {
        match self {
            Self::Active(authority)
            | Self::Renewing { authority, .. }
            | Self::Error { authority, .. }
            | Self::Closed { authority, .. }
            | Self::Revoked { authority, .. }
            | Self::Expired { authority, .. } => Some(authority),
            Self::Requested | Self::Refused(_) => None,
        }
    }
}

/// One pure lease aggregate. All fields are non-secret and mutations enforce
/// the complete v1 transition graph.
#[derive(Debug, Eq, PartialEq)]
pub struct Lease {
    binding: LeaseBinding,
    issuance_clock: ClockSample,
    state: LeaseState,
}

impl Lease {
    #[must_use]
    pub const fn requested(binding: LeaseBinding, issuance_clock: ClockSample) -> Self {
        Self {
            binding,
            issuance_clock,
            state: LeaseState::Requested,
        }
    }

    #[must_use]
    pub const fn binding(&self) -> &LeaseBinding {
        &self.binding
    }

    #[must_use]
    pub const fn issued_at(&self) -> &UtcTimestamp {
        &self.issuance_clock.wall
    }

    #[must_use]
    pub const fn status(&self) -> LeaseStatus {
        self.state.status()
    }

    #[must_use]
    pub const fn refusal_code(&self) -> Option<RefusalCode> {
        match self.state {
            LeaseState::Refused(code) => Some(code),
            _ => None,
        }
    }

    #[must_use]
    pub const fn reason_code(&self) -> Option<LeaseReasonCode> {
        match self.state {
            LeaseState::Error { reason, .. }
            | LeaseState::Closed { reason, .. }
            | LeaseState::Revoked { reason, .. }
            | LeaseState::Expired { reason, .. } => Some(reason),
            _ => None,
        }
    }

    #[must_use]
    pub const fn fencing_generation(&self) -> Option<FencingGeneration> {
        match self.state.authority() {
            Some(authority) => Some(authority.fencing_generation),
            None => None,
        }
    }

    #[must_use]
    pub const fn expires_at(&self) -> Option<&UtcTimestamp> {
        match self.state.authority() {
            Some(authority) => Some(&authority.expires_at),
            None => None,
        }
    }

    #[must_use]
    pub const fn maximum_expires_at(&self) -> Option<&UtcTimestamp> {
        match self.state.authority() {
            Some(authority) => Some(&authority.maximum_expires_at),
            None => None,
        }
    }

    #[must_use]
    pub const fn effective_policy_digest(&self) -> Option<Sha256Digest> {
        match self.state.authority() {
            Some(authority) => Some(authority.effective_policy_digest),
            None => None,
        }
    }

    #[must_use]
    pub const fn execution_handle(&self) -> Option<&ExecutionHandle> {
        match &self.state {
            LeaseState::Active(authority) | LeaseState::Renewing { authority, .. } => {
                Some(&authority.resolution.execution_handle)
            }
            _ => None,
        }
    }

    #[must_use]
    pub const fn renewal_acknowledgement_deadline(&self) -> Option<&UtcTimestamp> {
        match &self.state {
            LeaseState::Renewing {
                acknowledgement_deadline,
                ..
            } => Some(acknowledgement_deadline),
            _ => None,
        }
    }

    #[must_use]
    pub fn replay_binding(&self) -> ReplayBinding {
        ReplayBinding {
            lease_id: self.binding.lease_id.clone(),
            client_request_id: self.binding.client_request_id.clone(),
            authority_digest: self.binding.authority_digest,
            caller_subject: self.binding.caller_subject.clone(),
            host_identity: self.binding.host_identity.clone(),
            signed_authorization_expires_at: self.binding.signed_authorization_expires_at.clone(),
        }
    }

    pub fn refuse(&mut self, code: RefusalCode) -> Result<(), LeaseDomainError> {
        self.require_status(LeaseStatus::Requested)?;
        self.state = LeaseState::Refused(code);
        Ok(())
    }

    pub fn activate(
        &mut self,
        policy: &EffectivePolicy,
        resolution: LeaseResolution,
        now: &ClockSample,
    ) -> Result<(), LeaseDomainError> {
        self.require_status(LeaseStatus::Requested)?;
        self.validate_clock(now)?;
        self.validate_policy_binding(policy)?;
        if policy.requested_ttl_seconds != self.binding.initial_requested_ttl_seconds {
            return Err(LeaseDomainError::PolicyBindingMismatch);
        }
        validate_resolution(self.binding.provider, policy, &resolution)?;
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
        self.state = LeaseState::Active(ResolvedAuthority {
            resolution,
            effective_policy_digest: policy.digest(),
            fencing_generation: FencingGeneration::from_value(1)
                .map_err(|_| LeaseDomainError::GenerationExhausted)?,
            expires_at,
            maximum_expires_at,
            monotonic_deadline,
            monotonic_maximum_deadline,
        });
        Ok(())
    }

    /// Start renewal against a freshly recomputed effective policy.
    pub fn begin_renewal(
        &mut self,
        control: &LeaseControl<'_>,
        current_policy: &EffectivePolicy,
        now: &ClockSample,
    ) -> Result<FencingGeneration, LeaseDomainError> {
        self.validate_clock(now)?;
        if self.enforce_deadlines(now)? {
            return Err(self.state_error(LeaseStatus::Renewing));
        }
        self.require_status(LeaseStatus::Active)?;
        self.validate_control(control)?;
        self.validate_policy_binding(current_policy)?;
        if current_policy.requested_ttl_seconds > current_policy.maximum_ttl_seconds
            || current_policy.requested_ttl_seconds > current_policy.maximum_session_seconds
        {
            return Err(LeaseDomainError::SessionLimitReached);
        }
        let LeaseState::Active(authority) = &self.state else {
            return Err(LeaseDomainError::InvalidTransition {
                from: self.status(),
                to: LeaseStatus::Renewing,
            });
        };
        let current_policy_maximum =
            add_seconds(self.issued_at(), current_policy.maximum_session_seconds)?;
        let effective_maximum = earlier(
            &authority.maximum_expires_at,
            earlier(&current_policy.signed_expires_at, &current_policy_maximum),
        );
        let signed_runtime =
            wall_nanoseconds_between(self.issued_at(), &current_policy.signed_expires_at)?;
        let signed_monotonic_maximum = self
            .issuance_clock
            .monotonic
            .checked_add_nanoseconds(signed_runtime)
            .ok_or(LeaseDomainError::ClockOverflow)?;
        let policy_monotonic_maximum = self
            .issuance_clock
            .monotonic
            .checked_add_seconds(current_policy.maximum_session_seconds)
            .ok_or(LeaseDomainError::ClockOverflow)?;
        let monotonic_maximum_deadline = authority
            .monotonic_maximum_deadline
            .min(signed_monotonic_maximum)
            .min(policy_monotonic_maximum);
        let expires_at = add_seconds(&now.wall, current_policy.requested_ttl_seconds)?;
        let monotonic_deadline = now
            .monotonic
            .checked_add_seconds(current_policy.requested_ttl_seconds)
            .ok_or(LeaseDomainError::ClockOverflow)?;
        if effective_maximum.is_before(&expires_at)
            || monotonic_deadline > monotonic_maximum_deadline
            || !authority.expires_at.is_before(&expires_at)
            || monotonic_deadline <= authority.monotonic_deadline
        {
            return Err(LeaseDomainError::SessionLimitReached);
        }
        let next_generation = authority
            .fencing_generation
            .get()
            .checked_add(1)
            .ok_or(LeaseDomainError::GenerationExhausted)
            .and_then(|value| {
                FencingGeneration::from_value(value)
                    .map_err(|_| LeaseDomainError::GenerationExhausted)
            })?;
        let mut renewed = authority.clone();
        renewed.fencing_generation = next_generation;
        renewed.expires_at = expires_at;
        renewed.maximum_expires_at = effective_maximum.clone();
        renewed.monotonic_deadline = monotonic_deadline;
        renewed.monotonic_maximum_deadline = monotonic_maximum_deadline;
        renewed.effective_policy_digest = current_policy.digest();
        let acknowledgement_deadline = earlier(
            &add_seconds(&now.wall, RENEWAL_ACK_TIMEOUT_SECONDS)?,
            &renewed.expires_at,
        )
        .clone();
        let monotonic_acknowledgement_deadline = now
            .monotonic
            .checked_add_seconds(RENEWAL_ACK_TIMEOUT_SECONDS)
            .ok_or(LeaseDomainError::ClockOverflow)?
            .min(renewed.monotonic_deadline);
        self.state = LeaseState::Renewing {
            authority: renewed,
            acknowledgement_deadline,
            monotonic_acknowledgement_deadline,
        };
        Ok(next_generation)
    }

    pub fn acknowledge_renewal(
        &mut self,
        control: &LeaseControl<'_>,
        now: &ClockSample,
    ) -> Result<(), LeaseDomainError> {
        self.validate_clock(now)?;
        if self.enforce_deadlines(now)? {
            return Err(self.state_error(LeaseStatus::Active));
        }
        self.require_status(LeaseStatus::Renewing)?;
        let LeaseState::Renewing { authority, .. } = &self.state else {
            return Err(LeaseDomainError::LeaseNotActive);
        };
        let authority = authority.clone();
        if let Err(error) = self.validate_control(control) {
            self.state = LeaseState::Revoked {
                authority,
                reason: LeaseReasonCode::RenewalAcknowledgementFailed,
            };
            return Err(error);
        }
        self.state = LeaseState::Active(authority);
        Ok(())
    }

    pub fn close(
        &mut self,
        control: &LeaseControl<'_>,
        reason: LeaseReasonCode,
        now: &ClockSample,
    ) -> Result<(), LeaseDomainError> {
        if !matches!(
            reason,
            LeaseReasonCode::Completed | LeaseReasonCode::WorkerFailed
        ) {
            return Err(LeaseDomainError::InvalidReason {
                status: LeaseStatus::Closed,
                reason,
            });
        }
        self.validate_clock(now)?;
        if self.enforce_deadlines(now)? {
            return Err(self.state_error(LeaseStatus::Closed));
        }
        self.require_active_or_renewing(LeaseStatus::Closed)?;
        self.validate_control(control)?;
        let authority = self
            .state
            .authority()
            .cloned()
            .ok_or(LeaseDomainError::LeaseNotActive)?;
        self.state = LeaseState::Closed { authority, reason };
        Ok(())
    }

    pub fn revoke(&mut self, reason: LeaseReasonCode) -> Result<(), LeaseDomainError> {
        if !revocation_reason(reason) {
            return Err(LeaseDomainError::InvalidReason {
                status: LeaseStatus::Revoked,
                reason,
            });
        }
        if !matches!(
            self.status(),
            LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error
        ) {
            return Err(LeaseDomainError::LeaseNotActive);
        }
        let authority = self
            .state
            .authority()
            .cloned()
            .ok_or(LeaseDomainError::LeaseNotActive)?;
        self.state = LeaseState::Revoked { authority, reason };
        Ok(())
    }

    pub fn mark_error(&mut self, reason: LeaseReasonCode) -> Result<(), LeaseDomainError> {
        if !matches!(
            reason,
            LeaseReasonCode::ProcessUnverifiable
                | LeaseReasonCode::ServiceRecovery
                | LeaseReasonCode::InternalError
        ) {
            return Err(LeaseDomainError::InvalidReason {
                status: LeaseStatus::Error,
                reason,
            });
        }
        self.require_active_or_renewing(LeaseStatus::Error)?;
        let authority = self
            .state
            .authority()
            .cloned()
            .ok_or(LeaseDomainError::LeaseNotActive)?;
        self.state = LeaseState::Error { authority, reason };
        Ok(())
    }

    /// Enforce lease, maximum-lifetime, and pending-renewal deadlines.
    pub fn enforce_deadlines(&mut self, now: &ClockSample) -> Result<bool, LeaseDomainError> {
        self.validate_clock(now)?;
        if !matches!(
            self.status(),
            LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error
        ) {
            return Ok(false);
        }
        let authority = self
            .state
            .authority()
            .cloned()
            .ok_or(LeaseDomainError::LeaseNotActive)?;
        if let LeaseState::Renewing {
            acknowledgement_deadline,
            monotonic_acknowledgement_deadline,
            ..
        } = &self.state
            && deadline_reached(
                now,
                acknowledgement_deadline,
                *monotonic_acknowledgement_deadline,
            )
        {
            self.state = LeaseState::Revoked {
                authority,
                reason: LeaseReasonCode::RenewalAcknowledgementFailed,
            };
            return Ok(true);
        }
        let maximum_reached = deadline_reached(
            now,
            &authority.maximum_expires_at,
            authority.monotonic_maximum_deadline,
        );
        let interval_reached =
            deadline_reached(now, &authority.expires_at, authority.monotonic_deadline);
        let reason = if maximum_reached {
            Some(LeaseReasonCode::MaximumLifetimeReached)
        } else if interval_reached {
            Some(LeaseReasonCode::LeaseExpired)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.state = LeaseState::Expired { authority, reason };
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Revalidate current policy, binding, fencing, and deadlines before launch.
    pub fn authorize_launch(
        &mut self,
        control: &LeaseControl<'_>,
        current_policy: &EffectivePolicy,
        now: &ClockSample,
    ) -> Result<ExecutionHandle, LeaseDomainError> {
        self.validate_clock(now)?;
        if self.enforce_deadlines(now)? {
            return Err(self.state_error(LeaseStatus::Active));
        }
        self.require_status(LeaseStatus::Active)?;
        self.validate_control(control)?;
        self.validate_policy_binding(current_policy)?;
        let authority = self
            .state
            .authority()
            .cloned()
            .ok_or(LeaseDomainError::LeaseNotActive)?;
        if authority.effective_policy_digest != current_policy.digest() {
            self.state = LeaseState::Revoked {
                authority,
                reason: LeaseReasonCode::PolicyRevoked,
            };
            return Err(LeaseDomainError::LeaseRevoked);
        }
        Ok(authority.resolution.execution_handle)
    }

    fn validate_control(&self, control: &LeaseControl<'_>) -> Result<(), LeaseDomainError> {
        if control.tenant_id != &self.binding.tenant_id {
            return Err(LeaseDomainError::TenantMismatch);
        }
        if control.run_id != &self.binding.run_id {
            return Err(LeaseDomainError::RunMismatch);
        }
        if control.role != self.binding.role {
            return Err(LeaseDomainError::RoleMismatch);
        }
        if control.host_identity != &self.binding.host_identity {
            return Err(LeaseDomainError::HostMismatch);
        }
        let current = self
            .fencing_generation()
            .ok_or(LeaseDomainError::LeaseNotActive)?;
        require_generation(current, control.fencing_generation)
    }

    fn validate_clock(&self, now: &ClockSample) -> Result<(), LeaseDomainError> {
        if now.wall.is_before(&self.issuance_clock.wall)
            || now.monotonic < self.issuance_clock.monotonic
        {
            Err(LeaseDomainError::ClockOverflow)
        } else {
            Ok(())
        }
    }

    fn validate_policy_binding(&self, policy: &EffectivePolicy) -> Result<(), LeaseDomainError> {
        let matches = self.binding.client_request_id == policy.client_request_id
            && self.binding.authority_digest == policy.source_request_digest
            && self.binding.tenant_id == policy.tenant_id
            && self.binding.work_order_id == policy.work_order_id
            && self.binding.work_order_digest == policy.work_order_digest
            && self.binding.run_id == policy.run_id
            && self.binding.attempt_id == policy.attempt_id
            && self.binding.role == policy.role
            && self.binding.provider == policy.provider
            && self.binding.profile_uid == policy.profile_uid
            && self.binding.profile_ref == policy.profile_ref
            && self.binding.repository == policy.repository
            && self.binding.workspace_id == policy.workspace_id
            && self.binding.environment == policy.environment
            && self.binding.caller_subject == policy.caller_subject
            && self.binding.host_identity == policy.host_identity;
        let capacity_matches = self.binding.profile_uid == policy.capacity_claim.profile_uid
            && self.binding.provider == policy.capacity_claim.provider
            && self.binding.caller_subject == policy.capacity_claim.caller_subject
            && self.binding.host_identity == policy.capacity_claim.host_identity;
        if matches && capacity_matches {
            Ok(())
        } else {
            Err(LeaseDomainError::PolicyBindingMismatch)
        }
    }

    fn require_status(&self, expected: LeaseStatus) -> Result<(), LeaseDomainError> {
        if self.status() == expected {
            Ok(())
        } else {
            Err(self.state_error(expected))
        }
    }

    fn require_active_or_renewing(&self, target: LeaseStatus) -> Result<(), LeaseDomainError> {
        if matches!(self.status(), LeaseStatus::Active | LeaseStatus::Renewing) {
            Ok(())
        } else {
            Err(self.state_error(target))
        }
    }

    fn state_error(&self, target: LeaseStatus) -> LeaseDomainError {
        match self.status() {
            LeaseStatus::Closed | LeaseStatus::Refused => {
                LeaseDomainError::TerminalImmutable(self.status())
            }
            LeaseStatus::Revoked => LeaseDomainError::LeaseRevoked,
            LeaseStatus::Expired => LeaseDomainError::LeaseExpired,
            LeaseStatus::Requested
            | LeaseStatus::Active
            | LeaseStatus::Renewing
            | LeaseStatus::Error => LeaseDomainError::InvalidTransition {
                from: self.status(),
                to: target,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseDomainError {
    InvalidTransition {
        from: LeaseStatus,
        to: LeaseStatus,
    },
    TerminalImmutable(LeaseStatus),
    LeaseNotActive,
    LeaseExpired,
    LeaseRevoked,
    GenerationMismatch,
    GenerationExhausted,
    SessionLimitReached,
    TenantMismatch,
    RunMismatch,
    RoleMismatch,
    HostMismatch,
    PolicyBindingMismatch,
    InvalidReason {
        status: LeaseStatus,
        reason: LeaseReasonCode,
    },
    ClockOverflow,
}

impl LeaseDomainError {
    #[must_use]
    pub const fn automation_code(&self, operation: AutomationOperation) -> AutomationErrorCode {
        match self {
            Self::InvalidReason { .. } => AutomationErrorCode::InvalidRequest,
            Self::LeaseExpired => state_code(operation, AutomationErrorCode::LeaseExpired),
            Self::LeaseRevoked => state_code(operation, AutomationErrorCode::LeaseRevoked),
            Self::GenerationMismatch => {
                control_code(operation, AutomationErrorCode::GenerationMismatch, true)
            }
            Self::SessionLimitReached => {
                control_code(operation, AutomationErrorCode::SessionLimitReached, false)
            }
            Self::TenantMismatch => {
                control_code(operation, AutomationErrorCode::TenantMismatch, true)
            }
            Self::RunMismatch => control_code(operation, AutomationErrorCode::RunMismatch, true),
            Self::RoleMismatch => control_code(operation, AutomationErrorCode::RoleMismatch, true),
            Self::HostMismatch => control_code(operation, AutomationErrorCode::HostMismatch, true),
            Self::InvalidTransition { .. } | Self::TerminalImmutable(_) | Self::LeaseNotActive => {
                lease_not_active_code(operation)
            }
            Self::GenerationExhausted | Self::PolicyBindingMismatch | Self::ClockOverflow => {
                AutomationErrorCode::InternalError
            }
        }
    }
}

const fn state_code(
    operation: AutomationOperation,
    code: AutomationErrorCode,
) -> AutomationErrorCode {
    match operation {
        AutomationOperation::LeaseRenew
        | AutomationOperation::LeaseClose
        | AutomationOperation::ExecutionStart => code,
        AutomationOperation::LeaseRevoke => AutomationErrorCode::LeaseNotActive,
        _ => AutomationErrorCode::InternalError,
    }
}

const fn control_code(
    operation: AutomationOperation,
    code: AutomationErrorCode,
    close_allows: bool,
) -> AutomationErrorCode {
    match operation {
        AutomationOperation::LeaseRenew | AutomationOperation::ExecutionStart => code,
        AutomationOperation::LeaseClose if close_allows => code,
        _ => AutomationErrorCode::InternalError,
    }
}

const fn lease_not_active_code(operation: AutomationOperation) -> AutomationErrorCode {
    match operation {
        AutomationOperation::LeaseRenew
        | AutomationOperation::LeaseRevoke
        | AutomationOperation::LeaseClose
        | AutomationOperation::ExecutionStart => AutomationErrorCode::LeaseNotActive,
        _ => AutomationErrorCode::InternalError,
    }
}

fn require_generation(
    current: FencingGeneration,
    supplied: FencingGeneration,
) -> Result<(), LeaseDomainError> {
    if current == supplied {
        Ok(())
    } else {
        Err(LeaseDomainError::GenerationMismatch)
    }
}

const fn revocation_reason(reason: LeaseReasonCode) -> bool {
    matches!(
        reason,
        LeaseReasonCode::OperatorRevoked
            | LeaseReasonCode::PolicyRevoked
            | LeaseReasonCode::PrincipalMismatch
            | LeaseReasonCode::HeartbeatLost
            | LeaseReasonCode::ProcessUnverifiable
            | LeaseReasonCode::GenerationSuperseded
            | LeaseReasonCode::RenewalAcknowledgementFailed
            | LeaseReasonCode::ServiceRecovery
    )
}

fn validate_resolution(
    provider: Provider,
    policy: &EffectivePolicy,
    resolution: &LeaseResolution,
) -> Result<(), LeaseDomainError> {
    if !resolution.workspace_ref.matches_provider(provider)
        || !resolution.auth_mode.supports_provider(provider)
        || resolution.auth_mode != policy.auth_mode
        || resolution.isolation != policy.isolation
        || resolution.isolation == IsolationClassification::Unproven
    {
        return Err(LeaseDomainError::PolicyBindingMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[path = "lease/tests.rs"]
mod tests;
