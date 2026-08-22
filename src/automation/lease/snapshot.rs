use crate::automation::contracts::{
    ExecutionHandle, FencingGeneration, IdentityLeaseResponse, IdentityLeaseSchema,
    LeaseReasonCode, LeaseStatus, RefusalCode, WorkerIdentity,
};

use super::{
    ClockSample, Lease, LeaseBinding, LeaseDomainError, LeaseResolution, LeaseState,
    MonotonicMoment, ResolvedAuthority, ServiceClockGeneration,
};
use crate::automation::contracts::{Sha256Digest, UtcTimestamp};

#[path = "snapshot/validate.rs"]
mod validate;
use validate::{
    require_reason, validate_acknowledgement_pair, validate_authority, validate_live_high_water,
};

/// Lossless, non-secret persistence shape for a resolved lease authority.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PersistedResolvedAuthority {
    resolution: LeaseResolution,
    effective_policy_digest: Sha256Digest,
    fencing_generation: FencingGeneration,
    expires_at: UtcTimestamp,
    maximum_expires_at: UtcTimestamp,
    interval_anchor_wall: UtcTimestamp,
    interval_anchor_monotonic: MonotonicMoment,
    monotonic_deadline: MonotonicMoment,
    monotonic_maximum_deadline: MonotonicMoment,
}

impl PersistedResolvedAuthority {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        resolution: LeaseResolution,
        effective_policy_digest: Sha256Digest,
        fencing_generation: FencingGeneration,
        expires_at: UtcTimestamp,
        maximum_expires_at: UtcTimestamp,
        interval_anchor_wall: UtcTimestamp,
        interval_anchor_monotonic: MonotonicMoment,
        monotonic_deadline: MonotonicMoment,
        monotonic_maximum_deadline: MonotonicMoment,
    ) -> Self {
        Self {
            resolution,
            effective_policy_digest,
            fencing_generation,
            expires_at,
            maximum_expires_at,
            interval_anchor_wall,
            interval_anchor_monotonic,
            monotonic_deadline,
            monotonic_maximum_deadline,
        }
    }

    fn into_domain(self) -> ResolvedAuthority {
        ResolvedAuthority {
            resolution: self.resolution,
            effective_policy_digest: self.effective_policy_digest,
            fencing_generation: self.fencing_generation,
            expires_at: self.expires_at,
            maximum_expires_at: self.maximum_expires_at,
            interval_anchor_wall: self.interval_anchor_wall,
            interval_anchor_monotonic: self.interval_anchor_monotonic,
            monotonic_deadline: self.monotonic_deadline,
            monotonic_maximum_deadline: self.monotonic_maximum_deadline,
        }
    }
}

impl From<&ResolvedAuthority> for PersistedResolvedAuthority {
    fn from(value: &ResolvedAuthority) -> Self {
        Self {
            resolution: value.resolution.clone(),
            effective_policy_digest: value.effective_policy_digest,
            fencing_generation: value.fencing_generation,
            expires_at: value.expires_at.clone(),
            maximum_expires_at: value.maximum_expires_at.clone(),
            interval_anchor_wall: value.interval_anchor_wall.clone(),
            interval_anchor_monotonic: value.interval_anchor_monotonic,
            monotonic_deadline: value.monotonic_deadline,
            monotonic_maximum_deadline: value.monotonic_maximum_deadline,
        }
    }
}

/// Every durable lease state, including internally retained terminal authority.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum PersistedLeaseState {
    Requested,
    Active(PersistedResolvedAuthority),
    Renewing {
        authority: PersistedResolvedAuthority,
        acknowledgement_deadline: UtcTimestamp,
        monotonic_acknowledgement_deadline: MonotonicMoment,
    },
    Error {
        authority: PersistedResolvedAuthority,
        reason: LeaseReasonCode,
    },
    Closed {
        authority: PersistedResolvedAuthority,
        reason: LeaseReasonCode,
    },
    Revoked {
        authority: PersistedResolvedAuthority,
        reason: LeaseReasonCode,
    },
    Expired {
        authority: PersistedResolvedAuthority,
        reason: LeaseReasonCode,
    },
    Refused(RefusalCode),
}

/// Sealed aggregate snapshot used only by the durable automation boundary.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct LeaseSnapshot {
    binding: LeaseBinding,
    issuance_clock: ClockSample,
    monotonic_high_water: MonotonicMoment,
    state: PersistedLeaseState,
}

impl LeaseSnapshot {
    pub(crate) const fn new(
        binding: LeaseBinding,
        issuance_clock: ClockSample,
        monotonic_high_water: MonotonicMoment,
        state: PersistedLeaseState,
    ) -> Self {
        Self {
            binding,
            issuance_clock,
            monotonic_high_water,
            state,
        }
    }

    #[must_use]
    pub(crate) const fn service_generation(&self) -> ServiceClockGeneration {
        self.issuance_clock.service_generation
    }

    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn monotonic_high_water(&self) -> MonotonicMoment {
        self.monotonic_high_water
    }

    /// Compare sealed process evidence without exporting retained terminal
    /// authority from this snapshot.
    pub(crate) fn validate_process_binding(
        &self,
        origin_generation: ServiceClockGeneration,
        execution_handle: &ExecutionHandle,
        worker_identity: Option<&WorkerIdentity>,
        observed_fencing_generation: FencingGeneration,
    ) -> Result<(), LeaseDomainError> {
        if origin_generation != self.issuance_clock.service_generation {
            return Err(LeaseDomainError::InvalidSnapshot);
        }
        let authority = match &self.state {
            PersistedLeaseState::Active(authority)
            | PersistedLeaseState::Renewing { authority, .. }
            | PersistedLeaseState::Error { authority, .. }
            | PersistedLeaseState::Closed { authority, .. }
            | PersistedLeaseState::Revoked { authority, .. }
            | PersistedLeaseState::Expired { authority, .. } => authority,
            PersistedLeaseState::Requested | PersistedLeaseState::Refused(_) => {
                return Err(LeaseDomainError::InvalidSnapshot);
            }
        };
        if execution_handle == &authority.resolution.execution_handle
            && worker_identity == authority.resolution.worker_identity.as_ref()
            && observed_fencing_generation.get() <= authority.fencing_generation.get()
        {
            Ok(())
        } else {
            Err(LeaseDomainError::InvalidSnapshot)
        }
    }

    fn into_lease(self) -> Result<Lease, LeaseDomainError> {
        if self.issuance_clock.service_generation.get() == 0
            || self.monotonic_high_water < self.issuance_clock.monotonic
        {
            return Err(LeaseDomainError::InvalidSnapshot);
        }
        let high_water = self.monotonic_high_water;
        let state = match self.state {
            PersistedLeaseState::Requested => LeaseState::Requested,
            PersistedLeaseState::Refused(code) => LeaseState::Refused(code),
            PersistedLeaseState::Active(authority) => {
                validate_authority(&authority, &self.binding, &self.issuance_clock, high_water)?;
                validate_live_high_water(&authority, high_water)?;
                LeaseState::Active(authority.into_domain())
            }
            PersistedLeaseState::Renewing {
                authority,
                acknowledgement_deadline,
                monotonic_acknowledgement_deadline,
            } => {
                if authority.fencing_generation.get() == 1 {
                    return Err(LeaseDomainError::InvalidSnapshot);
                }
                validate_authority(&authority, &self.binding, &self.issuance_clock, high_water)?;
                validate_live_high_water(&authority, high_water)?;
                if authority.expires_at.is_before(&acknowledgement_deadline)
                    || monotonic_acknowledgement_deadline <= self.issuance_clock.monotonic
                    || monotonic_acknowledgement_deadline > authority.monotonic_deadline
                    || high_water >= monotonic_acknowledgement_deadline
                {
                    return Err(LeaseDomainError::InvalidSnapshot);
                }
                validate_acknowledgement_pair(
                    &authority,
                    &acknowledgement_deadline,
                    monotonic_acknowledgement_deadline,
                )?;
                LeaseState::Renewing {
                    authority: authority.into_domain(),
                    acknowledgement_deadline,
                    monotonic_acknowledgement_deadline,
                }
            }
            PersistedLeaseState::Error { authority, reason } => {
                validate_authority(&authority, &self.binding, &self.issuance_clock, high_water)?;
                require_reason(LeaseStatus::Error, reason)?;
                validate_live_high_water(&authority, high_water)?;
                LeaseState::Error {
                    authority: authority.into_domain(),
                    reason,
                }
            }
            PersistedLeaseState::Closed { authority, reason } => {
                validate_authority(&authority, &self.binding, &self.issuance_clock, high_water)?;
                require_reason(LeaseStatus::Closed, reason)?;
                LeaseState::Closed {
                    authority: authority.into_domain(),
                    reason,
                }
            }
            PersistedLeaseState::Revoked { authority, reason } => {
                validate_authority(&authority, &self.binding, &self.issuance_clock, high_water)?;
                require_reason(LeaseStatus::Revoked, reason)?;
                LeaseState::Revoked {
                    authority: authority.into_domain(),
                    reason,
                }
            }
            PersistedLeaseState::Expired { authority, reason } => {
                validate_authority(&authority, &self.binding, &self.issuance_clock, high_water)?;
                require_reason(LeaseStatus::Expired, reason)?;
                LeaseState::Expired {
                    authority: authority.into_domain(),
                    reason,
                }
            }
        };
        let lease = Lease {
            binding: self.binding,
            issuance_clock: self.issuance_clock,
            last_monotonic: high_water,
            state,
        };
        lease.identity_response()?;
        Ok(lease)
    }
}

impl core::fmt::Debug for LeaseSnapshot {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LeaseSnapshot")
            .field("lease_id", &self.binding.lease_id)
            .field("status", &persisted_status(&self.state))
            .field(
                "service_generation",
                &self.issuance_clock.service_generation,
            )
            .finish_non_exhaustive()
    }
}

const fn persisted_status(state: &PersistedLeaseState) -> LeaseStatus {
    match state {
        PersistedLeaseState::Requested => LeaseStatus::Requested,
        PersistedLeaseState::Active(_) => LeaseStatus::Active,
        PersistedLeaseState::Renewing { .. } => LeaseStatus::Renewing,
        PersistedLeaseState::Error { .. } => LeaseStatus::Error,
        PersistedLeaseState::Closed { .. } => LeaseStatus::Closed,
        PersistedLeaseState::Revoked { .. } => LeaseStatus::Revoked,
        PersistedLeaseState::Expired { .. } => LeaseStatus::Expired,
        PersistedLeaseState::Refused(_) => LeaseStatus::Refused,
    }
}

impl Lease {
    #[must_use]
    pub(crate) fn snapshot(&self) -> LeaseSnapshot {
        let state = match &self.state {
            LeaseState::Requested => PersistedLeaseState::Requested,
            LeaseState::Active(authority) => {
                PersistedLeaseState::Active(PersistedResolvedAuthority::from(authority))
            }
            LeaseState::Renewing {
                authority,
                acknowledgement_deadline,
                monotonic_acknowledgement_deadline,
            } => PersistedLeaseState::Renewing {
                authority: PersistedResolvedAuthority::from(authority),
                acknowledgement_deadline: acknowledgement_deadline.clone(),
                monotonic_acknowledgement_deadline: *monotonic_acknowledgement_deadline,
            },
            LeaseState::Error { authority, reason } => PersistedLeaseState::Error {
                authority: PersistedResolvedAuthority::from(authority),
                reason: *reason,
            },
            LeaseState::Closed { authority, reason } => PersistedLeaseState::Closed {
                authority: PersistedResolvedAuthority::from(authority),
                reason: *reason,
            },
            LeaseState::Revoked { authority, reason } => PersistedLeaseState::Revoked {
                authority: PersistedResolvedAuthority::from(authority),
                reason: *reason,
            },
            LeaseState::Expired { authority, reason } => PersistedLeaseState::Expired {
                authority: PersistedResolvedAuthority::from(authority),
                reason: *reason,
            },
            LeaseState::Refused(code) => PersistedLeaseState::Refused(*code),
        };
        LeaseSnapshot::new(
            self.binding.clone(),
            self.issuance_clock.clone(),
            self.last_monotonic,
            state,
        )
    }

    pub(crate) fn restore(snapshot: LeaseSnapshot) -> Result<Self, LeaseDomainError> {
        snapshot.into_lease()
    }

    pub(crate) fn identity_response(&self) -> Result<IdentityLeaseResponse, LeaseDomainError> {
        let authority = self.state.authority();
        let response = IdentityLeaseResponse {
            schema: IdentityLeaseSchema,
            lease_id: self.binding.lease_id.clone(),
            status: self.status(),
            tenant_id: self.binding.tenant_id.clone(),
            work_order_id: self.binding.work_order_id.clone(),
            work_order_digest: self.binding.work_order_digest,
            run_id: self.binding.run_id.clone(),
            attempt_id: self.binding.attempt_id.clone(),
            role: self.binding.role,
            provider: self.binding.provider,
            profile_uid: self.binding.profile_uid.clone(),
            profile_ref: self.binding.profile_ref.clone(),
            repository: self.binding.repository.clone(),
            workspace_id: self.binding.workspace_id.clone(),
            environment: self.binding.environment.clone(),
            caller_subject: self.binding.caller_subject.clone(),
            host_identity: self.binding.host_identity.clone(),
            worker_identity: authority.and_then(|value| value.resolution.worker_identity.clone()),
            principal_ref: authority.map(|value| value.resolution.principal_ref.clone()),
            workspace_ref: authority.map(|value| value.resolution.workspace_ref.clone()),
            auth_mode: authority.map(|value| value.resolution.auth_mode),
            fencing_generation: authority.map(|value| value.fencing_generation),
            issued_at: self.issuance_clock.wall.clone(),
            expires_at: authority.map(|value| value.expires_at.clone()),
            maximum_expires_at: authority.map(|value| value.maximum_expires_at.clone()),
            execution_handle: self.execution_handle().cloned(),
            isolation: authority.map(|value| value.resolution.isolation),
            effective_policy_digest: authority.map(|value| value.effective_policy_digest),
            refusal_code: self.refusal_code(),
            reason_code: self.reason_code(),
        };
        response
            .validate()
            .map_err(|_| LeaseDomainError::InvalidSnapshot)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::automation::{
        contracts::{
            AutomationAuthMode, ExecutionHandle, IdentityLeaseRequest, IsolationClassification,
            LeaseId, PrincipalRef, WorkerIdentity, WorkspaceRef,
        },
        lease::ServiceClockGeneration,
    };

    fn request() -> IdentityLeaseRequest {
        serde_json::from_str(include_str!(
            "../../../schemas/examples/identity-lease-request.v1.json"
        ))
        .unwrap_or_else(|error| panic!("request: {error}"))
    }

    fn parsed<T>(value: &str) -> T
    where
        T: FromStr,
        T::Err: core::fmt::Debug,
    {
        value
            .parse()
            .unwrap_or_else(|error| panic!("parse {value}: {error:?}"))
    }

    fn binding() -> LeaseBinding {
        LeaseBinding::from_request(
            parsed("lease_00000000000000000000000000"),
            &request(),
            parsed("caller:controller"),
            parsed("host:runner"),
        )
        .unwrap_or_else(|error| panic!("binding: {error}"))
    }

    fn issuance() -> ClockSample {
        ClockSample::new(
            parsed("2026-08-21T10:30:00Z"),
            MonotonicMoment::from_nanoseconds(100),
            ServiceClockGeneration::from_value(7),
        )
    }

    fn authority() -> PersistedResolvedAuthority {
        PersistedResolvedAuthority::new(
            LeaseResolution {
                execution_handle: ExecutionHandle::parse("exec_00000000000000000000000000")
                    .unwrap_or_else(|error| panic!("handle: {error}")),
                worker_identity: Some(parsed::<WorkerIdentity>("worker:harness")),
                principal_ref: parsed::<PrincipalRef>("service-account:automation"),
                workspace_ref: parsed::<WorkspaceRef>("chatgpt-workspace:production"),
                auth_mode: AutomationAuthMode::Wif,
                isolation: IsolationClassification::CredentialIsolated,
            },
            parsed("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            FencingGeneration::from_value(1).unwrap_or_else(|error| panic!("generation: {error}")),
            parsed("2026-08-21T10:45:00Z"),
            parsed("2026-08-21T12:00:00Z"),
            parsed("2026-08-21T10:30:00Z"),
            MonotonicMoment::from_nanoseconds(100),
            MonotonicMoment::from_nanoseconds(900_000_000_100),
            MonotonicMoment::from_nanoseconds(5_400_000_000_100),
        )
    }

    fn renewing_authority() -> PersistedResolvedAuthority {
        let mut authority = authority();
        authority.fencing_generation =
            FencingGeneration::from_value(2).unwrap_or_else(|error| panic!("generation: {error}"));
        // A later monotonic observation may have a rolled-back wall sample.
        authority.interval_anchor_wall = parsed("2026-08-21T10:29:00Z");
        authority.interval_anchor_monotonic = MonotonicMoment::from_nanoseconds(200);
        authority.expires_at = parsed("2026-08-21T10:44:00Z");
        authority.monotonic_deadline = MonotonicMoment::from_nanoseconds(900_000_000_200);
        authority
    }

    fn snapshots() -> Vec<LeaseSnapshot> {
        let active = authority();
        let renewing = renewing_authority();
        vec![
            LeaseSnapshot::new(
                binding(),
                issuance(),
                MonotonicMoment::from_nanoseconds(100),
                PersistedLeaseState::Requested,
            ),
            LeaseSnapshot::new(
                binding(),
                issuance(),
                MonotonicMoment::from_nanoseconds(10_000_000_100),
                PersistedLeaseState::Active(active.clone()),
            ),
            LeaseSnapshot::new(
                binding(),
                issuance(),
                MonotonicMoment::from_nanoseconds(10_000_000_200),
                PersistedLeaseState::Renewing {
                    authority: renewing,
                    acknowledgement_deadline: parsed("2026-08-21T10:29:30Z"),
                    monotonic_acknowledgement_deadline: MonotonicMoment::from_nanoseconds(
                        30_000_000_200,
                    ),
                },
            ),
            LeaseSnapshot::new(
                binding(),
                issuance(),
                MonotonicMoment::from_nanoseconds(10_000_000_100),
                PersistedLeaseState::Error {
                    authority: active.clone(),
                    reason: LeaseReasonCode::InternalError,
                },
            ),
            LeaseSnapshot::new(
                binding(),
                issuance(),
                MonotonicMoment::from_nanoseconds(6_000_000_000_100),
                PersistedLeaseState::Closed {
                    authority: active.clone(),
                    reason: LeaseReasonCode::Completed,
                },
            ),
            LeaseSnapshot::new(
                binding(),
                issuance(),
                MonotonicMoment::from_nanoseconds(6_000_000_000_100),
                PersistedLeaseState::Revoked {
                    authority: active.clone(),
                    reason: LeaseReasonCode::ServiceRecovery,
                },
            ),
            LeaseSnapshot::new(
                binding(),
                issuance(),
                MonotonicMoment::from_nanoseconds(6_000_000_000_100),
                PersistedLeaseState::Expired {
                    authority: active,
                    reason: LeaseReasonCode::MaximumLifetimeReached,
                },
            ),
            LeaseSnapshot::new(
                binding(),
                issuance(),
                MonotonicMoment::from_nanoseconds(100),
                PersistedLeaseState::Refused(RefusalCode::ProfileNotReady),
            ),
        ]
    }

    #[test]
    fn all_states_round_trip_losslessly_and_emit_valid_public_responses() {
        let expected_statuses = [
            LeaseStatus::Requested,
            LeaseStatus::Active,
            LeaseStatus::Renewing,
            LeaseStatus::Error,
            LeaseStatus::Closed,
            LeaseStatus::Revoked,
            LeaseStatus::Expired,
            LeaseStatus::Refused,
        ];
        for (snapshot, expected_status) in snapshots().into_iter().zip(expected_statuses) {
            let restored = Lease::restore(snapshot.clone())
                .unwrap_or_else(|error| panic!("restore {expected_status:?}: {error:?}"));
            assert_eq!(restored.snapshot(), snapshot);
            let response = restored
                .identity_response()
                .unwrap_or_else(|error| panic!("response {expected_status:?}: {error:?}"));
            assert_eq!(response.status, expected_status);
            response
                .validate()
                .unwrap_or_else(|error| panic!("validate {expected_status:?}: {error:?}"));
            let wire = serde_json::to_vec(&response)
                .unwrap_or_else(|error| panic!("serialize {expected_status:?}: {error}"));
            let round_trip: IdentityLeaseResponse = serde_json::from_slice(&wire)
                .unwrap_or_else(|error| panic!("deserialize {expected_status:?}: {error}"));
            assert_eq!(round_trip, response);
            assert_eq!(
                response.execution_handle.is_some(),
                matches!(expected_status, LeaseStatus::Active | LeaseStatus::Renewing)
            );
            if matches!(
                expected_status,
                LeaseStatus::Error
                    | LeaseStatus::Closed
                    | LeaseStatus::Revoked
                    | LeaseStatus::Expired
            ) {
                assert!(response.execution_handle.is_none());
            }
        }
    }

    #[test]
    fn renewing_snapshot_preserves_truthful_wall_rollback() {
        let snapshot = snapshots()[2].clone();
        if let PersistedLeaseState::Renewing {
            acknowledgement_deadline,
            ..
        } = &snapshot.state
        {
            assert!(acknowledgement_deadline.is_before(&snapshot.issuance_clock.wall));
        } else {
            panic!("expected renewing snapshot");
        }
        let restored = Lease::restore(snapshot.clone())
            .unwrap_or_else(|error| panic!("rollback restore: {error:?}"));
        assert_eq!(restored.snapshot(), snapshot);
    }

    #[test]
    fn malformed_snapshot_matrix_fails_closed() {
        let mut cases = Vec::new();

        let mut zero_generation = snapshots()[0].clone();
        zero_generation.issuance_clock.service_generation = ServiceClockGeneration::from_value(0);
        cases.push(zero_generation);

        let mut regressed = snapshots()[1].clone();
        regressed.monotonic_high_water = MonotonicMoment::from_nanoseconds(99);
        cases.push(regressed);

        let mut active_expired = snapshots()[1].clone();
        active_expired.monotonic_high_water = MonotonicMoment::from_nanoseconds(900_000_000_100);
        cases.push(active_expired);

        let mut error_expired = snapshots()[3].clone();
        error_expired.monotonic_high_water = MonotonicMoment::from_nanoseconds(900_000_000_100);
        cases.push(error_expired);

        let mut bad_reason = snapshots()[4].clone();
        if let PersistedLeaseState::Closed { reason, .. } = &mut bad_reason.state {
            *reason = LeaseReasonCode::InternalError;
        }
        cases.push(bad_reason);

        let mut bad_ack = snapshots()[2].clone();
        if let PersistedLeaseState::Renewing {
            monotonic_acknowledgement_deadline,
            ..
        } = &mut bad_ack.state
        {
            *monotonic_acknowledgement_deadline = MonotonicMoment::from_nanoseconds(
                monotonic_acknowledgement_deadline.as_nanoseconds() + 1,
            );
        }
        cases.push(bad_ack);

        let mut first_generation_renewing = snapshots()[2].clone();
        if let PersistedLeaseState::Renewing {
            authority: renewing_authority,
            acknowledgement_deadline,
            monotonic_acknowledgement_deadline,
        } = &mut first_generation_renewing.state
        {
            *renewing_authority = authority();
            *acknowledgement_deadline = parsed("2026-08-21T10:30:30Z");
            *monotonic_acknowledgement_deadline = MonotonicMoment::from_nanoseconds(30_000_000_100);
        }
        cases.push(first_generation_renewing);

        let mut skewed_interval = snapshots()[1].clone();
        if let PersistedLeaseState::Active(authority) = &mut skewed_interval.state {
            authority.monotonic_deadline = MonotonicMoment::from_nanoseconds(
                authority.monotonic_deadline.as_nanoseconds() + 1,
            );
        }
        cases.push(skewed_interval);

        let mut skewed_maximum = snapshots()[1].clone();
        if let PersistedLeaseState::Active(authority) = &mut skewed_maximum.state {
            authority.monotonic_maximum_deadline = MonotonicMoment::from_nanoseconds(
                authority.monotonic_maximum_deadline.as_nanoseconds() + 1,
            );
        }
        cases.push(skewed_maximum);

        let mut initial_ttl_mismatch = snapshots()[1].clone();
        if let PersistedLeaseState::Active(authority) = &mut initial_ttl_mismatch.state {
            authority.expires_at = parsed("2026-08-21T10:44:59Z");
            authority.monotonic_deadline = MonotonicMoment::from_nanoseconds(899_000_000_100);
        }
        cases.push(initial_ttl_mismatch);

        let mut widened_renewal_ttl = snapshots()[2].clone();
        if let PersistedLeaseState::Renewing { authority, .. } = &mut widened_renewal_ttl.state {
            authority.expires_at = parsed("2026-08-21T10:44:01Z");
            authority.monotonic_deadline = MonotonicMoment::from_nanoseconds(901_000_000_200);
        }
        cases.push(widened_renewal_ttl);

        let mut widened_session = snapshots()[1].clone();
        widened_session.binding.signed_authorization_expires_at = parsed("2026-08-22T10:30:00Z");
        if let PersistedLeaseState::Active(authority) = &mut widened_session.state {
            authority.maximum_expires_at = parsed("2026-08-21T14:30:01Z");
            authority.monotonic_maximum_deadline =
                MonotonicMoment::from_nanoseconds(14_401_000_000_100);
        }
        cases.push(widened_session);

        let mut pre_issuance_anchor = snapshots()[1].clone();
        if let PersistedLeaseState::Active(authority) = &mut pre_issuance_anchor.state {
            authority.fencing_generation = FencingGeneration::from_value(2)
                .unwrap_or_else(|error| panic!("generation: {error}"));
            authority.interval_anchor_monotonic = MonotonicMoment::from_nanoseconds(99);
            authority.monotonic_deadline = MonotonicMoment::from_nanoseconds(900_000_000_099);
        }
        cases.push(pre_issuance_anchor);

        let mut anchor_above_high_water = snapshots()[1].clone();
        if let PersistedLeaseState::Active(authority) = &mut anchor_above_high_water.state {
            authority.fencing_generation = FencingGeneration::from_value(2)
                .unwrap_or_else(|error| panic!("generation: {error}"));
            authority.interval_anchor_monotonic = MonotonicMoment::from_nanoseconds(10_000_000_101);
        }
        cases.push(anchor_above_high_water);

        let mut bad_maximum = snapshots()[6].clone();
        if let PersistedLeaseState::Expired { authority, .. } = &mut bad_maximum.state {
            authority.maximum_expires_at = parsed("2026-08-21T10:59:59Z");
        }
        cases.push(bad_maximum);

        let mut unproven = snapshots()[1].clone();
        if let PersistedLeaseState::Active(authority) = &mut unproven.state {
            authority.resolution.isolation = IsolationClassification::Unproven;
        }
        cases.push(unproven);

        let mut wrong_provider_refusal = snapshots()[7].clone();
        wrong_provider_refusal.state =
            PersistedLeaseState::Refused(RefusalCode::OrganizationMismatch);
        cases.push(wrong_provider_refusal);

        for snapshot in cases {
            assert_eq!(
                Lease::restore(snapshot),
                Err(LeaseDomainError::InvalidSnapshot)
            );
        }
    }

    #[test]
    fn snapshot_types_remain_crate_private_and_non_secret() {
        let debug = format!("{:?}", snapshots());
        let forbidden = [
            "signature",
            "token",
            "exec_",
            "worker:",
            "service-account:",
            "chatgpt-workspace:",
            "caller:",
            "workspace_id",
            "sha256:",
        ];
        for canary in forbidden {
            assert!(!debug.contains(canary), "snapshot debug leaked {canary}");
        }
        for snapshot in [snapshots()[1].clone(), snapshots()[4].clone()] {
            let lease = Lease::restore(snapshot)
                .unwrap_or_else(|error| panic!("restore for debug: {error:?}"));
            let debug = format!("{lease:?}");
            for canary in forbidden {
                assert!(!debug.contains(canary), "lease debug leaked {canary}");
            }
        }
        let _: LeaseId = parsed("lease_00000000000000000000000000");
    }
}
