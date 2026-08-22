use std::{fmt::Debug, str::FromStr};

use super::*;
use crate::automation::contracts::{
    AttemptId, CallerSubject, ClientRequestId, EnvironmentName, LeaseId, ProfileRef, ProfileUid,
    RepositoryId, TenantId, WorkOrderId, WorkspaceId,
};

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    value.parse().unwrap_or_else(|error| panic!("{error:?}"))
}

fn stamp(value: &str) -> UtcTimestamp {
    UtcTimestamp::parse(value).unwrap_or_else(|error| panic!("{error:?}"))
}

fn moment(seconds: u64) -> MonotonicMoment {
    MonotonicMoment::from_nanoseconds(u128::from(seconds) * 1_000_000_000)
}

fn generation(value: u64) -> FencingGeneration {
    FencingGeneration::from_value(value).unwrap_or_else(|error| panic!("{error:?}"))
}

const fn service_generation() -> ServiceClockGeneration {
    ServiceClockGeneration::from_value(1)
}

fn binding() -> LeaseBinding {
    LeaseBinding {
        lease_id: parsed::<LeaseId>("lease_01ARZ3NDEKTSV4RRFFQ69G5FB0"),
        client_request_id: parsed::<ClientRequestId>("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        authority_digest: parsed(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        tenant_id: parsed::<TenantId>("tenant-acme"),
        work_order_id: parsed::<WorkOrderId>("wo_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        work_order_digest: parsed(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        run_id: parsed::<RunId>("run_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        attempt_id: parsed::<AttemptId>("attempt-1"),
        role: AgentRole::Implementer,
        provider: Provider::Claude,
        profile_uid: parsed::<ProfileUid>("profile_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        profile_ref: parsed::<ProfileRef>("claude:automation"),
        repository: parsed::<RepositoryId>("github:acme/repo"),
        workspace_id: parsed::<WorkspaceId>("workspace-one"),
        environment: parsed::<EnvironmentName>("production"),
        initial_requested_ttl_seconds: 60,
        caller_subject: parsed::<CallerSubject>("caller:controller"),
        host_identity: parsed::<HostIdentity>("host:one"),
        signed_authorization_expires_at: stamp("2026-08-21T10:10:00Z"),
    }
}

fn authority() -> ResolvedAuthority {
    ResolvedAuthority {
        resolution: LeaseResolution {
            execution_handle: parsed("exec_01ARZ3NDEKTSV4RRFFQ69G5FB1"),
            worker_identity: Some(parsed("worker:one")),
            principal_ref: parsed("service-account:one"),
            workspace_ref: parsed("claude-organization:one"),
            auth_mode: AutomationAuthMode::Wif,
            isolation: IsolationClassification::CredentialIsolated,
        },
        effective_policy_digest: parsed(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        fencing_generation: generation(2),
        expires_at: stamp("2026-08-21T10:02:00Z"),
        maximum_expires_at: stamp("2026-08-21T10:10:00Z"),
        monotonic_deadline: moment(1_120),
        monotonic_maximum_deadline: moment(1_600),
    }
}

fn lease(state: LeaseState) -> Lease {
    Lease {
        binding: binding(),
        issuance_clock: ClockSample::new(
            stamp("2026-08-21T10:00:00Z"),
            moment(1_000),
            service_generation(),
        ),
        last_monotonic: moment(1_000),
        state,
    }
}

fn control_values(lease: &Lease) -> (CallerSubject, TenantId, RunId, HostIdentity) {
    (
        lease.binding.caller_subject.clone(),
        lease.binding.tenant_id.clone(),
        lease.binding.run_id.clone(),
        lease.binding.host_identity.clone(),
    )
}

#[test]
fn renewing_supports_only_the_documented_outbound_transitions() {
    let renewing = || LeaseState::Renewing {
        authority: authority(),
        acknowledgement_deadline: stamp("2026-08-21T10:00:30Z"),
        monotonic_acknowledgement_deadline: moment(1_030),
    };
    let now = ClockSample::new(
        stamp("2026-08-21T10:00:01Z"),
        moment(1_001),
        service_generation(),
    );

    let mut closed = lease(renewing());
    let (caller, tenant, run, host) = control_values(&closed);
    closed
        .close(
            &LeaseControl {
                caller_subject: &caller,
                tenant_id: &tenant,
                run_id: &run,
                role: AgentRole::Implementer,
                host_identity: &host,
                fencing_generation: generation(2),
            },
            LeaseReasonCode::Completed,
            &now,
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(closed.status(), LeaseStatus::Closed);

    let mut revoked = lease(renewing());
    revoked
        .revoke(LeaseReasonCode::GenerationSuperseded)
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(revoked.status(), LeaseStatus::Revoked);

    let mut errored = lease(renewing());
    errored
        .mark_error(LeaseReasonCode::ProcessUnverifiable)
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(errored.status(), LeaseStatus::Error);

    let mut unacknowledged = lease(renewing());
    assert!(
        unacknowledged
            .enforce_deadlines(&ClockSample::new(
                stamp("2026-08-21T10:02:00Z"),
                moment(1_120),
                service_generation(),
            ))
            .unwrap_or_else(|error| panic!("{error:?}"))
    );
    assert_eq!(unacknowledged.status(), LeaseStatus::Revoked);
    assert_eq!(
        unacknowledged.reason_code(),
        Some(LeaseReasonCode::RenewalAcknowledgementFailed)
    );
}

#[test]
fn error_expires_and_every_terminal_state_is_immutable() {
    let mut errored = lease(LeaseState::Error {
        authority: authority(),
        reason: LeaseReasonCode::ServiceRecovery,
    });
    assert!(
        errored
            .enforce_deadlines(&ClockSample::new(
                stamp("2026-08-21T10:00:05Z"),
                moment(1_120),
                service_generation(),
            ))
            .unwrap_or_else(|error| panic!("{error:?}"))
    );
    assert_eq!(errored.status(), LeaseStatus::Expired);

    for state in [
        LeaseState::Closed {
            authority: authority(),
            reason: LeaseReasonCode::Completed,
        },
        LeaseState::Revoked {
            authority: authority(),
            reason: LeaseReasonCode::OperatorRevoked,
        },
        LeaseState::Expired {
            authority: authority(),
            reason: LeaseReasonCode::LeaseExpired,
        },
        LeaseState::Refused(RefusalCode::ProfileNotReady),
    ] {
        let mut terminal = lease(state);
        let before = terminal.state.clone();
        assert!(terminal.mark_error(LeaseReasonCode::InternalError).is_err());
        assert_eq!(terminal.state, before);
        assert!(terminal.revoke(LeaseReasonCode::OperatorRevoked).is_err());
        assert_eq!(terminal.state, before);
    }
}

#[test]
fn invalid_reason_codes_fail_without_mutating_state() {
    let mut active = lease(LeaseState::Active(authority()));
    let before = active.state.clone();
    let (caller, tenant, run, host) = control_values(&active);
    assert!(
        active
            .close(
                &LeaseControl {
                    caller_subject: &caller,
                    tenant_id: &tenant,
                    run_id: &run,
                    role: AgentRole::Implementer,
                    host_identity: &host,
                    fencing_generation: generation(2),
                },
                LeaseReasonCode::InternalError,
                &ClockSample::new(
                    stamp("2026-08-21T10:00:01Z"),
                    moment(1_001),
                    service_generation(),
                ),
            )
            .is_err()
    );
    assert_eq!(active.state, before);
    assert!(active.revoke(LeaseReasonCode::Completed).is_err());
    assert_eq!(active.state, before);
    assert!(active.mark_error(LeaseReasonCode::Completed).is_err());
    assert_eq!(active.state, before);
}
