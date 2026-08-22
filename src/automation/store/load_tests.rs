use std::{fmt::Debug, str::FromStr};

use rusqlite::{Connection, params};
use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            CallerSubject, HostIdentity, IdentityLeaseRequest, LeaseId, LeaseStatus, RefusalCode,
            UtcTimestamp,
        },
        lease::{ClockSample, MonotonicMoment},
        store::{PersistedAcquireOutcome, ReadyStore, RecoveringStore, StoreError},
    },
    config::AppPaths,
    model::InstallationUid,
};

pub(super) struct Fixture {
    _temporary: TempDir,
    pub(super) paths: AppPaths,
    pub(super) installation: InstallationUid,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temporary
            .path()
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonicalize: {error}"));
        Self {
            paths: AppPaths::for_root(root.join("ctxlane")),
            installation: InstallationUid::generate()
                .unwrap_or_else(|error| panic!("installation: {error}")),
            _temporary: temporary,
        }
    }

    pub(super) fn ready(&self) -> ReadyStore {
        RecoveringStore::open(
            &self.paths,
            &self.installation,
            &stamp("2026-08-22T10:00:00Z"),
        )
        .unwrap_or_else(|error| panic!("open: {error:?}"))
        .into_ready(&stamp("2026-08-22T10:00:01Z"))
        .unwrap_or_else(|error| panic!("ready: {error:?}"))
    }
}

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    value
        .parse()
        .unwrap_or_else(|error| panic!("parse {value}: {error:?}"))
}

pub(super) fn stamp(value: &str) -> UtcTimestamp {
    parsed(value)
}

pub(super) fn caller() -> CallerSubject {
    parsed("caller:local-controller")
}

pub(super) fn host() -> HostIdentity {
    parsed("host:runner-01")
}

pub(super) fn request() -> IdentityLeaseRequest {
    let mut request: IdentityLeaseRequest = serde_json::from_str(include_str!(
        "../../../schemas/examples/identity-lease-request.v1.json"
    ))
    .unwrap_or_else(|error| panic!("request: {error}"));
    request.work_order_authorization.not_before = stamp("2026-08-22T09:00:00Z");
    request.work_order_authorization.expires_at = stamp("2026-08-23T14:00:00Z");
    request
}

pub(super) fn clock(store: &ReadyStore, monotonic: u128) -> ClockSample {
    ClockSample::new(
        stamp("2026-08-22T10:00:02Z"),
        MonotonicMoment::from_nanoseconds(monotonic),
        store.service_clock_generation(),
    )
}

pub(super) fn seed(ready: &mut ReadyStore, request: &IdentityLeaseRequest) -> LeaseId {
    ready
        .begin_acquire(request, &caller(), &host(), &clock(ready, 10))
        .unwrap_or_else(|error| panic!("seed: {error:?}"))
        .outcome()
        .lease_id()
        .clone()
}

pub(super) fn resolved_status(connection: &Connection, status: LeaseStatus) {
    let (label, reason, terminal) = match status {
        LeaseStatus::Active => ("ACTIVE", None, false),
        LeaseStatus::Renewing => ("RENEWING", None, false),
        LeaseStatus::Error => ("ERROR", Some("internal-error"), false),
        LeaseStatus::Closed => ("CLOSED", Some("completed"), true),
        LeaseStatus::Revoked => ("REVOKED", Some("service-recovery"), true),
        LeaseStatus::Expired => ("EXPIRED", Some("maximum-lifetime-reached"), true),
        LeaseStatus::Requested | LeaseStatus::Refused => panic!("not resolved"),
    };
    let issued_monotonic = connection
        .query_row("SELECT issued_monotonic_nanos FROM leases", [], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .unwrap_or_else(|error| panic!("issued monotonic: {error}"));
    let issued_monotonic = u128::from_be_bytes(
        issued_monotonic
            .try_into()
            .unwrap_or_else(|_| panic!("issued monotonic width")),
    );
    let renewing = status == LeaseStatus::Renewing;
    let fencing = if renewing { 2_i64 } else { 1_i64 };
    let anchor_monotonic = if renewing {
        issued_monotonic + 10
    } else {
        issued_monotonic
    };
    let deadline = (anchor_monotonic + 900_000_000_000).to_be_bytes();
    let maximum = (issued_monotonic + 7_200_000_000_000).to_be_bytes();
    let acknowledgement = (anchor_monotonic + 30_000_000_000).to_be_bytes();
    let high_water = if terminal {
        issued_monotonic + 8_000_000_000_000
    } else if renewing {
        anchor_monotonic + 10
    } else {
        issued_monotonic + 10
    };
    let high_water = high_water.to_be_bytes();
    let acknowledgement_wire = renewing.then_some("2026-08-22T10:00:34Z");
    let acknowledgement_seconds = renewing.then_some(1_787_392_834_i64);
    let renewed_wire = renewing.then_some("2026-08-22T10:00:04Z");
    let renewed_seconds = renewing.then_some(1_787_392_804_i64);
    let expires_wire = if renewing {
        "2026-08-22T10:15:04Z"
    } else {
        "2026-08-22T10:15:02Z"
    };
    let expires_seconds = if renewing {
        1_787_393_704_i64
    } else {
        1_787_393_702_i64
    };
    let anchor_wire = if renewing {
        "2026-08-22T10:00:04Z"
    } else {
        "2026-08-22T10:00:02Z"
    };
    let anchor_seconds = if renewing {
        1_787_392_804_i64
    } else {
        1_787_392_802_i64
    };
    let anchor_monotonic = anchor_monotonic.to_be_bytes();
    let terminal_wire = terminal.then_some("2026-08-22T10:00:05Z");
    let terminal_seconds = terminal.then_some(1_787_392_805_i64);
    connection
        .execute(
            "UPDATE leases SET
                status = ?1, reason_code = ?2,
                effective_policy_digest =
                    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                fencing_generation = ?3, clock_generation = service_generation,
                execution_handle = 'exec_00000000000000000000000000',
                worker_identity = 'worker:harness',
                principal_ref = 'service-account:resolved',
                workspace_ref = 'chatgpt-workspace:tenant',
                auth_mode = 'wif', isolation = 'credential-isolated',
                activated_at_utc = '2026-08-22T10:00:03Z',
                activated_at_seconds = 1787392803, activated_at_nanos = 0,
                renewed_at_utc = ?4, renewed_at_seconds = ?5,
                renewed_at_nanos = ?6,
                expires_at_utc = ?7,
                expires_at_seconds = ?8, expires_at_nanos = 0,
                expires_monotonic_nanos = ?9,
                maximum_expires_at_utc = '2026-08-22T12:00:02Z',
                maximum_expires_at_seconds = 1787400002,
                maximum_expires_at_nanos = 0,
                maximum_expires_monotonic_nanos = ?10,
                renewal_ack_deadline_utc = ?11,
                renewal_ack_deadline_seconds = ?12,
                renewal_ack_deadline_nanos = ?13,
                renewal_ack_deadline_monotonic_nanos = ?14,
                terminal_at_utc = ?15, terminal_at_seconds = ?16,
                terminal_at_nanos = ?17,
                next_audit_sequence = ?18,
                row_version = row_version + 1",
            params![
                label,
                reason,
                fencing,
                renewed_wire,
                renewed_seconds,
                renewed_wire.map(|_| 0_i64),
                expires_wire,
                expires_seconds,
                deadline.as_slice(),
                maximum.as_slice(),
                acknowledgement_wire,
                acknowledgement_seconds,
                acknowledgement_wire.map(|_| 0_i64),
                acknowledgement_wire.map(|_| acknowledgement.as_slice()),
                terminal_wire,
                terminal_seconds,
                terminal_wire.map(|_| 0_i64),
                if status == LeaseStatus::Active {
                    3_i64
                } else {
                    4_i64
                },
            ],
        )
        .unwrap_or_else(|error| panic!("set {status:?}: {error}"));
    append_resolved_audit(connection, status);
    connection
        .execute(
            "UPDATE lease_runtime_clocks
             SET monotonic_high_water_nanos = ?1,
                 interval_anchor_at_utc = ?2,
                 interval_anchor_at_seconds = ?3,
                 interval_anchor_at_nanos = 0,
                 interval_anchor_monotonic_nanos = ?4,
                 row_version = row_version + 1",
            params![
                high_water.as_slice(),
                anchor_wire,
                anchor_seconds,
                anchor_monotonic.as_slice(),
            ],
        )
        .unwrap_or_else(|error| panic!("clock {status:?}: {error}"));
}
pub(super) fn transition_to_revoked(connection: &Connection) {
    let sequence = connection
        .query_row("SELECT next_audit_sequence FROM leases", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or_else(|error| panic!("next audit sequence: {error}"));
    connection
        .execute_batch(
            "UPDATE leases SET status = 'REVOKED', reason_code = 'service-recovery',
                terminal_at_utc = '2026-08-22T10:00:05Z',
                terminal_at_seconds = 1787392805, terminal_at_nanos = 0,
                next_audit_sequence = next_audit_sequence + 1,
                row_version = row_version + 1;",
        )
        .unwrap_or_else(|error| panic!("revoke lease: {error}"));
    connection
        .execute(
            "INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest, reason_code
             )
             SELECT 'audit_00000000000000000000000004', l.lease_id, ?1,
                l.service_generation, 'lease.revoked', 'succeeded', 'REVOKED',
                'NONE', 0, l.terminal_at_utc, l.terminal_at_seconds,
                l.terminal_at_nanos, 'service', r.client_request_id, l.tenant_id,
                l.work_order_id, l.work_order_digest, l.run_id, l.attempt_id,
                l.role, l.provider, l.profile_uid, l.profile_ref, l.repository_id,
                l.workspace_id, l.environment, l.authenticated_caller,
                l.host_identity, l.fencing_generation, l.effective_policy_digest,
                l.reason_code
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id",
            [sequence],
        )
        .unwrap_or_else(|error| panic!("revoked audit: {error}"));
}
fn append_resolved_audit(connection: &Connection, status: LeaseStatus) {
    connection
        .execute_batch(
            "INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest
             )
             SELECT 'audit_00000000000000000000000002', l.lease_id, 2,
                l.service_generation, 'lease.activated', 'succeeded', 'ACTIVE',
                'NONE', 0, l.activated_at_utc, l.activated_at_seconds,
                l.activated_at_nanos, 'service', r.client_request_id, l.tenant_id,
                l.work_order_id, l.work_order_digest, l.run_id, l.attempt_id,
                l.role, l.provider, l.profile_uid, l.profile_ref, l.repository_id,
                l.workspace_id, l.environment, l.authenticated_caller,
                l.host_identity, 1, l.effective_policy_digest
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id;",
        )
        .unwrap_or_else(|error| panic!("activated audit: {error}"));
    if status == LeaseStatus::Active {
        return;
    }
    let (event_type, label, event_at, event_seconds) = match status {
        LeaseStatus::Renewing => (
            "lease.renewing",
            "RENEWING",
            "2026-08-22T10:00:04Z",
            1_787_392_804_i64,
        ),
        LeaseStatus::Error => (
            "lease.error",
            "ERROR",
            "2026-08-22T10:00:05Z",
            1_787_392_805_i64,
        ),
        LeaseStatus::Closed => (
            "lease.closed",
            "CLOSED",
            "2026-08-22T10:00:05Z",
            1_787_392_805_i64,
        ),
        LeaseStatus::Revoked => (
            "lease.revoked",
            "REVOKED",
            "2026-08-22T10:00:05Z",
            1_787_392_805_i64,
        ),
        LeaseStatus::Expired => (
            "lease.expired",
            "EXPIRED",
            "2026-08-22T10:00:05Z",
            1_787_392_805_i64,
        ),
        LeaseStatus::Requested | LeaseStatus::Active | LeaseStatus::Refused => {
            panic!("invalid resolved audit status")
        }
    };
    let outcome = if status == LeaseStatus::Error {
        "failed"
    } else {
        "succeeded"
    };
    connection
        .execute(
            "INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest, reason_code
             )
             SELECT 'audit_00000000000000000000000003', l.lease_id, 3,
                l.service_generation, ?1, ?2, ?3, 'NONE', 0, ?4, ?5, 0,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                l.fencing_generation, l.effective_policy_digest, l.reason_code
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id",
            params![event_type, outcome, label, event_at, event_seconds],
        )
        .unwrap_or_else(|error| panic!("latest audit {status:?}: {error}"));
}

#[test]
fn replay_reconstructs_full_valid_response_for_all_eight_states() {
    for status in [
        LeaseStatus::Requested,
        LeaseStatus::Active,
        LeaseStatus::Renewing,
        LeaseStatus::Error,
        LeaseStatus::Closed,
        LeaseStatus::Revoked,
        LeaseStatus::Expired,
        LeaseStatus::Refused,
    ] {
        let fixture = Fixture::new();
        let request = request();
        let mut ready = fixture.ready();
        let lease_id = seed(&mut ready, &request);
        match status {
            LeaseStatus::Requested => {}
            LeaseStatus::Refused => ready
                .refuse_requested(
                    &lease_id,
                    RefusalCode::ProfileNotReady,
                    &stamp("2026-08-22T10:00:03Z"),
                )
                .unwrap_or_else(|error| panic!("refuse: {error:?}")),
            _ => resolved_status(ready.test_connection(), status),
        }
        let changes_before = ready.test_connection().total_changes();
        let replay = ready
            .begin_acquire(&request, &caller(), &host(), &clock(&ready, 900))
            .unwrap_or_else(|error| panic!("replay {status:?}: {error:?}"));
        assert!(!format!("{replay:?}").contains("exec_"));
        assert!(replay.replayed());
        assert_eq!(ready.test_connection().total_changes(), changes_before);
        let response = replay.outcome().response();
        assert_eq!(response.status, status);
        assert_eq!(response.lease_id, lease_id);
        assert_eq!(response.tenant_id, request.tenant_id);
        assert_eq!(response.work_order_id, request.work_order_id);
        assert_eq!(response.run_id, request.run_id);
        assert_eq!(response.caller_subject, caller());
        assert_eq!(response.host_identity, host());
        assert_eq!(
            response.execution_handle.is_some(),
            matches!(status, LeaseStatus::Active | LeaseStatus::Renewing)
        );
        if matches!(status, LeaseStatus::Active | LeaseStatus::Renewing) {
            assert_eq!(
                response
                    .execution_handle
                    .as_ref()
                    .map(crate::automation::contracts::ExecutionHandle::as_str),
                Some("exec_00000000000000000000000000")
            );
        }
        response
            .validate()
            .unwrap_or_else(|error| panic!("response {status:?}: {error:?}"));
        let wire = serde_json::to_vec(response)
            .unwrap_or_else(|error| panic!("serialize {status:?}: {error}"));
        let decoded = serde_json::from_slice(&wire)
            .unwrap_or_else(|error| panic!("decode {status:?}: {error}"));
        assert_eq!(response, &decoded);
        assert_eq!(
            replay.outcome().issuance().service_generation(),
            ready.service_clock_generation()
        );
        assert!(matches!(
            (status, replay.outcome()),
            (
                LeaseStatus::Requested,
                PersistedAcquireOutcome::Requested { .. }
            ) | (
                LeaseStatus::Refused,
                PersistedAcquireOutcome::Refused { .. }
            ) | (
                LeaseStatus::Active
                    | LeaseStatus::Renewing
                    | LeaseStatus::Error
                    | LeaseStatus::Closed
                    | LeaseStatus::Revoked
                    | LeaseStatus::Expired,
                PersistedAcquireOutcome::Resolved { .. }
            )
        ));
        let second = ready
            .begin_acquire(&request, &caller(), &host(), &clock(&ready, 901))
            .unwrap_or_else(|error| panic!("second replay {status:?}: {error:?}"));
        assert_eq!(second, replay);
        assert_eq!(ready.test_connection().total_changes(), changes_before);
    }
}

#[derive(Clone, Copy, Debug)]
enum Corruption {
    CanonicalDigest,
    CanonicalClientKey,
    DenormalizedWorkspace,
    TimestampInteger,
    MonotonicHighWater,
    LeaseRowVersion,
    ClockRowVersion,
    U128Length,
}

#[test]
fn replay_loader_rejects_canonical_binding_clock_and_version_corruption() {
    for corruption in [
        Corruption::CanonicalDigest,
        Corruption::CanonicalClientKey,
        Corruption::DenormalizedWorkspace,
        Corruption::TimestampInteger,
        Corruption::MonotonicHighWater,
        Corruption::LeaseRowVersion,
        Corruption::ClockRowVersion,
        Corruption::U128Length,
    ] {
        let fixture = Fixture::new();
        let request = request();
        let mut ready = fixture.ready();
        seed(&mut ready, &request);
        let changes_before = {
            let connection = ready.test_connection();
            match corruption {
                Corruption::CanonicalDigest => {
                    connection
                        .execute_batch("DROP TRIGGER lease_requests_immutable;")
                        .unwrap_or_else(|error| panic!("drop request trigger: {error}"));
                    connection
                        .execute(
                            "UPDATE lease_requests SET canonical_authority_digest = ?1",
                            [format!("sha256:{}", "0".repeat(64))],
                        )
                        .unwrap_or_else(|error| panic!("digest: {error}"));
                }
                Corruption::CanonicalClientKey => {
                    connection
                        .execute_batch(
                            "DROP TRIGGER lease_requests_immutable;
                         UPDATE lease_requests SET client_request_id = 'corrupted-client-key';",
                        )
                        .unwrap_or_else(|error| panic!("client key: {error}"));
                }
                Corruption::DenormalizedWorkspace => {
                    connection
                        .execute("UPDATE leases SET workspace_id = 'different-workspace'", [])
                        .unwrap_or_else(|error| panic!("workspace: {error}"));
                }
                Corruption::TimestampInteger => {
                    connection
                        .execute_batch(
                            "DROP TRIGGER lease_requests_immutable;
                         UPDATE lease_requests
                         SET authorization_expires_at_seconds =
                             authorization_expires_at_seconds + 1;",
                        )
                        .unwrap_or_else(|error| panic!("timestamp: {error}"));
                }
                Corruption::MonotonicHighWater => {
                    connection
                        .execute_batch(
                            "DROP TRIGGER lease_runtime_clocks_advance_only;
                         UPDATE lease_runtime_clocks
                         SET monotonic_high_water_nanos = zeroblob(16);",
                        )
                        .unwrap_or_else(|error| panic!("high water: {error}"));
                }
                Corruption::LeaseRowVersion => {
                    connection
                        .execute_batch(
                            "PRAGMA ignore_check_constraints = ON;
                         UPDATE leases SET row_version = 0;
                         PRAGMA ignore_check_constraints = OFF;",
                        )
                        .unwrap_or_else(|error| panic!("lease version: {error}"));
                }
                Corruption::ClockRowVersion => {
                    connection
                    .execute_batch(
                        "DROP TRIGGER lease_runtime_clocks_advance_only;
                         PRAGMA ignore_check_constraints = ON;
                         UPDATE lease_runtime_clocks
                         SET row_version = 0, monotonic_high_water_nanos = monotonic_high_water_nanos;
                         PRAGMA ignore_check_constraints = OFF;",
                    )
                    .unwrap_or_else(|error| panic!("clock version: {error}"));
                }
                Corruption::U128Length => {
                    connection
                        .execute_batch(
                            "DROP TRIGGER leases_runtime_clock_identity_immutable;
                         PRAGMA ignore_check_constraints = ON;
                         UPDATE leases SET issued_monotonic_nanos = x'01';
                         PRAGMA ignore_check_constraints = OFF;",
                        )
                        .unwrap_or_else(|error| panic!("u128: {error}"));
                }
            }
            connection.total_changes()
        };
        let replay_clock = clock(&ready, 20);
        assert_eq!(
            ready.begin_acquire(&request, &caller(), &host(), &replay_clock),
            Err(StoreError::IntegrityCheckFailed),
            "{corruption:?}"
        );
        assert_eq!(
            ready.test_connection().total_changes(),
            changes_before,
            "{corruption:?}"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum AuditCorruption {
    SequenceGap,
    NextSequence,
    Actor,
    Outcome,
    Attribution,
    TimestampTuple,
    PerLeaseAuthenticationFailure,
    IntermediateReason,
    LatestRecoveryState,
    TransitionActor,
    ProcessRecoveryEscalation,
    ActivationFence,
    HistoricalTimestamp,
    CrossGenerationActivation,
}

#[test]
fn replay_loader_rejects_audit_chain_corruption() {
    for corruption in [
        AuditCorruption::SequenceGap,
        AuditCorruption::NextSequence,
        AuditCorruption::Actor,
        AuditCorruption::Outcome,
        AuditCorruption::Attribution,
        AuditCorruption::TimestampTuple,
        AuditCorruption::PerLeaseAuthenticationFailure,
        AuditCorruption::IntermediateReason,
        AuditCorruption::LatestRecoveryState,
        AuditCorruption::TransitionActor,
        AuditCorruption::ProcessRecoveryEscalation,
        AuditCorruption::ActivationFence,
        AuditCorruption::HistoricalTimestamp,
        AuditCorruption::CrossGenerationActivation,
    ] {
        let fixture = Fixture::new();
        let request = request();
        let mut ready = fixture.ready();
        seed(&mut ready, &request);
        let connection = ready.test_connection();
        match corruption {
            AuditCorruption::PerLeaseAuthenticationFailure
            | AuditCorruption::TransitionActor
            | AuditCorruption::ActivationFence
            | AuditCorruption::CrossGenerationActivation => {
                resolved_status(connection, LeaseStatus::Active);
            }
            AuditCorruption::ProcessRecoveryEscalation | AuditCorruption::HistoricalTimestamp => {
                resolved_status(connection, LeaseStatus::Active);
                super::recovery_tests::insert_running_evidence(connection);
            }
            AuditCorruption::IntermediateReason => {
                resolved_status(connection, LeaseStatus::Error);
                transition_to_revoked(connection);
            }
            _ => {}
        }
        connection
            .execute_batch("DROP TRIGGER audit_events_immutable;")
            .unwrap_or_else(|error| panic!("drop audit trigger: {error}"));
        match corruption {
            AuditCorruption::SequenceGap => {
                connection.execute("UPDATE audit_events SET sequence = 2", [])
            }
            AuditCorruption::NextSequence => {
                connection.execute("UPDATE leases SET next_audit_sequence = 3", [])
            }
            AuditCorruption::Actor => connection.execute(
                "UPDATE audit_events SET actor = 'caller:different-controller'",
                [],
            ),
            AuditCorruption::Outcome => {
                connection.execute("UPDATE audit_events SET outcome = 'succeeded'", [])
            }
            AuditCorruption::Attribution => connection.execute(
                "UPDATE audit_events SET workspace_id = 'different-workspace'",
                [],
            ),
            AuditCorruption::TimestampTuple => connection.execute(
                "UPDATE audit_events SET event_at_seconds = event_at_seconds + 1",
                [],
            ),
            AuditCorruption::PerLeaseAuthenticationFailure => connection.execute(
                "UPDATE audit_events SET event_type = 'caller.authentication-failed',
                    outcome = 'failed' WHERE sequence = 2",
                [],
            ),
            AuditCorruption::IntermediateReason => connection.execute(
                "UPDATE audit_events SET reason_code = 'completed' WHERE sequence = 3",
                [],
            ),
            AuditCorruption::LatestRecoveryState => {
                connection.execute("UPDATE leases SET recovery_state = 'REQUIRED'", [])
            }
            AuditCorruption::TransitionActor => connection.execute(
                "UPDATE audit_events SET actor = 'caller:local-controller' WHERE sequence = 2",
                [],
            ),
            AuditCorruption::ProcessRecoveryEscalation => connection
                .execute_batch(
                    "UPDATE audit_events SET recovery_state = 'REQUIRED' WHERE sequence = 4;
                     UPDATE leases SET recovery_state = 'REQUIRED';",
                )
                .map(|()| 1),
            AuditCorruption::ActivationFence => connection
                .execute_batch(
                    "UPDATE leases SET fencing_generation = 2,
                    renewed_at_utc = issued_at_utc,
                    renewed_at_seconds = issued_at_seconds,
                    renewed_at_nanos = issued_at_nanos,
                    renewal_acknowledged_at_utc = '2026-08-22T10:00:03Z',
                    renewal_acknowledged_at_seconds = 1787392803,
                    renewal_acknowledged_at_nanos = 0;
                 UPDATE audit_events SET fencing_generation = 2 WHERE sequence = 2;",
                )
                .map(|()| 1),
            AuditCorruption::HistoricalTimestamp => connection.execute(
                "UPDATE audit_events SET event_at_utc = '2026-08-22T10:00:04Z',
                    event_at_seconds = 1787392804 WHERE sequence = 2",
                [],
            ),
            AuditCorruption::CrossGenerationActivation => connection
                .execute_batch(
                    "INSERT INTO service_generations (
                    service_instance_id, boot_identity, start_outcome,
                    started_at_utc, started_at_seconds, started_at_nanos
                 ) VALUES (
                    'service_00000000000000000000000009', NULL, 'RECOVERY_INCOMPLETE',
                    '2026-08-22T10:00:04Z', 1787392804, 0
                 );
                 UPDATE audit_events SET service_generation = (
                    SELECT max(service_generation) FROM service_generations
                 ) WHERE sequence = 2;",
                )
                .map(|()| 1),
        }
        .unwrap_or_else(|error| panic!("corrupt {corruption:?}: {error}"));
        let changes_before = connection.total_changes();
        assert_eq!(
            ready.begin_acquire(&request, &caller(), &host(), &clock(&ready, 20)),
            Err(StoreError::IntegrityCheckFailed),
            "{corruption:?}"
        );
        assert_eq!(ready.test_connection().total_changes(), changes_before);
    }
}

#[test]
fn refusal_validates_the_full_row_before_any_mutation() {
    let fixture = Fixture::new();
    let request = request();
    let mut ready = fixture.ready();
    let lease_id = seed(&mut ready, &request);
    ready
        .test_connection()
        .execute(
            "UPDATE leases SET repository_id = 'github:other/repository'",
            [],
        )
        .unwrap_or_else(|error| panic!("corrupt: {error}"));
    let changes_before = ready.test_connection().total_changes();
    assert_eq!(
        ready.refuse_requested(
            &lease_id,
            RefusalCode::ProfileNotReady,
            &stamp("2026-08-22T10:00:03Z")
        ),
        Err(StoreError::IntegrityCheckFailed)
    );
    assert_eq!(ready.test_connection().total_changes(), changes_before);
    assert_eq!(
        ready
            .test_connection()
            .query_row("SELECT status FROM leases", [], |row| row
                .get::<_, String>(0))
            .unwrap_or_else(|error| panic!("status: {error}")),
        "REQUESTED"
    );
}
