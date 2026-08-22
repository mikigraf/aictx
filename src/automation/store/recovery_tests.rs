use std::{fmt::Debug, str::FromStr};

use rusqlite::Connection;
use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            CallerSubject, ClientRequestId, HostIdentity, IdentityLeaseRequest, LeaseStatus,
            RefusalCode, UtcTimestamp,
        },
        lease::{ClockSample, MonotonicMoment},
        store::{
            AuthenticatedRequestControl, PersistedAcquireOutcome, ReadyStore, RecoveringStore,
            StoreError,
        },
    },
    config::AppPaths,
    model::InstallationUid,
};

use super::lifecycle_types::NonCapacityRefusal;
use super::load_tests::{resolved_status, transition_to_revoked};
use super::test_support::TestAutomationProfile;

struct Fixture {
    _temporary: TempDir,
    paths: AppPaths,
    installation: InstallationUid,
    profile: TestAutomationProfile,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temporary
            .path()
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical tempdir: {error}"));
        let paths = AppPaths::for_root(root.join("ctxlane"));
        let profile = TestAutomationProfile::install(&paths);
        Self {
            paths,
            installation: profile.installation.clone(),
            profile,
            _temporary: temporary,
        }
    }

    fn recovering(&self, at: &str) -> RecoveringStore {
        RecoveringStore::open(&self.paths, &self.installation, &stamp(at))
            .unwrap_or_else(|error| panic!("open: {error:?}"))
    }

    fn ready(&self) -> ReadyStore {
        self.recovering("2026-08-22T10:00:00Z")
            .into_ready(&stamp("2026-08-22T10:00:01Z"))
            .unwrap_or_else(|error| panic!("ready: {error:?}"))
    }

    fn request(&self) -> IdentityLeaseRequest {
        let mut request = request();
        self.profile.bind_request(&mut request);
        request
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

fn stamp(value: &str) -> UtcTimestamp {
    parsed(value)
}

fn request() -> IdentityLeaseRequest {
    let mut request: IdentityLeaseRequest = serde_json::from_str(include_str!(
        "../../../schemas/examples/identity-lease-request.v1.json"
    ))
    .unwrap_or_else(|error| panic!("request fixture: {error}"));
    request.work_order_authorization.not_before = stamp("2026-08-22T09:00:00Z");
    request.work_order_authorization.expires_at = stamp("2026-08-23T14:00:00Z");
    request
}

fn caller() -> CallerSubject {
    parsed("caller:local-controller")
}

fn host() -> HostIdentity {
    parsed("host:runner-01")
}

fn refusal(code: RefusalCode) -> NonCapacityRefusal {
    NonCapacityRefusal::from_evaluation(code)
        .unwrap_or_else(|| panic!("capacity denial is activation-owned"))
}

fn clock(store: &ReadyStore, wall: &str, monotonic: u128) -> ClockSample {
    ClockSample::new(
        stamp(wall),
        MonotonicMoment::from_nanoseconds(monotonic),
        store.service_clock_generation(),
    )
}

fn seed_requested(ready: &mut ReadyStore, request: &IdentityLeaseRequest) {
    let issuance = clock(ready, "2026-08-22T10:00:02Z", 1);
    ready
        .begin_acquire(request, &caller(), &host(), &issuance)
        .unwrap_or_else(|error| panic!("seed request: {error:?}"));
}

fn request_with_id(fixture: &Fixture, value: &str) -> IdentityLeaseRequest {
    let mut request = fixture.request();
    let client_request_id = parsed::<ClientRequestId>(value);
    request.client_request_id = client_request_id.clone();
    request.work_order_authorization.client_request_id = client_request_id;
    request
}

fn seed_request(
    ready: &mut ReadyStore,
    request: &IdentityLeaseRequest,
    monotonic: u128,
) -> crate::automation::contracts::LeaseId {
    let issuance = clock(ready, "2026-08-22T10:00:02Z", monotonic);
    ready
        .begin_acquire(request, &caller(), &host(), &issuance)
        .unwrap_or_else(|error| panic!("seed request: {error:?}"))
        .outcome()
        .lease_id()
        .clone()
}

pub(super) fn insert_running_evidence(connection: &Connection) {
    connection
        .execute_batch(
            "INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos
             ) SELECT 'capacity_00000000000000000000000000', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'provider', provider, 4, 1, 'HELD', '2026-08-22T10:00:04Z',
                1787392804, 0 FROM leases;
             INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos
             ) SELECT 'capacity_00000000000000000000000001', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'profile', profile_uid, 3, 1, 'HELD', '2026-08-22T10:00:04Z',
                1787392804, 0 FROM leases;
             INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos
             ) SELECT 'capacity_00000000000000000000000002', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'caller', authenticated_caller, 2, 1, 'HELD',
                '2026-08-22T10:00:04Z', 1787392804, 0 FROM leases;
             INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos
             ) SELECT 'capacity_00000000000000000000000003', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'host', host_identity, 1, 1, 'HELD', '2026-08-22T10:00:04Z',
                1787392804, 0 FROM leases;
             INSERT INTO lease_processes (
                process_id, lease_id, service_generation, state, process_id_number,
                process_identity, execution_handle, worker_identity,
                observed_fencing_generation, launch_intent_at_utc,
                launch_intent_at_seconds, launch_intent_at_nanos,
                started_at_utc, started_at_seconds, started_at_nanos
             ) SELECT 'process_00000000000000000000000000', lease_id,
                service_generation, 'RUNNING', 4242, 'boot:start-token',
                execution_handle, worker_identity, fencing_generation,
                '2026-08-22T10:00:03Z', 1787392803, 0,
                '2026-08-22T10:00:04Z', 1787392804, 0 FROM leases;
             UPDATE leases SET next_audit_sequence = 5, row_version = row_version + 1;
             INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest
             ) SELECT 'audit_00000000000000000000000003', l.lease_id, 3,
                l.service_generation, 'process.launch-intent', 'recorded', 'ACTIVE',
                'NONE', 0, '2026-08-22T10:00:03Z', 1787392803, 0,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                l.fencing_generation, l.effective_policy_digest
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id;
             INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest
             ) SELECT 'audit_00000000000000000000000004', l.lease_id, 4,
                l.service_generation, 'process.started', 'succeeded', 'ACTIVE',
                'NONE', 0, '2026-08-22T10:00:04Z', 1787392804, 0,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                l.fencing_generation, l.effective_policy_digest
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id;",
        )
        .unwrap_or_else(|error| panic!("running evidence: {error}"));
}

fn append_launch_intent(connection: &Connection) {
    connection
        .execute_batch(
            "UPDATE leases SET next_audit_sequence = next_audit_sequence + 1;
             INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest
             ) SELECT 'audit_00000000000000000000000003', l.lease_id, 3,
                l.service_generation, 'process.launch-intent', 'recorded', 'ACTIVE',
                'NONE', 0, p.launch_intent_at_utc, p.launch_intent_at_seconds,
                p.launch_intent_at_nanos, 'service', r.client_request_id, l.tenant_id,
                l.work_order_id, l.work_order_digest, l.run_id, l.attempt_id, l.role,
                l.provider, l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                p.observed_fencing_generation, l.effective_policy_digest
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id
             JOIN lease_processes p ON p.lease_id = l.lease_id;",
        )
        .unwrap_or_else(|error| panic!("launch audit: {error}"));
}

fn append_process_exit(connection: &Connection) {
    connection
        .execute_batch(
            "UPDATE leases SET next_audit_sequence = next_audit_sequence + 1;
             INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest, reason_code
             ) SELECT 'audit_00000000000000000000000005', l.lease_id, 5,
                (SELECT max(service_generation) FROM service_generations),
                'process.exited', 'succeeded', l.status, l.recovery_state,
                l.quarantined, p.ended_at_utc, p.ended_at_seconds, p.ended_at_nanos,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                l.fencing_generation, l.effective_policy_digest, l.reason_code
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id
             JOIN lease_processes p ON p.lease_id = l.lease_id;",
        )
        .unwrap_or_else(|error| panic!("exit audit: {error}"));
}

#[test]
fn fractional_high_monotonic_refusal_replays_exactly_after_reopen() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let high_monotonic = u128::from(u64::MAX) + 9_876_543_210;
    let issuance = clock(&ready, "2026-08-22T10:00:02.123456789Z", high_monotonic);
    let begun = ready
        .begin_acquire(&fixture.request(), &caller(), &host(), &issuance)
        .unwrap_or_else(|error| panic!("fractional begin: {error:?}"));
    let lease_id = begun.outcome().lease_id().clone();
    let original_generation = ready.service_clock_generation();
    let authenticated_caller = caller();
    let authenticated_host = host();
    let control = AuthenticatedRequestControl::new(
        &lease_id,
        begun.row_version(),
        &authenticated_caller,
        &authenticated_host,
    );
    ready
        .refuse_requested(
            &control,
            refusal(RefusalCode::ProfileNotReady),
            &stamp("2026-08-22T10:00:03.987654321Z"),
        )
        .unwrap_or_else(|error| panic!("fractional refusal: {error:?}"));
    let expected = ready
        .begin_acquire(
            &fixture.request(),
            &caller(),
            &host(),
            &clock(&ready, "2026-08-22T10:00:04Z", high_monotonic + 1),
        )
        .unwrap_or_else(|error| panic!("same-generation replay: {error:?}"))
        .outcome()
        .clone();
    assert!(matches!(expected, PersistedAcquireOutcome::Refused { .. }));
    drop(ready);

    let mut reopened = fixture
        .recovering("2026-08-22T10:01:00Z")
        .into_ready(&stamp("2026-08-22T10:01:01Z"))
        .unwrap_or_else(|error| panic!("reopen ready: {error:?}"));
    assert_ne!(reopened.service_clock_generation(), original_generation);
    let replay = reopened
        .begin_acquire(
            &fixture.request(),
            &caller(),
            &host(),
            &clock(&reopened, "2026-08-22T11:00:00Z", high_monotonic + 2),
        )
        .unwrap_or_else(|error| panic!("reopen replay: {error:?}"));
    assert!(replay.replayed());
    assert_eq!(replay.outcome(), &expected);
    assert_eq!(
        replay.outcome().issuance().issued_at().as_str(),
        "2026-08-22T10:00:02.123456789Z"
    );
    assert_eq!(
        replay.outcome().issuance().monotonic().as_nanoseconds(),
        high_monotonic
    );
    assert_eq!(
        replay.outcome().issuance().service_generation(),
        original_generation
    );
}

#[derive(Clone, Copy, Debug)]
enum RecoveryGateCase {
    ErrorLease,
    Capacity(&'static str),
    Process,
}

#[test]
fn each_unresolved_state_independently_blocks_readiness_until_resolved() {
    let cases = [
        RecoveryGateCase::ErrorLease,
        RecoveryGateCase::Capacity("HELD"),
        RecoveryGateCase::Capacity("QUARANTINED"),
        RecoveryGateCase::Capacity("RECOVERY_REQUIRED"),
        RecoveryGateCase::Process,
    ];

    for case in cases {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        seed_requested(&mut ready, &fixture.request());
        match case {
            RecoveryGateCase::ErrorLease => {
                resolved_status(ready.test_connection(), LeaseStatus::Error);
            }
            RecoveryGateCase::Capacity(state) => {
                resolved_status(ready.test_connection(), LeaseStatus::Active);
                ready
                    .test_connection()
                    .execute(
                        "INSERT INTO capacity_reservations (
                            reservation_id, lease_id, provider, profile_uid,
                            authenticated_caller, host_identity, tenant_id,
                            capacity_dimension, capacity_key, capacity_limit, slot, state,
                            reserved_at_utc, reserved_at_seconds, reserved_at_nanos
                         ) SELECT
                            'capacity_00000000000000000000000000', lease_id, provider,
                            profile_uid, authenticated_caller, host_identity, tenant_id,
                            'provider', provider, 1, 1, 'HELD',
                            '2026-08-22T10:00:04Z', issued_at_seconds + 2, 0
                         FROM leases",
                        [],
                    )
                    .unwrap_or_else(|error| panic!("seed {case:?}: {error}"));
                if state != "HELD" {
                    ready
                        .test_connection()
                        .execute("UPDATE capacity_reservations SET state = ?1", [state])
                        .unwrap_or_else(|error| panic!("transition {case:?}: {error}"));
                }
                transition_to_revoked(ready.test_connection());
            }
            RecoveryGateCase::Process => {
                resolved_status(ready.test_connection(), LeaseStatus::Active);
                ready
                    .test_connection()
                    .execute_batch(
                        "INSERT INTO lease_processes (
                            process_id, lease_id, service_generation, state, execution_handle,
                            worker_identity, observed_fencing_generation, launch_intent_at_utc,
                            launch_intent_at_seconds, launch_intent_at_nanos
                         ) SELECT
                            'process_00000000000000000000000000', lease_id,
                            service_generation, 'LAUNCH_INTENT', execution_handle,
                            worker_identity, 1,
                            '2026-08-22T10:00:04Z', issued_at_seconds + 2, 0
                         FROM leases;",
                    )
                    .unwrap_or_else(|error| panic!("seed {case:?}: {error}"));
                append_launch_intent(ready.test_connection());
                transition_to_revoked(ready.test_connection());
            }
        }
        drop(ready);

        let blocked = fixture.recovering("2026-08-22T10:01:00Z");
        let blocked_result = blocked.into_ready(&stamp("2026-08-22T10:01:01Z"));
        let actual_error = blocked_result.as_ref().err().copied();
        assert!(
            matches!(blocked_result, Err(StoreError::RecoveryRequired)),
            "unexpected recovery result for {case:?}: {actual_error:?}"
        );

        let connection = Connection::open(fixture.paths.automation_lease_store())
            .unwrap_or_else(|error| panic!("resolve {case:?}: {error}"));
        match case {
            RecoveryGateCase::ErrorLease => transition_to_revoked(&connection),
            RecoveryGateCase::Capacity(_) => {
                connection
                    .execute_batch(
                        "UPDATE capacity_reservations SET state = 'RELEASED',
                            released_at_utc = '2026-08-22T10:01:02Z',
                            released_at_seconds = 1787392862,
                            released_at_nanos = 0;",
                    )
                    .unwrap_or_else(|error| panic!("release {case:?}: {error}"));
            }
            RecoveryGateCase::Process => {
                connection
                    .execute_batch(
                        "UPDATE lease_processes SET state = 'EXITED',
                            started_at_utc = '2026-08-22T10:00:04Z',
                            started_at_seconds = launch_intent_at_seconds,
                            started_at_nanos = 0,
                            ended_at_utc = '2026-08-22T10:01:02Z',
                            ended_at_seconds = 1787392862,
                            ended_at_nanos = 0;",
                    )
                    .unwrap_or_else(|error| panic!("exit {case:?}: {error}"));
                append_process_exit(&connection);
            }
        }
        drop(connection);

        let mut recovering = fixture.recovering("2026-08-22T10:02:00Z");
        assert!(
            recovering
                .clear_orphan_profile_fence(&fixture.profile.profile_uid)
                .unwrap_or_else(|error| panic!("clear resolved {case:?}: {error:?}"))
        );
        recovering
            .into_ready(&stamp("2026-08-22T10:02:01Z"))
            .unwrap_or_else(|error| panic!("resolved {case:?} remained blocked: {error:?}"));
    }
}

#[test]
fn recovery_pages_are_keyset_paginated_cross_generation_and_redacted() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let origin_generation = ready.service_clock_generation();
    for (id, monotonic) in [
        ("01ARZ3NDEKTSV4RRFFQ69G5FA0", 10_u128),
        ("01ARZ3NDEKTSV4RRFFQ69G5FA1", 11_u128),
        ("01ARZ3NDEKTSV4RRFFQ69G5FA2", 12_u128),
    ] {
        seed_request(&mut ready, &request_with_id(&fixture, id), monotonic);
    }
    drop(ready);

    let recovering = fixture.recovering("2026-08-22T10:01:00Z");
    let current_generation = recovering.service_clock_generation();
    assert_ne!(current_generation, origin_generation);
    assert_eq!(
        super::RecoveryPageRequest::first(0),
        Err(StoreError::InvalidRequest)
    );
    assert_eq!(
        super::RecoveryPageRequest::first(101),
        Err(StoreError::InvalidRequest)
    );
    let first = recovering
        .recovery_candidates(
            &super::RecoveryPageRequest::first(2)
                .unwrap_or_else(|error| panic!("first page request: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("first page: {error:?}"));
    assert_eq!(first.candidates().len(), 2);
    let cursor = first
        .next_cursor()
        .cloned()
        .unwrap_or_else(|| panic!("missing next cursor"));
    let second = recovering
        .recovery_candidates(
            &super::RecoveryPageRequest::after(cursor, 2)
                .unwrap_or_else(|error| panic!("second page request: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("second page: {error:?}"));
    assert_eq!(second.candidates().len(), 1);
    assert!(second.next_cursor().is_none());
    let mut ids = first
        .candidates()
        .iter()
        .chain(second.candidates())
        .map(|candidate| candidate.lease_id().as_str().to_owned())
        .collect::<Vec<_>>();
    let observed = ids.clone();
    ids.sort();
    assert_eq!(observed, ids);
    for candidate in first.candidates().iter().chain(second.candidates()) {
        assert_eq!(candidate.status(), LeaseStatus::Requested);
        assert_eq!(candidate.origin_generation(), origin_generation);
        assert_eq!(candidate.current_generation(), current_generation);
        assert!(!candidate.resume_permitted());
        assert!(candidate.capacity_evidence().is_empty());
        assert!(candidate.process_evidence().is_empty());
    }
    let rendered = format!("{first:?} {second:?}");
    for canary in [
        "caller:local-controller",
        "host:runner-01",
        "tenant-acme",
        "workspace_01J",
        "signature",
        "exec_",
    ] {
        assert!(!rendered.contains(canary), "debug leaked {canary}");
    }
}

#[test]
fn recovery_candidate_seals_typed_capacity_process_and_snapshot_evidence() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let origin_generation = ready.service_clock_generation();
    seed_requested(&mut ready, &fixture.request());
    resolved_status(ready.test_connection(), LeaseStatus::Active);
    insert_running_evidence(ready.test_connection());
    drop(ready);

    let recovering = fixture.recovering("2026-08-22T10:01:00Z");
    let page = recovering
        .recovery_candidates(
            &super::RecoveryPageRequest::first(10)
                .unwrap_or_else(|error| panic!("page request: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("page: {error:?}"));
    let candidate = page
        .candidates()
        .first()
        .unwrap_or_else(|| panic!("missing candidate"));
    assert_eq!(candidate.status(), LeaseStatus::Active);
    assert_eq!(candidate.origin_generation(), origin_generation);
    assert_eq!(candidate.capacity_evidence().len(), 4);
    assert_eq!(candidate.process_evidence().len(), 1);
    let process = &candidate.process_evidence()[0];
    assert_eq!(
        process.state(),
        super::recovery_types::ProcessState::Running
    );
    assert!(process.has_process_id());
    assert!(process.has_process_identity());
    assert_eq!(process.observed_fencing_generation().get(), 1);
    let rendered = format!("{page:?}");
    for canary in [
        "4242",
        "boot:start-token",
        "exec_00000000000000000000000000",
        "worker:harness",
        "service-account:resolved",
        "chatgpt-workspace:tenant",
    ] {
        assert!(!rendered.contains(canary), "debug leaked {canary}");
    }
    let (snapshot, processes) = page.candidates()[0].clone().into_private_evidence();
    assert_eq!(snapshot.service_generation(), origin_generation);
    assert_eq!(processes.len(), 1);
    assert_eq!(
        processes[0]
            .process_id_number
            .map(std::num::NonZeroU64::get),
        Some(4242)
    );
    assert_eq!(
        processes[0].execution_handle.as_str(),
        "exec_00000000000000000000000000"
    );
}

#[test]
fn frozen_v2_terminal_partial_capacity_without_marker_recovers_to_ready() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let issuance = clock(&ready, "2026-08-22T10:00:02Z", 1);
    let begun = ready
        .begin_acquire(&fixture.request(), &caller(), &host(), &issuance)
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    let lease_id = begun.outcome().lease_id().clone();
    let authenticated_caller = caller();
    let authenticated_host = host();
    let control = AuthenticatedRequestControl::new(
        &lease_id,
        begun.row_version(),
        &authenticated_caller,
        &authenticated_host,
    );
    ready
        .refuse_requested(
            &control,
            refusal(RefusalCode::ProfileNotReady),
            &stamp("2026-08-22T10:00:03Z"),
        )
        .unwrap_or_else(|error| panic!("refuse: {error:?}"));
    ready
        .test_connection()
        .execute_batch(
            "DROP TRIGGER capacity_reservations_insert_held;
             DROP TRIGGER capacity_reservations_transition_only;
             DROP TRIGGER capacity_reservations_delete_released;
             DROP INDEX capacity_reservations_lease_state;
             DROP INDEX lease_processes_lease_state;
             DELETE FROM schema_migrations WHERE version = 3;
             PRAGMA user_version = 2;
             INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos
             ) SELECT 'capacity_00000000000000000000000000', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'provider', provider, 1, 7, 'QUARANTINED',
                '2026-08-22T10:00:02Z', issued_at_seconds, issued_at_nanos FROM leases;
             INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos
             ) SELECT 'capacity_00000000000000000000000001', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'profile', profile_uid, 1, 2, 'RECOVERY_REQUIRED',
                '2026-08-22T10:00:02Z', issued_at_seconds, issued_at_nanos FROM leases;
             INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos
             ) SELECT 'capacity_00000000000000000000000002', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'caller', authenticated_caller, 1, 1, 'HELD',
                '2026-08-22T10:00:02Z', issued_at_seconds, issued_at_nanos FROM leases;",
        )
        .unwrap_or_else(|error| panic!("seed frozen v2 capacity: {error}"));
    drop(ready);

    assert!(matches!(
        fixture
            .recovering("2026-08-22T10:01:00Z")
            .into_ready(&stamp("2026-08-22T10:01:01Z")),
        Err(StoreError::RecoveryRequired)
    ));
    let mut recovering = fixture.recovering("2026-08-22T10:02:00Z");
    assert!(recovering.recovered_profile_fences().is_empty());
    let candidate = recovering
        .recovery_candidates(
            &super::RecoveryPageRequest::first(10)
                .unwrap_or_else(|error| panic!("page request: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("candidate: {error:?}"));
    let row_version = candidate.candidates()[0].lease_row_version();
    let result = recovering
        .terminalize_prior_generation(&lease_id, row_version, &stamp("2026-08-22T10:02:01Z"))
        .unwrap_or_else(|error| panic!("terminal capacity recovery: {error:?}"));
    assert_eq!(result.status(), LeaseStatus::Refused);
    assert_eq!(result.released_reservations(), 3);
    assert_eq!(result.row_version(), row_version + 1);
    assert!(result.changed());
    assert!(!result.cleanup_deferred());
    assert!(recovering.recovered_profile_fences().is_empty());
    assert_eq!(
        recovering
            .test_connection()
            .query_row(
                "SELECT count(*) FROM capacity_reservations WHERE state = 'RELEASED'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("released count: {error}")),
        3
    );
    recovering
        .into_ready(&stamp("2026-08-22T10:02:02Z"))
        .unwrap_or_else(|error| panic!("ready after terminal recovery: {error:?}"));
}

#[derive(Clone, Copy, Debug)]
enum ProcessCorruption {
    Identifier,
    Fence,
    Worker,
    MissingIdentity,
    TimestampTuple,
}

#[test]
fn recovery_rejects_corrupt_process_evidence_without_exposing_it() {
    for corruption in [
        ProcessCorruption::Identifier,
        ProcessCorruption::Fence,
        ProcessCorruption::Worker,
        ProcessCorruption::MissingIdentity,
        ProcessCorruption::TimestampTuple,
    ] {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        seed_requested(&mut ready, &fixture.request());
        resolved_status(ready.test_connection(), LeaseStatus::Active);
        insert_running_evidence(ready.test_connection());
        drop(ready);
        let recovering = fixture.recovering("2026-08-22T10:01:00Z");
        let connection = recovering.test_connection();
        match corruption {
            ProcessCorruption::Identifier => connection.execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE lease_processes SET process_id = 'process_NOT-CROCKFORD';
                 PRAGMA ignore_check_constraints = OFF;",
            ),
            ProcessCorruption::Fence => connection
                .execute_batch("UPDATE lease_processes SET observed_fencing_generation = 2;"),
            ProcessCorruption::Worker => connection
                .execute_batch("UPDATE lease_processes SET worker_identity = 'worker:different';"),
            ProcessCorruption::MissingIdentity => connection.execute_batch(
                "UPDATE lease_processes SET process_id_number = NULL, process_identity = NULL;",
            ),
            ProcessCorruption::TimestampTuple => connection.execute_batch(
                "UPDATE lease_processes SET started_at_seconds = started_at_seconds + 1;",
            ),
        }
        .unwrap_or_else(|error| panic!("corrupt {corruption:?}: {error}"));
        assert!(
            matches!(
                recovering.recovery_candidates(
                    &super::RecoveryPageRequest::first(10)
                        .unwrap_or_else(|error| panic!("page request: {error:?}"))
                ),
                Err(StoreError::IntegrityCheckFailed)
            ),
            "{corruption:?}"
        );
    }
}
