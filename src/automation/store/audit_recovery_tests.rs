use rusqlite::{Connection, params};

use crate::automation::{
    contracts::{LeaseStatus, Sha256Digest},
    store::{RecoveringStore, StoreError, load_tests, recovery_tests},
};

#[test]
fn authority_progress_cannot_clear_a_recovery_gate() {
    let fixture = load_tests::Fixture::new();
    let request = fixture.request();
    let mut ready = fixture.ready();
    load_tests::seed(&mut ready, &request);
    let connection = ready.test_connection();
    load_tests::resolved_status(connection, LeaseStatus::Renewing);
    inject_recovery_gate_before_renewal(connection);

    let changes_before = connection.total_changes();
    assert_eq!(
        ready.begin_acquire(
            &request,
            &load_tests::caller(),
            &load_tests::host(),
            &load_tests::clock(&ready, 20),
        ),
        Err(StoreError::IntegrityCheckFailed),
    );
    assert_eq!(ready.test_connection().total_changes(), changes_before);
}

fn inject_recovery_gate_before_renewal(connection: &Connection) {
    connection
        .execute_batch(
            "DROP TRIGGER audit_events_immutable;
             UPDATE audit_events SET sequence = 4 WHERE sequence = 3;
             INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest
             )
             SELECT 'audit_00000000000000000000000004', l.lease_id, 3,
                l.service_generation, 'lease.recovery-required', 'failed', 'ACTIVE',
                'REQUIRED', 0, '2026-08-22T10:00:03.5Z', 1787392803, 500000000,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity, 1,
                l.effective_policy_digest
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id;
             UPDATE leases SET next_audit_sequence = 5;",
        )
        .unwrap_or_else(|error| panic!("inject recovery gate: {error}"));
}

#[test]
fn process_start_requires_a_matching_launch_intent() {
    let fixture = load_tests::Fixture::new();
    let request = fixture.request();
    let mut ready = fixture.ready();
    load_tests::seed(&mut ready, &request);
    let connection = ready.test_connection();
    load_tests::resolved_status(connection, LeaseStatus::Active);
    recovery_tests::insert_running_evidence(connection);
    connection
        .execute_batch(
            "DROP TRIGGER audit_events_immutable;
             DELETE FROM lease_processes;
             DELETE FROM audit_events WHERE sequence = 3;
             UPDATE audit_events SET sequence = 3 WHERE sequence = 4;
             UPDATE leases SET next_audit_sequence = 4;",
        )
        .unwrap_or_else(|error| panic!("remove launch evidence: {error}"));

    assert_eq!(
        ready.begin_acquire(
            &request,
            &load_tests::caller(),
            &load_tests::host(),
            &load_tests::clock(&ready, 20),
        ),
        Err(StoreError::IntegrityCheckFailed),
    );
}

#[test]
fn unmatched_process_audit_cannot_escape_the_recovery_gate() {
    let fixture = load_tests::Fixture::new();
    let request = fixture.request();
    let mut ready = fixture.ready();
    load_tests::seed(&mut ready, &request);
    load_tests::resolved_status(ready.test_connection(), LeaseStatus::Active);
    recovery_tests::insert_running_evidence(ready.test_connection());
    ready
        .test_connection()
        .execute("DELETE FROM lease_processes", [])
        .unwrap_or_else(|error| panic!("remove process evidence: {error}"));
    let before = ready
        .test_connection()
        .query_row(
            "SELECT (SELECT count(*) FROM service_generations),
                    (SELECT count(*) FROM audit_events), status, row_version,
                    (SELECT count(*) FROM lease_processes)
             FROM leases",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("corrupt projection: {error}"));
    drop(ready);

    assert!(matches!(
        RecoveringStore::open(
            &fixture.paths,
            &fixture.installation,
            &load_tests::stamp("2026-08-22T10:01:00Z"),
        ),
        Err(StoreError::IntegrityCheckFailed)
    ));
    let connection = Connection::open(fixture.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("inspect rejected open: {error}"));
    let after = connection
        .query_row(
            "SELECT (SELECT count(*) FROM service_generations),
                    (SELECT count(*) FROM audit_events), status, row_version,
                    (SELECT count(*) FROM lease_processes)
             FROM leases",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("rejected-open projection: {error}"));
    assert_eq!(after, before);
}

#[test]
fn an_error_lease_can_expire_without_becoming_replay_corruption() {
    let fixture = load_tests::Fixture::new();
    let request = fixture.request();
    let mut ready = fixture.ready();
    load_tests::seed(&mut ready, &request);
    load_tests::resolved_status(ready.test_connection(), LeaseStatus::Error);
    expire_error_lease(ready.test_connection());

    let replay = ready
        .begin_acquire(
            &request,
            &load_tests::caller(),
            &load_tests::host(),
            &load_tests::clock(&ready, 20),
        )
        .unwrap_or_else(|error| panic!("replay expired error lease: {error:?}"));
    assert_eq!(replay.outcome().response().status, LeaseStatus::Expired);
}

fn expire_error_lease(connection: &Connection) {
    connection
        .execute_batch(
            "UPDATE leases SET status = 'EXPIRED',
                reason_code = 'maximum-lifetime-reached',
                terminal_at_utc = maximum_expires_at_utc,
                terminal_at_seconds = maximum_expires_at_seconds,
                terminal_at_nanos = maximum_expires_at_nanos,
                next_audit_sequence = 5, row_version = row_version + 1;
             INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest, reason_code
             ) SELECT 'audit_00000000000000000000000004', l.lease_id, 4,
                l.service_generation, 'lease.expired', 'succeeded', 'EXPIRED',
                'NONE', 0, l.terminal_at_utc, l.terminal_at_seconds,
                l.terminal_at_nanos, 'service', r.client_request_id, l.tenant_id,
                l.work_order_id, l.work_order_digest, l.run_id, l.attempt_id,
                l.role, l.provider, l.profile_uid, l.profile_ref, l.repository_id,
                l.workspace_id, l.environment, l.authenticated_caller,
                l.host_identity, l.fencing_generation, l.effective_policy_digest,
                l.reason_code
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id;",
        )
        .unwrap_or_else(|error| panic!("expire error lease: {error}"));
}

#[test]
fn recovery_markers_cannot_rewrite_the_error_reason() {
    let fixture = load_tests::Fixture::new();
    let request = fixture.request();
    let mut ready = fixture.ready();
    load_tests::seed(&mut ready, &request);
    load_tests::resolved_status(ready.test_connection(), LeaseStatus::Error);
    rewrite_error_reason_through_recovery(ready.test_connection());

    assert_eq!(
        ready.begin_acquire(
            &request,
            &load_tests::caller(),
            &load_tests::host(),
            &load_tests::clock(&ready, 20),
        ),
        Err(StoreError::IntegrityCheckFailed),
    );
}

fn rewrite_error_reason_through_recovery(connection: &Connection) {
    connection
        .execute_batch(
            "UPDATE leases SET recovery_state = 'REQUIRED',
                reason_code = 'service-recovery', next_audit_sequence = 5;
             INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest, reason_code
             ) SELECT 'audit_00000000000000000000000004', l.lease_id, 4,
                l.service_generation, 'lease.recovery-required', 'failed', 'ERROR',
                'REQUIRED', 0, '2026-08-22T10:00:06Z', 1787392806, 0,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                l.fencing_generation, l.effective_policy_digest, l.reason_code
             FROM leases l JOIN lease_requests r
               ON r.request_record_id = l.request_record_id;",
        )
        .unwrap_or_else(|error| panic!("rewrite reason through recovery: {error}"));
}

#[test]
fn every_historical_authority_digest_honors_the_request_assertion() {
    let fixture = load_tests::Fixture::new();
    let mut request = fixture.request();
    request.policy_digest = Some(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse::<Sha256Digest>()
            .unwrap_or_else(|error| panic!("policy digest: {error:?}")),
    );
    let mut ready = fixture.ready();
    load_tests::seed(&mut ready, &request);
    load_tests::resolved_status(ready.test_connection(), LeaseStatus::Renewing);
    ready
        .test_connection()
        .execute_batch(
            "DROP TRIGGER audit_events_immutable;
             UPDATE audit_events SET effective_policy_digest =
                'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
             WHERE sequence = 2;",
        )
        .unwrap_or_else(|error| panic!("historical digest: {error}"));

    assert_eq!(
        ready.begin_acquire(
            &request,
            &load_tests::caller(),
            &load_tests::host(),
            &load_tests::clock(&ready, 20),
        ),
        Err(StoreError::IntegrityCheckFailed),
    );
}

#[derive(Clone, Copy)]
enum DeadlineCorruption {
    InitialTtl,
    RenewalTtl,
    MaximumSession,
}

#[test]
fn persisted_deadlines_cannot_widen_or_replace_signed_request_limits() {
    for corruption in [
        DeadlineCorruption::InitialTtl,
        DeadlineCorruption::RenewalTtl,
        DeadlineCorruption::MaximumSession,
    ] {
        let fixture = load_tests::Fixture::new();
        let request = fixture.request();
        let mut ready = fixture.ready();
        load_tests::seed(&mut ready, &request);
        let status = if matches!(corruption, DeadlineCorruption::RenewalTtl) {
            LeaseStatus::Renewing
        } else {
            LeaseStatus::Active
        };
        load_tests::resolved_status(ready.test_connection(), status);
        corrupt_deadline(ready.test_connection(), corruption);

        let changes_before = ready.test_connection().total_changes();
        assert_eq!(
            ready.begin_acquire(
                &request,
                &load_tests::caller(),
                &load_tests::host(),
                &load_tests::clock(&ready, 20),
            ),
            Err(StoreError::IntegrityCheckFailed),
        );
        assert_eq!(ready.test_connection().total_changes(), changes_before);
    }
}

fn corrupt_deadline(connection: &Connection, corruption: DeadlineCorruption) {
    let issued = connection
        .query_row("SELECT issued_monotonic_nanos FROM leases", [], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .unwrap_or_else(|error| panic!("issued monotonic: {error}"));
    let issued = u128::from_be_bytes(
        issued
            .try_into()
            .unwrap_or_else(|_| panic!("issued monotonic width")),
    );
    match corruption {
        DeadlineCorruption::InitialTtl => {
            let deadline = (issued + 899_000_000_000).to_be_bytes();
            connection
                .execute(
                    "UPDATE leases SET expires_at_utc = '2026-08-22T10:15:01Z',
                        expires_at_seconds = 1787393701,
                        expires_monotonic_nanos = ?1",
                    [deadline.as_slice()],
                )
                .unwrap_or_else(|error| panic!("initial TTL mismatch: {error}"));
        }
        DeadlineCorruption::RenewalTtl => {
            let deadline = (issued + 10 + 901_000_000_000).to_be_bytes();
            connection
                .execute(
                    "UPDATE leases SET expires_at_utc = '2026-08-22T10:15:05Z',
                        expires_at_seconds = 1787393705,
                        expires_monotonic_nanos = ?1",
                    [deadline.as_slice()],
                )
                .unwrap_or_else(|error| panic!("renewal TTL widening: {error}"));
        }
        DeadlineCorruption::MaximumSession => {
            let deadline = (issued + 14_401_000_000_000).to_be_bytes();
            connection
                .execute(
                    "UPDATE leases SET maximum_expires_at_utc = '2026-08-22T14:00:03Z',
                        maximum_expires_at_seconds = 1787407203,
                        maximum_expires_monotonic_nanos = ?1",
                    params![deadline.as_slice()],
                )
                .unwrap_or_else(|error| panic!("session widening: {error}"));
        }
    }
}
