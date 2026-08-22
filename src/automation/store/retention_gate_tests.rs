use crate::{
    automation::{
        contracts::{IsolationClassification, LeaseReasonCode, RefusalCode},
        policy::test_support::effective_policy,
        store::{AuthenticatedRequestControl, RecoveringStore},
    },
    model::AutomationConcurrencyMode,
};

use super::{
    activation_lifecycle_tests::{Fixture, begin, caller, clock, control, host, resolution, stamp},
    lifecycle_types::NonCapacityRefusal,
};

pub(super) fn refuse(
    fixture: &Fixture,
    store: &mut super::ReadyStore,
    id: &str,
    at: &str,
) -> crate::automation::contracts::LeaseId {
    let request = fixture.request(id);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, row_version) = begin(store, &request, 100);
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        row_version,
        &authenticated_caller,
        &authenticated_host,
    );
    store
        .refuse_requested(
            &request_control,
            NonCapacityRefusal::from_evaluation(RefusalCode::ProfileNotReady)
                .unwrap_or_else(|| panic!("non-capacity refusal")),
            &stamp(at),
        )
        .unwrap_or_else(|error| panic!("refuse: {error:?}"));
    lease_id
}

fn lease_count(store: &super::ReadyStore) -> i64 {
    store
        .test_connection()
        .query_row("SELECT count(*) FROM leases", [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("lease count: {error}"))
}

fn released_history(
    store: &super::ReadyStore,
    lease_id: &crate::automation::contracts::LeaseId,
) -> Vec<(String, String, i64, String, String, i64, i64)> {
    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT reservation_id, capacity_dimension, slot, state,
                    released_at_utc, released_at_seconds, released_at_nanos
             FROM capacity_reservations WHERE lease_id = ?1 ORDER BY reservation_id",
        )
        .unwrap_or_else(|error| panic!("released history statement: {error}"));
    statement
        .query_map([lease_id.as_str()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .unwrap_or_else(|error| panic!("released history query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("released history rows: {error}"))
}

#[derive(Clone, Copy, Debug)]
enum RecentGate {
    Terminal,
    ReservationRelease,
}

#[test]
fn each_recent_terminal_and_release_timestamp_independently_blocks_prune() {
    for (index, gate) in [RecentGate::Terminal, RecentGate::ReservationRelease]
        .into_iter()
        .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let id = format!("01ARZ3NDEKTSV4RRFFQ69G5FC{index}");
        let refusal_at = if matches!(gate, RecentGate::Terminal) {
            "2026-09-04T10:00:00Z"
        } else {
            "2026-08-22T10:00:03Z"
        };
        let lease_id = refuse(&fixture, &mut store, &id, refusal_at);
        match gate {
            RecentGate::Terminal => {}
            RecentGate::ReservationRelease => {
                store
                    .test_connection()
                    .execute_batch(&format!(
                        "INSERT INTO capacity_reservations (
                            reservation_id, lease_id, provider, profile_uid,
                            authenticated_caller, host_identity, tenant_id,
                            capacity_dimension, capacity_key, capacity_limit, slot, state,
                            reserved_at_utc, reserved_at_seconds, reserved_at_nanos
                         ) SELECT 'capacity_00000000000000000000000000', lease_id,
                            provider, profile_uid, authenticated_caller, host_identity,
                            tenant_id, 'provider', provider, 1, 1, 'HELD',
                            '2026-08-22T10:00:03Z', 1787392803, 0 FROM leases
                         WHERE lease_id = '{lease_id}';
                         UPDATE capacity_reservations SET state = 'RELEASED',
                            released_at_utc = '2026-09-04T10:00:00Z',
                            released_at_seconds = unixepoch('2026-09-04T10:00:00Z'),
                            released_at_nanos = 0 WHERE lease_id = '{lease_id}';"
                    ))
                    .unwrap_or_else(|error| panic!("recent release: {error}"));
            }
        }

        assert!(
            !store
                .prune_retained(&stamp("2026-09-10T10:00:00Z"))
                .unwrap_or_else(|error| panic!("blocked {gate:?} prune: {error:?}"))
                .changed()
        );
        assert_eq!(lease_count(&store), 1);
        let later = store
            .prune_retained(&stamp("2026-09-20T10:00:00Z"))
            .unwrap_or_else(|error| panic!("later {gate:?} prune: {error:?}"));
        assert_eq!(later.deleted_leases(), 1);
        assert_eq!(
            later.deleted_reservations(),
            u64::from(matches!(gate, RecentGate::ReservationRelease))
        );
    }
}

pub(super) fn closed_with_exited_process(
    fixture: &Fixture,
    store: &mut super::ReadyStore,
    id: &str,
    ended_at: &str,
    exited_audit_at: &str,
) -> crate::automation::contracts::LeaseId {
    let request = fixture.request(id);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, requested_version) = begin(store, &request, 100);
    let policy = effective_policy(
        &request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [1, 1, 1, 1],
    );
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        requested_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let active = store
        .activate_requested(
            &request_control,
            &policy,
            resolution('D', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("activate: {error:?}"));
    store
        .test_connection()
        .execute_batch(&format!(
            "INSERT INTO lease_processes (
                process_id, lease_id, service_generation, state, process_id_number,
                process_identity, execution_handle, worker_identity,
                observed_fencing_generation, launch_intent_at_utc,
                launch_intent_at_seconds, launch_intent_at_nanos,
                started_at_utc, started_at_seconds, started_at_nanos,
                ended_at_utc, ended_at_seconds, ended_at_nanos, exit_code
             ) SELECT 'process_00000000000000000000000000', lease_id,
                service_generation, 'EXITED', 4242, 'boot:start-token',
                execution_handle, worker_identity, fencing_generation,
                '2026-08-22T10:00:04Z', 1787392804, 0,
                '2026-08-22T10:00:05Z', 1787392805, 0,
                '{ended_at}', unixepoch('{ended_at}'), 0, 0
             FROM leases WHERE lease_id = '{lease_id}';
             UPDATE leases SET next_audit_sequence = 6 WHERE lease_id = '{lease_id}';
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
                'NONE', 0, '2026-08-22T10:00:04Z', 1787392804, 0,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                l.fencing_generation, l.effective_policy_digest
             FROM leases l JOIN lease_requests r USING (request_record_id)
             WHERE l.lease_id = '{lease_id}';
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
                'NONE', 0, '2026-08-22T10:00:05Z', 1787392805, 0,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                l.fencing_generation, l.effective_policy_digest
             FROM leases l JOIN lease_requests r USING (request_record_id)
             WHERE l.lease_id = '{lease_id}';
             INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest
             ) SELECT 'audit_00000000000000000000000005', l.lease_id, 5,
                l.service_generation, 'process.exited', 'succeeded', 'ACTIVE',
                'NONE', 0, '{exited_audit_at}', unixepoch('{exited_audit_at}'), 0,
                'service', r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity,
                l.fencing_generation, l.effective_policy_digest
             FROM leases l JOIN lease_requests r USING (request_record_id)
             WHERE l.lease_id = '{lease_id}';"
        ))
        .unwrap_or_else(|error| panic!("process history: {error}"));
    let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    store
        .close_lease(
            &lease_id,
            active
                .successful_row_version()
                .unwrap_or_else(|| panic!("active version")),
            &lease_control,
            LeaseReasonCode::Completed,
            &clock(store, "2026-08-22T10:00:07Z", 102),
        )
        .unwrap_or_else(|error| panic!("close: {error:?}"));
    lease_id
}

#[test]
fn recent_process_end_and_exit_audit_independently_block_prune() {
    for (index, (ended_at, exited_audit_at)) in [
        ("2026-09-04T10:00:00Z", "2026-08-22T10:00:06Z"),
        ("2026-08-22T10:00:06Z", "2026-09-04T10:00:00Z"),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        closed_with_exited_process(
            &fixture,
            &mut store,
            &format!("01ARZ3NDEKTSV4RRFFQ69G5FC{}", index + 3),
            ended_at,
            exited_audit_at,
        );
        assert!(
            !store
                .prune_retained(&stamp("2026-09-10T10:00:00Z"))
                .unwrap_or_else(|error| panic!("recent process prune: {error:?}"))
                .changed()
        );
        let later = store
            .prune_retained(&stamp("2026-09-20T10:00:00Z"))
            .unwrap_or_else(|error| panic!("later process prune: {error:?}"));
        assert_eq!(later.deleted_processes(), 1);
        assert_eq!(later.deleted_reservations(), 4);
        assert_eq!(later.deleted_leases(), 1);
    }
}

#[test]
fn old_global_audit_and_multiple_released_history_are_summarized_and_pruned() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let lease_id = refuse(
        &fixture,
        &mut store,
        "01ARZ3NDEKTSV4RRFFQ69G5FC4",
        "2026-08-22T10:00:03Z",
    );
    super::migration_tests::downgrade_to_frozen_v2(store.test_connection());
    store
        .test_connection()
        .execute_batch(
            "INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos, released_at_utc, released_at_seconds, released_at_nanos
             ) SELECT 'capacity_00000000000000000000000000', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'provider', provider, 1, 7, 'RELEASED',
                '2026-08-22T10:00:02Z', 1787392802, 0,
                '2026-08-22T10:00:03Z', 1787392803, 0 FROM leases;
             INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos, released_at_utc, released_at_seconds, released_at_nanos
             ) SELECT 'capacity_00000000000000000000000001', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'provider', provider, 1, 8, 'RELEASED',
                '2026-08-22T10:00:02Z', 1787392802, 0,
                '2026-08-22T10:00:03Z', 1787392803, 0 FROM leases;",
        )
        .unwrap_or_else(|error| panic!("legacy history: {error}"));
    let legacy = released_history(&store, &lease_id);
    assert_eq!(legacy.len(), 2);
    drop(store);
    let mut store = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:01:00Z"),
    )
    .unwrap_or_else(|error| panic!("v3 reopen: {error:?}"))
    .into_ready(&stamp("2026-08-22T10:01:01Z"))
    .unwrap_or_else(|error| panic!("v3 ready: {error:?}"));
    assert_eq!(
        store
            .test_connection()
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap_or_else(|error| panic!("v3 version: {error}")),
        3
    );
    assert_eq!(released_history(&store, &lease_id), legacy);
    assert_eq!(
        store
            .test_connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name IN (
                    'capacity_reservations_lease_state',
                    'lease_processes_lease_state',
                    'capacity_reservations_insert_held',
                    'capacity_reservations_transition_only',
                    'capacity_reservations_delete_released')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("v3 objects: {error}")),
        5
    );
    store
        .test_connection()
        .execute_batch(
            "INSERT INTO audit_events (
                audit_event_id, service_generation, event_type, outcome,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                prune_cutoff_utc, prune_deleted_requests, prune_deleted_leases,
                prune_deleted_reservations, prune_deleted_processes, prune_deleted_events,
                prune_oldest_event_utc, prune_oldest_event_seconds,
                prune_oldest_event_nanos, prune_newest_event_utc,
                prune_newest_event_seconds, prune_newest_event_nanos
             ) VALUES (
                'audit_00000000000000000000000009',
                (SELECT max(service_generation) FROM service_generations),
                'audit.pruned', 'succeeded', '2026-08-01T00:00:00Z',
                unixepoch('2026-08-01T00:00:00Z'), 0, 'service',
                '2026-07-25T00:00:00Z', 0, 0, 0, 0, 1,
                '2026-07-01T00:00:00Z', unixepoch('2026-07-01T00:00:00Z'), 0,
                '2026-07-01T00:00:00Z', unixepoch('2026-07-01T00:00:00Z'), 0
             );",
        )
        .unwrap_or_else(|error| panic!("global audit: {error}"));

    let result = store
        .prune_retained(&stamp("2026-09-10T10:00:00Z"))
        .unwrap_or_else(|error| panic!("legacy prune: {error:?}"));
    assert_eq!(result.deleted_requests(), 1);
    assert_eq!(result.deleted_leases(), 1);
    assert_eq!(result.deleted_reservations(), 2);
    assert_eq!(result.deleted_events(), 3);
    let summary: (i64, i64, String, String) = store
        .test_connection()
        .query_row(
            "SELECT prune_deleted_reservations, prune_deleted_events,
                    prune_oldest_event_utc, prune_newest_event_utc
             FROM audit_events WHERE event_type = 'audit.pruned'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap_or_else(|error| panic!("summary: {error}"));
    assert_eq!(
        summary,
        (
            2,
            3,
            "2026-08-01T00:00:00Z".to_owned(),
            "2026-08-22T10:00:03Z".to_owned()
        )
    );
}
