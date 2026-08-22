use core::str::FromStr;

use rusqlite::{params, types::Value};

use crate::{
    automation::{
        contracts::IdentityLeaseRequest,
        store::{RecoveringStore, StoreError},
    },
    config::{acquire_profile_lock, profile_automation_fence_presence},
    model::ProfileId,
};

use super::activation_lifecycle_tests::{Fixture, begin, stamp};

fn install_failure(store: &RecoveringStore, body: &str) {
    store
        .test_connection()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_recovery_statement {body}
             BEGIN SELECT RAISE(ABORT, 'injected recovery statement failure'); END;"
        ))
        .unwrap_or_else(|error| panic!("install recovery failure: {error}"));
}

fn clear_failure(store: &RecoveringStore) {
    store
        .test_connection()
        .execute_batch("DROP TRIGGER temp.fail_recovery_statement;")
        .unwrap_or_else(|error| panic!("drop recovery failure: {error}"));
}

fn table_rows(store: &RecoveringStore, table: &str, order: &str) -> Vec<Vec<Value>> {
    let sql = format!("SELECT * FROM {table} ORDER BY {order}");
    let mut statement = store
        .test_connection()
        .prepare(&sql)
        .unwrap_or_else(|error| panic!("recovery graph {table}: {error}"));
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })
        .unwrap_or_else(|error| panic!("recovery graph query {table}: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("recovery graph rows {table}: {error}"))
}

fn full_graph(store: &RecoveringStore) -> Vec<Vec<Vec<Value>>> {
    vec![
        table_rows(store, "leases", "lease_id"),
        table_rows(store, "lease_runtime_clocks", "lease_id"),
        table_rows(store, "capacity_reservations", "reservation_id"),
        table_rows(store, "lease_processes", "process_id"),
        table_rows(store, "audit_events", "audit_event_id"),
    ]
}

fn seed_mixed_live_capacity(
    connection: &rusqlite::Connection,
    lease_id: &crate::automation::contracts::LeaseId,
) {
    for (index, (dimension, key_column, state)) in [
        ("profile", "profile_uid", "HELD"),
        ("provider", "provider", "QUARANTINED"),
        ("caller", "authenticated_caller", "RECOVERY_REQUIRED"),
    ]
    .into_iter()
    .enumerate()
    {
        connection
            .execute_batch(&format!(
                "INSERT INTO capacity_reservations (
                    reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                    host_identity, tenant_id, capacity_dimension, capacity_key,
                    capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                    reserved_at_nanos
                 ) SELECT 'capacity_0000000000000000000000000{index}', lease_id,
                    provider, profile_uid, authenticated_caller, host_identity, tenant_id,
                    '{dimension}', {key_column}, 1, 7, '{state}', issued_at_utc,
                    issued_at_seconds, issued_at_nanos FROM leases
                 WHERE lease_id = '{lease_id}';"
            ))
            .unwrap_or_else(|error| panic!("seed mixed recovery capacity: {error}"));
    }
}

fn assert_fence_exclusion(fixture: &Fixture, request: &IdentityLeaseRequest) {
    assert!(
        profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
            .unwrap_or_else(|error| panic!("recovery marker presence: {error}"))
    );
    let profile_ref = ProfileId::from_str(request.profile_ref.as_str())
        .unwrap_or_else(|error| panic!("recovery profile ref: {error:?}"));
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_lock(profile_ref.provider(), profile_ref.name()),
            false,
        )
        .is_err(),
        "recovery alias exclusion was lost"
    );
    assert!(
        acquire_profile_lock(
            &fixture.paths.profile_lifecycle_lock(&request.profile_uid),
            true,
        )
        .is_err(),
        "recovery lifecycle exclusion was lost"
    );
}

fn projection(
    store: &RecoveringStore,
    lease_id: &crate::automation::contracts::LeaseId,
) -> (String, i64, i64, Vec<(String, Option<String>)>) {
    let (status, row_version, audits) = store
        .test_connection()
        .query_row(
            "SELECT status, row_version,
                    (SELECT count(*) FROM audit_events a WHERE a.lease_id = leases.lease_id)
             FROM leases WHERE lease_id = ?1",
            [lease_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("recovery failure lease: {error}"));
    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT state, released_at_utc FROM capacity_reservations
             WHERE lease_id = ?1 ORDER BY reservation_id",
        )
        .unwrap_or_else(|error| panic!("recovery failure capacity statement: {error}"));
    let capacity = statement
        .query_map([lease_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap_or_else(|error| panic!("recovery failure capacity query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("recovery failure capacity rows: {error}"));
    (status, row_version, audits, capacity)
}

#[test]
fn prior_requested_transition_rolls_back_lease_and_audit_statements() {
    for (index, stage) in [
        "BEFORE UPDATE ON main.leases",
        "BEFORE INSERT ON main.audit_events WHEN NEW.event_type = 'lease.refused'",
        "BEFORE UPDATE ON main.capacity_reservations WHEN OLD.state <> 'RELEASED'",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FV{index}"));
        let (lease_id, row_version) = begin(&mut ready, &request, 100);
        super::migration_tests::downgrade_to_frozen_v2(ready.test_connection());
        seed_mixed_live_capacity(ready.test_connection(), &lease_id);
        drop(ready);
        let mut recovering = RecoveringStore::open(
            &fixture.paths,
            &fixture.profile.installation,
            &stamp("2026-08-22T10:01:00Z"),
        )
        .unwrap_or_else(|error| panic!("requested recovery open: {error:?}"));
        let before = full_graph(&recovering);
        install_failure(&recovering, stage);
        assert!(matches!(
            recovering.terminalize_prior_generation(
                &lease_id,
                row_version,
                &stamp("2026-08-22T10:01:01Z")
            ),
            Err(StoreError::DatabaseUnavailable)
        ));
        clear_failure(&recovering);
        assert_eq!(full_graph(&recovering), before, "{stage}");
        assert_fence_exclusion(&fixture, &request);
        let recovered = recovering
            .terminalize_prior_generation(&lease_id, row_version, &stamp("2026-08-22T10:01:02Z"))
            .unwrap_or_else(|error| panic!("requested recovery retry: {error:?}"));
        assert!(recovered.changed());
        assert_eq!(recovered.released_reservations(), 3);
    }
}

#[test]
fn terminal_capacity_cleanup_rolls_back_release_and_cas_bump_together() {
    for (index, stage) in [
        "BEFORE UPDATE ON main.capacity_reservations WHEN OLD.state <> 'RELEASED'",
        "BEFORE UPDATE ON main.leases",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FW{index}"));
        let (lease_id, row_version) = begin(&mut ready, &request, 100);
        let authenticated_caller = super::activation_lifecycle_tests::caller();
        let authenticated_host = super::activation_lifecycle_tests::host();
        let request_control = super::AuthenticatedRequestControl::new(
            &lease_id,
            row_version,
            &authenticated_caller,
            &authenticated_host,
        );
        let refused = ready
            .refuse_requested(
                &request_control,
                super::lifecycle_types::NonCapacityRefusal::from_evaluation(
                    crate::automation::contracts::RefusalCode::ProfileNotReady,
                )
                .unwrap_or_else(|| panic!("recovery failure refusal")),
                &stamp("2026-08-22T10:00:03Z"),
            )
            .unwrap_or_else(|error| panic!("recovery failure refusal: {error:?}"));
        let terminal_version = refused
            .successful_row_version()
            .unwrap_or_else(|| panic!("recovery failure terminal version"));
        super::migration_tests::downgrade_to_frozen_v2(ready.test_connection());
        ready
            .test_connection()
            .execute(
                "INSERT INTO capacity_reservations (
                    reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                    host_identity, tenant_id, capacity_dimension, capacity_key,
                    capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                    reserved_at_nanos
                 ) SELECT 'capacity_00000000000000000000000000', lease_id, provider,
                    profile_uid, authenticated_caller, host_identity, tenant_id,
                    'provider', provider, 1, 7, 'QUARANTINED', issued_at_utc,
                    issued_at_seconds, issued_at_nanos FROM leases WHERE lease_id = ?1",
                params![lease_id.as_str()],
            )
            .unwrap_or_else(|error| panic!("recovery failure seed: {error}"));
        drop(ready);
        let mut recovering = RecoveringStore::open(
            &fixture.paths,
            &fixture.profile.installation,
            &stamp("2026-08-22T10:01:00Z"),
        )
        .unwrap_or_else(|error| panic!("terminal recovery open: {error:?}"));
        let before = full_graph(&recovering);
        install_failure(&recovering, stage);
        assert!(matches!(
            recovering.terminalize_prior_generation(
                &lease_id,
                terminal_version,
                &stamp("2026-08-22T10:01:01Z")
            ),
            Err(StoreError::DatabaseUnavailable)
        ));
        clear_failure(&recovering);
        assert_eq!(full_graph(&recovering), before, "{stage}");
        assert_fence_exclusion(&fixture, &request);
        let recovered = recovering
            .terminalize_prior_generation(
                &lease_id,
                terminal_version,
                &stamp("2026-08-22T10:01:02Z"),
            )
            .unwrap_or_else(|error| panic!("terminal recovery retry: {error:?}"));
        assert_eq!(recovered.released_reservations(), 1);
        assert_eq!(recovered.row_version(), terminal_version + 1);
    }
}

#[test]
fn recovery_commit_ambiguity_retains_interlocks_and_blocks_same_process_readiness() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FW2");
    let (lease_id, row_version) = begin(&mut ready, &request, 100);
    drop(ready);
    let mut recovering = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:01:00Z"),
    )
    .unwrap_or_else(|error| panic!("ambiguous recovery open: {error:?}"));
    let before = full_graph(&recovering);
    recovering
        .test_connection()
        .commit_hook(Some(|| true))
        .unwrap_or_else(|error| panic!("recovery commit hook: {error}"));
    assert!(matches!(
        recovering.terminalize_prior_generation(
            &lease_id,
            row_version,
            &stamp("2026-08-22T10:01:01Z"),
        ),
        Err(StoreError::DatabaseUnavailable)
    ));
    recovering
        .test_connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap_or_else(|error| panic!("clear recovery commit hook: {error}"));
    assert_eq!(full_graph(&recovering), before);
    assert_fence_exclusion(&fixture, &request);
    assert!(matches!(
        recovering.clear_orphan_profile_fence(&request.profile_uid),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(matches!(
        recovering.into_ready(&stamp("2026-08-22T10:01:02Z")),
        Err(StoreError::RecoveryRequired)
    ));
}
