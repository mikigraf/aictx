use super::{
    RecoveringStore, StoreError,
    activation_lifecycle_tests::{Fixture, stamp},
    retention_gate_tests::{closed_with_exited_process, refuse},
};

fn capacity_projection(store: &super::ReadyStore) -> Vec<(String, String, i64, i64)> {
    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT reservation_id, released_at_utc, released_at_seconds, released_at_nanos
             FROM capacity_reservations ORDER BY reservation_id",
        )
        .unwrap_or_else(|error| panic!("capacity projection statement: {error}"));
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap_or_else(|error| panic!("capacity projection query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("capacity projection rows: {error}"))
}

fn process_projection(store: &super::ReadyStore) -> Vec<(String, String, i64, i64)> {
    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT process_id, ended_at_utc, ended_at_seconds, ended_at_nanos
             FROM lease_processes ORDER BY process_id",
        )
        .unwrap_or_else(|error| panic!("process projection statement: {error}"));
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap_or_else(|error| panic!("process projection query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("process projection rows: {error}"))
}

type DurableProjection = (Vec<(i64, String)>, Vec<(String, String, i64)>);

fn durable_projection(connection: &rusqlite::Connection) -> DurableProjection {
    let mut generations = connection
        .prepare(
            "SELECT service_generation, start_outcome
             FROM service_generations ORDER BY service_generation",
        )
        .unwrap_or_else(|error| panic!("history generation statement: {error}"));
    let generations = generations
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap_or_else(|error| panic!("history generation query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("history generation rows: {error}"));
    let mut leases = connection
        .prepare("SELECT lease_id, status, row_version FROM leases ORDER BY lease_id")
        .unwrap_or_else(|error| panic!("history lease statement: {error}"));
    let leases = leases
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap_or_else(|error| panic!("history lease query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("history lease rows: {error}"));
    (generations, leases)
}

fn readiness_is_integrity_failure(fixture: &Fixture, before: &DurableProjection) {
    assert!(matches!(
        RecoveringStore::open(
            &fixture.paths,
            &fixture.profile.installation,
            &stamp("2026-09-10T10:00:01Z"),
        ),
        Err(StoreError::IntegrityCheckFailed)
    ));
    let connection = rusqlite::Connection::open(fixture.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("inspect rejected history open: {error}"));
    assert_eq!(&durable_projection(&connection), before);
}

#[test]
fn forged_released_timestamp_tuple_blocks_prune_and_readiness_without_mutation() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let lease_id = refuse(
        &fixture,
        &mut store,
        "01ARZ3NDEKTSV4RRFFQ69G5FCE",
        "2026-08-22T10:00:03Z",
    );
    store
        .test_connection()
        .execute_batch(&format!(
            "INSERT INTO capacity_reservations (
                reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                host_identity, tenant_id, capacity_dimension, capacity_key,
                capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                reserved_at_nanos
             ) SELECT 'capacity_00000000000000000000000000', lease_id, provider,
                profile_uid, authenticated_caller, host_identity, tenant_id,
                'provider', provider, 1, 1, 'HELD',
                '2026-08-22T10:00:02Z', 1787392802, 0 FROM leases
             WHERE lease_id = '{lease_id}';
             UPDATE capacity_reservations SET state = 'RELEASED',
                released_at_utc = '2026-09-04T10:00:00Z',
                released_at_seconds = 1787392803, released_at_nanos = 0
             WHERE lease_id = '{lease_id}';"
        ))
        .unwrap_or_else(|error| panic!("forged release history: {error}"));
    let before = capacity_projection(&store);
    assert_eq!(
        store.prune_retained(&stamp("2026-09-10T10:00:00Z")),
        Err(StoreError::IntegrityCheckFailed)
    );
    assert_eq!(capacity_projection(&store), before);
    let durable_before = durable_projection(store.test_connection());
    drop(store);
    readiness_is_integrity_failure(&fixture, &durable_before);
}

#[test]
fn forged_exited_process_tuple_blocks_prune_and_readiness_without_mutation() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    closed_with_exited_process(
        &fixture,
        &mut store,
        "01ARZ3NDEKTSV4RRFFQ69G5FCF",
        "2026-09-04T10:00:00Z",
        "2026-08-22T10:00:06Z",
    );
    store
        .test_connection()
        .execute(
            "UPDATE lease_processes SET ended_at_seconds = 1787392806",
            [],
        )
        .unwrap_or_else(|error| panic!("forge process history: {error}"));
    let before = process_projection(&store);
    assert_eq!(
        store.prune_retained(&stamp("2026-09-10T10:00:00Z")),
        Err(StoreError::IntegrityCheckFailed)
    );
    assert_eq!(process_projection(&store), before);
    let durable_before = durable_projection(store.test_connection());
    drop(store);
    readiness_is_integrity_failure(&fixture, &durable_before);
}
