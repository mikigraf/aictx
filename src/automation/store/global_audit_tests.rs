use super::{
    RecoveringStore, StoreError,
    activation_lifecycle_tests::{Fixture, stamp},
};

fn global_projection_connection(connection: &rusqlite::Connection) -> Vec<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT * FROM audit_events WHERE lease_id IS NULL ORDER BY audit_event_id")
        .unwrap_or_else(|error| panic!("global statement: {error}"));
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| {
                    Ok(match row.get_ref(index)? {
                        rusqlite::types::ValueRef::Null => "null".to_owned(),
                        rusqlite::types::ValueRef::Integer(value) => format!("i:{value}"),
                        rusqlite::types::ValueRef::Real(value) => format!("r:{value}"),
                        rusqlite::types::ValueRef::Text(value) => {
                            format!("t:{}", String::from_utf8_lossy(value))
                        }
                        rusqlite::types::ValueRef::Blob(value) => {
                            format!("b:{value:?}")
                        }
                    })
                })
                .collect::<Result<Vec<_>, rusqlite::Error>>()
        })
        .unwrap_or_else(|error| panic!("global query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("global rows: {error}"))
}

fn global_projection(store: &super::ReadyStore) -> Vec<Vec<String>> {
    global_projection_connection(store.test_connection())
}

type DurableOpenProjection = (
    Vec<(i64, String)>,
    Vec<(String, String, i64, i64)>,
    Vec<Vec<String>>,
);

fn durable_open_projection(connection: &rusqlite::Connection) -> DurableOpenProjection {
    let mut generations = connection
        .prepare(
            "SELECT service_generation, start_outcome
             FROM service_generations ORDER BY service_generation",
        )
        .unwrap_or_else(|error| panic!("generation projection statement: {error}"));
    let generations = generations
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap_or_else(|error| panic!("generation projection query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("generation projection rows: {error}"));
    let mut leases = connection
        .prepare(
            "SELECT lease_id, status, row_version, next_audit_sequence
             FROM leases ORDER BY lease_id",
        )
        .unwrap_or_else(|error| panic!("lease projection statement: {error}"));
    let leases = leases
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap_or_else(|error| panic!("lease projection query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("lease projection rows: {error}"));
    (
        generations,
        leases,
        global_projection_connection(connection),
    )
}

#[test]
fn schema_valid_corrupt_global_audits_block_prune_and_readiness_without_mutation() {
    for malformed in [
        "INSERT INTO audit_events (
            audit_event_id, service_generation, event_type, outcome,
            event_at_utc, event_at_seconds, event_at_nanos, actor
         ) VALUES (
            'audit_00000000000000000000000008',
            (SELECT max(service_generation) FROM service_generations),
            'caller.authentication-failed', 'failed',
            '2026-09-09T10:00:00Z', 1788948000, 0, 'caller:untrusted')",
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
            'audit.pruned', 'succeeded', '2026-09-09T10:00:00Z', 1788948000, 0,
            'service', '2026-09-01T10:00:00Z', 0, 0, 0, 0, 1,
            '2026-08-01T00:00:00Z', 1785542400, 0,
            '2026-08-01T00:00:00Z', 1785542400, 0)",
        "INSERT INTO audit_events (
            audit_event_id, service_generation, event_type, outcome,
            event_at_utc, event_at_seconds, event_at_nanos, actor
         ) VALUES (
            'audit_0000000000000000000000000A',
            (SELECT max(service_generation) FROM service_generations),
            'caller.authentication-failed', 'failed',
            '2026-09-09T10:00:00Z', 0, 0, 'service')",
        "INSERT INTO audit_events (
            audit_event_id, service_generation, event_type, outcome,
            event_at_utc, event_at_seconds, event_at_nanos, actor, tenant_id
         ) VALUES (
            'audit_0000000000000000000000000B',
            (SELECT max(service_generation) FROM service_generations),
            'caller.authentication-failed', 'failed',
            '2026-09-09T10:00:00Z', 1788948000, 0, 'service', 'tenant-acme')",
        "INSERT INTO audit_events (
            audit_event_id, service_generation, event_type, outcome,
            event_at_utc, event_at_seconds, event_at_nanos, actor,
            prune_cutoff_utc, prune_deleted_requests, prune_deleted_leases,
            prune_deleted_reservations, prune_deleted_processes, prune_deleted_events,
            prune_oldest_event_utc, prune_oldest_event_seconds, prune_oldest_event_nanos,
            prune_newest_event_utc, prune_newest_event_seconds, prune_newest_event_nanos
         ) VALUES (
            'audit_0000000000000000000000000C',
            (SELECT max(service_generation) FROM service_generations),
            'audit.pruned', 'succeeded',
            '2026-09-09T10:00:00Z', unixepoch('2026-09-09T10:00:00Z'), 0, 'service',
            '2026-09-01T10:00:00Z', 0, 0, 1, 0, 1,
            '2026-08-01T00:00:00Z', unixepoch('2026-08-01T00:00:00Z'), 0,
            '2026-08-01T00:00:00Z', unixepoch('2026-08-01T00:00:00Z'), 0)",
        "INSERT INTO audit_events (
            audit_event_id, service_generation, event_type, outcome,
            event_at_utc, event_at_seconds, event_at_nanos, actor,
            prune_cutoff_utc, prune_deleted_requests, prune_deleted_leases,
            prune_deleted_reservations, prune_deleted_processes, prune_deleted_events,
            prune_oldest_event_utc, prune_oldest_event_seconds, prune_oldest_event_nanos,
            prune_newest_event_utc, prune_newest_event_seconds, prune_newest_event_nanos
         ) VALUES (
            'audit_0000000000000000000000000D',
            (SELECT max(service_generation) FROM service_generations),
            'audit.pruned', 'succeeded',
            '2026-09-09T10:00:00Z', unixepoch('2026-09-09T10:00:00Z'), 0, 'service',
            '2026-09-01T10:00:00Z', 0, 0, 0, 0, 1,
            '2026-08-01T00:00:00Z', unixepoch('2026-08-01T00:00:00Z'), 0,
            '2026-09-02T00:00:00Z', unixepoch('2026-09-02T00:00:00Z'), 0)",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        store
            .test_connection()
            .execute(malformed, [])
            .unwrap_or_else(|error| panic!("malformed global insert: {error}"));
        let before = global_projection(&store);
        assert_eq!(
            store.prune_retained(&stamp("2026-09-10T10:00:00Z")),
            Err(StoreError::IntegrityCheckFailed)
        );
        assert_eq!(global_projection(&store), before);
        let durable_before = durable_open_projection(store.test_connection());
        drop(store);
        assert!(matches!(
            RecoveringStore::open(
                &fixture.paths,
                &fixture.profile.installation,
                &stamp("2026-09-10T10:00:01Z"),
            ),
            Err(StoreError::IntegrityCheckFailed)
        ));
        let connection = rusqlite::Connection::open(fixture.paths.automation_lease_store())
            .unwrap_or_else(|error| panic!("inspect rejected open: {error}"));
        assert_eq!(durable_open_projection(&connection), durable_before);
    }
}

#[test]
fn closed_authentication_failure_shape_validates_without_disclosure() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    store
        .test_connection()
        .execute_batch(
            "INSERT INTO audit_events (
                audit_event_id, service_generation, event_type, outcome,
                event_at_utc, event_at_seconds, event_at_nanos, actor
             ) VALUES (
                'audit_00000000000000000000000008',
                (SELECT max(service_generation) FROM service_generations),
                'caller.authentication-failed', 'failed',
                '2026-09-09T10:00:00Z', 1788948000, 0, 'service');",
        )
        .unwrap_or_else(|error| panic!("valid authentication failure: {error}"));
    let result = store
        .prune_retained(&stamp("2026-09-10T10:00:00Z"))
        .unwrap_or_else(|error| panic!("validate auth failure: {error:?}"));
    assert!(!result.changed());
    assert_eq!(global_projection(&store).len(), 1);
}
