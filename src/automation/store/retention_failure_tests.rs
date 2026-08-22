use rusqlite::types::Value;

use crate::automation::store::StoreError;

use super::{
    ReadyStore,
    activation_lifecycle_tests::{Fixture, stamp},
    retention_gate_tests::closed_with_exited_process,
};

#[derive(Debug, PartialEq)]
struct RetainedGraph {
    requests: Vec<Vec<Value>>,
    leases: Vec<Vec<Value>>,
    clocks: Vec<Vec<Value>>,
    reservations: Vec<Vec<Value>>,
    processes: Vec<Vec<Value>>,
    audits: Vec<Vec<Value>>,
}

fn rows(store: &ReadyStore, table: &str, order: &str) -> Vec<Vec<Value>> {
    let sql = format!("SELECT * FROM {table} ORDER BY {order}");
    let mut statement = store
        .test_connection()
        .prepare(&sql)
        .unwrap_or_else(|error| panic!("retention snapshot {table}: {error}"));
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })
        .unwrap_or_else(|error| panic!("retention snapshot query {table}: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("retention snapshot rows {table}: {error}"))
}

fn graph(store: &ReadyStore) -> RetainedGraph {
    RetainedGraph {
        requests: rows(store, "lease_requests", "request_record_id"),
        leases: rows(store, "leases", "lease_id"),
        clocks: rows(store, "lease_runtime_clocks", "lease_id"),
        reservations: rows(store, "capacity_reservations", "reservation_id"),
        processes: rows(store, "lease_processes", "process_id"),
        audits: rows(store, "audit_events", "audit_event_id"),
    }
}

fn seed_old_global_audit(store: &ReadyStore) {
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
                1785542400, 0, 'service', '2026-07-25T00:00:00Z',
                0, 0, 0, 0, 1,
                '2026-07-01T00:00:00Z', 1782864000, 0,
                '2026-07-01T00:00:00Z', 1782864000, 0
             );",
        )
        .unwrap_or_else(|error| panic!("seed old global audit: {error}"));
}

fn install_failure(store: &ReadyStore, body: &str) {
    store
        .test_connection()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_prune_statement {body}
             BEGIN SELECT RAISE(ABORT, 'injected prune statement failure'); END;"
        ))
        .unwrap_or_else(|error| panic!("install prune failure: {error}"));
}

fn clear_failure(store: &ReadyStore) {
    store
        .test_connection()
        .execute_batch("DROP TRIGGER temp.fail_prune_statement;")
        .unwrap_or_else(|error| panic!("drop prune failure: {error}"));
}

#[test]
fn every_prune_delete_class_aborts_the_complete_graph_atomically() {
    let stages = [
        "BEFORE DELETE ON main.audit_events WHEN OLD.lease_id IS NULL",
        "BEFORE DELETE ON main.audit_events WHEN OLD.lease_id IS NOT NULL",
        "BEFORE DELETE ON main.lease_processes",
        "BEFORE DELETE ON main.capacity_reservations",
        "BEFORE DELETE ON main.leases",
        "BEFORE DELETE ON main.lease_requests",
    ];
    for (index, stage) in stages.into_iter().enumerate() {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        closed_with_exited_process(
            &fixture,
            &mut store,
            &format!("01ARZ3NDEKTSV4RRFFQ69G5FX{index}"),
            "2026-08-22T10:00:06Z",
            "2026-08-22T10:00:06Z",
        );
        seed_old_global_audit(&store);
        let before = graph(&store);
        assert_eq!(before.reservations.len(), 4);
        assert_eq!(before.processes.len(), 1);
        install_failure(&store, stage);
        assert_eq!(
            store.prune_retained(&stamp("2026-09-10T10:00:00Z")),
            Err(StoreError::DatabaseUnavailable),
            "{stage}"
        );
        clear_failure(&store);
        assert_eq!(graph(&store), before, "{stage}");
    }
}
