use rusqlite::params;

use crate::automation::{
    contracts::{LeaseStatus, RefusalCode},
    store::{AuthenticatedRequestControl, RecoveringStore, StoreError},
};

use super::{
    activation_lifecycle_tests::{Fixture, begin, caller, host, stamp},
    lifecycle_types::NonCapacityRefusal,
};

type LegacyReservationRow = (String, String, i64, i64, String, Option<String>);
type SeededV2Rows = (
    crate::automation::contracts::LeaseId,
    u64,
    i64,
    Vec<LegacyReservationRow>,
);

fn rows(store: &RecoveringStore) -> Vec<LegacyReservationRow> {
    rows_connection(store.test_connection())
}

fn rows_connection(connection: &rusqlite::Connection) -> Vec<LegacyReservationRow> {
    let mut statement = connection
        .prepare(
            "SELECT reservation_id, capacity_dimension, capacity_limit, slot, state,
                    released_at_utc
             FROM capacity_reservations ORDER BY reservation_id",
        )
        .unwrap_or_else(|error| panic!("legacy rows statement: {error}"));
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .unwrap_or_else(|error| panic!("legacy rows query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("legacy rows: {error}"))
}

fn seed_v2_rows(fixture: &Fixture, count: usize) -> SeededV2Rows {
    let mut ready = fixture.ready();
    let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FT{count}"));
    let (lease_id, row_version) = begin(&mut ready, &request, 100);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        row_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let refused = ready
        .refuse_requested(
            &request_control,
            NonCapacityRefusal::from_evaluation(RefusalCode::ProfileNotReady)
                .unwrap_or_else(|| panic!("legacy refusal")),
            &stamp("2026-08-22T10:00:03Z"),
        )
        .unwrap_or_else(|error| panic!("legacy refusal: {error:?}"));
    let terminal_version = refused
        .successful_row_version()
        .unwrap_or_else(|| panic!("legacy terminal version"));
    let audit_count = ready
        .test_connection()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE lease_id = ?1",
            [lease_id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|error| panic!("legacy audit count: {error}"));
    super::migration_tests::downgrade_to_frozen_v2(ready.test_connection());
    let dimensions = ["provider", "profile", "caller"];
    let states = match count {
        1 => ["HELD", "HELD", "HELD"],
        2 => ["QUARANTINED", "RECOVERY_REQUIRED", "HELD"],
        3 => ["HELD", "QUARANTINED", "RECOVERY_REQUIRED"],
        _ => unreachable!(),
    };
    for index in 0..count {
        let reservation_id = format!("capacity_0000000000000000000000000{index}");
        ready
            .test_connection()
            .execute(
                "INSERT INTO capacity_reservations (
                    reservation_id, lease_id, provider, profile_uid, authenticated_caller,
                    host_identity, tenant_id, capacity_dimension, capacity_key,
                    capacity_limit, slot, state, reserved_at_utc, reserved_at_seconds,
                    reserved_at_nanos
                 ) SELECT ?1, lease_id, provider, profile_uid, authenticated_caller,
                    host_identity, tenant_id, ?2,
                    CASE ?2 WHEN 'provider' THEN provider WHEN 'profile' THEN profile_uid
                        ELSE authenticated_caller END,
                    1, ?3, ?4, issued_at_utc, issued_at_seconds, issued_at_nanos
                 FROM leases WHERE lease_id = ?5",
                params![
                    reservation_id,
                    dimensions[index],
                    if index == 0 {
                        7_i64
                    } else {
                        i64::try_from(index + 1).unwrap_or(1)
                    },
                    states[index],
                    lease_id.as_str(),
                ],
            )
            .unwrap_or_else(|error| panic!("seed legacy row {index}: {error}"));
    }
    let seeded = rows_connection(ready.test_connection());
    drop(ready);
    (lease_id, terminal_version, audit_count, seeded)
}

#[test]
fn frozen_v2_one_two_and_three_live_histories_migrate_unchanged_then_release_atomically() {
    for count in 1..=3 {
        let fixture = Fixture::new();
        let (lease_id, old_version, audit_count, seeded) = seed_v2_rows(&fixture, count);
        let blocked = RecoveringStore::open(
            &fixture.paths,
            &fixture.profile.installation,
            &stamp("2026-08-22T10:01:00Z"),
        )
        .unwrap_or_else(|error| panic!("legacy blocked open: {error:?}"));
        assert_eq!(rows(&blocked), seeded, "count={count}");
        assert_eq!(
            blocked
                .test_connection()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0)),
            Ok(3)
        );
        assert!(matches!(
            blocked.into_ready(&stamp("2026-08-22T10:01:01Z")),
            Err(StoreError::RecoveryRequired)
        ));

        let mut recovering = RecoveringStore::open(
            &fixture.paths,
            &fixture.profile.installation,
            &stamp("2026-08-22T10:02:00Z"),
        )
        .unwrap_or_else(|error| panic!("legacy recovery open: {error:?}"));
        let result = recovering
            .terminalize_prior_generation(
                &lease_id,
                old_version,
                &stamp("2026-08-22T10:02:01.123456789Z"),
            )
            .unwrap_or_else(|error| panic!("legacy release count={count}: {error:?}"));
        assert_eq!(result.status(), LeaseStatus::Refused);
        assert_eq!(result.released_reservations(), count as u64);
        assert_eq!(result.row_version(), old_version + 1);
        for row in rows(&recovering) {
            assert_eq!(row.4, "RELEASED");
            assert_eq!(row.5.as_deref(), Some("2026-08-22T10:02:01.123456789Z"));
        }
        assert_eq!(
            recovering.test_connection().query_row(
                "SELECT count(*) FROM audit_events WHERE lease_id = ?1",
                [lease_id.as_str()],
                |row| row.get::<_, i64>(0),
            ),
            Ok(audit_count)
        );
        let released = rows(&recovering);
        assert!(matches!(
            recovering.terminalize_prior_generation(
                &lease_id,
                old_version,
                &stamp("2026-08-22T10:02:02Z")
            ),
            Err(StoreError::ConcurrentMutation)
        ));
        assert_eq!(rows(&recovering), released);
        let retry = recovering
            .terminalize_prior_generation(
                &lease_id,
                old_version + 1,
                &stamp("2026-08-22T10:02:03Z"),
            )
            .unwrap_or_else(|error| panic!("legacy exact retry: {error:?}"));
        assert!(!retry.changed());
        assert_eq!(retry.released_reservations(), 0);
        assert_eq!(retry.row_version(), old_version + 1);
        assert_eq!(rows(&recovering), released);
        recovering
            .into_ready(&stamp("2026-08-22T10:02:04Z"))
            .unwrap_or_else(|error| panic!("legacy ready count={count}: {error:?}"));
    }
}
