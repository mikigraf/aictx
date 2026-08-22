use std::{fmt::Debug, fs, path::PathBuf, str::FromStr};

use rusqlite::Connection;
use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{CallerSubject, HostIdentity, IdentityLeaseRequest, LeaseStatus, UtcTimestamp},
        lease::{ClockSample, MonotonicMoment},
        store::{ReadyStore, RecoveringStore, StoreError},
    },
    config::AppPaths,
    model::InstallationUid,
};

use super::load_tests::resolved_status;
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

    fn ready(&self) -> ReadyStore {
        RecoveringStore::open(
            &self.paths,
            &self.installation,
            &stamp("2026-08-22T10:00:00Z"),
        )
        .unwrap_or_else(|error| panic!("open: {error:?}"))
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

fn seed_requested(ready: &mut ReadyStore, request: &IdentityLeaseRequest, monotonic: u128) {
    let clock = ClockSample::new(
        stamp("2026-08-22T10:00:02Z"),
        MonotonicMoment::from_nanoseconds(monotonic),
        ready.service_clock_generation(),
    );
    ready
        .begin_acquire(
            request,
            &parsed::<CallerSubject>("caller:local-controller"),
            &parsed::<HostIdentity>("host:runner-01"),
            &clock,
        )
        .unwrap_or_else(|error| panic!("seed request: {error:?}"));
}

fn downgrade_to_frozen_v1(connection: &Connection) {
    connection
        .execute_batch(
            "DROP TRIGGER capacity_reservations_insert_held;
             DROP TRIGGER capacity_reservations_transition_only;
             DROP TRIGGER capacity_reservations_delete_released;
             DROP INDEX capacity_reservations_lease_state;
             DROP INDEX lease_processes_lease_state;
             DELETE FROM schema_migrations WHERE version = 3;
             DROP TRIGGER lease_runtime_clocks_advance_only;
             DROP TRIGGER leases_runtime_clock_identity_immutable;
             DROP TRIGGER leases_runtime_clock_insert;
             DROP INDEX lease_runtime_clocks_generation;
             DROP TABLE lease_runtime_clocks;
             DROP INDEX leases_generation_identity;
             DELETE FROM schema_migrations WHERE version = 2;
             PRAGMA user_version = 1;",
        )
        .unwrap_or_else(|error| panic!("downgrade fixture: {error}"));
    assert_eq!(scalar::<i64>(connection, "PRAGMA user_version"), 1);
    assert_eq!(
        scalar::<i64>(connection, "SELECT count(*) FROM schema_migrations"),
        1
    );
    assert_eq!(
        scalar::<i64>(
            connection,
            "SELECT count(*) FROM sqlite_schema
             WHERE name LIKE 'lease_runtime_clock%' OR name = 'leases_generation_identity'"
        ),
        0
    );
}

pub(super) fn downgrade_to_frozen_v2(connection: &Connection) {
    connection
        .execute_batch(
            "DROP TRIGGER capacity_reservations_insert_held;
             DROP TRIGGER capacity_reservations_transition_only;
             DROP TRIGGER capacity_reservations_delete_released;
             DROP INDEX capacity_reservations_lease_state;
             DROP INDEX lease_processes_lease_state;
             DELETE FROM schema_migrations WHERE version = 3;
             PRAGMA user_version = 2;",
        )
        .unwrap_or_else(|error| panic!("downgrade v2 fixture: {error}"));
}

fn scalar<T: rusqlite::types::FromSql>(connection: &Connection, sql: &str) -> T {
    connection
        .query_row(sql, [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("query scalar: {error}"))
}

fn sidecar(path: PathBuf, suffix: &str) -> PathBuf {
    let mut value = path.into_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[test]
fn populated_frozen_v1_migrates_atomically_and_runtime_clock_guards_hold() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let issued = u128::from(u64::MAX) + 41;
    seed_requested(&mut ready, &fixture.request(), issued);
    downgrade_to_frozen_v1(ready.test_connection());
    drop(ready);

    let recovering = RecoveringStore::open(
        &fixture.paths,
        &fixture.installation,
        &stamp("2026-08-22T10:01:00Z"),
    )
    .unwrap_or_else(|error| panic!("migrate v1: {error:?}"));
    drop(recovering);

    let connection = Connection::open(fixture.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("inspect current schema: {error}"));
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap_or_else(|error| panic!("foreign keys: {error}"));
    assert_eq!(scalar::<i64>(&connection, "PRAGMA user_version"), 3);
    assert_eq!(
        scalar::<i64>(&connection, "SELECT count(*) FROM schema_migrations"),
        3
    );
    assert_eq!(
        scalar::<i64>(&connection, "SELECT count(*) FROM lease_runtime_clocks"),
        1
    );
    let (stored_issued, high_water, anchor, row_version) = connection
        .query_row(
            "SELECT l.issued_monotonic_nanos, c.monotonic_high_water_nanos,
                    c.interval_anchor_at_utc, c.row_version
             FROM leases l JOIN lease_runtime_clocks c USING (lease_id)",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("clock row: {error}"));
    assert_eq!(stored_issued, issued.to_be_bytes());
    assert_eq!(high_water, stored_issued);
    assert_eq!(anchor, None);
    assert_eq!(row_version, 1);

    connection
        .execute(
            "UPDATE lease_runtime_clocks
             SET monotonic_high_water_nanos = monotonic_high_water_nanos,
                 row_version = row_version + 1",
            [],
        )
        .unwrap_or_else(|error| panic!("equal observation: {error}"));
    let above_u64 = (u128::from(u64::MAX) + 100).to_be_bytes();
    let next = (u128::from(u64::MAX) + 101).to_be_bytes();
    for value in [&above_u64, &next] {
        connection
            .execute(
                "UPDATE lease_runtime_clocks
                 SET monotonic_high_water_nanos = ?1, row_version = row_version + 1",
                [value.as_slice()],
            )
            .unwrap_or_else(|error| panic!("advance high water: {error}"));
    }
    assert!(
        connection
            .execute(
                "UPDATE lease_runtime_clocks
                 SET monotonic_high_water_nanos = ?1, row_version = row_version + 1",
                [above_u64.as_slice()],
            )
            .is_err()
    );
    assert_eq!(
        scalar::<Vec<u8>>(
            &connection,
            "SELECT monotonic_high_water_nanos FROM lease_runtime_clocks"
        ),
        next
    );

    let other_generation = scalar::<i64>(
        &connection,
        "SELECT max(service_generation) FROM service_generations",
    );
    assert!(
        connection
            .execute(
                "INSERT INTO lease_runtime_clocks (
                    lease_id, service_generation, monotonic_high_water_nanos, row_version
                 ) SELECT lease_id, ?1, issued_monotonic_nanos, 1 FROM leases",
                [other_generation],
            )
            .is_err()
    );

    connection
        .execute_batch(
            "DELETE FROM audit_events;
             DELETE FROM leases;",
        )
        .unwrap_or_else(|error| panic!("prune parent: {error}"));
    assert_eq!(
        scalar::<i64>(&connection, "SELECT count(*) FROM lease_runtime_clocks"),
        0
    );
}

#[test]
fn failure_after_v3_ddl_rolls_the_entire_migration_back() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    seed_requested(&mut ready, &fixture.request(), 10);
    downgrade_to_frozen_v2(ready.test_connection());
    ready
        .test_connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap_or_else(|error| panic!("checkpoint before failure: {error}"));
    let database = fixture.paths.automation_lease_store();
    let before = fs::read(&database).unwrap_or_else(|error| panic!("read before: {error}"));

    ready
        .test_connection()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_v3_migration
             BEFORE INSERT ON main.schema_migrations WHEN NEW.version = 3
             BEGIN SELECT RAISE(ABORT, 'injected v3 migration failure'); END;",
        )
        .unwrap_or_else(|error| panic!("install migration-row failure: {error}"));
    let installation = fixture.installation.clone();
    assert_eq!(
        super::migrations::test_apply_v3(
            ready.test_connection_mut(),
            &installation,
            &stamp("2026-08-22T10:01:00Z"),
        ),
        Err(StoreError::DatabaseUnavailable)
    );
    ready
        .test_connection()
        .execute_batch("DROP TRIGGER temp.fail_v3_migration;")
        .unwrap_or_else(|error| panic!("drop migration failure: {error}"));
    assert_eq!(
        scalar::<i64>(ready.test_connection(), "PRAGMA user_version"),
        2
    );
    assert_eq!(
        scalar::<i64>(
            ready.test_connection(),
            "SELECT count(*) FROM sqlite_schema
             WHERE name IN (
                'capacity_reservations_lease_state',
                'lease_processes_lease_state',
                'capacity_reservations_insert_held',
                'capacity_reservations_transition_only',
                'capacity_reservations_delete_released'
             )"
        ),
        0
    );
    assert_eq!(
        scalar::<i64>(
            ready.test_connection(),
            "SELECT count(*) FROM schema_migrations"
        ),
        2
    );
    drop(ready);
    let after = fs::read(&database).unwrap_or_else(|error| panic!("read after: {error}"));
    assert_eq!(after, before);
    assert!(!sidecar(database.clone(), "-journal").exists());
    assert!(!sidecar(database.clone(), "-wal").exists());
    assert!(!sidecar(database, "-shm").exists());
}

#[test]
fn resolved_v1_without_a_trustworthy_high_water_rolls_back_byte_identically() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    seed_requested(&mut ready, &fixture.request(), 10);
    resolved_status(ready.test_connection(), LeaseStatus::Active);
    downgrade_to_frozen_v1(ready.test_connection());
    drop(ready);

    let database = fixture.paths.automation_lease_store();
    let before = fs::read(&database).unwrap_or_else(|error| panic!("read before: {error}"));
    let before_generations = {
        let connection =
            Connection::open(&database).unwrap_or_else(|error| panic!("inspect before: {error}"));
        scalar::<i64>(&connection, "SELECT count(*) FROM service_generations")
    };
    assert!(matches!(
        RecoveringStore::open(
            &fixture.paths,
            &fixture.installation,
            &stamp("2026-08-22T10:01:00Z")
        ),
        Err(StoreError::IntegrityCheckFailed)
    ));
    let after = fs::read(&database).unwrap_or_else(|error| panic!("read after: {error}"));
    assert_eq!(after, before);
    for suffix in ["-journal", "-wal", "-shm"] {
        assert!(!sidecar(database.clone(), suffix).exists(), "{suffix}");
    }
    let connection =
        Connection::open(&database).unwrap_or_else(|error| panic!("inspect rollback: {error}"));
    assert_eq!(scalar::<i64>(&connection, "PRAGMA user_version"), 1);
    assert_eq!(
        scalar::<i64>(&connection, "SELECT count(*) FROM schema_migrations"),
        1
    );
    assert_eq!(
        scalar::<i64>(&connection, "SELECT count(*) FROM service_generations"),
        before_generations
    );
    assert_eq!(
        scalar::<i64>(
            &connection,
            "SELECT count(*) FROM sqlite_schema WHERE name = 'lease_runtime_clocks'"
        ),
        0
    );
}

#[test]
fn invalid_frozen_v1_is_qualified_before_the_first_v2_write() {
    for corruption in ["installation", "checksum", "schema"] {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        seed_requested(&mut ready, &fixture.request(), 10);
        downgrade_to_frozen_v1(ready.test_connection());
        match corruption {
            "checksum" => {
                ready
                    .test_connection()
                    .execute(
                        "UPDATE schema_migrations SET checksum = ?1 WHERE version = 1",
                        [format!("sha256:{}", "0".repeat(64))],
                    )
                    .unwrap_or_else(|error| panic!("checksum fixture: {error}"));
            }
            "schema" => ready
                .test_connection()
                .execute_batch("CREATE VIEW unexpected_v1_view AS SELECT 1 AS value;")
                .unwrap_or_else(|error| panic!("schema fixture: {error}")),
            "installation" => {}
            _ => unreachable!(),
        }
        drop(ready);
        let database = fixture.paths.automation_lease_store();
        let before = fs::read(&database).unwrap_or_else(|error| panic!("read before: {error}"));
        let attempted_installation = if corruption == "installation" {
            InstallationUid::generate().unwrap_or_else(|error| panic!("other uid: {error}"))
        } else {
            fixture.installation.clone()
        };
        let result = RecoveringStore::open(
            &fixture.paths,
            &attempted_installation,
            &stamp("2026-08-22T10:01:00Z"),
        );
        assert!(
            matches!(
                (corruption, result),
                ("installation", Err(StoreError::UnsafeStorage))
                    | ("checksum", Err(StoreError::MigrationChecksumMismatch))
                    | ("schema", Err(StoreError::IntegrityCheckFailed))
            ),
            "{corruption}"
        );
        assert_eq!(
            fs::read(&database).unwrap_or_else(|error| panic!("read after: {error}")),
            before,
            "{corruption}"
        );
        for suffix in ["-journal", "-wal", "-shm"] {
            assert!(
                !sidecar(database.clone(), suffix).exists(),
                "{corruption} {suffix}"
            );
        }
    }
}
