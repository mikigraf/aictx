use std::{fmt::Debug, fs, path::PathBuf, str::FromStr};

use rusqlite::Connection;
use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            CallerSubject, HostIdentity, IdentityLeaseRequest, RefusalCode, Sha256Digest,
            UtcTimestamp,
        },
        lease::{ClockSample, MonotonicMoment},
        store::{PersistedAcquireOutcome, ReadyStore, RecoveringStore, StoreError},
    },
    config::{AppPaths, ensure_secure_directory},
    model::InstallationUid,
};

struct Fixture {
    _temporary: TempDir,
    paths: AppPaths,
    installation: InstallationUid,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temporary
            .path()
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical tempdir: {error}"));
        Self {
            paths: AppPaths::for_root(root.join("ctxlane")),
            installation: InstallationUid::generate()
                .unwrap_or_else(|error| panic!("installation: {error}")),
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
    serde_json::from_str(include_str!(
        "../../../schemas/examples/identity-lease-request.v1.json"
    ))
    .unwrap_or_else(|error| panic!("request fixture: {error}"))
}

fn caller(value: &str) -> CallerSubject {
    parsed(value)
}

fn host(value: &str) -> HostIdentity {
    parsed(value)
}

fn clock(store: &ReadyStore, wall: &str, monotonic: u128) -> ClockSample {
    ClockSample::new(
        stamp(wall),
        MonotonicMoment::from_nanoseconds(monotonic),
        store.service_clock_generation(),
    )
}

fn scalar<T: rusqlite::types::FromSql>(connection: &Connection, sql: &str) -> T {
    connection
        .query_row(sql, [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("query scalar: {error}"))
}

fn authority_row_counts(connection: &Connection) -> (i64, i64, i64) {
    (
        scalar(connection, "SELECT count(*) FROM lease_requests"),
        scalar(connection, "SELECT count(*) FROM leases"),
        scalar(connection, "SELECT count(*) FROM audit_events"),
    )
}

#[test]
fn schema_settings_integrity_and_extension_boundary_are_enforced() {
    let fixture = Fixture::new();
    let ready = fixture.ready();
    let connection = ready.test_connection();

    assert_eq!(
        scalar::<i64>(connection, "PRAGMA application_id"),
        0x4354_584c
    );
    assert_eq!(scalar::<i64>(connection, "PRAGMA user_version"), 1);
    assert_eq!(scalar::<i64>(connection, "PRAGMA foreign_keys"), 1);
    assert_eq!(scalar::<String>(connection, "PRAGMA journal_mode"), "wal");
    assert_eq!(scalar::<i64>(connection, "PRAGMA synchronous"), 2);
    assert_eq!(scalar::<i64>(connection, "PRAGMA trusted_schema"), 0);
    assert_eq!(scalar::<i64>(connection, "PRAGMA fullfsync"), 1);
    assert_eq!(scalar::<i64>(connection, "PRAGMA checkpoint_fullfsync"), 1);
    assert_eq!(scalar::<i64>(connection, "PRAGMA busy_timeout"), 5_000);
    assert_eq!(scalar::<String>(connection, "PRAGMA quick_check"), "ok");
    assert_eq!(
        scalar::<i64>(connection, "SELECT count(*) FROM pragma_foreign_key_check"),
        0
    );
    assert_eq!(
        scalar::<i64>(
            connection,
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name IN (
                'store_metadata', 'schema_migrations', 'service_generations', 'lease_requests',
                'leases', 'capacity_reservations', 'lease_processes', 'audit_events')"
        ),
        8
    );
    assert!(
        connection
            .execute(
                "INSERT INTO lease_requests (
                    request_record_id, client_request_id, canonical_authority_digest,
                    canonical_request, authenticated_caller, host_identity,
                    authorization_expires_at_utc, authorization_expires_at_seconds,
                    authorization_expires_at_nanos, replay_retain_until_utc,
                    replay_retain_until_seconds, replay_retain_until_nanos,
                    recorded_at_utc, recorded_at_seconds, recorded_at_nanos
                 ) VALUES (
                    'request_00000000000000000000000000', 'too-short-retention',
                    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    x'7b7d', 'caller:test', 'host:test',
                    '2026-08-22T11:00:00Z', 4600, 0,
                    '2026-08-22T11:00:00Z', 4600, 0,
                    '2026-08-22T10:00:00Z', 1000, 0
                 )",
                [],
            )
            .is_err()
    );

    for sql in [
        "SELECT load_extension('forbidden')",
        "SELECT load_extension('forbidden', 'entry')",
    ] {
        let error = connection
            .query_row(sql, [], |row| row.get::<_, String>(0))
            .err()
            .unwrap_or_else(|| panic!("load_extension unexpectedly succeeded"));
        assert!(matches!(
            error,
            rusqlite::Error::SqliteFailure(_, Some(ref message))
                if message == "ctxlane extension loading disabled"
        ));
    }
    let attach = connection
        .execute("ATTACH DATABASE ':memory:' AS forbidden", [])
        .err()
        .unwrap_or_else(|| panic!("ATTACH unexpectedly succeeded"));
    assert!(matches!(
        attach,
        rusqlite::Error::SqliteFailure(details, _)
            if details.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
                && details.extended_code == 23
    ));
    let detach = connection
        .execute("DETACH DATABASE forbidden", [])
        .err()
        .unwrap_or_else(|| panic!("DETACH unexpectedly succeeded"));
    assert!(matches!(
        detach,
        rusqlite::Error::SqliteFailure(details, _)
            if details.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
                && details.extended_code == 23
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let directory_mode = fs::metadata(fixture.paths.automation_state_dir())
            .unwrap_or_else(|error| panic!("automation metadata: {error}"))
            .permissions()
            .mode();
        let database_mode = fs::metadata(fixture.paths.automation_lease_store())
            .unwrap_or_else(|error| panic!("database metadata: {error}"))
            .permissions()
            .mode();
        assert_eq!(directory_mode & 0o077, 0);
        assert_eq!(database_mode & 0o077, 0);
    }
}

#[test]
fn lifetime_lock_survives_typestate_and_empty_generation_reopens() {
    let fixture = Fixture::new();
    let recovering = fixture.recovering("2026-08-22T10:00:00Z");
    assert_eq!(recovering.service_clock_generation().get(), 1);
    assert!(matches!(
        RecoveringStore::open(
            &fixture.paths,
            &fixture.installation,
            &stamp("2026-08-22T10:00:01Z")
        ),
        Err(StoreError::ServiceBusy)
    ));
    drop(recovering);

    let second = fixture.recovering("2026-08-22T10:00:02Z");
    assert_eq!(second.service_clock_generation().get(), 2);
    let ready = second
        .into_ready(&stamp("2026-08-22T10:00:03Z"))
        .unwrap_or_else(|error| panic!("empty recovery: {error:?}"));
    assert!(matches!(
        RecoveringStore::open(
            &fixture.paths,
            &fixture.installation,
            &stamp("2026-08-22T10:00:04Z")
        ),
        Err(StoreError::ServiceBusy)
    ));
    drop(ready);
}

#[test]
fn exact_replay_preserves_original_issuance_and_conflicts_disclose_nothing() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = request();
    let caller_subject = caller("caller:local-controller");
    let host_identity = host("host:runner-01");
    let first_clock = clock(&ready, "2026-08-22T10:00:02Z", 42);
    let first = ready
        .begin_acquire(&request, &caller_subject, &host_identity, &first_clock)
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    assert!(!first.replayed());
    let original = first.outcome().clone();
    assert_eq!(
        original.issuance().issued_at().as_str(),
        "2026-08-22T10:00:02Z"
    );
    assert_eq!(original.issuance().monotonic().as_nanoseconds(), 42);

    let later_clock = clock(&ready, "2026-08-22T11:00:00Z", 9_999);
    let replay = ready
        .begin_acquire(&request, &caller_subject, &host_identity, &later_clock)
        .unwrap_or_else(|error| panic!("replay: {error:?}"));
    assert!(replay.replayed());
    assert_eq!(replay.outcome(), &original);
    assert_eq!(
        original.issuance().clock_sample().service_generation(),
        ready.service_clock_generation()
    );
    let persisted_counts = authority_row_counts(ready.test_connection());

    let mut changed = request.clone();
    changed.policy_digest = Some(parsed::<Sha256Digest>(
        "sha256:bb42590da6d8c5c0c0103b67572979c60d3c44a5a5a2cfa74f469e8cd7cf3d12",
    ));
    for result in [
        ready.begin_acquire(&changed, &caller_subject, &host_identity, &later_clock),
        ready.begin_acquire(
            &request,
            &caller("caller:other-controller"),
            &host_identity,
            &later_clock,
        ),
        ready.begin_acquire(
            &request,
            &caller_subject,
            &host("host:runner-02"),
            &later_clock,
        ),
    ] {
        assert_eq!(result, Err(StoreError::IdempotencyConflict));
        let conflict = result
            .err()
            .unwrap_or_else(|| panic!("conflicting replay unexpectedly succeeded"));
        let rendered = format!("{conflict:?}");
        assert!(!rendered.contains(original.lease_id().as_str()));
        assert_eq!(
            authority_row_counts(ready.test_connection()),
            persisted_counts
        );
    }
}

#[test]
fn wrong_clock_generation_is_rejected_before_any_write() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let wrong_generation = crate::automation::lease::ServiceClockGeneration::from_value(
        ready.service_clock_generation().get() + 1,
    );
    let wrong_clock = ClockSample::new(
        stamp("2026-08-22T10:00:02Z"),
        MonotonicMoment::from_nanoseconds(9),
        wrong_generation,
    );
    assert_eq!(
        ready.begin_acquire(
            &request(),
            &caller("caller:local-controller"),
            &host("host:runner-01"),
            &wrong_clock,
        ),
        Err(StoreError::InvalidRequest)
    );
    assert_eq!(authority_row_counts(ready.test_connection()), (0, 0, 0));
}

#[test]
fn refusal_replays_with_original_issuance_and_monotonic_audit_sequence() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = request();
    let caller = caller("caller:local-controller");
    let host = host("host:runner-01");
    let issuance = clock(&ready, "2026-08-22T10:00:02Z", 77);
    let first = ready
        .begin_acquire(&request, &caller, &host, &issuance)
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    let lease_id = first.outcome().lease_id().clone();
    ready
        .refuse_requested(
            &lease_id,
            RefusalCode::ProfileNotReady,
            &stamp("2026-08-22T10:00:03Z"),
        )
        .unwrap_or_else(|error| panic!("refuse: {error:?}"));
    let replay = ready
        .begin_acquire(
            &request,
            &caller,
            &host,
            &clock(&ready, "2026-08-22T12:00:00Z", 5_000),
        )
        .unwrap_or_else(|error| panic!("refused replay: {error:?}"));
    assert!(matches!(
        replay.outcome(),
        PersistedAcquireOutcome::Refused {
            refusal_code: RefusalCode::ProfileNotReady,
            ..
        }
    ));
    assert_eq!(replay.outcome().issuance().monotonic().as_nanoseconds(), 77);
    assert_eq!(
        scalar::<i64>(
            ready.test_connection(),
            "SELECT count(*) FROM audit_events WHERE sequence IN (1, 2)"
        ),
        2
    );
    assert_eq!(
        scalar::<i64>(
            ready.test_connection(),
            "SELECT next_audit_sequence FROM leases"
        ),
        3
    );
    assert_eq!(
        ready.refuse_requested(
            &lease_id,
            RefusalCode::ProfileNotReady,
            &stamp("2026-08-22T10:00:04Z")
        ),
        Err(StoreError::InvalidTransition)
    );

    drop(ready);
    let mut reopened = fixture
        .recovering("2026-08-22T10:00:05Z")
        .into_ready(&stamp("2026-08-22T10:00:06Z"))
        .unwrap_or_else(|error| panic!("terminal-only reopen: {error:?}"));
    let replay = reopened
        .begin_acquire(
            &request,
            &caller,
            &host,
            &clock(&reopened, "2026-08-22T12:30:00Z", 8_000),
        )
        .unwrap_or_else(|error| panic!("reopen replay: {error:?}"));
    assert!(replay.replayed());
    assert_eq!(replay.outcome().issuance().monotonic().as_nanoseconds(), 77);
}

#[test]
fn refusal_audit_failure_rolls_back_the_terminal_transition() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let issuance = clock(&ready, "2026-08-22T10:00:02Z", 12);
    let begun = ready
        .begin_acquire(
            &request(),
            &caller("caller:local-controller"),
            &host("host:runner-01"),
            &issuance,
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    ready
        .test_connection()
        .execute_batch(
            "CREATE TRIGGER fail_refused_audit BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'lease.refused'
             BEGIN SELECT RAISE(ABORT, 'injected refusal audit failure'); END;",
        )
        .unwrap_or_else(|error| panic!("failure trigger: {error}"));
    assert_eq!(
        ready.refuse_requested(
            begun.outcome().lease_id(),
            RefusalCode::ProfileNotReady,
            &stamp("2026-08-22T10:00:03Z")
        ),
        Err(StoreError::DatabaseUnavailable)
    );
    assert_eq!(
        scalar::<String>(ready.test_connection(), "SELECT status FROM leases"),
        "REQUESTED"
    );
    assert_eq!(
        scalar::<i64>(
            ready.test_connection(),
            "SELECT next_audit_sequence FROM leases"
        ),
        2
    );
    assert_eq!(
        scalar::<i64>(ready.test_connection(), "SELECT count(*) FROM audit_events"),
        1
    );
}

#[test]
fn audit_failure_rolls_back_request_and_lease_atomically() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    ready
        .test_connection()
        .execute_batch(
            "CREATE TRIGGER fail_requested_audit BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'lease.requested'
             BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
        )
        .unwrap_or_else(|error| panic!("failure trigger: {error}"));
    let result = ready.begin_acquire(
        &request(),
        &caller("caller:local-controller"),
        &host("host:runner-01"),
        &clock(&ready, "2026-08-22T10:00:02Z", 1),
    );
    assert_eq!(result, Err(StoreError::DatabaseUnavailable));
    for table in ["lease_requests", "leases", "audit_events"] {
        let query = format!("SELECT count(*) FROM {table}");
        assert_eq!(scalar::<i64>(ready.test_connection(), &query), 0);
    }
}

#[test]
fn requested_state_survives_crash_and_blocks_ready_until_recovery_exists() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let issuance = clock(&ready, "2026-08-22T10:00:02Z", 1);
    ready
        .begin_acquire(
            &request(),
            &caller("caller:local-controller"),
            &host("host:runner-01"),
            &issuance,
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    drop(ready);

    let recovering = fixture.recovering("2026-08-22T10:01:00Z");
    assert!(matches!(
        recovering.into_ready(&stamp("2026-08-22T10:01:01Z")),
        Err(StoreError::RecoveryRequired)
    ));
    let connection = Connection::open(fixture.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("inspect requested: {error}"));
    assert_eq!(
        scalar::<String>(&connection, "SELECT status FROM leases"),
        "REQUESTED"
    );
}

#[test]
fn error_is_live_and_resolved_handles_remain_bound_through_terminal_state() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let issuance = clock(&ready, "2026-08-22T10:00:02Z", 88);
    ready
        .begin_acquire(
            &request(),
            &caller("caller:local-controller"),
            &host("host:runner-01"),
            &issuance,
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    let connection = ready.test_connection();
    connection
        .execute_batch(
            "UPDATE leases SET
                status = 'ACTIVE',
                effective_policy_digest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                fencing_generation = 1,
                clock_generation = service_generation,
                execution_handle = 'exec_00000000000000000000000000',
                principal_ref = 'principal:resolved',
                workspace_ref = 'chatgpt-workspace:tenant',
                auth_mode = 'wif', isolation = 'credential-isolated',
                activated_at_utc = '2026-08-22T10:00:03Z',
                activated_at_seconds = issued_at_seconds + 1, activated_at_nanos = 0,
                expires_at_utc = '2026-08-22T11:00:02Z',
                expires_at_seconds = issued_at_seconds + 3600, expires_at_nanos = 0,
                expires_monotonic_nanos = zeroblob(16),
                maximum_expires_at_utc = '2026-08-22T12:00:02Z',
                maximum_expires_at_seconds = issued_at_seconds + 7200,
                maximum_expires_at_nanos = 0,
                maximum_expires_monotonic_nanos = zeroblob(16);
             INSERT INTO lease_processes (
                process_id, lease_id, service_generation, state, execution_handle,
                observed_fencing_generation, launch_intent_at_utc,
                launch_intent_at_seconds, launch_intent_at_nanos
             ) SELECT
                'process_00000000000000000000000000', lease_id, service_generation,
                'LAUNCH_INTENT', execution_handle, 1,
                '2026-08-22T10:00:03Z', issued_at_seconds + 1, 0
             FROM leases;
             UPDATE leases SET status = 'ERROR', reason_code = 'internal-error';",
        )
        .unwrap_or_else(|error| panic!("resolved error setup: {error}"));
    assert_eq!(
        scalar::<String>(connection, "SELECT status FROM leases"),
        "ERROR"
    );
    assert_eq!(
        scalar::<String>(connection, "SELECT execution_handle FROM leases"),
        "exec_00000000000000000000000000"
    );
    assert_eq!(
        scalar::<i64>(
            connection,
            "SELECT count(*) FROM lease_processes p JOIN leases l
             ON (p.lease_id, p.execution_handle) = (l.lease_id, l.execution_handle)"
        ),
        1
    );
    assert!(
        connection
            .execute_batch(
                "UPDATE leases SET terminal_at_utc = '2026-08-22T10:00:04Z',
                terminal_at_seconds = issued_at_seconds + 2, terminal_at_nanos = 0;"
            )
            .is_err()
    );
    connection
        .execute_batch(
            "UPDATE leases SET status = 'REVOKED', reason_code = 'service-recovery',
                terminal_at_utc = '2026-08-22T10:00:05Z',
                terminal_at_seconds = issued_at_seconds + 3, terminal_at_nanos = 0;
             UPDATE lease_processes SET state = 'EXITED',
                started_at_utc = '2026-08-22T10:00:03Z',
                started_at_seconds = launch_intent_at_seconds, started_at_nanos = 0,
                ended_at_utc = '2026-08-22T10:00:05Z',
                ended_at_seconds = launch_intent_at_seconds + 2, ended_at_nanos = 0;",
        )
        .unwrap_or_else(|error| panic!("terminal transition: {error}"));
    assert_eq!(
        scalar::<String>(connection, "SELECT execution_handle FROM leases"),
        "exec_00000000000000000000000000"
    );
    drop(ready);
    fixture
        .recovering("2026-08-22T10:01:00Z")
        .into_ready(&stamp("2026-08-22T10:01:01Z"))
        .unwrap_or_else(|error| panic!("terminal recovery: {error:?}"));
}

#[test]
fn replay_retention_is_at_least_seven_days() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let issuance = clock(&ready, "2026-08-22T10:00:02Z", 1);
    ready
        .begin_acquire(
            &request(),
            &caller("caller:local-controller"),
            &host("host:runner-01"),
            &issuance,
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    assert_eq!(
        scalar::<String>(
            ready.test_connection(),
            "SELECT replay_retain_until_utc FROM lease_requests"
        ),
        "2026-08-29T10:00:02Z"
    );

    let long_fixture = Fixture::new();
    let mut long_ready = long_fixture.ready();
    let mut long_request = request();
    long_request.work_order_authorization.expires_at = stamp("2026-09-30T12:34:56Z");
    let issuance = clock(&long_ready, "2026-08-22T10:00:02Z", 2);
    long_ready
        .begin_acquire(
            &long_request,
            &caller("caller:local-controller"),
            &host("host:runner-01"),
            &issuance,
        )
        .unwrap_or_else(|error| panic!("long authorization begin: {error:?}"));
    assert_eq!(
        scalar::<String>(
            long_ready.test_connection(),
            "SELECT replay_retain_until_utc FROM lease_requests"
        ),
        "2026-09-30T12:34:56Z"
    );
}

#[test]
fn installation_schema_and_migration_identity_fail_closed() {
    let fixture = Fixture::new();
    drop(fixture.ready());
    let other = InstallationUid::generate().unwrap_or_else(|error| panic!("uid: {error}"));
    assert!(matches!(
        RecoveringStore::open(&fixture.paths, &other, &stamp("2026-08-22T11:00:00Z")),
        Err(StoreError::InstallationMismatch)
    ));

    let database = fixture.paths.automation_lease_store();
    let connection =
        Connection::open(&database).unwrap_or_else(|error| panic!("raw open: {error}"));
    connection
        .execute(
            "UPDATE schema_migrations SET checksum = ?1",
            [format!("sha256:{}", "0".repeat(64))],
        )
        .unwrap_or_else(|error| panic!("tamper checksum: {error}"));
    drop(connection);
    assert!(matches!(
        RecoveringStore::open(
            &fixture.paths,
            &fixture.installation,
            &stamp("2026-08-22T11:00:01Z")
        ),
        Err(StoreError::MigrationChecksumMismatch)
    ));

    let future = Fixture::new();
    drop(future.ready());
    let connection = Connection::open(future.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("future open: {error}"));
    connection
        .pragma_update(None, "user_version", 2)
        .unwrap_or_else(|error| panic!("future version: {error}"));
    drop(connection);
    assert!(matches!(
        RecoveringStore::open(
            &future.paths,
            &future.installation,
            &stamp("2026-08-22T11:00:02Z")
        ),
        Err(StoreError::UnsupportedSchema)
    ));
}

#[test]
fn pristine_precreated_database_is_retryable() {
    let fixture = Fixture::new();
    ensure_secure_directory(&fixture.paths.automation_state_dir())
        .unwrap_or_else(|error| panic!("automation dir: {error}"));
    let database = fixture.paths.automation_lease_store();
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&database)
        .unwrap_or_else(|error| panic!("precreate database: {error}"));
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("database permissions: {error}"));
    }
    let ready = fixture.ready();
    assert_eq!(ready.service_clock_generation().get(), 1);
}

#[test]
fn all_store_errors_are_stable_and_redacted() {
    let canary = "CREDENTIAL_CANARY_/private/lease-store.sqlite3";
    let errors = [
        StoreError::UnsupportedPlatform,
        StoreError::ServiceBusy,
        StoreError::UnsafeStorage,
        StoreError::DatabaseUnavailable,
        StoreError::DatabaseIdentityMismatch,
        StoreError::InstallationMismatch,
        StoreError::UnsupportedSchema,
        StoreError::MigrationChecksumMismatch,
        StoreError::IntegrityCheckFailed,
        StoreError::RecoveryRequired,
        StoreError::InvalidRequest,
        StoreError::IdempotencyConflict,
        StoreError::EntropyUnavailable,
        StoreError::IdentifierCollision,
        StoreError::InvalidTransition,
    ];
    for error in errors {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(canary));
        assert!(!rendered.contains("/private/"));
        assert!(!rendered.to_ascii_lowercase().contains("sqlite"));
        assert!(!rendered.contains("SELECT"));
    }
}

fn sidecar(path: PathBuf, suffix: &str) -> PathBuf {
    let mut value = path.into_os_string();
    value.push(suffix);
    PathBuf::from(value)
}
