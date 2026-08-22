use std::{fmt::Debug, str::FromStr};

use rusqlite::{Connection, params};
use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{CallerSubject, HostIdentity, IdentityLeaseRequest, RefusalCode, UtcTimestamp},
        lease::{ClockSample, MonotonicMoment},
        store::{PersistedAcquireOutcome, ReadyStore, RecoveringStore, StoreError},
    },
    config::AppPaths,
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

fn caller() -> CallerSubject {
    parsed("caller:local-controller")
}

fn host() -> HostIdentity {
    parsed("host:runner-01")
}

fn clock(store: &ReadyStore, wall: &str, monotonic: u128) -> ClockSample {
    ClockSample::new(
        stamp(wall),
        MonotonicMoment::from_nanoseconds(monotonic),
        store.service_clock_generation(),
    )
}

fn seed_requested(ready: &mut ReadyStore) {
    let issuance = clock(ready, "2026-08-22T10:00:02Z", 1);
    ready
        .begin_acquire(&request(), &caller(), &host(), &issuance)
        .unwrap_or_else(|error| panic!("seed request: {error:?}"));
}

fn set_resolved_status(connection: &Connection, terminal: bool) {
    let (status, reason, terminal_wire, terminal_seconds, terminal_nanos) = if terminal {
        (
            "REVOKED",
            "service-recovery",
            Some("2026-08-22T10:00:05Z"),
            Some(1_787_392_805_i64),
            Some(0_i64),
        )
    } else {
        ("ERROR", "internal-error", None, None, None)
    };
    let changed = connection
        .execute(
            "UPDATE leases SET
                status = ?1, reason_code = ?2,
                effective_policy_digest =
                    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                fencing_generation = 1, clock_generation = service_generation,
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
                maximum_expires_monotonic_nanos = zeroblob(16),
                terminal_at_utc = ?3, terminal_at_seconds = ?4, terminal_at_nanos = ?5",
            params![
                status,
                reason,
                terminal_wire,
                terminal_seconds,
                terminal_nanos
            ],
        )
        .unwrap_or_else(|error| panic!("set resolved status: {error}"));
    assert_eq!(changed, 1);
}

#[test]
fn fractional_high_monotonic_refusal_replays_exactly_after_reopen() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let high_monotonic = u128::from(u64::MAX) + 9_876_543_210;
    let issuance = clock(&ready, "2026-08-22T10:00:02.123456789Z", high_monotonic);
    let begun = ready
        .begin_acquire(&request(), &caller(), &host(), &issuance)
        .unwrap_or_else(|error| panic!("fractional begin: {error:?}"));
    let lease_id = begun.outcome().lease_id().clone();
    let original_generation = ready.service_clock_generation();
    ready
        .refuse_requested(
            &lease_id,
            RefusalCode::ProfileNotReady,
            &stamp("2026-08-22T10:00:03.987654321Z"),
        )
        .unwrap_or_else(|error| panic!("fractional refusal: {error:?}"));
    let expected = ready
        .begin_acquire(
            &request(),
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
            &request(),
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
        seed_requested(&mut ready);
        match case {
            RecoveryGateCase::ErrorLease => {
                set_resolved_status(ready.test_connection(), false);
            }
            RecoveryGateCase::Capacity(state) => {
                set_resolved_status(ready.test_connection(), true);
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
                            'provider', provider, 1, 1, ?1,
                            '2026-08-22T10:00:04Z', issued_at_seconds + 2, 0
                         FROM leases",
                        [state],
                    )
                    .unwrap_or_else(|error| panic!("seed {case:?}: {error}"));
            }
            RecoveryGateCase::Process => {
                set_resolved_status(ready.test_connection(), true);
                ready
                    .test_connection()
                    .execute_batch(
                        "INSERT INTO lease_processes (
                            process_id, lease_id, service_generation, state, execution_handle,
                            observed_fencing_generation, launch_intent_at_utc,
                            launch_intent_at_seconds, launch_intent_at_nanos
                         ) SELECT
                            'process_00000000000000000000000000', lease_id,
                            service_generation, 'LAUNCH_INTENT', execution_handle, 1,
                            '2026-08-22T10:00:04Z', issued_at_seconds + 2, 0
                         FROM leases;",
                    )
                    .unwrap_or_else(|error| panic!("seed {case:?}: {error}"));
            }
        }
        drop(ready);

        let blocked = fixture.recovering("2026-08-22T10:01:00Z");
        assert!(matches!(
            blocked.into_ready(&stamp("2026-08-22T10:01:01Z")),
            Err(StoreError::RecoveryRequired)
        ));

        let connection = Connection::open(fixture.paths.automation_lease_store())
            .unwrap_or_else(|error| panic!("resolve {case:?}: {error}"));
        match case {
            RecoveryGateCase::ErrorLease => set_resolved_status(&connection, true),
            RecoveryGateCase::Capacity(_) => {
                connection
                    .execute_batch(
                        "UPDATE capacity_reservations SET state = 'RELEASED',
                            released_at_utc = '2026-08-22T10:01:02Z',
                            released_at_seconds = reserved_at_seconds + 1,
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
                            ended_at_seconds = launch_intent_at_seconds + 1,
                            ended_at_nanos = 0;",
                    )
                    .unwrap_or_else(|error| panic!("exit {case:?}: {error}"));
            }
        }
        drop(connection);

        fixture
            .recovering("2026-08-22T10:02:00Z")
            .into_ready(&stamp("2026-08-22T10:02:01Z"))
            .unwrap_or_else(|error| panic!("resolved {case:?} remained blocked: {error:?}"));
    }
}
