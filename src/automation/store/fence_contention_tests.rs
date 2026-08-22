use std::{fmt::Debug, os::unix::fs::PermissionsExt, str::FromStr};

use rusqlite::Connection;
use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{CallerSubject, HostIdentity, IdentityLeaseRequest, UtcTimestamp},
        lease::{ClockSample, MonotonicMoment},
        store::{RecoveringStore, StoreError},
    },
    config::{AppPaths, acquire_profile_lock, profile_automation_fence_presence},
    model::ProfileId,
};

use super::test_support::TestAutomationProfile;

struct Fixture {
    _temporary: TempDir,
    paths: AppPaths,
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
            _temporary: temporary,
            paths,
            profile,
        }
    }

    fn ready(&self) -> super::ReadyStore {
        RecoveringStore::open(
            &self.paths,
            &self.profile.installation,
            &stamp("2026-08-22T10:00:00Z"),
        )
        .unwrap_or_else(|error| panic!("open: {error:?}"))
        .into_ready(&stamp("2026-08-22T10:00:01Z"))
        .unwrap_or_else(|error| panic!("ready: {error:?}"))
    }

    fn request(&self) -> IdentityLeaseRequest {
        let mut request: IdentityLeaseRequest = serde_json::from_str(include_str!(
            "../../../schemas/examples/identity-lease-request.v1.json"
        ))
        .unwrap_or_else(|error| panic!("request fixture: {error}"));
        request.work_order_authorization.not_before = stamp("2026-08-22T09:00:00Z");
        request.work_order_authorization.expires_at = stamp("2026-08-23T14:00:00Z");
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

fn caller() -> CallerSubject {
    parsed("caller:local-controller")
}

fn host() -> HostIdentity {
    parsed("host:runner-01")
}

fn clock(store: &super::ReadyStore) -> ClockSample {
    ClockSample::new(
        stamp("2026-08-22T10:00:02Z"),
        MonotonicMoment::from_nanoseconds(1),
        store.service_clock_generation(),
    )
}

fn row_counts(connection: &Connection) -> (i64, i64, i64) {
    connection
        .query_row(
            "SELECT
                (SELECT count(*) FROM lease_requests),
                (SELECT count(*) FROM leases),
                (SELECT count(*) FROM audit_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("row counts: {error}"))
}

#[test]
fn unseen_acquire_reports_busy_without_db_or_marker_then_retries() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = fixture.request();
    let profile_ref = parsed::<ProfileId>(request.profile_ref.as_str());
    let alias = acquire_profile_lock(
        &fixture
            .paths
            .profile_lock(profile_ref.provider(), profile_ref.name()),
        false,
    )
    .unwrap_or_else(|error| panic!("ordinary alias lock: {error}"));
    let before = row_counts(ready.test_connection());

    assert!(matches!(
        ready.begin_acquire(&request, &caller(), &host(), &clock(&ready)),
        Err(StoreError::ServiceBusy)
    ));
    assert_eq!(row_counts(ready.test_connection()), before);
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );

    drop(alias);
    let result = ready
        .begin_acquire(&request, &caller(), &host(), &clock(&ready))
        .unwrap_or_else(|error| panic!("retry begin: {error:?}"));
    assert!(matches!(
        result.outcome(),
        super::PersistedAcquireOutcome::Requested { .. }
    ));
    assert_eq!(row_counts(ready.test_connection()), (1, 1, 1));
}

#[test]
fn recovery_open_reports_busy_before_generation_write_then_retries() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = fixture.request();
    ready
        .begin_acquire(&request, &caller(), &host(), &clock(&ready))
        .unwrap_or_else(|error| panic!("seed request: {error:?}"));
    let generations: i64 = ready
        .test_connection()
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("generation count: {error}"));
    drop(ready);

    let profile_ref = parsed::<ProfileId>(request.profile_ref.as_str());
    let alias = acquire_profile_lock(
        &fixture
            .paths
            .profile_lock(profile_ref.provider(), profile_ref.name()),
        false,
    )
    .unwrap_or_else(|error| panic!("ordinary alias lock: {error}"));
    assert!(matches!(
        RecoveringStore::open(
            &fixture.paths,
            &fixture.profile.installation,
            &stamp("2026-08-22T10:00:03Z")
        ),
        Err(StoreError::ServiceBusy)
    ));
    let connection = Connection::open(fixture.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("read store: {error}"));
    let unchanged: i64 = connection
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("generation count after busy: {error}"));
    assert_eq!(unchanged, generations);
    drop(connection);

    drop(alias);
    let recovered = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:00:04Z"),
    )
    .unwrap_or_else(|error| panic!("retry open: {error:?}"));
    let advanced: i64 = recovered
        .test_connection()
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("generation count after retry: {error}"));
    assert_eq!(advanced, generations + 1);
}

#[test]
fn unsafe_alias_lock_is_not_classified_as_transient_contention() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = fixture.request();
    let profile_ref = parsed::<ProfileId>(request.profile_ref.as_str());
    let alias_path = fixture
        .paths
        .profile_lock(profile_ref.provider(), profile_ref.name());
    drop(
        acquire_profile_lock(&alias_path, true)
            .unwrap_or_else(|error| panic!("create alias lock: {error}")),
    );
    let mut permissions = std::fs::metadata(&alias_path)
        .unwrap_or_else(|error| panic!("alias metadata: {error}"))
        .permissions();
    permissions.set_mode(0o644);
    std::fs::set_permissions(&alias_path, permissions)
        .unwrap_or_else(|error| panic!("make alias unsafe: {error}"));
    let before = row_counts(ready.test_connection());

    assert!(matches!(
        ready.begin_acquire(&request, &caller(), &host(), &clock(&ready)),
        Err(StoreError::UnsafeStorage)
    ));
    assert_eq!(row_counts(ready.test_connection()), before);
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );

    let mut permissions = std::fs::metadata(&alias_path)
        .unwrap_or_else(|error| panic!("alias metadata: {error}"))
        .permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(&alias_path, permissions)
        .unwrap_or_else(|error| panic!("restore alias: {error}"));
    ready
        .begin_acquire(&request, &caller(), &host(), &clock(&ready))
        .unwrap_or_else(|error| panic!("retry begin: {error:?}"));
}
