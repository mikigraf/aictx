use std::{fmt::Debug, str::FromStr};

use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{CallerSubject, HostIdentity, IdentityLeaseRequest, RefusalCode, UtcTimestamp},
        lease::{ClockSample, MonotonicMoment},
        store::{AuthenticatedRequestControl, ReadyStore, RecoveringStore, StoreError},
    },
    config::AppPaths,
};

use super::{lifecycle_types::NonCapacityRefusal, test_support::TestAutomationProfile};

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
            paths,
            profile,
            _temporary: temporary,
        }
    }

    fn ready(&self) -> ReadyStore {
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

fn seed_refused(
    ready: &mut ReadyStore,
    request: &IdentityLeaseRequest,
) -> crate::automation::contracts::LeaseId {
    seed_refused_at(
        ready,
        request,
        "2026-08-22T10:00:02Z",
        "2026-08-22T10:00:03Z",
    )
}

fn seed_refused_at(
    ready: &mut ReadyStore,
    request: &IdentityLeaseRequest,
    issued_at: &str,
    refused_at: &str,
) -> crate::automation::contracts::LeaseId {
    let authenticated_caller = caller();
    let authenticated_host = host();
    let issuance = ClockSample::new(
        stamp(issued_at),
        MonotonicMoment::from_nanoseconds(1),
        ready.service_clock_generation(),
    );
    let begun = ready
        .begin_acquire(
            request,
            &authenticated_caller,
            &authenticated_host,
            &issuance,
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    let lease_id = begun.outcome().lease_id().clone();
    let control = AuthenticatedRequestControl::new(
        &lease_id,
        begun.row_version(),
        &authenticated_caller,
        &authenticated_host,
    );
    ready
        .refuse_requested(
            &control,
            NonCapacityRefusal::from_evaluation(RefusalCode::ProfileNotReady)
                .unwrap_or_else(|| panic!("non-capacity refusal")),
            &stamp(refused_at),
        )
        .unwrap_or_else(|error| panic!("refuse: {error:?}"));
    lease_id
}

fn counts(ready: &ReadyStore) -> (i64, i64, i64) {
    ready
        .test_connection()
        .query_row(
            "SELECT
                (SELECT count(*) FROM lease_requests),
                (SELECT count(*) FROM leases),
                (SELECT count(*) FROM audit_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("counts: {error}"))
}

#[test]
fn no_op_then_eligible_prune_records_exact_redacted_summary() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    seed_refused(&mut ready, &fixture.request());

    let no_op = ready
        .prune_retained(&stamp("2026-08-28T10:00:00Z"))
        .unwrap_or_else(|error| panic!("no-op prune: {error:?}"));
    assert!(!no_op.changed());
    assert_eq!(counts(&ready), (1, 1, 2));

    let pruned = ready
        .prune_retained(&stamp("2026-09-10T10:00:00Z"))
        .unwrap_or_else(|error| panic!("eligible prune: {error:?}"));
    assert_eq!(pruned.deleted_requests(), 1);
    assert_eq!(pruned.deleted_leases(), 1);
    assert_eq!(pruned.deleted_reservations(), 0);
    assert_eq!(pruned.deleted_processes(), 0);
    assert_eq!(pruned.deleted_events(), 2);
    assert_eq!(counts(&ready), (0, 0, 1));
    let summary = ready
        .test_connection()
        .query_row(
            "SELECT actor, prune_cutoff_utc, prune_deleted_requests,
                    prune_deleted_leases, prune_deleted_reservations,
                    prune_deleted_processes, prune_deleted_events,
                    prune_oldest_event_utc, prune_newest_event_utc,
                    lease_id, client_request_id
             FROM audit_events WHERE event_type = 'audit.pruned'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("prune summary: {error}"));
    assert_eq!(summary.0, "service");
    assert_eq!(summary.1, "2026-09-03T10:00:00Z");
    assert_eq!(
        (summary.2, summary.3, summary.4, summary.5, summary.6),
        (1, 1, 0, 0, 2)
    );
    assert_eq!(summary.7, "2026-08-22T10:00:02Z");
    assert_eq!(summary.8, "2026-08-22T10:00:03Z");
    assert_eq!((summary.9, summary.10), (None, None));
}

#[test]
fn signed_expiry_and_pruned_audit_failure_each_preserve_history() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let mut request = fixture.request();
    request.work_order_authorization.expires_at = stamp("2026-09-30T12:34:56Z");
    seed_refused(&mut ready, &request);
    assert!(
        !ready
            .prune_retained(&stamp("2026-09-10T10:00:00Z"))
            .unwrap_or_else(|error| panic!("signed horizon: {error:?}"))
            .changed()
    );
    assert_eq!(counts(&ready), (1, 1, 2));

    ready
        .test_connection()
        .execute_batch(
            "CREATE TRIGGER fail_pruned_audit BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'audit.pruned'
             BEGIN SELECT RAISE(ABORT, 'injected prune audit failure'); END;",
        )
        .unwrap_or_else(|error| panic!("failure trigger: {error}"));
    assert_eq!(
        ready.prune_retained(&stamp("2026-10-10T10:00:00Z")),
        Err(StoreError::DatabaseUnavailable)
    );
    assert_eq!(counts(&ready), (1, 1, 2));
}

#[test]
fn uncertain_prune_commit_rolls_back_and_latches_new_authority() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    seed_refused(&mut ready, &fixture.request());
    ready
        .test_connection()
        .commit_hook(Some(|| true))
        .unwrap_or_else(|error| panic!("commit hook: {error}"));
    assert_eq!(
        ready.prune_retained(&stamp("2026-09-10T10:00:00Z")),
        Err(StoreError::DatabaseUnavailable)
    );
    ready
        .test_connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap_or_else(|error| panic!("clear commit hook: {error}"));
    assert_eq!(counts(&ready), (1, 1, 2));
    assert_eq!(
        ready.prune_retained(&stamp("2026-09-10T10:00:01Z")),
        Err(StoreError::RecoveryRequired)
    );
}

#[test]
fn local_replay_horizon_uses_exact_fractional_nanosecond_boundary() {
    for (now, eligible) in [
        ("2026-08-29T10:00:02.123456788Z", false),
        ("2026-08-29T10:00:02.123456789Z", true),
        ("2026-08-29T10:00:02.123456790Z", true),
    ] {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        seed_refused_at(
            &mut ready,
            &fixture.request(),
            "2026-08-22T10:00:02.123456789Z",
            "2026-08-22T10:00:02.123456789Z",
        );
        let result = ready
            .prune_retained(&stamp(now))
            .unwrap_or_else(|error| panic!("fractional boundary prune: {error:?}"));
        assert_eq!(result.deleted_leases(), u64::from(eligible));
        assert_eq!(counts(&ready).1, i64::from(!eligible));
    }
}

#[test]
fn long_signed_expiry_is_retained_until_its_exact_fractional_boundary() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let mut request = fixture.request();
    request.work_order_authorization.expires_at = stamp("2026-09-30T12:34:56.987654321Z");
    seed_refused_at(
        &mut ready,
        &request,
        "2026-08-22T10:00:02Z",
        "2026-08-22T10:00:02Z",
    );
    assert!(
        !ready
            .prune_retained(&stamp("2026-09-30T12:34:56.987654320Z"))
            .unwrap_or_else(|error| panic!("before signed expiry: {error:?}"))
            .changed()
    );
    let exact = ready
        .prune_retained(&stamp("2026-09-30T12:34:56.987654321Z"))
        .unwrap_or_else(|error| panic!("exact signed expiry: {error:?}"));
    assert_eq!(exact.deleted_leases(), 1);
    assert_eq!(counts(&ready), (0, 0, 1));
}

#[test]
fn old_global_audit_only_emits_one_redacted_prune_summary() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    ready
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
                'audit.pruned', 'succeeded', '2026-08-01T00:00:00.123456789Z',
                1785542400, 123456789, 'service', '2026-07-25T00:00:00.123456789Z',
                0, 0, 0, 0, 1,
                '2026-07-01T00:00:00.1Z', 1782864000, 100000000,
                '2026-07-01T00:00:00.1Z', 1782864000, 100000000
             );",
        )
        .unwrap_or_else(|error| panic!("old global audit: {error}"));
    let result = ready
        .prune_retained(&stamp("2026-09-10T10:00:00Z"))
        .unwrap_or_else(|error| panic!("global-only prune: {error:?}"));
    assert_eq!(
        (
            result.deleted_requests(),
            result.deleted_leases(),
            result.deleted_reservations(),
            result.deleted_processes(),
            result.deleted_events(),
        ),
        (0, 0, 0, 0, 1)
    );
    let summary = ready
        .test_connection()
        .query_row(
            "SELECT count(*), prune_deleted_events, lease_id, client_request_id,
                    prune_oldest_event_utc, prune_newest_event_utc
             FROM audit_events WHERE event_type = 'audit.pruned'",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("global summary: {error}"));
    assert_eq!(
        summary,
        (
            1,
            1,
            None,
            None,
            "2026-08-01T00:00:00.123456789Z".to_owned(),
            "2026-08-01T00:00:00.123456789Z".to_owned(),
        )
    );
}
