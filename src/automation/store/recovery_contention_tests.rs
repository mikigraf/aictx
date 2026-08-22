use std::{fmt::Debug, str::FromStr};

use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            CallerSubject, ClientRequestId, HostIdentity, IdentityLeaseRequest, ProfileRef,
            Provider, RefusalCode, Sha256Digest, UtcTimestamp,
        },
        lease::{ClockSample, MonotonicMoment},
        store::{AuthenticatedRequestControl, RecoveringStore, StoreError},
    },
    config::{AppPaths, acquire_profile_lock, profile_automation_fence_presence},
    model::ProfileId,
};

use super::{
    lifecycle_types::NonCapacityRefusal, load_tests::resolved_status,
    test_support::TestAutomationProfile,
};

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

fn clock(store: &super::ReadyStore, wall: &str, monotonic: u128) -> ClockSample {
    ClockSample::new(
        stamp(wall),
        MonotonicMoment::from_nanoseconds(monotonic),
        store.service_clock_generation(),
    )
}

fn request_with_id(fixture: &Fixture, value: &str) -> IdentityLeaseRequest {
    let mut request = fixture.request();
    let id = parsed::<ClientRequestId>(value);
    request.client_request_id = id.clone();
    request.work_order_authorization.client_request_id = id;
    request
}

fn rewrite_requested_aliases(
    connection: &rusqlite::Connection,
    rewrites: &[(
        crate::automation::contracts::LeaseId,
        IdentityLeaseRequest,
        ProfileId,
    )],
) {
    let request_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'lease_requests_immutable'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("request trigger SQL: {error}"));
    let audit_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'audit_events_immutable'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("audit trigger SQL: {error}"));
    let transaction = connection
        .unchecked_transaction()
        .unwrap_or_else(|error| panic!("rewrite aliases transaction: {error}"));
    transaction
        .execute_batch(
            "DROP TRIGGER lease_requests_immutable;
             DROP TRIGGER audit_events_immutable;",
        )
        .unwrap_or_else(|error| panic!("drop immutable triggers: {error}"));
    for (lease_id, mut request, profile_id) in rewrites.iter().cloned() {
        let profile_ref = parsed::<ProfileRef>(&profile_id.to_string());
        request.profile_ref = profile_ref.clone();
        request.work_order_authorization.profile_ref = profile_ref;
        let canonical = request
            .canonical_authority_json()
            .unwrap_or_else(|error| panic!("historical canonical request: {error:?}"));
        let digest = Sha256Digest::hash(&canonical).to_string();
        transaction
            .execute(
                "UPDATE lease_requests
                 SET canonical_authority_digest = ?1, canonical_request = ?2
                 WHERE request_record_id = (
                     SELECT request_record_id FROM leases WHERE lease_id = ?3)",
                rusqlite::params![digest, canonical, lease_id.as_str()],
            )
            .unwrap_or_else(|error| panic!("rewrite historical request: {error}"));
        transaction
            .execute(
                "UPDATE leases SET provider = ?1, profile_ref = ?2 WHERE lease_id = ?3",
                rusqlite::params![
                    request.provider.to_string(),
                    profile_id.to_string(),
                    lease_id.as_str()
                ],
            )
            .unwrap_or_else(|error| panic!("rewrite historical lease: {error}"));
        transaction
            .execute(
                "UPDATE audit_events SET provider = ?1, profile_ref = ?2 WHERE lease_id = ?3",
                rusqlite::params![
                    request.provider.to_string(),
                    profile_id.to_string(),
                    lease_id.as_str()
                ],
            )
            .unwrap_or_else(|error| panic!("rewrite historical audit: {error}"));
    }
    transaction
        .execute_batch(&format!("{request_trigger};\n{audit_trigger};"))
        .unwrap_or_else(|error| panic!("restore immutable triggers: {error}"));
    transaction
        .commit()
        .unwrap_or_else(|error| panic!("commit historical aliases: {error}"));
}

fn assert_alias_busy(paths: &AppPaths, profile_ref: &ProfileId, busy: bool) {
    let acquired = acquire_profile_lock(
        &paths.profile_lock(profile_ref.provider(), profile_ref.name()),
        false,
    );
    assert_eq!(acquired.is_err(), busy, "legacy alias {profile_ref}");
}

fn blocker_projection(store: &RecoveringStore) -> Vec<(String, String, i64, i64)> {
    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT lease_id, status, row_version, next_audit_sequence
             FROM leases ORDER BY lease_id",
        )
        .unwrap_or_else(|error| panic!("blocker projection statement: {error}"));
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap_or_else(|error| panic!("blocker projection query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("blocker projection rows: {error}"))
}

fn projection(store: &RecoveringStore) -> (String, i64, i64, i64, String, Option<String>) {
    store
        .test_connection()
        .query_row(
            "SELECT l.status, l.row_version, l.next_audit_sequence,
                    (SELECT count(*) FROM audit_events WHERE lease_id = l.lease_id),
                    c.state, c.released_at_utc
             FROM leases l JOIN capacity_reservations c USING (lease_id)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("recovery projection: {error}"))
}

#[test]
fn recovery_fence_busy_keeps_terminal_candidate_exact_then_retries() {
    let fixture = Fixture::new();
    let mut ready = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:00:00Z"),
    )
    .unwrap_or_else(|error| panic!("open: {error:?}"))
    .into_ready(&stamp("2026-08-22T10:00:01Z"))
    .unwrap_or_else(|error| panic!("ready: {error:?}"));
    let request = fixture.request();
    let begun = ready
        .begin_acquire(
            &request,
            &caller(),
            &host(),
            &clock(&ready, "2026-08-22T10:00:02Z", 1),
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    let lease_id = begun.outcome().lease_id().clone();
    let authenticated_caller = caller();
    let authenticated_host = host();
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
            &stamp("2026-08-22T10:00:03Z"),
        )
        .unwrap_or_else(|error| panic!("refuse: {error:?}"));
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
                'provider', provider, 1, 1, 'HELD',
                '2026-08-22T10:00:03Z', 1787392803, 0 FROM leases",
            [],
        )
        .unwrap_or_else(|error| panic!("seed legacy capacity: {error}"));
    drop(ready);

    let mut recovering = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:01:00Z"),
    )
    .unwrap_or_else(|error| panic!("recovering open: {error:?}"));
    let before = projection(&recovering);
    let profile_ref = parsed::<ProfileId>(request.profile_ref.as_str());
    let alias = acquire_profile_lock(
        &fixture
            .paths
            .profile_lock(profile_ref.provider(), profile_ref.name()),
        false,
    )
    .unwrap_or_else(|error| panic!("ordinary alias lock: {error}"));
    assert!(matches!(
        recovering.terminalize_prior_generation(
            &lease_id,
            u64::try_from(before.1).unwrap_or_else(|error| panic!("row version: {error}")),
            &stamp("2026-08-22T10:01:01Z")
        ),
        Err(StoreError::ServiceBusy)
    ));
    assert_eq!(projection(&recovering), before);
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );

    drop(alias);
    let result = recovering
        .terminalize_prior_generation(
            &lease_id,
            u64::try_from(before.1).unwrap_or_else(|error| panic!("row version: {error}")),
            &stamp("2026-08-22T10:01:02Z"),
        )
        .unwrap_or_else(|error| panic!("retry terminal recovery: {error:?}"));
    assert_eq!(result.released_reservations(), 1);
    assert_eq!(
        result.row_version(),
        u64::try_from(before.1 + 1).unwrap_or_else(|error| panic!("row version: {error}"))
    );
    let after = projection(&recovering);
    assert_eq!(after.0, "REFUSED");
    assert_eq!(after.1, before.1 + 1);
    assert_eq!(after.2, before.2);
    assert_eq!(after.3, before.3);
    assert_eq!(after.4, "RELEASED");
    assert_eq!(after.5.as_deref(), Some("2026-08-22T10:01:02Z"));
    let release_tuple: (String, i64, i64) = recovering
        .test_connection()
        .query_row(
            "SELECT released_at_utc, released_at_seconds, released_at_nanos
             FROM capacity_reservations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("release tuple: {error}"));
    assert_eq!(
        release_tuple,
        ("2026-08-22T10:01:02Z".to_owned(), 1_787_392_862, 0)
    );

    assert!(matches!(
        recovering.terminalize_prior_generation(
            &lease_id,
            u64::try_from(before.1).unwrap_or_else(|error| panic!("row version: {error}")),
            &stamp("2026-08-22T10:01:03Z")
        ),
        Err(StoreError::ConcurrentMutation)
    ));
    assert_eq!(projection(&recovering), after);
    let retry = recovering
        .terminalize_prior_generation(
            &lease_id,
            result.row_version(),
            &stamp("2026-08-22T10:01:04Z"),
        )
        .unwrap_or_else(|error| panic!("exact recovery retry: {error:?}"));
    assert!(!retry.changed());
    assert_eq!(retry.released_reservations(), 0);
    assert_eq!(retry.row_version(), result.row_version());
    assert_eq!(projection(&recovering), after);
    assert_eq!(
        recovering
            .test_connection()
            .query_row(
                "SELECT released_at_utc, released_at_seconds, released_at_nanos
                 FROM capacity_reservations",
                [],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?
                )),
            )
            .unwrap_or_else(|error| panic!("release tuple after retry: {error}")),
        release_tuple
    );
    recovering
        .into_ready(&stamp("2026-08-22T10:01:05Z"))
        .unwrap_or_else(|error| panic!("ready after recovery: {error:?}"));
}

#[test]
fn resolved_terminal_without_a_recovered_fence_fails_closed() {
    let fixture = Fixture::new();
    let mut ready = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:00:00Z"),
    )
    .unwrap_or_else(|error| panic!("open: {error:?}"))
    .into_ready(&stamp("2026-08-22T10:00:01Z"))
    .unwrap_or_else(|error| panic!("ready: {error:?}"));
    let request = fixture.request();
    let begun = ready
        .begin_acquire(
            &request,
            &caller(),
            &host(),
            &clock(&ready, "2026-08-22T10:00:02Z", 1),
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    let lease_id = begun.outcome().lease_id().clone();
    resolved_status(
        ready.test_connection(),
        crate::automation::contracts::LeaseStatus::Closed,
    );
    assert!(
        ready
            .core
            .try_clear_profile_fence(&fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("clear synthetic terminal fence: {error:?}"))
    );
    let before: (String, i64, i64, i64) = ready
        .test_connection()
        .query_row(
            "SELECT status, row_version, next_audit_sequence,
                    (SELECT count(*) FROM audit_events WHERE lease_id = leases.lease_id)
             FROM leases",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap_or_else(|error| panic!("terminal projection: {error}"));
    drop(ready);

    let mut recovering = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:01:00Z"),
    )
    .unwrap_or_else(|error| panic!("recovering open: {error:?}"));
    assert!(matches!(
        recovering.terminalize_prior_generation(
            &lease_id,
            u64::try_from(before.1).unwrap_or_else(|error| panic!("row version: {error}")),
            &stamp("2026-08-22T10:01:01Z"),
        ),
        Err(StoreError::RecoveryRequired)
    ));
    let after = recovering
        .test_connection()
        .query_row(
            "SELECT status, row_version, next_audit_sequence,
                    (SELECT count(*) FROM audit_events WHERE lease_id = leases.lease_id)
             FROM leases",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("terminal projection after denial: {error}"));
    assert_eq!(after, before);
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );
}

#[test]
fn recovery_fences_every_same_uid_blocker_alias_before_terminalizing_one() {
    let fixture = Fixture::new();
    let mut ready = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:00:00Z"),
    )
    .unwrap_or_else(|error| panic!("alias open: {error:?}"))
    .into_ready(&stamp("2026-08-22T10:00:01Z"))
    .unwrap_or_else(|error| panic!("alias ready: {error:?}"));
    let request_a = request_with_id(&fixture, "01ARZ3NDEKTSV4RRFFQ69G5FCA");
    let request_b = request_with_id(&fixture, "01ARZ3NDEKTSV4RRFFQ69G5FCB");
    let current = parsed::<ProfileId>(request_a.profile_ref.as_str());
    let begun_a = ready
        .begin_acquire(
            &request_a,
            &caller(),
            &host(),
            &clock(&ready, "2026-08-22T10:00:02Z", 1),
        )
        .unwrap_or_else(|error| panic!("alias begin A: {error:?}"));
    let begun_b = ready
        .begin_acquire(
            &request_b,
            &caller(),
            &host(),
            &clock(&ready, "2026-08-22T10:00:03Z", 2),
        )
        .unwrap_or_else(|error| panic!("alias begin B: {error:?}"));
    let historical_a = parsed::<ProfileId>("codex:historical-a");
    let historical_b = parsed::<ProfileId>("codex:historical-b");
    rewrite_requested_aliases(
        ready.test_connection(),
        &[
            (
                begun_a.outcome().lease_id().clone(),
                request_a,
                historical_a.clone(),
            ),
            (
                begun_b.outcome().lease_id().clone(),
                request_b,
                historical_b.clone(),
            ),
        ],
    );
    let lease_a = begun_a.outcome().lease_id().clone();
    let lease_b = begun_b.outcome().lease_id().clone();
    let version_a = begun_a.row_version();
    let version_b = begun_b.row_version();
    drop(ready);

    let mut recovering = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:01:00Z"),
    )
    .unwrap_or_else(|error| panic!("alias recovery open: {error:?}"));
    let before = blocker_projection(&recovering);
    let busy_b = acquire_profile_lock(
        &fixture
            .paths
            .profile_lock(historical_b.provider(), historical_b.name()),
        false,
    )
    .unwrap_or_else(|error| panic!("hold historical B alias: {error}"));
    assert!(matches!(
        recovering.terminalize_prior_generation(
            &lease_a,
            version_a,
            &stamp("2026-08-22T10:01:01Z")
        ),
        Err(StoreError::ServiceBusy)
    ));
    assert_eq!(blocker_projection(&recovering), before);
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("alias marker while B busy: {error}"))
    );
    assert_alias_busy(&fixture.paths, &historical_a, true);
    assert_alias_busy(&fixture.paths, &current, true);
    drop(busy_b);
    let first = recovering
        .terminalize_prior_generation(&lease_a, version_a, &stamp("2026-08-22T10:01:02Z"))
        .unwrap_or_else(|error| panic!("terminalize alias A: {error:?}"));
    assert_eq!(
        first.status(),
        crate::automation::contracts::LeaseStatus::Refused
    );
    for profile_ref in [&historical_a, &historical_b, &current] {
        assert_alias_busy(&fixture.paths, profile_ref, true);
    }
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("alias marker after A: {error}"))
    );

    let second = recovering
        .terminalize_prior_generation(&lease_b, version_b, &stamp("2026-08-22T10:01:03Z"))
        .unwrap_or_else(|error| panic!("terminalize alias B: {error:?}"));
    assert_eq!(
        second.status(),
        crate::automation::contracts::LeaseStatus::Refused
    );
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("alias marker after B: {error}"))
    );
    for profile_ref in [&historical_a, &historical_b, &current] {
        assert_alias_busy(&fixture.paths, profile_ref, false);
    }
    recovering
        .into_ready(&stamp("2026-08-22T10:01:04Z"))
        .unwrap_or_else(|error| panic!("ready after alias recovery: {error:?}"));
}

#[test]
fn mixed_provider_blocker_set_fails_before_alias_or_database_mutation() {
    let fixture = Fixture::new();
    let mut ready = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:00:00Z"),
    )
    .unwrap_or_else(|error| panic!("mixed-provider open: {error:?}"))
    .into_ready(&stamp("2026-08-22T10:00:01Z"))
    .unwrap_or_else(|error| panic!("mixed-provider ready: {error:?}"));
    let request_a = request_with_id(&fixture, "01ARZ3NDEKTSV4RRFFQ69G5FCC");
    let mut request_b = request_with_id(&fixture, "01ARZ3NDEKTSV4RRFFQ69G5FCD");
    let current = parsed::<ProfileId>(request_a.profile_ref.as_str());
    let begun_a = ready
        .begin_acquire(
            &request_a,
            &caller(),
            &host(),
            &clock(&ready, "2026-08-22T10:00:02Z", 1),
        )
        .unwrap_or_else(|error| panic!("mixed-provider begin A: {error:?}"));
    let begun_b = ready
        .begin_acquire(
            &request_b,
            &caller(),
            &host(),
            &clock(&ready, "2026-08-22T10:00:03Z", 2),
        )
        .unwrap_or_else(|error| panic!("mixed-provider begin B: {error:?}"));
    let historical_a = parsed::<ProfileId>("codex:historical-a");
    let historical_b = parsed::<ProfileId>("claude:historical-b");
    request_b.provider = Provider::Claude;
    request_b.work_order_authorization.provider = Provider::Claude;
    rewrite_requested_aliases(
        ready.test_connection(),
        &[
            (
                begun_a.outcome().lease_id().clone(),
                request_a,
                historical_a.clone(),
            ),
            (
                begun_b.outcome().lease_id().clone(),
                request_b,
                historical_b.clone(),
            ),
        ],
    );
    let lease_a = begun_a.outcome().lease_id().clone();
    let version_a = begun_a.row_version();
    drop(ready);

    let mut recovering = RecoveringStore::open(
        &fixture.paths,
        &fixture.profile.installation,
        &stamp("2026-08-22T10:01:00Z"),
    )
    .unwrap_or_else(|error| panic!("mixed-provider recovery open: {error:?}"));
    let before = blocker_projection(&recovering);
    assert!(matches!(
        recovering.terminalize_prior_generation(
            &lease_a,
            version_a,
            &stamp("2026-08-22T10:01:01Z"),
        ),
        Err(StoreError::IntegrityCheckFailed)
    ));
    assert_eq!(blocker_projection(&recovering), before);
    assert_alias_busy(&fixture.paths, &historical_a, false);
    assert_alias_busy(&fixture.paths, &historical_b, false);
    assert_alias_busy(&fixture.paths, &current, true);
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("mixed-provider marker: {error}"))
    );
}
