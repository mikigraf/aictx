use std::{fmt::Debug, str::FromStr};

use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            AutomationAuthMode, AutomationErrorCode, CallerSubject, ClientRequestId,
            ExecutionHandle, FencingGeneration, HostIdentity, IdentityLeaseRequest,
            IsolationClassification, LeaseReasonCode, LeaseStatus, PrincipalRef, RefusalCode,
            Sha256Digest, UtcTimestamp, WorkerIdentity, WorkspaceRef,
        },
        lease::{
            ClockSample, LeaseControl, LeaseDomainError, LeaseResolution, MonotonicMoment,
            ServiceClockGeneration,
        },
        policy::test_support::effective_policy,
        store::{AuthenticatedRequestControl, ReadyStore, RecoveringStore, StoreError},
    },
    config::{AppPaths, acquire_profile_lock, profile_automation_fence_presence},
    model::{AutomationConcurrencyMode, SharedStateIsolationRequirement},
};

use super::{load_tests::resolved_status, test_support::TestAutomationProfile};

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

    fn request(&self, client_request_id: &str) -> IdentityLeaseRequest {
        let mut request: IdentityLeaseRequest = serde_json::from_str(include_str!(
            "../../../schemas/examples/identity-lease-request.v1.json"
        ))
        .unwrap_or_else(|error| panic!("request fixture: {error}"));
        request.work_order_authorization.not_before = stamp("2026-08-22T09:00:00Z");
        request.work_order_authorization.expires_at = stamp("2026-08-23T14:00:00Z");
        let client_request_id = parsed::<ClientRequestId>(client_request_id);
        request.client_request_id = client_request_id.clone();
        request.work_order_authorization.client_request_id = client_request_id;
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

fn clock(store: &ReadyStore, wall: &str, monotonic: u128) -> ClockSample {
    ClockSample::new(
        stamp(wall),
        MonotonicMoment::from_nanoseconds(monotonic),
        store.service_clock_generation(),
    )
}

fn begin(
    ready: &mut ReadyStore,
    request: &IdentityLeaseRequest,
    monotonic: u128,
) -> (crate::automation::contracts::LeaseId, u64) {
    let begun = ready
        .begin_acquire(
            request,
            &caller(),
            &host(),
            &clock(ready, "2026-08-22T10:00:02Z", monotonic),
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    (begun.outcome().lease_id().clone(), begun.row_version())
}

fn resolution(suffix: char, isolation: IsolationClassification) -> LeaseResolution {
    LeaseResolution {
        execution_handle: parsed::<ExecutionHandle>(&format!(
            "exec_0000000000000000000000000{suffix}"
        )),
        worker_identity: Some(parsed::<WorkerIdentity>("worker:harness")),
        principal_ref: parsed::<PrincipalRef>("service-account:resolved"),
        workspace_ref: parsed::<WorkspaceRef>("chatgpt-workspace:tenant"),
        auth_mode: AutomationAuthMode::ChatgptOauth,
        isolation,
    }
}

fn control<'a>(
    request: &'a IdentityLeaseRequest,
    authenticated_caller: &'a CallerSubject,
    authenticated_host: &'a HostIdentity,
    generation: u64,
) -> LeaseControl<'a> {
    LeaseControl {
        caller_subject: authenticated_caller,
        tenant_id: &request.tenant_id,
        run_id: &request.run_id,
        role: request.role,
        host_identity: authenticated_host,
        fencing_generation: FencingGeneration::from_value(generation)
            .unwrap_or_else(|error| panic!("generation: {error:?}")),
    }
}

fn row_projection(ready: &ReadyStore) -> (String, i64, i64, Vec<u8>, Option<String>, i64) {
    ready
        .test_connection()
        .query_row(
            "SELECT l.status, l.row_version, l.next_audit_sequence,
                    c.monotonic_high_water_nanos, l.reason_code,
                    (SELECT count(*) FROM audit_events WHERE lease_id = l.lease_id)
             FROM leases l JOIN lease_runtime_clocks c USING (lease_id)",
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
        .unwrap_or_else(|error| panic!("row projection: {error}"))
}

fn stored_row_version(ready: &ReadyStore) -> u64 {
    let value = ready
        .test_connection()
        .query_row("SELECT row_version FROM leases", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or_else(|error| panic!("row version: {error}"));
    u64::try_from(value).unwrap_or_else(|error| panic!("negative row version: {error}"))
}

struct ActiveLease {
    request: IdentityLeaseRequest,
    lease_id: crate::automation::contracts::LeaseId,
    row_version: u64,
}

fn activate_shared_pair(
    fixture: &Fixture,
    ready: &mut ReadyStore,
    ids: [(&str, char, u128); 2],
) -> Vec<ActiveLease> {
    let authenticated_caller = caller();
    let authenticated_host = host();
    ids.into_iter()
        .map(|(id, suffix, monotonic)| {
            let request = fixture.request(id);
            let (lease_id, row_version) = begin(ready, &request, monotonic);
            let request_control = AuthenticatedRequestControl::new(
                &lease_id,
                row_version,
                &authenticated_caller,
                &authenticated_host,
            );
            let policy = effective_policy(
                &request,
                &authenticated_caller,
                &authenticated_host,
                AutomationConcurrencyMode::Shared,
                IsolationClassification::CredentialIsolated,
                Some(SharedStateIsolationRequirement::Stateless),
                [2, 10, 10, 10],
            );
            let activated = ready
                .activate_requested(
                    &request_control,
                    &policy,
                    resolution(suffix, IsolationClassification::CredentialIsolated),
                    &clock(ready, "2026-08-22T10:00:03Z", monotonic + 1),
                )
                .unwrap_or_else(|error| panic!("shared activation: {error:?}"));
            assert_eq!(
                activated
                    .successful_response()
                    .map(|response| response.status),
                Some(LeaseStatus::Active)
            );
            ActiveLease {
                request,
                lease_id,
                row_version: activated
                    .successful_row_version()
                    .unwrap_or_else(|| panic!("active row version")),
            }
        })
        .collect()
}

#[test]
fn foreign_exact_ack_is_read_only_outside_renewing() {
    for (index, status) in [LeaseStatus::Active, LeaseStatus::Error, LeaseStatus::Closed]
        .into_iter()
        .enumerate()
    {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5F{}", index + 1));
        let (lease_id, _) = begin(&mut ready, &request, 100);
        resolved_status(ready.test_connection(), status);
        let row_version = stored_row_version(&ready);
        let wrong = parsed::<CallerSubject>("caller:foreign-controller");
        let authenticated_host = host();
        let control = control(&request, &wrong, &authenticated_host, 1);
        let before = row_projection(&ready);
        let denied = ready
            .acknowledge_renewal(
                &lease_id,
                row_version,
                &control,
                &clock(&ready, "2026-08-22T11:00:00Z", 9_000_000_000_000),
            )
            .unwrap_or_else(|error| panic!("foreign {status:?} ACK: {error:?}"));
        assert_eq!(
            denied.domain_result(),
            &Err(LeaseDomainError::CallerUnauthorized)
        );
        assert!(denied.successful_response().is_none());
        assert!(!denied.cleanup_deferred());
        assert_eq!(row_projection(&ready), before);
        let wire = denied
            .automation_error(None, &lease_id)
            .unwrap_or_else(|error| panic!("wire error: {error:?}"))
            .unwrap_or_else(|| panic!("missing wire error"));
        assert_eq!(wire.code, AutomationErrorCode::CallerUnauthorized);
        assert!(wire.lease_id.is_none());
    }
}

#[test]
fn exact_renewing_foreign_ack_revokes_even_with_invalid_clock_and_no_resource() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FA1");
    let (lease_id, _) = begin(&mut ready, &request, 100);
    resolved_status(ready.test_connection(), LeaseStatus::Renewing);
    let row_version = stored_row_version(&ready);
    let wrong = parsed::<CallerSubject>("caller:foreign-controller");
    let authenticated_host = host();
    let control = control(&request, &wrong, &authenticated_host, 2);
    let invalid_clock = ClockSample::new(
        stamp("2026-08-22T09:00:00Z"),
        MonotonicMoment::from_nanoseconds(0),
        ServiceClockGeneration::from_value(999),
    );
    let denied = ready
        .acknowledge_renewal(&lease_id, row_version, &control, &invalid_clock)
        .unwrap_or_else(|error| panic!("foreign renewing ACK: {error:?}"));
    assert_eq!(
        denied.domain_result(),
        &Err(LeaseDomainError::CallerUnauthorized)
    );
    assert_eq!(
        ready
            .test_connection()
            .query_row("SELECT status, reason_code FROM leases", [], |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?
            )),),
        Ok((
            "REVOKED".to_owned(),
            "renewal-acknowledgement-failed".to_owned()
        ))
    );
}

#[test]
fn missing_resource_never_suppresses_deadline_reductions() {
    for (status, target, wall, monotonic) in [
        (
            LeaseStatus::Active,
            "EXPIRED",
            "2026-08-22T10:16:00Z",
            901_000_000_100_u128,
        ),
        (
            LeaseStatus::Renewing,
            "REVOKED",
            "2026-08-22T10:01:00Z",
            60_000_000_100_u128,
        ),
    ] {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FA2");
        let (lease_id, _) = begin(&mut ready, &request, 100);
        resolved_status(ready.test_connection(), status);
        let row_version = stored_row_version(&ready);
        let authenticated_caller = caller();
        let authenticated_host = host();
        let control = control(
            &request,
            &authenticated_caller,
            &authenticated_host,
            if status == LeaseStatus::Renewing {
                2
            } else {
                1
            },
        );
        if status == LeaseStatus::Active {
            let policy = effective_policy(
                &request,
                &authenticated_caller,
                &authenticated_host,
                AutomationConcurrencyMode::Exclusive,
                IsolationClassification::CredentialIsolated,
                None,
                [1, 2, 3, 4],
            );
            let result = ready
                .begin_renewal(
                    &lease_id,
                    row_version,
                    &control,
                    &policy,
                    &clock(&ready, wall, monotonic),
                )
                .unwrap_or_else(|error| panic!("due renewal: {error:?}"));
            assert!(result.domain_result().is_err());
        } else {
            let result = ready
                .acknowledge_renewal(
                    &lease_id,
                    row_version,
                    &control,
                    &clock(&ready, wall, monotonic),
                )
                .unwrap_or_else(|error| panic!("due ACK: {error:?}"));
            assert!(result.domain_result().is_err());
        }
        assert_eq!(
            ready
                .test_connection()
                .query_row("SELECT status FROM leases", [], |row| row
                    .get::<_, String>(0))
                .unwrap_or_else(|error| panic!("status: {error}")),
            target
        );
    }
}

#[test]
fn shared_leases_coexist_capacity_wins_and_last_terminal_clears_fence() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let authenticated_caller = caller();
    let authenticated_host = host();
    let active = activate_shared_pair(
        &fixture,
        &mut ready,
        [
            ("01ARZ3NDEKTSV4RRFFQ69G5FA3", '1', 100),
            ("01ARZ3NDEKTSV4RRFFQ69G5FA4", '2', 200),
        ],
    );
    assert_eq!(
        ready
            .test_connection()
            .query_row(
                "SELECT count(*) FROM capacity_reservations WHERE state = 'HELD'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("held count: {error}")),
        8
    );

    let capacity_request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FA5");
    let (capacity_id, capacity_version) = begin(&mut ready, &capacity_request, 300);
    let capacity_control = AuthenticatedRequestControl::new(
        &capacity_id,
        capacity_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let capacity_policy = effective_policy(
        &capacity_request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Shared,
        IsolationClassification::CredentialIsolated,
        Some(SharedStateIsolationRequirement::Stateless),
        [2, 10, 10, 10],
    );
    let refused = ready
        .activate_requested(
            &capacity_control,
            &capacity_policy,
            resolution('3', IsolationClassification::CredentialIsolated),
            &clock(&ready, "2026-08-22T10:00:03Z", 301),
        )
        .unwrap_or_else(|error| panic!("capacity refusal: {error:?}"));
    let response = refused
        .successful_response()
        .unwrap_or_else(|| panic!("refusal response"));
    assert_eq!(response.status, LeaseStatus::Refused);
    assert_eq!(response.refusal_code, Some(RefusalCode::CapacityExceeded));

    let first = &active[0];
    let first_control = control(
        &first.request,
        &authenticated_caller,
        &authenticated_host,
        1,
    );
    ready
        .close_lease(
            &first.lease_id,
            first.row_version,
            &first_control,
            LeaseReasonCode::Completed,
            &clock(&ready, "2026-08-22T10:00:10Z", 10_000_000_000),
        )
        .unwrap_or_else(|error| panic!("close first shared: {error:?}"));
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );

    let exclusive_request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FA6");
    let (exclusive_id, exclusive_version) = begin(&mut ready, &exclusive_request, 400);
    let exclusive_control = AuthenticatedRequestControl::new(
        &exclusive_id,
        exclusive_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let exclusive_policy = effective_policy(
        &exclusive_request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [10, 10, 10, 10],
    );
    let mixed = ready
        .activate_requested(
            &exclusive_control,
            &exclusive_policy,
            resolution('4', IsolationClassification::CredentialIsolated),
            &clock(&ready, "2026-08-22T10:00:03Z", 401),
        )
        .unwrap_or_else(|error| panic!("mixed refusal: {error:?}"));
    assert_eq!(
        mixed
            .successful_response()
            .and_then(|response| response.refusal_code),
        Some(RefusalCode::ProfileNotReady)
    );

    let last = &active[1];
    let last_control = control(&last.request, &authenticated_caller, &authenticated_host, 1);
    ready
        .close_lease(
            &last.lease_id,
            last.row_version,
            &last_control,
            LeaseReasonCode::Completed,
            &clock(&ready, "2026-08-22T10:00:11Z", 11_000_000_000),
        )
        .unwrap_or_else(|error| panic!("close last shared: {error:?}"));
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );
}

#[test]
fn retryable_shared_cleanup_releases_only_terminal_resource_and_unblocks_renewal() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let active = activate_shared_pair(
        &fixture,
        &mut ready,
        [
            ("01ARZ3NDEKTSV4RRFFQ69G5FB1", '6', 100),
            ("01ARZ3NDEKTSV4RRFFQ69G5FB2", '7', 200),
        ],
    );
    let authenticated_caller = caller();
    let authenticated_host = host();
    ready.test_fail_next_post_terminal_cleanup();
    let first = &active[0];
    let first_control = control(
        &first.request,
        &authenticated_caller,
        &authenticated_host,
        1,
    );
    let closed = ready
        .close_lease(
            &first.lease_id,
            first.row_version,
            &first_control,
            LeaseReasonCode::Completed,
            &clock(&ready, "2026-08-22T10:00:10Z", 10_000_000_000),
        )
        .unwrap_or_else(|error| panic!("close with cleanup failure: {error:?}"));
    assert!(closed.domain_result().is_ok());
    assert!(closed.cleanup_deferred());
    assert!(
        !ready
            .retry_profile_fence_cleanup(&fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("retry cleanup: {error:?}"))
    );

    let second = &active[1];
    let second_control = control(
        &second.request,
        &authenticated_caller,
        &authenticated_host,
        1,
    );
    let policy = effective_policy(
        &second.request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Shared,
        IsolationClassification::CredentialIsolated,
        Some(SharedStateIsolationRequirement::Stateless),
        [2, 10, 10, 10],
    );
    let renewing = ready
        .begin_renewal(
            &second.lease_id,
            second.row_version,
            &second_control,
            &policy,
            &clock(&ready, "2026-08-22T10:00:10Z", 10_000_000_000),
        )
        .unwrap_or_else(|error| panic!("renew remaining shared lease: {error:?}"));
    assert!(renewing.domain_result().is_ok());
    let closing_control = control(
        &second.request,
        &authenticated_caller,
        &authenticated_host,
        2,
    );
    ready
        .close_lease(
            &second.lease_id,
            renewing
                .successful_row_version()
                .unwrap_or_else(|| panic!("renewed row version")),
            &closing_control,
            LeaseReasonCode::Completed,
            &clock(&ready, "2026-08-22T10:00:11Z", 11_000_000_000),
        )
        .unwrap_or_else(|error| panic!("close remaining shared lease: {error:?}"));
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );
}

#[test]
fn postcommit_integrity_cleanup_failure_is_hard_latched_until_restart() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FB3");
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, row_version) = begin(&mut ready, &request, 100);
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        row_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let policy = effective_policy(
        &request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [4, 4, 4, 4],
    );
    let activated = ready
        .activate_requested(
            &request_control,
            &policy,
            resolution('8', IsolationClassification::CredentialIsolated),
            &clock(&ready, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("hard-cleanup activation: {error:?}"));
    let active_version = activated
        .successful_row_version()
        .unwrap_or_else(|| panic!("hard-cleanup active version"));
    ready.test_fail_next_post_terminal_cleanup_integrity();
    let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    let closed = ready
        .close_lease(
            &lease_id,
            active_version,
            &lease_control,
            LeaseReasonCode::Completed,
            &clock(&ready, "2026-08-22T10:00:04Z", 102),
        )
        .unwrap_or_else(|error| panic!("hard-cleanup close: {error:?}"));
    assert!(closed.domain_result().is_ok());
    assert!(closed.cleanup_deferred());
    assert!(matches!(
        ready.retry_profile_fence_cleanup(&fixture.profile.profile_uid),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("hard-cleanup marker: {error}"))
    );
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_resource_lock(&fixture.profile.profile_uid),
            true,
        )
        .is_err(),
        "hard cleanup latch must retain the lease resource"
    );
    assert_eq!(row_projection(&ready).0, "CLOSED");
}

#[test]
fn cleanup_latch_blocks_exact_active_replay_but_not_conflict_classification() {
    let fixture = Fixture::new();
    let mut ready = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FA7");
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, row_version) = begin(&mut ready, &request, 100);
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        row_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let policy = effective_policy(
        &request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [1, 2, 3, 4],
    );
    ready
        .activate_requested(
            &request_control,
            &policy,
            resolution('5', IsolationClassification::CredentialIsolated),
            &clock(&ready, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("activate: {error:?}"));
    let before = row_projection(&ready);
    ready.test_latch_durability_uncertain();
    let exact = ready.begin_acquire(
        &request,
        &authenticated_caller,
        &authenticated_host,
        &clock(&ready, "2026-08-22T10:00:04Z", 102),
    );
    assert!(matches!(exact, Err(StoreError::RecoveryRequired)));
    assert_eq!(row_projection(&ready), before);
    let wire = StoreError::RecoveryRequired
        .acquire_automation_error(Some(request.client_request_id.clone()));
    assert_eq!(wire.code, AutomationErrorCode::ServiceRecovering);
    assert!(wire.lease_id.is_none());

    let mut conflicting = request.clone();
    conflicting.policy_digest = Some(parsed::<Sha256Digest>(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ));
    assert!(matches!(
        ready.begin_acquire(
            &conflicting,
            &authenticated_caller,
            &authenticated_host,
            &clock(&ready, "2026-08-22T10:00:04Z", 102),
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(row_projection(&ready), before);
}
