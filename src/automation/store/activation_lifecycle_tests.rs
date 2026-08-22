use std::{fmt::Debug, str::FromStr};

use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            AutomationAuthMode, CallerSubject, ClientRequestId, ExecutionHandle, FencingGeneration,
            HostIdentity, IdentityLeaseRequest, IsolationClassification, LeaseStatus, PrincipalRef,
            RefusalCode, UtcTimestamp, WorkerIdentity, WorkspaceRef,
        },
        lease::{ClockSample, LeaseControl, LeaseDomainError, LeaseResolution, MonotonicMoment},
        policy::test_support::effective_policy,
        store::{
            AuthenticatedRequestControl, PersistedAcquireOutcome, RecoveringStore, StoreError,
        },
    },
    config::{AppPaths, acquire_profile_lock, profile_automation_fence_presence},
    model::{AutomationConcurrencyMode, SharedStateIsolationRequirement},
};

use super::test_support::TestAutomationProfile;

pub(super) struct Fixture {
    _temporary: TempDir,
    pub(super) paths: AppPaths,
    pub(super) profile: TestAutomationProfile,
}

impl Fixture {
    pub(super) fn new() -> Self {
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

    pub(super) fn ready(&self) -> super::ReadyStore {
        RecoveringStore::open(
            &self.paths,
            &self.profile.installation,
            &stamp("2026-08-22T10:00:00Z"),
        )
        .unwrap_or_else(|error| panic!("open: {error:?}"))
        .into_ready(&stamp("2026-08-22T10:00:01Z"))
        .unwrap_or_else(|error| panic!("ready: {error:?}"))
    }

    pub(super) fn request(&self, id: &str) -> IdentityLeaseRequest {
        let mut request: IdentityLeaseRequest = serde_json::from_str(include_str!(
            "../../../schemas/examples/identity-lease-request.v1.json"
        ))
        .unwrap_or_else(|error| panic!("request fixture: {error}"));
        request.work_order_authorization.not_before = stamp("2026-08-22T09:00:00Z");
        request.work_order_authorization.expires_at = stamp("2026-08-23T14:00:00Z");
        let id = parsed::<ClientRequestId>(id);
        request.client_request_id = id.clone();
        request.work_order_authorization.client_request_id = id;
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

pub(super) fn stamp(value: &str) -> UtcTimestamp {
    parsed(value)
}

pub(super) fn caller() -> CallerSubject {
    parsed("caller:local-controller")
}

pub(super) fn host() -> HostIdentity {
    parsed("host:runner-01")
}

pub(super) fn clock(store: &super::ReadyStore, wall: &str, monotonic: u128) -> ClockSample {
    ClockSample::new(
        stamp(wall),
        MonotonicMoment::from_nanoseconds(monotonic),
        store.service_clock_generation(),
    )
}

pub(super) fn resolution(suffix: char, isolation: IsolationClassification) -> LeaseResolution {
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

pub(super) fn control<'a>(
    request: &'a IdentityLeaseRequest,
    caller: &'a CallerSubject,
    host: &'a HostIdentity,
    generation: u64,
) -> LeaseControl<'a> {
    LeaseControl {
        caller_subject: caller,
        tenant_id: &request.tenant_id,
        run_id: &request.run_id,
        role: request.role,
        host_identity: host,
        fencing_generation: FencingGeneration::from_value(generation)
            .unwrap_or_else(|error| panic!("generation: {error:?}")),
    }
}

pub(super) fn begin(
    store: &mut super::ReadyStore,
    request: &IdentityLeaseRequest,
    monotonic: u128,
) -> (crate::automation::contracts::LeaseId, u64) {
    let result = store
        .begin_acquire(
            request,
            &caller(),
            &host(),
            &clock(store, "2026-08-22T10:00:02Z", monotonic),
        )
        .unwrap_or_else(|error| panic!("begin: {error:?}"));
    (result.outcome().lease_id().clone(), result.row_version())
}

#[test]
fn activation_commits_exact_response_four_capacity_rows_audit_and_replay() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FB3");
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, requested_version) = begin(&mut store, &request, 100);
    let policy = effective_policy(
        &request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [3, 4, 5, 6],
    );
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        requested_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let activated = store
        .activate_requested(
            &request_control,
            &policy,
            resolution('1', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03.000000101Z", 101),
        )
        .unwrap_or_else(|error| panic!("activate: {error:?}"));
    assert_eq!(activated.domain_result(), &Ok(()));
    let response = activated
        .successful_response()
        .unwrap_or_else(|| panic!("active response"));
    assert_eq!(response.status, LeaseStatus::Active);
    assert_eq!(
        response.fencing_generation.map(FencingGeneration::get),
        Some(1)
    );
    assert_eq!(
        response.execution_handle,
        Some(parsed("exec_00000000000000000000000001"))
    );
    assert_eq!(
        activated.successful_row_version(),
        Some(requested_version + 1)
    );

    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT capacity_dimension, capacity_limit, slot, state, reserved_at_utc
             FROM capacity_reservations WHERE lease_id = ?1 ORDER BY capacity_dimension",
        )
        .unwrap_or_else(|error| panic!("capacity query: {error}"));
    let rows = statement
        .query_map([lease_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .unwrap_or_else(|error| panic!("capacity rows: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("capacity collect: {error}"));
    assert_eq!(
        rows,
        vec![
            (
                "caller".to_owned(),
                5,
                1,
                "HELD".to_owned(),
                "2026-08-22T10:00:03.000000101Z".to_owned()
            ),
            (
                "host".to_owned(),
                6,
                1,
                "HELD".to_owned(),
                "2026-08-22T10:00:03.000000101Z".to_owned()
            ),
            (
                "profile".to_owned(),
                3,
                1,
                "HELD".to_owned(),
                "2026-08-22T10:00:03.000000101Z".to_owned()
            ),
            (
                "provider".to_owned(),
                4,
                1,
                "HELD".to_owned(),
                "2026-08-22T10:00:03.000000101Z".to_owned()
            ),
        ]
    );
    drop(statement);
    let projection: (String, i64, i64, Vec<u8>) = store
        .test_connection()
        .query_row(
            "SELECT l.status, l.row_version, l.next_audit_sequence,
                    c.monotonic_high_water_nanos
             FROM leases l JOIN lease_runtime_clocks c USING (lease_id)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap_or_else(|error| panic!("lease projection: {error}"));
    assert_eq!(
        projection,
        ("ACTIVE".to_owned(), 2, 3, 101_u128.to_be_bytes().to_vec())
    );
    let audit = store
        .test_connection()
        .prepare(
            "SELECT sequence, event_type, actor, lease_status FROM audit_events ORDER BY sequence",
        )
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_else(|error| panic!("audit chain: {error}"));
    assert_eq!(
        audit,
        vec![
            (
                1,
                "lease.requested".to_owned(),
                authenticated_caller.to_string(),
                "REQUESTED".to_owned()
            ),
            (
                2,
                "lease.activated".to_owned(),
                "service".to_owned(),
                "ACTIVE".to_owned()
            ),
        ]
    );

    let replay = store
        .begin_acquire(
            &request,
            &authenticated_caller,
            &authenticated_host,
            &clock(&store, "2026-08-22T10:00:10Z", 999),
        )
        .unwrap_or_else(|error| panic!("replay: {error:?}"));
    assert!(replay.replayed());
    assert_eq!(replay.row_version(), requested_version + 1);
    assert!(matches!(
        replay.outcome(),
        PersistedAcquireOutcome::Resolved { .. }
    ));
    assert_eq!(replay.outcome().response(), response);
}

#[test]
fn invalid_policy_precedes_full_capacity_then_capacity_refusal_has_no_rows() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let authenticated_caller = caller();
    let authenticated_host = host();
    let first = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FB4");
    let (first_id, first_version) = begin(&mut store, &first, 100);
    let first_control = AuthenticatedRequestControl::new(
        &first_id,
        first_version,
        &authenticated_caller,
        &authenticated_host,
    );
    store
        .activate_requested(
            &first_control,
            &effective_policy(
                &first,
                &authenticated_caller,
                &authenticated_host,
                AutomationConcurrencyMode::Exclusive,
                IsolationClassification::CredentialIsolated,
                None,
                [1, 1, 1, 1],
            ),
            resolution('2', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("first activation: {error:?}"));

    let second = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FB5");
    let (second_id, second_version) = begin(&mut store, &second, 200);
    let second_control = AuthenticatedRequestControl::new(
        &second_id,
        second_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let inconsistent = effective_policy(
        &second,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Shared,
        IsolationClassification::CopiedCredentialDevelopment,
        Some(SharedStateIsolationRequirement::Stateless),
        [1, 1, 1, 1],
    );
    let denied = store
        .activate_requested(
            &second_control,
            &inconsistent,
            resolution('3', IsolationClassification::CopiedCredentialDevelopment),
            &clock(&store, "2026-08-22T10:00:04Z", 201),
        )
        .unwrap_or_else(|error| panic!("inconsistent activation: {error:?}"));
    assert_eq!(
        denied.domain_result(),
        &Err(LeaseDomainError::PolicyBindingMismatch)
    );
    assert_eq!(
        store.test_connection().query_row(
            "SELECT l.status, l.row_version, l.next_audit_sequence,
                    c.monotonic_high_water_nanos
             FROM leases l JOIN lease_runtime_clocks c USING (lease_id)
             WHERE l.lease_id = ?1",
            [second_id.as_str()],
            |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?
            )),
        ),
        Ok((
            "REQUESTED".to_owned(),
            2,
            2,
            201_u128.to_be_bytes().to_vec()
        ))
    );

    let capacity_control = AuthenticatedRequestControl::new(
        &second_id,
        second_version + 1,
        &authenticated_caller,
        &authenticated_host,
    );
    let refused = store
        .activate_requested(
            &capacity_control,
            &effective_policy(
                &second,
                &authenticated_caller,
                &authenticated_host,
                AutomationConcurrencyMode::Exclusive,
                IsolationClassification::CredentialIsolated,
                None,
                [1, 1, 1, 1],
            ),
            resolution('4', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:05Z", 202),
        )
        .unwrap_or_else(|error| panic!("capacity denial: {error:?}"));
    assert_eq!(
        refused
            .successful_response()
            .map(|response| (response.status, response.refusal_code)),
        Some((LeaseStatus::Refused, Some(RefusalCode::CapacityExceeded)))
    );
    assert_eq!(
        store
            .test_connection()
            .query_row(
                "SELECT count(*) FROM capacity_reservations WHERE lease_id = ?1",
                [second_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("refused capacity count: {error}")),
        0
    );
    assert_eq!(
        store
            .test_connection()
            .query_row(
                "SELECT count(*) FROM capacity_reservations WHERE state = 'HELD'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("held capacity count: {error}")),
        4
    );
}

#[test]
fn renewal_and_ack_commit_exact_versions_deadlines_audit_and_capacity_identity() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FB6");
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, requested_version) = begin(&mut store, &request, 100);
    let policy = effective_policy(
        &request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [2, 3, 4, 5],
    );
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        requested_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let active = store
        .activate_requested(
            &request_control,
            &policy,
            resolution('5', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("activate: {error:?}"));
    let active_version = active
        .successful_row_version()
        .unwrap_or_else(|| panic!("active version"));
    let first_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    let renewing = store
        .begin_renewal(
            &lease_id,
            active_version,
            &first_control,
            &policy,
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        )
        .unwrap_or_else(|error| panic!("begin renewal: {error:?}"));
    assert_eq!(
        renewing.domain_result(),
        &Ok(FencingGeneration::from_value(2)
            .unwrap_or_else(|error| panic!("generation: {error:?}")))
    );
    let renewing_version = renewing
        .successful_row_version()
        .unwrap_or_else(|| panic!("renewing version"));
    let renewing_response = renewing
        .successful_response()
        .unwrap_or_else(|| panic!("renewing response"));
    assert_eq!(renewing_response.status, LeaseStatus::Renewing);
    assert!(renewing_response.expires_at.is_some());
    let second_control = control(&request, &authenticated_caller, &authenticated_host, 2);
    let acknowledged = store
        .acknowledge_renewal(
            &lease_id,
            renewing_version,
            &second_control,
            &clock(&store, "2026-08-22T10:00:05Z", 103),
        )
        .unwrap_or_else(|error| panic!("ack renewal: {error:?}"));
    assert_eq!(acknowledged.domain_result(), &Ok(()));
    assert_eq!(
        acknowledged.successful_row_version(),
        Some(renewing_version + 1)
    );
    assert_eq!(
        acknowledged.successful_response().map(|response| (
            response.status,
            response.fencing_generation.map(FencingGeneration::get)
        )),
        Some((LeaseStatus::Active, Some(2)))
    );
    let state: (Option<String>, Option<String>, i64, i64) = store
        .test_connection()
        .query_row(
            "SELECT renewal_ack_deadline_utc, renewal_acknowledged_at_utc,
                    next_audit_sequence,
                    (SELECT count(*) FROM capacity_reservations
                     WHERE lease_id = leases.lease_id AND state = 'HELD')
             FROM leases WHERE lease_id = ?1",
            [lease_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap_or_else(|error| panic!("renewal state: {error}"));
    assert_eq!(state.0, None);
    assert_eq!(state.1.as_deref(), Some("2026-08-22T10:00:05Z"));
    assert_eq!((state.2, state.3), (5, 4));
    let events = store
        .test_connection()
        .prepare("SELECT event_type FROM audit_events WHERE lease_id = ?1 ORDER BY sequence")
        .and_then(|mut statement| {
            statement
                .query_map([lease_id.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_else(|error| panic!("renewal audit: {error}"));
    assert_eq!(
        events,
        [
            "lease.requested",
            "lease.activated",
            "lease.renewing",
            "lease.renewed"
        ]
    );
}

#[test]
fn policy_mode_mismatch_commits_only_high_water_and_does_not_latch_cleanup() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FB7");
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, requested_version) = begin(&mut store, &request, 100);
    let exclusive = effective_policy(
        &request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [2, 3, 4, 5],
    );
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        requested_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let active = store
        .activate_requested(
            &request_control,
            &exclusive,
            resolution('6', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("activate: {error:?}"));
    let active_version = active
        .successful_row_version()
        .unwrap_or_else(|| panic!("active version"));
    let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    let shared = effective_policy(
        &request,
        &authenticated_caller,
        &authenticated_host,
        AutomationConcurrencyMode::Shared,
        IsolationClassification::CredentialIsolated,
        Some(SharedStateIsolationRequirement::Stateless),
        [2, 3, 4, 5],
    );
    let denied = store
        .begin_renewal(
            &lease_id,
            active_version,
            &lease_control,
            &shared,
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        )
        .unwrap_or_else(|error| panic!("mode mismatch: {error:?}"));
    assert_eq!(
        denied.domain_result(),
        &Err(LeaseDomainError::PolicyBindingMismatch)
    );
    let after_error = store
        .test_connection()
        .query_row(
            "SELECT l.status, l.row_version, l.next_audit_sequence,
                    c.monotonic_high_water_nanos
             FROM leases l JOIN lease_runtime_clocks c USING (lease_id)",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("mode projection: {error}"));
    assert_eq!(
        after_error,
        ("ACTIVE".to_owned(), 3, 3, 102_u128.to_be_bytes().to_vec())
    );
    let renewed = store
        .begin_renewal(
            &lease_id,
            3,
            &lease_control,
            &exclusive,
            &clock(&store, "2026-08-22T10:00:05Z", 103),
        )
        .unwrap_or_else(|error| panic!("renew after policy mismatch: {error:?}"));
    assert!(renewed.domain_result().is_ok());
}

#[test]
fn activation_commit_error_retains_exclusive_resource_and_latches_recovery() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FB8");
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, requested_version) = begin(&mut store, &request, 100);
    let control = AuthenticatedRequestControl::new(
        &lease_id,
        requested_version,
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
        [2, 3, 4, 5],
    );
    store
        .test_connection()
        .commit_hook(Some(|| true))
        .unwrap_or_else(|error| panic!("commit hook: {error}"));
    assert!(matches!(
        store.activate_requested(
            &control,
            &policy,
            resolution('7', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        ),
        Err(StoreError::DatabaseUnavailable)
    ));
    store
        .test_connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap_or_else(|error| panic!("clear commit hook: {error}"));
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_resource_lock(&fixture.profile.profile_uid),
            true,
        )
        .is_err(),
        "commit-attempt ambiguity must retain the exclusive resource guard"
    );
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("fence presence: {error}"))
    );
    assert!(matches!(
        store.begin_acquire(
            &request,
            &authenticated_caller,
            &authenticated_host,
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        ),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(matches!(
        store.retry_profile_fence_cleanup(&fixture.profile.profile_uid),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_resource_lock(&fixture.profile.profile_uid),
            true,
        )
        .is_err(),
        "same-process retry must not release a commit-uncertain resource"
    );
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("fence after retry: {error}"))
    );
}
