use core::str::FromStr;

use crate::{
    automation::{
        contracts::{
            AutomationErrorCode, CallerSubject, IsolationClassification, LeaseId, LeaseReasonCode,
        },
        lease::LeaseDomainError,
        policy::{EffectivePolicy, test_support::effective_policy},
        store::{AuthenticatedRequestControl, CommittedMutation},
    },
    config::{acquire_profile_lock, profile_automation_fence_presence},
    model::AutomationConcurrencyMode,
};

use super::{
    activation_lifecycle_tests::{Fixture, begin, caller, clock, control, host, resolution},
    lifecycle_types::NonCapacityRefusal,
};

fn foreign_caller() -> CallerSubject {
    CallerSubject::from_str("caller:foreign-controller")
        .unwrap_or_else(|error| panic!("foreign caller: {error:?}"))
}

fn absent_id() -> LeaseId {
    LeaseId::parse("lease_0000000000000000000000000Z")
        .unwrap_or_else(|error| panic!("absent lease id: {error}"))
}

type GraphRow = (String, String, i64, i64, Vec<u8>, i64, i64);

fn graph(store: &super::ReadyStore) -> Vec<GraphRow> {
    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT l.lease_id, l.status, l.row_version, l.next_audit_sequence,
                    c.monotonic_high_water_nanos,
                    (SELECT count(*) FROM audit_events a WHERE a.lease_id = l.lease_id),
                    (SELECT count(*) FROM capacity_reservations r WHERE r.lease_id = l.lease_id)
             FROM leases l JOIN lease_runtime_clocks c USING (lease_id) ORDER BY l.lease_id",
        )
        .unwrap_or_else(|error| panic!("oracle graph statement: {error}"));
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .unwrap_or_else(|error| panic!("oracle graph query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("oracle graph rows: {error}"))
}

fn denied_surface<T>(result: &CommittedMutation<T>, lease_id: &LeaseId) -> (String, String) {
    assert_eq!(
        result.domain_result().as_ref().err(),
        Some(&LeaseDomainError::CallerUnauthorized)
    );
    assert!(result.successful_response().is_none());
    assert!(result.successful_row_version().is_none());
    assert!(!result.cleanup_deferred());
    let error = result
        .automation_error(None, lease_id)
        .unwrap_or_else(|store_error| panic!("wire projection: {store_error:?}"))
        .unwrap_or_else(|| panic!("wire denial"));
    assert_eq!(error.code, AutomationErrorCode::CallerUnauthorized);
    assert!(error.lease_id.is_none());
    error
        .validate()
        .unwrap_or_else(|validation| panic!("wire validation: {validation:?}"));
    (
        format!("{result:?}"),
        serde_json::to_string(&error).unwrap_or_else(|error| panic!("wire JSON: {error}")),
    )
}

fn request_policy(
    _fixture: &Fixture,
    request: &crate::automation::contracts::IdentityLeaseRequest,
) -> EffectivePolicy {
    effective_policy(
        request,
        &caller(),
        &host(),
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [2, 2, 2, 2],
    )
}

fn rewrite_lease_caller_only(
    store: &super::ReadyStore,
    lease_id: &LeaseId,
    caller: &CallerSubject,
) {
    store
        .test_connection()
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .unwrap_or_else(|error| panic!("disable foreign keys for oracle fixture: {error}"));
    store
        .test_connection()
        .execute(
            "UPDATE leases SET authenticated_caller = ?1 WHERE lease_id = ?2",
            rusqlite::params![caller.as_str(), lease_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("rewrite denormalized caller: {error}"));
    store
        .test_connection()
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap_or_else(|error| panic!("restore foreign keys for oracle fixture: {error}"));
}

fn corrupt_issued_at(store: &super::ReadyStore, lease_id: &LeaseId) {
    store
        .test_connection()
        .execute(
            "UPDATE leases SET issued_at_seconds = issued_at_seconds + 1 WHERE lease_id = ?1",
            [lease_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt issued timestamp: {error}"));
}

#[test]
fn requested_activation_and_refusal_collapse_absent_and_foreign_before_state_or_fs() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FF0");
    let (lease_id, _) = begin(&mut store, &request, 100);
    let absent = absent_id();
    let foreign = foreign_caller();
    let authenticated_host = host();
    let before = graph(&store);
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("requested fence before: {error}"))
    );
    let policy = request_policy(&fixture, &request);
    let resolution = resolution('3', IsolationClassification::CredentialIsolated);
    let refusal = NonCapacityRefusal::from_evaluation(
        crate::automation::contracts::RefusalCode::ProfileNotReady,
    )
    .unwrap_or_else(|| panic!("non-capacity refusal"));
    for expected_version in [0, 1] {
        let absent_control = AuthenticatedRequestControl::new(
            &absent,
            expected_version,
            &foreign,
            &authenticated_host,
        );
        let foreign_control = AuthenticatedRequestControl::new(
            &lease_id,
            expected_version,
            &foreign,
            &authenticated_host,
        );
        let absent_activation = store
            .activate_requested(
                &absent_control,
                &policy,
                resolution.clone(),
                &clock(&store, "2026-08-22T10:00:03Z", 101),
            )
            .unwrap_or_else(|error| panic!("absent activation: {error:?}"));
        let foreign_activation = store
            .activate_requested(
                &foreign_control,
                &policy,
                resolution.clone(),
                &clock(&store, "2026-08-22T10:00:03Z", 101),
            )
            .unwrap_or_else(|error| panic!("foreign activation: {error:?}"));
        assert_eq!(
            denied_surface(&absent_activation, &absent),
            denied_surface(&foreign_activation, &lease_id)
        );
        let absent_refusal = store
            .refuse_requested(
                &absent_control,
                refusal,
                clock(&store, "2026-08-22T10:00:04Z", 102).wall(),
            )
            .unwrap_or_else(|error| panic!("absent refusal: {error:?}"));
        let foreign_refusal = store
            .refuse_requested(
                &foreign_control,
                refusal,
                clock(&store, "2026-08-22T10:00:04Z", 102).wall(),
            )
            .unwrap_or_else(|error| panic!("foreign refusal: {error:?}"));
        assert_eq!(
            denied_surface(&absent_refusal, &absent),
            denied_surface(&foreign_refusal, &lease_id)
        );
    }
    assert_eq!(graph(&store), before);
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("requested fence after: {error}"))
    );
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_resource_lock(&fixture.profile.profile_uid),
            true,
        )
        .is_ok(),
        "requested denials must not acquire the resource lock"
    );
}

fn activate(
    fixture: &Fixture,
    store: &mut super::ReadyStore,
    request: &crate::automation::contracts::IdentityLeaseRequest,
) -> (LeaseId, u64, EffectivePolicy) {
    let policy = request_policy(fixture, request);
    let (lease_id, row_version) = begin(store, request, 100);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        row_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let activated = store
        .activate_requested(
            &request_control,
            &policy,
            resolution('4', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("oracle activation: {error:?}"));
    (
        lease_id,
        activated
            .successful_row_version()
            .unwrap_or_else(|| panic!("active version")),
        policy,
    )
}

#[test]
fn resolved_mutations_collapse_absent_and_foreign_stale_probes_on_every_surface() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FF1");
    let (lease_id, _row_version, policy) = activate(&fixture, &mut store, &request);
    let absent = absent_id();
    let foreign = foreign_caller();
    let authenticated_host = host();
    let foreign_control = control(&request, &foreign, &authenticated_host, 1);
    let before = graph(&store);
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_resource_lock(&fixture.profile.profile_uid),
            true,
        )
        .is_err(),
        "active lease must retain the exclusive resource"
    );

    for expected_version in [0, 1] {
        let absent_renew = store
            .begin_renewal(
                &absent,
                expected_version,
                &foreign_control,
                &policy,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("absent renew: {error:?}"));
        let foreign_renew = store
            .begin_renewal(
                &lease_id,
                expected_version,
                &foreign_control,
                &policy,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("foreign renew: {error:?}"));
        assert_eq!(
            denied_surface(&absent_renew, &absent),
            denied_surface(&foreign_renew, &lease_id)
        );

        let absent_ack = store
            .acknowledge_renewal(
                &absent,
                expected_version,
                &foreign_control,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("absent ack: {error:?}"));
        let foreign_ack = store
            .acknowledge_renewal(
                &lease_id,
                expected_version,
                &foreign_control,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("foreign ack: {error:?}"));
        assert_eq!(
            denied_surface(&absent_ack, &absent),
            denied_surface(&foreign_ack, &lease_id)
        );

        let absent_close = store
            .close_lease(
                &absent,
                expected_version,
                &foreign_control,
                LeaseReasonCode::Completed,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("absent close: {error:?}"));
        let foreign_close = store
            .close_lease(
                &lease_id,
                expected_version,
                &foreign_control,
                LeaseReasonCode::Completed,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("foreign close: {error:?}"));
        assert_eq!(
            denied_surface(&absent_close, &absent),
            denied_surface(&foreign_close, &lease_id)
        );

        let absent_revoke = store
            .revoke_authenticated(
                &absent,
                expected_version,
                &foreign_control,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("absent revoke: {error:?}"));
        let foreign_revoke = store
            .revoke_authenticated(
                &lease_id,
                expected_version,
                &foreign_control,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("foreign revoke: {error:?}"));
        assert_eq!(
            denied_surface(&absent_revoke, &absent),
            denied_surface(&foreign_revoke, &lease_id)
        );
    }
    assert_eq!(graph(&store), before);
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_resource_lock(&fixture.profile.profile_uid),
            true,
        )
        .is_err(),
        "foreign probes must not release the retained resource"
    );
    assert!(
        profile_automation_fence_presence(&fixture.paths, &fixture.profile.profile_uid)
            .unwrap_or_else(|error| panic!("active fence after: {error}"))
    );
}

#[test]
fn requested_foreign_semantic_corruption_is_indistinguishable_from_absence() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FF2");
    let (lease_id, row_version) = begin(&mut store, &request, 100);
    let absent = absent_id();
    let foreign = foreign_caller();
    let authenticated_host = host();
    rewrite_lease_caller_only(&store, &lease_id, &foreign);
    let before = graph(&store);
    let absent_control =
        AuthenticatedRequestControl::new(&absent, row_version, &foreign, &authenticated_host);
    let foreign_control =
        AuthenticatedRequestControl::new(&lease_id, row_version, &foreign, &authenticated_host);
    let policy = request_policy(&fixture, &request);
    let absent_result = store
        .activate_requested(
            &absent_control,
            &policy,
            resolution('5', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("absent corrupt-request probe: {error:?}"));
    let foreign_result = store
        .activate_requested(
            &foreign_control,
            &policy,
            resolution('5', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("foreign corrupt-request probe: {error:?}"));
    assert_eq!(
        denied_surface(&absent_result, &absent),
        denied_surface(&foreign_result, &lease_id)
    );
    assert_eq!(graph(&store), before);

    rewrite_lease_caller_only(&store, &lease_id, &caller());
    corrupt_issued_at(&store, &lease_id);
    let owner = caller();
    let owner_control =
        AuthenticatedRequestControl::new(&lease_id, row_version, &owner, &authenticated_host);
    assert!(matches!(
        store.activate_requested(
            &owner_control,
            &policy,
            resolution('5', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        ),
        Err(super::StoreError::IntegrityCheckFailed)
    ));
}

#[test]
fn resolved_foreign_semantic_corruption_is_indistinguishable_from_absence() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FF3");
    let (lease_id, row_version, policy) = activate(&fixture, &mut store, &request);
    let absent = absent_id();
    let foreign = foreign_caller();
    let authenticated_host = host();
    let foreign_control = control(&request, &foreign, &authenticated_host, 1);
    rewrite_lease_caller_only(&store, &lease_id, &foreign);
    let before = graph(&store);

    let absent = store
        .begin_renewal(
            &absent,
            row_version,
            &foreign_control,
            &policy,
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        )
        .unwrap_or_else(|error| panic!("absent corrupt-resolved probe: {error:?}"));
    let existing = store
        .begin_renewal(
            &lease_id,
            row_version,
            &foreign_control,
            &policy,
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        )
        .unwrap_or_else(|error| panic!("foreign corrupt-resolved probe: {error:?}"));
    assert_eq!(
        denied_surface(&absent, &absent_id()),
        denied_surface(&existing, &lease_id)
    );
    assert_eq!(graph(&store), before);

    rewrite_lease_caller_only(&store, &lease_id, &caller());
    corrupt_issued_at(&store, &lease_id);
    let owner = caller();
    let owner_host = host();
    let owner_control = control(&request, &owner, &owner_host, 1);
    assert!(matches!(
        store.begin_renewal(
            &lease_id,
            row_version,
            &owner_control,
            &policy,
            &clock(&store, "2026-08-22T10:00:05Z", 103),
        ),
        Err(super::StoreError::IntegrityCheckFailed)
    ));
}
