use core::str::FromStr;

use crate::{
    automation::{
        contracts::{LeaseStatus, ProfileRef, Provider, RefusalCode},
        store::{AuthenticatedRequestControl, StoreError},
    },
    config::profile_automation_fence_presence,
};

use super::{
    activation_lifecycle_tests::{Fixture, caller, clock, host, stamp},
    lifecycle_types::NonCapacityRefusal,
};

fn row_counts(store: &super::ReadyStore) -> (i64, i64, i64, i64) {
    store
        .test_connection()
        .query_row(
            "SELECT
                (SELECT count(*) FROM lease_requests),
                (SELECT count(*) FROM leases),
                (SELECT count(*) FROM lease_runtime_clocks),
                (SELECT count(*) FROM audit_events WHERE lease_id IS NOT NULL)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap_or_else(|error| panic!("acquire failure counts: {error}"))
}

fn install_failure(store: &super::ReadyStore, body: &str) {
    store
        .test_connection()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_acquire_statement {body}
             BEGIN SELECT RAISE(ABORT, 'injected acquire statement failure'); END;"
        ))
        .unwrap_or_else(|error| panic!("install acquire failure: {error}"));
}

fn clear_failure(store: &super::ReadyStore) {
    store
        .test_connection()
        .execute_batch("DROP TRIGGER temp.fail_acquire_statement;")
        .unwrap_or_else(|error| panic!("drop acquire failure: {error}"));
}

#[test]
fn unseen_begin_rolls_back_each_request_lease_clock_and_audit_insert() {
    for (index, stage) in [
        "BEFORE INSERT ON main.lease_requests",
        "BEFORE INSERT ON main.leases",
        "BEFORE INSERT ON main.lease_runtime_clocks",
        "BEFORE INSERT ON main.audit_events WHEN NEW.event_type = 'lease.requested'",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FQ{index}"));
        assert_eq!(row_counts(&store), (0, 0, 0, 0));
        install_failure(&store, stage);
        assert!(matches!(
            store.begin_acquire(
                &request,
                &caller(),
                &host(),
                &clock(&store, "2026-08-22T10:00:02Z", 100),
            ),
            Err(StoreError::DatabaseUnavailable)
        ));
        clear_failure(&store);
        assert_eq!(row_counts(&store), (0, 0, 0, 0), "{stage}");
        assert!(
            !profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
                .unwrap_or_else(|error| panic!("failed acquire marker: {error}")),
            "orphan marker after {stage}"
        );
        let retry = store
            .begin_acquire(
                &request,
                &caller(),
                &host(),
                &clock(&store, "2026-08-22T10:00:02Z", 100),
            )
            .unwrap_or_else(|error| panic!("acquire retry after {stage}: {error:?}"));
        assert!(!retry.replayed());
    }
}

#[test]
fn immediate_profile_refusal_rolls_back_requested_and_refused_updates_together() {
    for (index, stage) in [
        "BEFORE UPDATE ON main.leases",
        "BEFORE INSERT ON main.audit_events WHEN NEW.event_type = 'lease.refused'",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let mut request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FR{index}"));
        let missing = ProfileRef::from_str("codex:missing-automation-profile")
            .unwrap_or_else(|error| panic!("missing profile ref: {error:?}"));
        request.profile_ref = missing.clone();
        request.work_order_authorization.profile_ref = missing;
        install_failure(&store, stage);
        assert!(matches!(
            store.begin_acquire(
                &request,
                &caller(),
                &host(),
                &clock(&store, "2026-08-22T10:00:02Z", 100),
            ),
            Err(StoreError::DatabaseUnavailable)
        ));
        clear_failure(&store);
        assert_eq!(row_counts(&store), (0, 0, 0, 0), "{stage}");
        assert!(
            !profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
                .unwrap_or_else(|error| panic!("refusal marker: {error}"))
        );
        let retry = store
            .begin_acquire(
                &request,
                &caller(),
                &host(),
                &clock(&store, "2026-08-22T10:00:02Z", 100),
            )
            .unwrap_or_else(|error| panic!("refusal retry after {stage}: {error:?}"));
        assert_eq!(
            retry.outcome().response().refusal_code,
            Some(RefusalCode::ProfileNotFound)
        );
        assert!(!retry.replayed());
    }
}

#[test]
fn bad_unseen_aliases_are_durable_refusals_without_poisoning_a_live_fence() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request_a = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FR3");
    let begun_a = store
        .begin_acquire(
            &request_a,
            &caller(),
            &host(),
            &clock(&store, "2026-08-22T10:00:02Z", 100),
        )
        .unwrap_or_else(|error| panic!("begin retained A: {error:?}"));
    assert_eq!(begun_a.outcome().response().status, LeaseStatus::Requested);
    let a_version = begun_a.row_version();

    for (index, (profile_ref, cross_provider)) in [
        ("codex:missing-automation-profile", false),
        ("claude:cross-provider-profile", true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut bad = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FR{}", index + 4));
        let bad_ref = ProfileRef::from_str(profile_ref)
            .unwrap_or_else(|error| panic!("bad profile ref: {error:?}"));
        bad.profile_ref = bad_ref.clone();
        bad.work_order_authorization.profile_ref = bad_ref;
        if cross_provider {
            bad.provider = Provider::Claude;
            bad.work_order_authorization.provider = Provider::Claude;
        }
        let refused = store
            .begin_acquire(
                &bad,
                &caller(),
                &host(),
                &clock(&store, "2026-08-22T10:00:03Z", 101 + index as u128),
            )
            .unwrap_or_else(|error| panic!("bad alias refusal: {error:?}"));
        assert_eq!(refused.outcome().response().status, LeaseStatus::Refused);
        assert_eq!(
            refused.outcome().response().refusal_code,
            Some(RefusalCode::ProfileNotFound)
        );
        assert!(!store.core.has_cleanup_deferred());
        let replay_a = store
            .begin_acquire(
                &request_a,
                &caller(),
                &host(),
                &clock(&store, "2026-08-22T10:00:04Z", 110 + index as u128),
            )
            .unwrap_or_else(|error| panic!("replay A after bad alias: {error:?}"));
        assert!(replay_a.replayed());
        assert_eq!(replay_a.row_version(), a_version);
        assert_eq!(replay_a.outcome().response().status, LeaseStatus::Requested);
        assert!(
            profile_automation_fence_presence(&fixture.paths, &request_a.profile_uid)
                .unwrap_or_else(|error| panic!("retained A marker: {error}"))
        );
    }
}

#[test]
fn cross_provider_refusal_history_does_not_poison_later_current_profile_readiness() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let mut foreign = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FS0");
    let foreign_ref = ProfileRef::from_str("claude:historical-cross-provider")
        .unwrap_or_else(|error| panic!("foreign profile ref: {error:?}"));
    foreign.profile_ref = foreign_ref.clone();
    foreign.work_order_authorization.profile_ref = foreign_ref;
    foreign.provider = Provider::Claude;
    foreign.work_order_authorization.provider = Provider::Claude;
    let refused = store
        .begin_acquire(
            &foreign,
            &caller(),
            &host(),
            &clock(&store, "2026-08-22T10:00:02Z", 100),
        )
        .unwrap_or_else(|error| panic!("foreign refusal: {error:?}"));
    assert_eq!(refused.outcome().response().status, LeaseStatus::Refused);
    assert_eq!(
        refused.outcome().response().refusal_code,
        Some(RefusalCode::ProfileNotFound)
    );
    assert!(!store.core.has_cleanup_deferred());

    let current = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FS1");
    let begun = store
        .begin_acquire(
            &current,
            &caller(),
            &host(),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("current request after foreign history: {error:?}"));
    assert_eq!(begun.outcome().response().status, LeaseStatus::Requested);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let control = AuthenticatedRequestControl::new(
        begun.outcome().lease_id(),
        begun.row_version(),
        &authenticated_caller,
        &authenticated_host,
    );
    let terminal = store
        .refuse_requested(
            &control,
            NonCapacityRefusal::from_evaluation(RefusalCode::ProfileNotReady)
                .unwrap_or_else(|| panic!("non-capacity refusal")),
            &stamp("2026-08-22T10:00:04Z"),
        )
        .unwrap_or_else(|error| panic!("terminal current request: {error:?}"));
    assert!(terminal.domain_result().is_ok());
    assert!(!store.core.has_cleanup_deferred());
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &current.profile_uid)
            .unwrap_or_else(|error| panic!("cleared marker: {error}"))
    );
    drop(store);
    let reopened = fixture.ready();
    assert_eq!(row_counts(&reopened), (2, 2, 2, 4));
}

#[test]
fn tampered_live_marker_makes_unseen_begin_fail_without_a_database_write() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request_a = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FR6");
    store
        .begin_acquire(
            &request_a,
            &caller(),
            &host(),
            &clock(&store, "2026-08-22T10:00:02Z", 100),
        )
        .unwrap_or_else(|error| panic!("begin marker A: {error:?}"));
    let before = row_counts(&store);
    std::fs::write(
        fixture
            .paths
            .profile_automation_fence(&request_a.profile_uid),
        b"invalid marker\n",
    )
    .unwrap_or_else(|error| panic!("tamper live marker: {error}"));
    let request_b = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FR7");
    assert!(matches!(
        store.begin_acquire(
            &request_b,
            &caller(),
            &host(),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        ),
        Err(StoreError::UnsafeStorage)
    ));
    assert_eq!(row_counts(&store), before);
    assert!(store.core.has_cleanup_deferred());
}
