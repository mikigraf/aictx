use crate::{
    automation::{
        contracts::{IsolationClassification, LeaseStatus, RefusalCode},
        lease::{ClockSample, LeaseDomainError, MonotonicMoment, ServiceClockGeneration},
        policy::test_support::effective_policy,
        store::AuthenticatedRequestControl,
    },
    model::AutomationConcurrencyMode,
};

use super::activation_lifecycle_tests::{Fixture, begin, caller, clock, host, resolution, stamp};

fn fill_profile_capacity(fixture: &Fixture, store: &mut super::ReadyStore, id: &str) {
    let request = fixture.request(id);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, row_version) = begin(store, &request, 100);
    let control = AuthenticatedRequestControl::new(
        &lease_id,
        row_version,
        &authenticated_caller,
        &authenticated_host,
    );
    store
        .activate_requested(
            &control,
            &effective_policy(
                &request,
                &authenticated_caller,
                &authenticated_host,
                AutomationConcurrencyMode::Exclusive,
                IsolationClassification::CredentialIsolated,
                None,
                [1, 1, 1, 1],
            ),
            resolution('8', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("capacity owner activation: {error:?}"));
}

fn requested_projection(
    store: &super::ReadyStore,
    lease_id: &crate::automation::contracts::LeaseId,
) -> (String, i64, i64, Vec<u8>, i64, i64) {
    store
        .test_connection()
        .query_row(
            "SELECT l.status, l.row_version, l.next_audit_sequence,
                    c.monotonic_high_water_nanos,
                    (SELECT count(*) FROM audit_events a WHERE a.lease_id = l.lease_id),
                    (SELECT count(*) FROM capacity_reservations r WHERE r.lease_id = l.lease_id)
             FROM leases l JOIN lease_runtime_clocks c USING (lease_id)
             WHERE l.lease_id = ?1",
            [lease_id.as_str()],
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
        .unwrap_or_else(|error| panic!("requested projection: {error}"))
}

#[test]
fn source_digest_mismatch_precedes_full_capacity_without_resource_or_refusal() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    fill_profile_capacity(&fixture, &mut store, "01ARZ3NDEKTSV4RRFFQ69G5FB9");
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FBA");
    let other = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FBB");
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, row_version) = begin(&mut store, &request, 200);
    let control = AuthenticatedRequestControl::new(
        &lease_id,
        row_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let denied = store
        .activate_requested(
            &control,
            &effective_policy(
                &other,
                &authenticated_caller,
                &authenticated_host,
                AutomationConcurrencyMode::Exclusive,
                IsolationClassification::CredentialIsolated,
                None,
                [1, 1, 1, 1],
            ),
            resolution('9', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:04Z", 201),
        )
        .unwrap_or_else(|error| panic!("digest mismatch: {error:?}"));
    assert_eq!(
        denied.domain_result(),
        &Err(LeaseDomainError::PolicyBindingMismatch)
    );
    assert_eq!(
        requested_projection(&store, &lease_id),
        (
            "REQUESTED".to_owned(),
            2,
            2,
            201_u128.to_be_bytes().to_vec(),
            1,
            0,
        )
    );
    assert_eq!(
        store
            .test_connection()
            .query_row(
                "SELECT count(*) FROM capacity_reservations WHERE state = 'HELD'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("held capacity: {error}")),
        4
    );
}

#[test]
fn requested_ttl_above_each_policy_ceiling_is_a_binding_error_before_capacity() {
    for (index, ceiling) in ["maximum-ttl", "maximum-session"].into_iter().enumerate() {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        fill_profile_capacity(&fixture, &mut store, "01ARZ3NDEKTSV4RRFFQ69G5FH0");
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FH{}", index + 1));
        let authenticated_caller = caller();
        let authenticated_host = host();
        let (lease_id, row_version) = begin(&mut store, &request, 200);
        let control = AuthenticatedRequestControl::new(
            &lease_id,
            row_version,
            &authenticated_caller,
            &authenticated_host,
        );
        let mut invalid = effective_policy(
            &request,
            &authenticated_caller,
            &authenticated_host,
            AutomationConcurrencyMode::Exclusive,
            IsolationClassification::CredentialIsolated,
            None,
            [1, 1, 1, 1],
        );
        match ceiling {
            "maximum-ttl" => invalid.maximum_ttl_seconds = invalid.requested_ttl_seconds - 1,
            "maximum-session" => {
                invalid.maximum_session_seconds = invalid.requested_ttl_seconds - 1;
            }
            _ => unreachable!(),
        }
        let denied = store
            .activate_requested(
                &control,
                &invalid,
                resolution('D', IsolationClassification::CredentialIsolated),
                &clock(&store, "2026-08-22T10:00:04Z", 201),
            )
            .unwrap_or_else(|error| panic!("invalid {ceiling}: {error:?}"));
        assert_eq!(
            denied.domain_result(),
            &Err(LeaseDomainError::PolicyBindingMismatch)
        );
        assert_eq!(
            requested_projection(&store, &lease_id),
            (
                "REQUESTED".to_owned(),
                2,
                2,
                201_u128.to_be_bytes().to_vec(),
                1,
                0,
            ),
            "{ceiling}"
        );
    }
}

#[test]
fn invalid_activation_clocks_precede_full_capacity_and_are_read_only() {
    for (id, sample, expected) in [
        (
            "01ARZ3NDEKTSV4RRFFQ69G5FBC",
            ClockSample::new(
                stamp("2026-08-22T10:00:04Z"),
                MonotonicMoment::from_nanoseconds(201),
                ServiceClockGeneration::from_value(999),
            ),
            LeaseDomainError::ClockGenerationMismatch,
        ),
        (
            "01ARZ3NDEKTSV4RRFFQ69G5FBD",
            ClockSample::new(
                stamp("2026-08-22T10:00:04Z"),
                MonotonicMoment::from_nanoseconds(199),
                ServiceClockGeneration::from_value(1),
            ),
            LeaseDomainError::MonotonicRegression,
        ),
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        fill_profile_capacity(&fixture, &mut store, "01ARZ3NDEKTSV4RRFFQ69G5FBE");
        let request = fixture.request(id);
        let authenticated_caller = caller();
        let authenticated_host = host();
        let (lease_id, row_version) = begin(&mut store, &request, 200);
        let before = requested_projection(&store, &lease_id);
        let control = AuthenticatedRequestControl::new(
            &lease_id,
            row_version,
            &authenticated_caller,
            &authenticated_host,
        );
        let denied = store
            .activate_requested(
                &control,
                &effective_policy(
                    &request,
                    &authenticated_caller,
                    &authenticated_host,
                    AutomationConcurrencyMode::Exclusive,
                    IsolationClassification::CredentialIsolated,
                    None,
                    [1, 1, 1, 1],
                ),
                resolution('A', IsolationClassification::CredentialIsolated),
                &sample,
            )
            .unwrap_or_else(|error| panic!("invalid clock activation: {error:?}"));
        assert_eq!(denied.domain_result(), &Err(expected));
        assert_eq!(requested_projection(&store, &lease_id), before);
    }
}

#[test]
fn valid_clock_plus_resource_busy_persists_profile_not_ready_and_high_water() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let authenticated_caller = caller();
    let authenticated_host = host();
    let first = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FBF");
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
                [10, 10, 10, 10],
            ),
            resolution('B', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("first activation: {error:?}"));

    let second = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FBG");
    let (second_id, second_version) = begin(&mut store, &second, 200);
    let second_control = AuthenticatedRequestControl::new(
        &second_id,
        second_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let refused = store
        .activate_requested(
            &second_control,
            &effective_policy(
                &second,
                &authenticated_caller,
                &authenticated_host,
                AutomationConcurrencyMode::Exclusive,
                IsolationClassification::CredentialIsolated,
                None,
                [10, 10, 10, 10],
            ),
            resolution('C', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:04Z", 201),
        )
        .unwrap_or_else(|error| panic!("resource refusal: {error:?}"));
    assert_eq!(
        refused
            .successful_response()
            .map(|response| (response.status, response.refusal_code)),
        Some((LeaseStatus::Refused, Some(RefusalCode::ProfileNotReady)))
    );
    assert_eq!(
        store.test_connection().query_row(
            "SELECT c.monotonic_high_water_nanos,
                        (SELECT count(*) FROM capacity_reservations r
                         WHERE r.lease_id = l.lease_id),
                        (SELECT count(*) FROM audit_events a
                         WHERE a.lease_id = l.lease_id AND a.event_type = 'lease.refused')
                 FROM leases l JOIN lease_runtime_clocks c USING (lease_id)
                 WHERE l.lease_id = ?1",
            [second_id.as_str()],
            |row| Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?
            )),
        ),
        Ok((201_u128.to_be_bytes().to_vec(), 0, 1))
    );
}
