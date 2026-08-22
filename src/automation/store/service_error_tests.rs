use crate::{
    automation::{
        contracts::{IsolationClassification, LeaseReasonCode, LeaseStatus},
        lease::{ClockSample, LeaseDomainError, MonotonicMoment, ServiceClockGeneration},
        policy::test_support::effective_policy,
        store::AuthenticatedRequestControl,
    },
    model::AutomationConcurrencyMode,
};

use super::activation_lifecycle_tests::{Fixture, begin, caller, clock, host, resolution, stamp};

fn active(
    fixture: &Fixture,
    store: &mut super::ReadyStore,
    id: &str,
) -> (crate::automation::contracts::LeaseId, u64) {
    let request = fixture.request(id);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let (lease_id, requested_version) = begin(store, &request, 100);
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        requested_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let activated = store
        .activate_requested(
            &request_control,
            &effective_policy(
                &request,
                &authenticated_caller,
                &authenticated_host,
                AutomationConcurrencyMode::Exclusive,
                IsolationClassification::CredentialIsolated,
                None,
                [1, 1, 1, 1],
            ),
            resolution('E', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("activate service case: {error:?}"));
    (
        lease_id,
        activated
            .successful_row_version()
            .unwrap_or_else(|| panic!("active version")),
    )
}

fn projection(
    store: &super::ReadyStore,
    lease_id: &crate::automation::contracts::LeaseId,
) -> (String, i64, Vec<u8>, i64, String, String, String, i64) {
    store
        .test_connection()
        .query_row(
            "SELECT l.status, l.row_version, c.monotonic_high_water_nanos,
                    l.next_audit_sequence,
                    (SELECT event_type FROM audit_events a WHERE a.lease_id = l.lease_id
                     ORDER BY sequence DESC LIMIT 1),
                    (SELECT actor FROM audit_events a WHERE a.lease_id = l.lease_id
                     ORDER BY sequence DESC LIMIT 1),
                    coalesce(l.reason_code, ''),
                    (SELECT count(*) FROM capacity_reservations r
                     WHERE r.lease_id = l.lease_id AND r.state = 'RELEASED')
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
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("service projection: {error}"))
}

#[test]
fn invalid_service_revoke_and_error_reasons_commit_high_water_before_reason_error() {
    for (index, mark_error) in [false, true].into_iter().enumerate() {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let (lease_id, row_version) = active(
            &fixture,
            &mut store,
            &format!("01ARZ3NDEKTSV4RRFFQ69G5FE{index}"),
        );
        let result = if mark_error {
            store.mark_error(
                &lease_id,
                row_version,
                LeaseReasonCode::Completed,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
        } else {
            store.revoke_by_service(
                &lease_id,
                row_version,
                LeaseReasonCode::Completed,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
        }
        .unwrap_or_else(|error| panic!("invalid service reason: {error:?}"));
        assert_eq!(
            result.domain_result(),
            &Err(LeaseDomainError::InvalidReason {
                status: if mark_error {
                    LeaseStatus::Error
                } else {
                    LeaseStatus::Revoked
                },
                reason: LeaseReasonCode::Completed,
            })
        );
        assert_eq!(
            projection(&store, &lease_id),
            (
                "ACTIVE".to_owned(),
                3,
                102_u128.to_be_bytes().to_vec(),
                3,
                "lease.activated".to_owned(),
                "service".to_owned(),
                String::new(),
                0,
            )
        );
    }
}

#[test]
fn invalid_service_reasons_still_commit_due_expiry_and_release_capacity() {
    for (index, mark_error) in [false, true].into_iter().enumerate() {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let (lease_id, row_version) = active(
            &fixture,
            &mut store,
            &format!("01ARZ3NDEKTSV4RRFFQ69G5FE{}", index + 2),
        );
        let due = clock(&store, "2026-08-22T10:15:02Z", 900_000_000_100);
        let result = if mark_error {
            store.mark_error(&lease_id, row_version, LeaseReasonCode::Completed, &due)
        } else {
            store.revoke_by_service(&lease_id, row_version, LeaseReasonCode::Completed, &due)
        }
        .unwrap_or_else(|error| panic!("due invalid service reason: {error:?}"));
        assert!(matches!(
            result.domain_result(),
            Err(LeaseDomainError::InvalidReason {
                reason: LeaseReasonCode::Completed,
                ..
            })
        ));
        assert_eq!(
            projection(&store, &lease_id),
            (
                "EXPIRED".to_owned(),
                3,
                900_000_000_100_u128.to_be_bytes().to_vec(),
                4,
                "lease.expired".to_owned(),
                "service".to_owned(),
                "lease-expired".to_owned(),
                4,
            )
        );
    }
}

#[test]
fn invalid_service_clock_does_not_change_state_even_when_reason_is_invalid() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let (lease_id, row_version) = active(&fixture, &mut store, "01ARZ3NDEKTSV4RRFFQ69G5FE4");
    let before = projection(&store, &lease_id);
    let invalid = ClockSample::new(
        stamp("2026-08-22T10:00:04Z"),
        MonotonicMoment::from_nanoseconds(102),
        ServiceClockGeneration::from_value(999),
    );
    let result = store
        .revoke_by_service(&lease_id, row_version, LeaseReasonCode::Completed, &invalid)
        .unwrap_or_else(|error| panic!("invalid clock/reason: {error:?}"));
    assert!(matches!(
        result.domain_result(),
        Err(LeaseDomainError::InvalidReason { .. })
    ));
    assert_eq!(projection(&store, &lease_id), before);
}
