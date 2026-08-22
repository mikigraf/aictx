use core::str::FromStr;

use crate::{
    automation::{
        contracts::{CallerSubject, HostIdentity, IsolationClassification},
        lease::{ClockSample, LeaseDomainError, MonotonicMoment, ServiceClockGeneration},
        policy::{EffectivePolicy, test_support::effective_policy},
        store::{AuthenticatedRequestControl, StoreError},
    },
    config::profile_automation_fence_presence,
    model::AutomationConcurrencyMode,
};

use super::activation_lifecycle_tests::{
    Fixture, begin, caller, clock, control, host, resolution, stamp,
};

fn policy(request: &crate::automation::contracts::IdentityLeaseRequest) -> EffectivePolicy {
    effective_policy(
        request,
        &caller(),
        &host(),
        AutomationConcurrencyMode::Exclusive,
        IsolationClassification::CredentialIsolated,
        None,
        [4, 4, 4, 4],
    )
}

fn active(
    store: &mut super::ReadyStore,
    request: &crate::automation::contracts::IdentityLeaseRequest,
) -> (crate::automation::contracts::LeaseId, u64) {
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
            &policy(request),
            resolution('F', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("guard activation: {error:?}"));
    (
        lease_id,
        activated
            .successful_row_version()
            .unwrap_or_else(|| panic!("guard active version")),
    )
}

fn projection(
    store: &super::ReadyStore,
    lease_id: &crate::automation::contracts::LeaseId,
) -> (String, i64, i64, Vec<u8>, i64, i64) {
    store
        .test_connection()
        .query_row(
            "SELECT l.status, l.row_version, l.next_audit_sequence,
                    c.monotonic_high_water_nanos,
                    (SELECT count(*) FROM audit_events a WHERE a.lease_id = l.lease_id),
                    (SELECT count(*) FROM capacity_reservations r
                     WHERE r.lease_id = l.lease_id AND r.state <> 'RELEASED')
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
        .unwrap_or_else(|error| panic!("guard projection: {error}"))
}

#[test]
fn authority_bearing_error_outcomes_require_exact_guards_before_clock_mutation() {
    for (index, operation) in [
        "renew-wrong-host",
        "ack-active-wrong-host",
        "renew-invalid-clock",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FL{index}"));
        let (lease_id, row_version) = active(&mut store, &request);
        let before = projection(&store, &lease_id);
        store.core.release_resource(&lease_id);
        let authenticated_caller = caller();
        let authenticated_host = host();
        let wrong_host = HostIdentity::from_str("host:wrong-owner-host")
            .unwrap_or_else(|error| panic!("wrong host: {error:?}"));
        let wrong_control = control(&request, &authenticated_caller, &wrong_host, 1);
        let valid_control = control(&request, &authenticated_caller, &authenticated_host, 1);
        let failed = match operation {
            "renew-wrong-host" => store
                .begin_renewal(
                    &lease_id,
                    row_version,
                    &wrong_control,
                    &policy(&request),
                    &clock(&store, "2026-08-22T10:00:04Z", 102),
                )
                .map(|_| ()),
            "ack-active-wrong-host" => store
                .acknowledge_renewal(
                    &lease_id,
                    row_version,
                    &wrong_control,
                    &clock(&store, "2026-08-22T10:00:04Z", 102),
                )
                .map(|_| ()),
            "renew-invalid-clock" => store
                .begin_renewal(
                    &lease_id,
                    row_version,
                    &valid_control,
                    &policy(&request),
                    &ClockSample::new(
                        stamp("2026-08-22T10:00:04Z"),
                        MonotonicMoment::from_nanoseconds(102),
                        ServiceClockGeneration::from_value(999),
                    ),
                )
                .map(|_| ()),
            _ => unreachable!(),
        };
        assert!(
            matches!(failed, Err(StoreError::RecoveryRequired)),
            "{operation}"
        );
        assert_eq!(projection(&store, &lease_id), before, "{operation}");
    }
}

#[test]
fn exact_renewing_control_mismatch_revokes_without_guards() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FL3");
    let (lease_id, row_version) = active(&mut store, &request);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    let renewing = store
        .begin_renewal(
            &lease_id,
            row_version,
            &lease_control,
            &policy(&request),
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        )
        .unwrap_or_else(|error| panic!("guard renewal: {error:?}"));
    let renewing_version = renewing
        .successful_row_version()
        .unwrap_or_else(|| panic!("guard renewing version"));
    store.core.release_resource(&lease_id);
    let wrong_host = HostIdentity::from_str("host:wrong-owner-host")
        .unwrap_or_else(|error| panic!("wrong host: {error:?}"));
    let wrong_control = control(&request, &authenticated_caller, &wrong_host, 2);
    let denied = store
        .acknowledge_renewal(
            &lease_id,
            renewing_version,
            &wrong_control,
            &clock(&store, "2026-08-22T10:00:05Z", 103),
        )
        .unwrap_or_else(|error| panic!("guardless bad ack: {error:?}"));
    assert_eq!(denied.domain_result(), &Err(LeaseDomainError::HostMismatch));
    assert_eq!(projection(&store, &lease_id).0, "REVOKED");
    assert_eq!(projection(&store, &lease_id).5, 0);
    assert!(
        !profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
            .unwrap_or_else(|error| panic!("guardless revoke fence: {error}"))
    );
}

#[test]
fn due_deadline_terminalizes_without_resource_guard() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FL4");
    let (lease_id, row_version) = active(&mut store, &request);
    store.core.release_resource(&lease_id);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    let expired = store
        .begin_renewal(
            &lease_id,
            row_version,
            &lease_control,
            &policy(&request),
            &clock(&store, "2026-08-22T11:00:00Z", 4_000_000_000_000),
        )
        .unwrap_or_else(|error| panic!("guardless expiry: {error:?}"));
    assert_eq!(
        expired.domain_result(),
        &Err(LeaseDomainError::LeaseExpired)
    );
    assert_eq!(projection(&store, &lease_id).0, "EXPIRED");
    assert_eq!(projection(&store, &lease_id).5, 0);
}

#[test]
fn cleanup_latch_preserves_identity_precedence_and_blocks_valid_authority_changes() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FL5");
    let (lease_id, row_version) = active(&mut store, &request);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let wrong_host = HostIdentity::from_str("host:wrong-owner-host")
        .unwrap_or_else(|error| panic!("wrong host: {error:?}"));
    let wrong_control = control(&request, &authenticated_caller, &wrong_host, 1);
    let valid_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    let before = projection(&store, &lease_id);
    store
        .core
        .latch_profile_cleanup(request.profile_uid.clone());

    let wrong_begin = store
        .begin_renewal(
            &lease_id,
            row_version,
            &wrong_control,
            &policy(&request),
            &clock(&store, "2026-08-22T11:00:00Z", 4_000_000_000_000),
        )
        .unwrap_or_else(|error| panic!("latched wrong-host begin: {error:?}"));
    assert_eq!(
        wrong_begin.domain_result(),
        &Err(LeaseDomainError::HostMismatch)
    );
    let wrong_ack = store
        .acknowledge_renewal(
            &lease_id,
            row_version,
            &wrong_control,
            &clock(&store, "2026-08-22T11:00:00Z", 4_000_000_000_000),
        )
        .unwrap_or_else(|error| panic!("latched wrong-host active ack: {error:?}"));
    assert_eq!(
        wrong_ack.domain_result(),
        &Err(LeaseDomainError::HostMismatch)
    );
    assert_eq!(projection(&store, &lease_id), before);
    assert!(matches!(
        store.begin_renewal(
            &lease_id,
            row_version,
            &valid_control,
            &policy(&request),
            &clock(&store, "2026-08-22T11:00:00Z", 4_000_000_000_000),
        ),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(matches!(
        store.acknowledge_renewal(
            &lease_id,
            row_version,
            &valid_control,
            &clock(&store, "2026-08-22T11:00:00Z", 4_000_000_000_000),
        ),
        Err(StoreError::RecoveryRequired)
    ));
    assert_eq!(projection(&store, &lease_id), before);
}

#[test]
fn exact_renewing_mismatch_still_revokes_under_cleanup_latch() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FL6");
    let (lease_id, row_version) = active(&mut store, &request);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let valid_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    let renewing = store
        .begin_renewal(
            &lease_id,
            row_version,
            &valid_control,
            &policy(&request),
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        )
        .unwrap_or_else(|error| panic!("latched-case renewal: {error:?}"));
    let renewing_version = renewing
        .successful_row_version()
        .unwrap_or_else(|| panic!("latched-case renewing version"));
    store
        .core
        .latch_profile_cleanup(request.profile_uid.clone());
    let wrong_host = HostIdentity::from_str("host:wrong-owner-host")
        .unwrap_or_else(|error| panic!("wrong host: {error:?}"));
    let wrong_control = control(&request, &authenticated_caller, &wrong_host, 2);
    let denied = store
        .acknowledge_renewal(
            &lease_id,
            renewing_version,
            &wrong_control,
            &ClockSample::new(
                stamp("2026-08-22T10:00:05Z"),
                MonotonicMoment::from_nanoseconds(1),
                ServiceClockGeneration::from_value(999),
            ),
        )
        .unwrap_or_else(|error| panic!("latched bad ack: {error:?}"));
    assert_eq!(denied.domain_result(), &Err(LeaseDomainError::HostMismatch));
    let after = projection(&store, &lease_id);
    assert_eq!(after.0, "REVOKED");
    assert_eq!(after.5, 0);
    assert!(
        profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
            .unwrap_or_else(|error| panic!("latched revoke marker: {error}"))
    );
}

#[test]
fn renewing_ack_control_mismatch_requires_exact_nonzero_cas_before_revocation() {
    for (identity_index, identity) in ["host", "generation", "caller"].into_iter().enumerate() {
        for (version_index, version_kind) in ["zero", "stale", "exact"].into_iter().enumerate() {
            let fixture = Fixture::new();
            let mut store = fixture.ready();
            let suffix =
                char::from(b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[identity_index * 3 + version_index]);
            let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FM{suffix}"));
            let (lease_id, row_version) = active(&mut store, &request);
            let authenticated_caller = caller();
            let authenticated_host = host();
            let valid_control = control(&request, &authenticated_caller, &authenticated_host, 1);
            let renewing = store
                .begin_renewal(
                    &lease_id,
                    row_version,
                    &valid_control,
                    &policy(&request),
                    &clock(&store, "2026-08-22T10:00:04Z", 102),
                )
                .unwrap_or_else(|error| panic!("CAS matrix renewal: {error:?}"));
            let renewing_version = renewing
                .successful_row_version()
                .unwrap_or_else(|| panic!("CAS matrix renewing version"));
            let wrong_host = HostIdentity::from_str("host:wrong-owner-host")
                .unwrap_or_else(|error| panic!("wrong host: {error:?}"));
            let foreign = CallerSubject::from_str("caller:foreign-controller")
                .unwrap_or_else(|error| panic!("foreign caller: {error:?}"));
            let supplied_caller = if identity == "caller" {
                &foreign
            } else {
                &authenticated_caller
            };
            let supplied_host = if identity == "host" {
                &wrong_host
            } else {
                &authenticated_host
            };
            let bad_control = control(
                &request,
                supplied_caller,
                supplied_host,
                if identity == "generation" { 1 } else { 2 },
            );
            let expected_version = match version_kind {
                "zero" => 0,
                "stale" => renewing_version - 1,
                "exact" => renewing_version,
                _ => unreachable!(),
            };
            let before = projection(&store, &lease_id);
            store.core.release_resource(&lease_id);
            let denied = store
                .acknowledge_renewal(
                    &lease_id,
                    expected_version,
                    &bad_control,
                    &ClockSample::new(
                        stamp("2026-08-22T10:00:05Z"),
                        MonotonicMoment::from_nanoseconds(1),
                        ServiceClockGeneration::from_value(999),
                    ),
                )
                .unwrap_or_else(|error| panic!("CAS matrix {identity}/{version_kind}: {error:?}"));
            let expected_error = match identity {
                "host" => LeaseDomainError::HostMismatch,
                "generation" => LeaseDomainError::GenerationMismatch,
                "caller" => LeaseDomainError::CallerUnauthorized,
                _ => unreachable!(),
            };
            assert_eq!(denied.domain_result(), &Err(expected_error.clone()));
            if version_kind == "exact" {
                let after = projection(&store, &lease_id);
                assert_eq!(after.0, "REVOKED", "{identity}");
                assert_eq!(after.1, before.1 + 1, "{identity}");
                assert_eq!(after.4, before.4 + 1, "{identity}");
                assert_eq!(after.5, 0, "{identity}");
                let retry = store
                    .acknowledge_renewal(
                        &lease_id,
                        expected_version,
                        &bad_control,
                        &ClockSample::new(
                            stamp("2026-08-22T10:00:06Z"),
                            MonotonicMoment::from_nanoseconds(1),
                            ServiceClockGeneration::from_value(999),
                        ),
                    )
                    .unwrap_or_else(|error| panic!("CAS matrix retry: {error:?}"));
                assert_eq!(retry.domain_result(), &Err(expected_error));
                assert_eq!(projection(&store, &lease_id), after);
            } else {
                assert_eq!(
                    projection(&store, &lease_id),
                    before,
                    "{identity}/{version_kind}"
                );
            }
        }
    }
}
