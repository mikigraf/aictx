use crate::{
    automation::{
        contracts::{
            AutomationAuthMode, HostIdentity, IdentityLeaseRequest, IsolationClassification,
            LeaseStatus, RequestedTtlSeconds,
        },
        lease::LeaseDomainError,
        policy::{EffectivePolicy, test_support::effective_policy},
        store::AuthenticatedRequestControl,
    },
    model::{AutomationConcurrencyMode, SharedStateIsolationRequirement},
};

use super::activation_lifecycle_tests::{
    Fixture, begin, caller, clock, control, host, resolution, stamp,
};

fn policy(_fixture: &Fixture, request: &IdentityLeaseRequest) -> EffectivePolicy {
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

fn pinned(fixture: &Fixture, id: &str) -> (IdentityLeaseRequest, EffectivePolicy) {
    let mut request = fixture.request(id);
    let digest = policy(fixture, &request).digest();
    request.policy_digest = Some(digest);
    let policy = policy(fixture, &request);
    assert_eq!(request.policy_digest, Some(policy.digest()));
    (request, policy)
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
        .unwrap_or_else(|error| panic!("policy projection: {error}"))
}

#[test]
fn pinned_activation_digest_mismatch_commits_only_clock_observation_and_replays() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let (request, expected) = pinned(&fixture, "01ARZ3NDEKTSV4RRFFQ69G5FD0");
    let mut mismatched = expected.clone();
    mismatched.maximum_session_seconds -= 1;
    assert_ne!(mismatched.digest(), expected.digest());
    let (lease_id, row_version) = begin(&mut store, &request, 100);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let request_control = AuthenticatedRequestControl::new(
        &lease_id,
        row_version,
        &authenticated_caller,
        &authenticated_host,
    );
    let result = store
        .activate_requested(
            &request_control,
            &mismatched,
            resolution('0', IsolationClassification::CredentialIsolated),
            &clock(&store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("pinned mismatch: {error:?}"));
    assert_eq!(
        result.domain_result(),
        &Err(LeaseDomainError::PolicyBindingMismatch)
    );
    assert_eq!(
        projection(&store, &lease_id),
        (
            "REQUESTED".to_owned(),
            2,
            2,
            101_u128.to_be_bytes().to_vec(),
            1,
            0,
        )
    );
    let replay = store
        .begin_acquire(
            &request,
            &authenticated_caller,
            &authenticated_host,
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        )
        .unwrap_or_else(|error| panic!("pinned replay: {error:?}"));
    assert!(replay.replayed());
    assert_eq!(replay.outcome().response().status, LeaseStatus::Requested);
}

#[test]
fn widened_signed_envelope_fields_are_policy_mismatches_before_authority() {
    for (index, field) in ["maximum-ttl", "maximum-session", "signed-expiry"]
        .into_iter()
        .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FD{}", index + 1));
        let mut widened = policy(&fixture, &request);
        match field {
            "maximum-ttl" => {
                widened.maximum_ttl_seconds =
                    request.work_order_authorization.maximum_ttl_seconds.get() + 1;
            }
            "maximum-session" => {
                widened.maximum_session_seconds = request
                    .work_order_authorization
                    .maximum_session_seconds
                    .get()
                    + 1;
            }
            "signed-expiry" => widened.signed_expires_at = stamp("2026-08-24T14:00:00Z"),
            _ => unreachable!(),
        }
        let (lease_id, row_version) = begin(&mut store, &request, 100);
        let authenticated_caller = caller();
        let authenticated_host = host();
        let request_control = AuthenticatedRequestControl::new(
            &lease_id,
            row_version,
            &authenticated_caller,
            &authenticated_host,
        );
        let result = store
            .activate_requested(
                &request_control,
                &widened,
                resolution('1', IsolationClassification::CredentialIsolated),
                &clock(&store, "2026-08-22T10:00:03Z", 101),
            )
            .unwrap_or_else(|error| panic!("widened {field}: {error:?}"));
        assert_eq!(
            result.domain_result(),
            &Err(LeaseDomainError::PolicyBindingMismatch)
        );
        assert_eq!(projection(&store, &lease_id).3, 101_u128.to_be_bytes());
        assert_eq!(projection(&store, &lease_id).4, 1);
        assert_eq!(projection(&store, &lease_id).5, 0);
    }
}

fn activate(
    store: &mut super::ReadyStore,
    request: &IdentityLeaseRequest,
    policy: &EffectivePolicy,
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
            policy,
            resolution('2', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("policy activation: {error:?}"));
    let version = activated
        .successful_row_version()
        .unwrap_or_else(|| panic!("active row version"));
    (lease_id, version)
}

#[test]
fn pinned_ttl_and_every_signed_widening_block_renewal_but_keep_replay_valid() {
    for (index, mismatch) in [
        "pinned-ttl",
        "maximum-ttl",
        "maximum-session",
        "signed-expiry",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let (request, base) = if mismatch == "pinned-ttl" {
            pinned(&fixture, &format!("01ARZ3NDEKTSV4RRFFQ69G5FD{}", index + 4))
        } else {
            let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FD{}", index + 4));
            let base = policy(&fixture, &request);
            (request, base)
        };
        let (lease_id, row_version) = activate(&mut store, &request, &base);
        let renewed = match mismatch {
            "pinned-ttl" => base
                .for_renewal_ttl(
                    RequestedTtlSeconds::from_seconds(600)
                        .unwrap_or_else(|error| panic!("renewal ttl: {error:?}")),
                )
                .unwrap_or_else(|error| panic!("renewal policy: {error:?}")),
            "maximum-ttl" => {
                let mut widened = base.clone();
                widened.maximum_ttl_seconds =
                    request.work_order_authorization.maximum_ttl_seconds.get() + 1;
                widened
            }
            "maximum-session" => {
                let mut widened = base.clone();
                widened.maximum_session_seconds = request
                    .work_order_authorization
                    .maximum_session_seconds
                    .get()
                    + 1;
                widened
            }
            "signed-expiry" => {
                let mut widened = base.clone();
                widened.signed_expires_at = stamp("2026-08-24T14:00:00Z");
                widened
            }
            _ => unreachable!(),
        };
        let authenticated_caller = caller();
        let authenticated_host = host();
        let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
        let result = store
            .begin_renewal(
                &lease_id,
                row_version,
                &lease_control,
                &renewed,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("renewal {mismatch}: {error:?}"));
        assert_eq!(
            result.domain_result(),
            &Err(LeaseDomainError::PolicyBindingMismatch)
        );
        assert_eq!(
            projection(&store, &lease_id),
            (
                "ACTIVE".to_owned(),
                3,
                3,
                102_u128.to_be_bytes().to_vec(),
                2,
                4,
            )
        );
        assert!(
            store
                .begin_acquire(
                    &request,
                    &authenticated_caller,
                    &authenticated_host,
                    &clock(&store, "2026-08-22T10:00:05Z", 103),
                )
                .unwrap_or_else(|error| panic!("resolved replay: {error:?}"))
                .replayed()
        );
    }
}

#[test]
fn unpinned_auth_mode_and_isolation_changes_cannot_rotate_stale_resolution() {
    for (index, auth_change) in [true, false].into_iter().enumerate() {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FE{index}"));
        let base = policy(&fixture, &request);
        let (lease_id, row_version) = activate(&mut store, &request, &base);
        let mut changed = base.clone();
        if auth_change {
            changed.auth_mode = AutomationAuthMode::ApiKey;
        } else {
            changed.isolation = IsolationClassification::PerLeaseIsolated;
        }
        let authenticated_caller = caller();
        let authenticated_host = host();
        let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
        let result = store
            .begin_renewal(
                &lease_id,
                row_version,
                &lease_control,
                &changed,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("resolution mismatch: {error:?}"));
        assert_eq!(
            result.domain_result(),
            &Err(LeaseDomainError::PolicyBindingMismatch)
        );
        assert_eq!(projection(&store, &lease_id).0, "ACTIVE");
        assert_eq!(projection(&store, &lease_id).3, 102_u128.to_be_bytes());
        assert_eq!(projection(&store, &lease_id).4, 2);
        assert_eq!(projection(&store, &lease_id).5, 4);
    }
}

#[test]
fn mode_mismatch_preserves_binding_error_while_observing_clock_and_deadline() {
    for due in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(if due {
            "01ARZ3NDEKTSV4RRFFQ69G5FF1"
        } else {
            "01ARZ3NDEKTSV4RRFFQ69G5FF0"
        });
        let base = policy(&fixture, &request);
        let (lease_id, row_version) = activate(&mut store, &request, &base);
        let mut changed = base;
        changed.concurrency_mode = AutomationConcurrencyMode::Shared;
        changed.shared_state_isolation = Some(SharedStateIsolationRequirement::Stateless);
        let authenticated_caller = caller();
        let wrong_host = "host:wrong-mode-owner"
            .parse::<HostIdentity>()
            .unwrap_or_else(|error| panic!("wrong host: {error:?}"));
        let lease_control = control(&request, &authenticated_caller, &wrong_host, 1);
        let monotonic = if due { 900_000_000_102 } else { 102 };
        let wall = if due {
            "2026-08-22T10:16:00Z"
        } else {
            "2026-08-22T10:00:04Z"
        };
        let result = store
            .begin_renewal(
                &lease_id,
                row_version,
                &lease_control,
                &changed,
                &clock(&store, wall, monotonic),
            )
            .unwrap_or_else(|error| panic!("mode/control mismatch: {error:?}"));
        assert_eq!(result.domain_result(), &Err(LeaseDomainError::HostMismatch));
        let observed = projection(&store, &lease_id);
        assert_eq!(observed.1, 3);
        assert_eq!(observed.3, monotonic.to_be_bytes());
        assert_eq!(observed.5, 4);
        if due {
            assert_eq!(
                (observed.0.as_str(), observed.2, observed.4),
                ("EXPIRED", 4, 3)
            );
        } else {
            assert_eq!(
                (observed.0.as_str(), observed.2, observed.4),
                ("ACTIVE", 3, 2)
            );
        }
        let (held, released): (i64, i64) = store
            .test_connection()
            .query_row(
                "SELECT count(*) FILTER (WHERE state = 'HELD'),
                        count(*) FILTER (WHERE state = 'RELEASED')
                 FROM capacity_reservations WHERE lease_id = ?1",
                [lease_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or_else(|error| panic!("reservation states: {error}"));
        assert_eq!((held, released), if due { (0, 4) } else { (4, 0) });
    }
}
