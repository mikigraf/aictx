use super::*;

#[test]
fn delayed_activation_consumes_the_issuance_clock_authority() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let mut delayed = requested_lease(&fixture);
    valid(delayed.activate(
        &policy,
        resolution(),
        &sample("2026-08-21T10:00:30Z", 1_030),
    ));
    assert_eq!(
        delayed.expires_at(),
        Some(&timestamp("2026-08-21T10:01:00Z"))
    );
    assert_eq!(
        delayed.maximum_expires_at(),
        Some(&timestamp("2026-08-21T10:10:00Z"))
    );

    let mut expired = requested_lease(&fixture);
    assert_eq!(
        expired.activate(
            &policy,
            resolution(),
            &sample("2026-08-21T10:01:00Z", 1_060),
        ),
        Err(LeaseDomainError::SessionLimitReached)
    );
}

#[test]
fn renewal_derived_policy_cannot_widen_initial_activation() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let widened = valid(policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(90))));
    let mut lease = requested_lease(&fixture);
    assert_eq!(
        lease.activate(
            &widened,
            resolution(),
            &sample("2026-08-21T10:00:00Z", 1_000),
        ),
        Err(LeaseDomainError::PolicyBindingMismatch)
    );
}

#[test]
fn launch_revalidates_the_current_effective_policy_digest() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let mut lease = active_lease(&fixture, &policy);
    let narrowed = valid(policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(59))));
    assert_eq!(
        lease.authorize_launch(
            &control(&fixture, 1),
            &narrowed,
            &sample("2026-08-21T10:00:01Z", 1_001),
        ),
        Err(LeaseDomainError::LeaseRevoked)
    );
    assert_eq!(lease.status(), LeaseStatus::Revoked);
    assert_eq!(lease.reason_code(), Some(LeaseReasonCode::PolicyRevoked));
    assert!(lease.execution_handle().is_none());
    assert_eq!(
        lease.authorize_launch(
            &control(&fixture, 1),
            &policy,
            &sample("2026-08-21T10:00:02Z", 1_002),
        ),
        Err(LeaseDomainError::LeaseRevoked)
    );
}

#[test]
fn renewal_ttl_equality_is_allowed_and_one_second_overrun_is_refused() {
    let mut fixture = Fixture::new();
    fixture.request.work_order_authorization.expires_at = timestamp("2026-08-21T10:02:30Z");
    fixture
        .request
        .work_order_authorization
        .maximum_session_seconds = valid(DurationSeconds::from_seconds(150));
    let policy = fixture.policy();
    assert_eq!(
        policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(121))),
        Err(RefusalCode::RequestedTtlNotAllowed)
    );
    let renewed = valid(policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(120))));
    let mut equality = active_lease(&fixture, &policy);
    assert_eq!(
        valid(equality.begin_renewal(
            &control(&fixture, 1),
            &renewed,
            &sample("2026-08-21T10:00:30Z", 1_030),
        )),
        generation(2)
    );
    assert_eq!(
        equality.expires_at(),
        Some(&timestamp("2026-08-21T10:02:30Z"))
    );

    let mut overrun = active_lease(&fixture, &policy);
    assert_eq!(
        overrun.begin_renewal(
            &control(&fixture, 1),
            &renewed,
            &sample("2026-08-21T10:00:31Z", 1_031),
        ),
        Err(LeaseDomainError::SessionLimitReached)
    );
}

#[test]
fn renewal_narrows_the_original_wall_and_monotonic_maximum() {
    let mut fixture = Fixture::new();
    let original = fixture.policy();
    let mut lease = active_lease(&fixture, &original);
    fixture.controller.maximum_session_seconds = valid(DurationSeconds::from_seconds(100));
    let current = fixture.policy();
    valid(lease.begin_renewal(
        &control(&fixture, 1),
        &current,
        &sample("2026-08-21T10:00:30Z", 1_030),
    ));
    assert_eq!(
        lease.maximum_expires_at(),
        Some(&timestamp("2026-08-21T10:01:40Z"))
    );
    valid(lease.acknowledge_renewal(
        &control(&fixture, 2),
        &sample("2026-08-21T10:00:31Z", 1_031),
    ));
    assert!(valid(
        lease.enforce_deadlines(&sample("2026-08-21T10:01:29Z", 1_100))
    ));
    assert_eq!(
        lease.reason_code(),
        Some(LeaseReasonCode::MaximumLifetimeReached)
    );
}

#[test]
fn renewal_acknowledgement_is_bound_to_the_attached_host() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let renewed = valid(policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(90))));
    let mut lease = active_lease(&fixture, &policy);
    valid(lease.begin_renewal(
        &control(&fixture, 1),
        &renewed,
        &sample("2026-08-21T10:00:30Z", 1_030),
    ));
    let other_host = parsed("host:runner-02");
    let mut wrong_host = control(&fixture, 2);
    wrong_host.host_identity = &other_host;
    assert_eq!(
        lease.acknowledge_renewal(&wrong_host, &sample("2026-08-21T10:00:31Z", 1_031)),
        Err(LeaseDomainError::HostMismatch)
    );
    assert_eq!(lease.status(), LeaseStatus::Revoked);
    assert_eq!(
        lease.reason_code(),
        Some(LeaseReasonCode::RenewalAcknowledgementFailed)
    );
}

#[test]
fn pending_acknowledgement_wins_when_its_deadline_equals_lease_expiry() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let renewed = valid(policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(20))));
    let mut lease = active_lease(&fixture, &policy);
    valid(lease.begin_renewal(
        &control(&fixture, 1),
        &renewed,
        &sample("2026-08-21T10:00:50Z", 1_050),
    ));
    assert_eq!(
        lease.renewal_acknowledgement_deadline(),
        Some(&timestamp("2026-08-21T10:01:10Z"))
    );
    assert!(valid(
        lease.enforce_deadlines(&sample("2026-08-21T10:01:10Z", 1_070))
    ));
    assert_eq!(lease.status(), LeaseStatus::Revoked);
    assert_eq!(
        lease.reason_code(),
        Some(LeaseReasonCode::RenewalAcknowledgementFailed)
    );
}
