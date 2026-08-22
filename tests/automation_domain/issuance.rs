use super::*;

fn sample_in_generation(wall: &str, seconds: u64, generation: u64) -> ClockSample {
    ClockSample::new(
        timestamp(wall),
        MonotonicMoment::from_nanoseconds(u128::from(seconds) * 1_000_000_000),
        ServiceClockGeneration::from_value(generation),
    )
}

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
    assert_eq!(expired.status(), LeaseStatus::Requested);
    assert_eq!(
        expired.activate(
            &policy,
            resolution(),
            &sample("2026-08-21T10:00:30Z", 1_030),
        ),
        Err(LeaseDomainError::MonotonicRegression)
    );
    assert_eq!(expired.status(), LeaseStatus::Requested);
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

#[test]
fn every_control_operation_is_bound_to_the_authenticated_caller() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let other_caller = parsed("caller:other-controller");
    let mut wrong_caller = control(&fixture, 1);
    wrong_caller.caller_subject = &other_caller;
    let mut lease = active_lease(&fixture, &policy);
    let renewed = valid(policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(90))));
    assert_eq!(
        lease.begin_renewal(
            &wrong_caller,
            &renewed,
            &sample("2026-08-22T10:00:00Z", 10_000),
        ),
        Err(LeaseDomainError::CallerUnauthorized)
    );
    assert_eq!(lease.status(), LeaseStatus::Active);
    assert_eq!(lease.fencing_generation(), Some(generation(1)));
    assert_eq!(
        lease.close(
            &wrong_caller,
            LeaseReasonCode::Completed,
            &sample("2026-08-22T10:00:00Z", 10_000),
        ),
        Err(LeaseDomainError::CallerUnauthorized)
    );
    assert_eq!(lease.status(), LeaseStatus::Active);
    assert_eq!(
        lease.close(
            &wrong_caller,
            LeaseReasonCode::InternalError,
            &sample("2026-08-22T10:00:00Z", 10_000),
        ),
        Err(LeaseDomainError::CallerUnauthorized)
    );
    assert_eq!(lease.status(), LeaseStatus::Active);
    assert_eq!(
        lease.authorize_launch(
            &wrong_caller,
            &policy,
            &sample("2026-08-22T10:00:00Z", 10_000),
        ),
        Err(LeaseDomainError::CallerUnauthorized)
    );
    assert_eq!(lease.status(), LeaseStatus::Active);
    assert!(lease.execution_handle().is_some());
    for operation in [
        AutomationOperation::LeaseRenew,
        AutomationOperation::LeaseClose,
        AutomationOperation::ExecutionStart,
    ] {
        assert_eq!(
            LeaseDomainError::CallerUnauthorized.automation_code(operation),
            AutomationErrorCode::CallerUnauthorized
        );
    }

    valid(lease.begin_renewal(
        &control(&fixture, 1),
        &renewed,
        &sample("2026-08-21T10:00:30Z", 1_030),
    ));
    wrong_caller.fencing_generation = generation(2);
    assert_eq!(
        lease.acknowledge_renewal(&wrong_caller, &sample("2026-08-21T10:00:31Z", 1_031),),
        Err(LeaseDomainError::CallerUnauthorized)
    );
    assert_eq!(lease.status(), LeaseStatus::Revoked);
    assert_eq!(
        lease.reason_code(),
        Some(LeaseReasonCode::RenewalAcknowledgementFailed)
    );
}

#[test]
fn runtime_wall_rollback_still_expires_on_monotonic_time() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let mut lease = active_lease(&fixture, &policy);
    assert!(!valid(
        lease.enforce_deadlines(&sample("2026-08-21T09:59:00Z", 1_059,))
    ));
    assert_eq!(lease.status(), LeaseStatus::Active);
    assert!(valid(
        lease.enforce_deadlines(&sample("2026-08-21T09:59:00Z", 1_060,))
    ));
    assert_eq!(lease.status(), LeaseStatus::Expired);
    assert_eq!(lease.reason_code(), Some(LeaseReasonCode::LeaseExpired));
}

#[test]
fn runtime_rejects_clock_generation_change_and_monotonic_regression() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let mut lease = active_lease(&fixture, &policy);
    assert!(!valid(
        lease.enforce_deadlines(&sample("2026-08-21T10:00:05Z", 1_005,))
    ));
    assert_eq!(
        lease.enforce_deadlines(&sample("2026-08-21T10:00:06Z", 1_004)),
        Err(LeaseDomainError::MonotonicRegression)
    );
    assert_eq!(
        lease.enforce_deadlines(&sample_in_generation("2026-08-21T10:00:06Z", 1_006, 2,)),
        Err(LeaseDomainError::ClockGenerationMismatch)
    );
    assert_eq!(lease.status(), LeaseStatus::Active);
}

#[test]
fn activation_is_clock_strict_and_rolled_back_renewal_cannot_extend() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let mut before_wall = requested_lease(&fixture);
    assert_eq!(
        before_wall.activate(
            &policy,
            resolution(),
            &sample("2026-08-21T09:59:59Z", 1_001),
        ),
        Err(LeaseDomainError::ClockBeforeIssuance)
    );
    let mut before_monotonic = requested_lease(&fixture);
    assert_eq!(
        before_monotonic.activate(&policy, resolution(), &sample("2026-08-21T10:00:00Z", 999),),
        Err(LeaseDomainError::MonotonicRegression)
    );
    let mut other_generation = requested_lease(&fixture);
    assert_eq!(
        other_generation.activate(
            &policy,
            resolution(),
            &sample_in_generation("2026-08-21T10:00:00Z", 1_000, 2),
        ),
        Err(LeaseDomainError::ClockGenerationMismatch)
    );

    let mut lease = active_lease(&fixture, &policy);
    let original_expiry = lease.expires_at().cloned();
    let renewed = valid(policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(90))));
    assert_eq!(
        lease.begin_renewal(
            &control(&fixture, 1),
            &renewed,
            &sample("2026-08-21T09:59:00Z", 1_030),
        ),
        Err(LeaseDomainError::SessionLimitReached)
    );
    assert_eq!(lease.status(), LeaseStatus::Active);
    assert_eq!(lease.expires_at().cloned(), original_expiry);
    assert_eq!(lease.fencing_generation(), Some(generation(1)));
}
