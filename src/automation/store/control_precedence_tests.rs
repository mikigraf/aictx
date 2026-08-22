use core::str::FromStr;

use crate::{
    automation::{
        contracts::{
            AgentRole, CallerSubject, HostIdentity, IsolationClassification, RunId, TenantId,
        },
        lease::{LeaseControl, LeaseDomainError},
        policy::{EffectivePolicy, test_support::effective_policy},
        store::AuthenticatedRequestControl,
    },
    model::AutomationConcurrencyMode,
};

use super::activation_lifecycle_tests::{Fixture, begin, caller, clock, control, host, resolution};

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: core::fmt::Debug,
{
    value
        .parse()
        .unwrap_or_else(|error| panic!("parse {value}: {error:?}"))
}

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
            resolution('N', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("control activation: {error:?}"));
    (
        lease_id,
        activated
            .successful_row_version()
            .unwrap_or_else(|| panic!("control active version")),
    )
}

fn projection(
    store: &super::ReadyStore,
    lease_id: &crate::automation::contracts::LeaseId,
) -> (String, i64, i64, Vec<u8>, i64, i64, Option<String>) {
    store
        .test_connection()
        .query_row(
            "SELECT l.status, l.row_version, l.next_audit_sequence,
                    c.monotonic_high_water_nanos,
                    (SELECT count(*) FROM audit_events a WHERE a.lease_id = l.lease_id),
                    (SELECT count(*) FROM capacity_reservations r
                     WHERE r.lease_id = l.lease_id AND r.state <> 'RELEASED'),
                    (SELECT actor FROM audit_events a WHERE a.lease_id = l.lease_id
                     ORDER BY sequence DESC LIMIT 1)
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
                ))
            },
        )
        .unwrap_or_else(|error| panic!("control projection: {error}"))
}

fn mismatched_control<'a>(
    request: &'a crate::automation::contracts::IdentityLeaseRequest,
    authenticated_caller: &'a CallerSubject,
    authenticated_host: &'a HostIdentity,
    other_tenant: &'a TenantId,
    other_run: &'a RunId,
    other_host: &'a HostIdentity,
    kind: &str,
) -> LeaseControl<'a> {
    LeaseControl {
        caller_subject: authenticated_caller,
        tenant_id: if kind == "tenant" {
            other_tenant
        } else {
            &request.tenant_id
        },
        run_id: if kind == "run" {
            other_run
        } else {
            &request.run_id
        },
        role: if kind == "role" {
            AgentRole::LocalReviewer
        } else {
            request.role
        },
        host_identity: if kind == "host" {
            other_host
        } else {
            authenticated_host
        },
        fencing_generation: crate::automation::contracts::FencingGeneration::from_value(
            if kind == "generation" { 2 } else { 1 },
        )
        .unwrap_or_else(|error| panic!("control generation: {error:?}")),
    }
}

#[test]
fn owner_binding_errors_precede_state_while_clock_and_due_terminal_are_committed() {
    let cases = [
        ("tenant", LeaseDomainError::TenantMismatch),
        ("run", LeaseDomainError::RunMismatch),
        ("role", LeaseDomainError::RoleMismatch),
        ("host", LeaseDomainError::HostMismatch),
        ("generation", LeaseDomainError::GenerationMismatch),
    ];
    for (index, (kind, expected)) in cases.into_iter().enumerate() {
        for due in [false, true] {
            let fixture = Fixture::new();
            let mut store = fixture.ready();
            let suffix =
                char::from(b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[index * 2 + usize::from(due)]);
            let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FS{suffix}"));
            let (lease_id, row_version) = active(&mut store, &request);
            let authenticated_caller = caller();
            let authenticated_host = host();
            let other_tenant = parsed::<TenantId>("tenant-other");
            let other_run = parsed::<RunId>("run_01ARZ3NDEKTSV4RRFFQ69G5FAW");
            let other_host = parsed::<HostIdentity>("host:other-runner");
            let bad = mismatched_control(
                &request,
                &authenticated_caller,
                &authenticated_host,
                &other_tenant,
                &other_run,
                &other_host,
                kind,
            );
            let denied = store
                .begin_renewal(
                    &lease_id,
                    row_version,
                    &bad,
                    &policy(&request),
                    &clock(
                        &store,
                        if due {
                            "2026-08-22T11:00:00Z"
                        } else {
                            "2026-08-22T10:00:04Z"
                        },
                        if due { 4_000_000_000_000 } else { 102 },
                    ),
                )
                .unwrap_or_else(|error| panic!("{kind} due={due}: {error:?}"));
            assert_eq!(denied.domain_result(), &Err(expected.clone()));
            let after = projection(&store, &lease_id);
            if due {
                assert_eq!(after.0, "EXPIRED", "{kind}");
                assert_eq!(after.2, 4, "{kind}");
                assert_eq!(after.4, 3, "{kind}");
                assert_eq!(after.5, 0, "{kind}");
                assert_eq!(after.6.as_deref(), Some("service"), "{kind}");
            } else {
                assert_eq!(after.0, "ACTIVE", "{kind}");
                assert_eq!(after.2, 3, "{kind}");
                assert_eq!(after.4, 2, "{kind}");
                assert_eq!(after.5, 4, "{kind}");
            }
            assert_eq!(after.1, 3, "{kind}");
        }
    }
}

#[test]
fn wrong_caller_is_read_only_and_close_binding_precedes_invalid_reason() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FSA");
    let (lease_id, row_version) = active(&mut store, &request);
    let before = projection(&store, &lease_id);
    let foreign = parsed::<CallerSubject>("caller:foreign-controller");
    let authenticated_host = host();
    let foreign_control = control(&request, &foreign, &authenticated_host, 1);
    let denied = store
        .begin_renewal(
            &lease_id,
            row_version,
            &foreign_control,
            &policy(&request),
            &clock(&store, "2026-08-22T11:00:00Z", 4_000_000_000_000),
        )
        .unwrap_or_else(|error| panic!("wrong caller: {error:?}"));
    assert_eq!(
        denied.domain_result(),
        &Err(LeaseDomainError::CallerUnauthorized)
    );
    assert_eq!(projection(&store, &lease_id), before);

    let authenticated_caller = caller();
    let wrong_host = parsed::<HostIdentity>("host:other-runner");
    let wrong_host_control = control(&request, &authenticated_caller, &wrong_host, 1);
    let closed = store
        .close_lease(
            &lease_id,
            row_version,
            &wrong_host_control,
            crate::automation::contracts::LeaseReasonCode::InternalError,
            &clock(&store, "2026-08-22T11:00:00Z", 4_000_000_000_000),
        )
        .unwrap_or_else(|error| panic!("wrong host invalid close reason: {error:?}"));
    assert_eq!(closed.domain_result(), &Err(LeaseDomainError::HostMismatch));
    let after = projection(&store, &lease_id);
    assert_eq!(after.0, "EXPIRED");
    assert_eq!(after.4, 3);
    assert_eq!(after.5, 0);
    assert_eq!(after.6.as_deref(), Some("service"));
}
