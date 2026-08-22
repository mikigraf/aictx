use crate::{
    automation::{
        contracts::{IsolationClassification, LeaseReasonCode},
        policy::{EffectivePolicy, test_support::effective_policy},
        store::{AuthenticatedRequestControl, StoreError},
    },
    config::{acquire_profile_lock, profile_automation_fence_presence},
    model::AutomationConcurrencyMode,
};

use super::activation_lifecycle_tests::{Fixture, begin, caller, clock, control, host, resolution};

type LeaseGraph = (
    String,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
);
type AuditGraph = (i64, String, String, Option<String>, Option<String>);

#[derive(Debug, Eq, PartialEq)]
struct Graph {
    lease: LeaseGraph,
    clock: (Vec<u8>, Option<String>, i64),
    audits: Vec<AuditGraph>,
    capacity: Vec<(String, String, i64, i64, String, Option<String>)>,
}

fn graph(store: &super::ReadyStore, lease_id: &crate::automation::contracts::LeaseId) -> Graph {
    let connection = store.test_connection();
    let lease = connection
        .query_row(
            "SELECT status, row_version, next_audit_sequence, execution_handle,
                    effective_policy_digest, fencing_generation, terminal_at_utc
             FROM leases WHERE lease_id = ?1",
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
        .unwrap_or_else(|error| panic!("failure lease graph: {error}"));
    let clock = connection
        .query_row(
            "SELECT monotonic_high_water_nanos, interval_anchor_at_utc, row_version
             FROM lease_runtime_clocks WHERE lease_id = ?1",
            [lease_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("failure clock graph: {error}"));
    let mut audits_statement = connection
        .prepare(
            "SELECT sequence, event_type, lease_status, refusal_code, reason_code
             FROM audit_events WHERE lease_id = ?1 ORDER BY sequence",
        )
        .unwrap_or_else(|error| panic!("failure audit statement: {error}"));
    let audits = audits_statement
        .query_map([lease_id.as_str()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap_or_else(|error| panic!("failure audit query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("failure audit rows: {error}"));
    let mut capacity_statement = connection
        .prepare(
            "SELECT capacity_dimension, capacity_key, capacity_limit, slot, state, released_at_utc
             FROM capacity_reservations WHERE lease_id = ?1
             ORDER BY capacity_dimension, slot",
        )
        .unwrap_or_else(|error| panic!("failure capacity statement: {error}"));
    let capacity = capacity_statement
        .query_map([lease_id.as_str()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .unwrap_or_else(|error| panic!("failure capacity query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("failure capacity rows: {error}"));
    Graph {
        lease,
        clock,
        audits,
        capacity,
    }
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

fn install_failure(store: &super::ReadyStore, body: &str) {
    store
        .test_connection()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_lifecycle_statement {body}
             BEGIN SELECT RAISE(ABORT, 'injected lifecycle statement failure'); END;"
        ))
        .unwrap_or_else(|error| panic!("install failure trigger: {error}"));
}

fn clear_failure(store: &super::ReadyStore) {
    store
        .test_connection()
        .execute_batch("DROP TRIGGER temp.fail_lifecycle_statement;")
        .unwrap_or_else(|error| panic!("drop failure trigger: {error}"));
}

fn activate(
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
            resolution('G', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("failure setup activation: {error:?}"));
    (
        lease_id,
        activated
            .successful_row_version()
            .unwrap_or_else(|| panic!("failure active version")),
    )
}

#[test]
fn activation_rolls_back_every_capacity_projection_and_audit_statement() {
    let stages = [
        "BEFORE INSERT ON main.capacity_reservations WHEN NEW.capacity_dimension = 'profile'",
        "BEFORE INSERT ON main.capacity_reservations WHEN NEW.capacity_dimension = 'provider'",
        "BEFORE INSERT ON main.capacity_reservations WHEN NEW.capacity_dimension = 'caller'",
        "BEFORE INSERT ON main.capacity_reservations WHEN NEW.capacity_dimension = 'host'",
        "BEFORE UPDATE ON main.leases",
        "BEFORE UPDATE ON main.lease_runtime_clocks",
        "BEFORE INSERT ON main.audit_events WHEN NEW.event_type = 'lease.activated'",
    ];
    for (index, stage) in stages.into_iter().enumerate() {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FM{index}"));
        let (lease_id, row_version) = begin(&mut store, &request, 100);
        let before = graph(&store, &lease_id);
        install_failure(&store, stage);
        let authenticated_caller = caller();
        let authenticated_host = host();
        let request_control = AuthenticatedRequestControl::new(
            &lease_id,
            row_version,
            &authenticated_caller,
            &authenticated_host,
        );
        assert!(matches!(
            store.activate_requested(
                &request_control,
                &policy(&request),
                resolution('H', IsolationClassification::CredentialIsolated),
                &clock(&store, "2026-08-22T10:00:03Z", 101),
            ),
            Err(StoreError::DatabaseUnavailable)
        ));
        clear_failure(&store);
        assert_eq!(graph(&store, &lease_id), before, "{stage}");
        assert!(
            acquire_profile_lock(
                &fixture.paths.profile_resource_lock(&request.profile_uid),
                true,
            )
            .is_ok(),
            "precommit activation failure leaked resource: {stage}"
        );
        assert!(
            profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
                .unwrap_or_else(|error| panic!("failure fence: {error}")),
            "REQUESTED marker lost: {stage}"
        );
    }
}

#[test]
fn renewal_ack_and_terminal_writers_roll_back_each_projection_statement() {
    for (index, operation) in ["renew", "ack", "close"].into_iter().enumerate() {
        let stages: &[&str] = match operation {
            "renew" => &[
                "BEFORE UPDATE ON main.leases",
                "BEFORE UPDATE ON main.lease_runtime_clocks",
                "BEFORE INSERT ON main.audit_events WHEN NEW.event_type = 'lease.renewing'",
            ],
            "ack" => &[
                "BEFORE UPDATE ON main.leases",
                "BEFORE UPDATE ON main.lease_runtime_clocks",
                "BEFORE INSERT ON main.audit_events WHEN NEW.event_type = 'lease.renewed'",
            ],
            "close" => &[
                "BEFORE UPDATE ON main.leases",
                "BEFORE UPDATE ON main.lease_runtime_clocks",
                "BEFORE INSERT ON main.audit_events WHEN NEW.event_type = 'lease.closed'",
                "BEFORE UPDATE ON main.capacity_reservations WHEN OLD.state = 'HELD'",
            ],
            _ => unreachable!(),
        };
        for (stage_index, stage) in stages.iter().enumerate() {
            let fixture = Fixture::new();
            let mut store = fixture.ready();
            let suffix = char::from(b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[index * 4 + stage_index]);
            let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FN{suffix}"));
            let (lease_id, mut row_version) = activate(&mut store, &request);
            let authenticated_caller = caller();
            let authenticated_host = host();
            let active_control = control(&request, &authenticated_caller, &authenticated_host, 1);
            if operation == "ack" {
                let renewing = store
                    .begin_renewal(
                        &lease_id,
                        row_version,
                        &active_control,
                        &policy(&request),
                        &clock(&store, "2026-08-22T10:00:04Z", 102),
                    )
                    .unwrap_or_else(|error| panic!("failure setup renewal: {error:?}"));
                row_version = renewing
                    .successful_row_version()
                    .unwrap_or_else(|| panic!("failure renewing version"));
            }
            let before = graph(&store, &lease_id);
            install_failure(&store, stage);
            let result = match operation {
                "renew" => store
                    .begin_renewal(
                        &lease_id,
                        row_version,
                        &active_control,
                        &policy(&request),
                        &clock(&store, "2026-08-22T10:00:04Z", 102),
                    )
                    .map(|_| ()),
                "ack" => {
                    let renewing_control =
                        control(&request, &authenticated_caller, &authenticated_host, 2);
                    store
                        .acknowledge_renewal(
                            &lease_id,
                            row_version,
                            &renewing_control,
                            &clock(&store, "2026-08-22T10:00:05Z", 103),
                        )
                        .map(|_| ())
                }
                "close" => store
                    .close_lease(
                        &lease_id,
                        row_version,
                        &active_control,
                        LeaseReasonCode::Completed,
                        &clock(&store, "2026-08-22T10:00:04Z", 102),
                    )
                    .map(|_| ()),
                _ => unreachable!(),
            };
            assert!(
                matches!(result, Err(StoreError::DatabaseUnavailable)),
                "{operation} {stage}"
            );
            clear_failure(&store);
            assert_eq!(graph(&store, &lease_id), before, "{operation} {stage}");
            assert!(
                acquire_profile_lock(
                    &fixture.paths.profile_resource_lock(&request.profile_uid),
                    true,
                )
                .is_err(),
                "rollback lost retained authority resource: {operation} {stage}"
            );
        }
    }
}

#[test]
fn activation_refusal_and_high_water_error_roll_back_projection_updates() {
    for (index, stage) in [
        "BEFORE UPDATE ON main.leases",
        "BEFORE UPDATE ON main.lease_runtime_clocks",
        "BEFORE INSERT ON main.audit_events WHEN NEW.event_type = 'lease.refused'",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let owner = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FP0");
        let _ = activate(&mut store, &owner);
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FP{}", index + 1));
        let (lease_id, row_version) = begin(&mut store, &request, 200);
        let before = graph(&store, &lease_id);
        install_failure(&store, stage);
        let authenticated_caller = caller();
        let authenticated_host = host();
        let request_control = AuthenticatedRequestControl::new(
            &lease_id,
            row_version,
            &authenticated_caller,
            &authenticated_host,
        );
        assert!(matches!(
            store.activate_requested(
                &request_control,
                &policy(&request),
                resolution('J', IsolationClassification::CredentialIsolated),
                &clock(&store, "2026-08-22T10:00:04Z", 201),
            ),
            Err(StoreError::DatabaseUnavailable)
        ));
        clear_failure(&store);
        assert_eq!(graph(&store, &lease_id), before, "refusal {stage}");
    }

    for (index, stage) in [
        "BEFORE UPDATE ON main.leases",
        "BEFORE UPDATE ON main.lease_runtime_clocks",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FP{}", index + 4));
        let other = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FP{}", index + 6));
        let (lease_id, row_version) = begin(&mut store, &request, 200);
        let before = graph(&store, &lease_id);
        install_failure(&store, stage);
        let authenticated_caller = caller();
        let authenticated_host = host();
        let request_control = AuthenticatedRequestControl::new(
            &lease_id,
            row_version,
            &authenticated_caller,
            &authenticated_host,
        );
        assert!(matches!(
            store.activate_requested(
                &request_control,
                &policy(&other),
                resolution('K', IsolationClassification::CredentialIsolated),
                &clock(&store, "2026-08-22T10:00:04Z", 201),
            ),
            Err(StoreError::DatabaseUnavailable)
        ));
        clear_failure(&store);
        assert_eq!(graph(&store, &lease_id), before, "domain error {stage}");
        assert!(
            acquire_profile_lock(
                &fixture.paths.profile_resource_lock(&request.profile_uid),
                true,
            )
            .is_ok(),
            "domain error acquired a resource: {stage}"
        );
    }
}

#[test]
fn terminal_commit_ambiguity_is_a_hard_latch_that_same_process_cleanup_cannot_clear() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FP8");
    let (lease_id, row_version) = activate(&mut store, &request);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
    store
        .test_connection()
        .commit_hook(Some(|| true))
        .unwrap_or_else(|error| panic!("terminal commit hook: {error}"));
    assert!(matches!(
        store.close_lease(
            &lease_id,
            row_version,
            &lease_control,
            LeaseReasonCode::Completed,
            &clock(&store, "2026-08-22T10:00:04Z", 102),
        ),
        Err(StoreError::DatabaseUnavailable)
    ));
    store
        .test_connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap_or_else(|error| panic!("clear terminal commit hook: {error}"));
    assert!(matches!(
        store.retry_profile_fence_cleanup(&request.profile_uid),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(
        acquire_profile_lock(
            &fixture.paths.profile_resource_lock(&request.profile_uid),
            true,
        )
        .is_err(),
        "commit-uncertain terminal attempt released its resource"
    );
    assert!(
        profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
            .unwrap_or_else(|error| panic!("uncertain terminal fence: {error}"))
    );
    assert!(matches!(
        store.begin_acquire(
            &request,
            &authenticated_caller,
            &authenticated_host,
            &clock(&store, "2026-08-22T10:00:05Z", 103),
        ),
        Err(StoreError::RecoveryRequired)
    ));
}

#[test]
fn revoked_expired_and_error_audit_aborts_roll_back_authority_and_capacity() {
    for (index, (operation, event)) in [
        ("revoke", "lease.revoked"),
        ("expire", "lease.expired"),
        ("error", "lease.error"),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FY{index}"));
        let (lease_id, row_version) = activate(&mut store, &request);
        let before = graph(&store, &lease_id);
        install_failure(
            &store,
            &format!("BEFORE INSERT ON main.audit_events WHEN NEW.event_type = '{event}'"),
        );
        let result = match operation {
            "revoke" => store
                .revoke_by_service(
                    &lease_id,
                    row_version,
                    LeaseReasonCode::PolicyRevoked,
                    &clock(&store, "2026-08-22T10:00:04Z", 102),
                )
                .map(|_| ()),
            "expire" => store
                .enforce_expiration(
                    &lease_id,
                    row_version,
                    &clock(&store, "2026-08-22T10:15:02Z", 900_000_000_100),
                )
                .map(|_| ()),
            "error" => store
                .mark_error(
                    &lease_id,
                    row_version,
                    LeaseReasonCode::InternalError,
                    &clock(&store, "2026-08-22T10:00:04Z", 102),
                )
                .map(|_| ()),
            _ => unreachable!(),
        };
        assert!(
            matches!(result, Err(StoreError::DatabaseUnavailable)),
            "{operation}"
        );
        clear_failure(&store);
        assert_eq!(graph(&store, &lease_id), before, "{operation}");
        assert!(
            acquire_profile_lock(
                &fixture.paths.profile_resource_lock(&request.profile_uid),
                true,
            )
            .is_err(),
            "{operation} abort released authority resource"
        );
        assert!(
            profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
                .unwrap_or_else(|error| panic!("{operation} fence: {error}"))
        );
    }
}
