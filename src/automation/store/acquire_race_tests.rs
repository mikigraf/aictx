use crate::{
    automation::{
        contracts::{IsolationClassification, LeaseReasonCode, LeaseStatus},
        policy::{EffectivePolicy, test_support::effective_policy},
        store::{AuthenticatedRequestControl, BeginAcquireResult, StoreError},
    },
    config::{
        MetadataStore, ProfileAutomationFencePreparation, acquire_profile_lock,
        prepare_profile_automation_fence, profile_automation_fence_presence,
    },
    model::{AutomationConcurrencyMode, ProfileId},
};

use super::{
    activation_lifecycle_tests::{Fixture, begin, caller, clock, control, host, resolution},
    lifecycle_types::NonCapacityRefusal,
    sqlite::{AcquireSecondPhase, finish_acquire_second_phase, outcome_from_loaded},
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
            resolution('E', IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", 101),
        )
        .unwrap_or_else(|error| panic!("race activation: {error:?}"));
    (
        lease_id,
        activated
            .successful_row_version()
            .unwrap_or_else(|| panic!("race active row version")),
    )
}

fn replay_result(
    store: &super::ReadyStore,
    lease_id: &crate::automation::contracts::LeaseId,
) -> BeginAcquireResult {
    let transaction = store
        .test_connection()
        .unchecked_transaction()
        .unwrap_or_else(|error| panic!("race replay transaction: {error}"));
    let loaded = super::load::lease_by_id(&transaction, lease_id.as_str())
        .unwrap_or_else(|error| panic!("race replay load: {error:?}"))
        .unwrap_or_else(|| panic!("race replay lease"));
    let row_version = loaded.row_version;
    let outcome = outcome_from_loaded(loaded)
        .unwrap_or_else(|error| panic!("race replay outcome: {error:?}"));
    transaction
        .commit()
        .unwrap_or_else(|error| panic!("race replay commit: {error}"));
    BeginAcquireResult::new(outcome, true, row_version)
}

fn graph(store: &super::ReadyStore) -> Vec<(String, String, i64, i64, i64)> {
    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT l.lease_id, l.status, l.row_version,
                    (SELECT count(*) FROM audit_events a WHERE a.lease_id = l.lease_id),
                    (SELECT count(*) FROM capacity_reservations c WHERE c.lease_id = l.lease_id)
             FROM leases l ORDER BY l.lease_id",
        )
        .unwrap_or_else(|error| panic!("race graph statement: {error}"));
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap_or_else(|error| panic!("race graph query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("race graph rows: {error}"))
}

fn retain_created_fence(
    store: &mut super::ReadyStore,
    request: &crate::automation::contracts::IdentityLeaseRequest,
) {
    let profile_ref = request
        .profile_ref
        .as_str()
        .parse::<ProfileId>()
        .unwrap_or_else(|error| panic!("race profile ref: {error:?}"));
    let metadata = MetadataStore::new(store.core.paths.clone());
    let ProfileAutomationFencePreparation::Prepared(guard) = prepare_profile_automation_fence(
        &metadata,
        &store.core.installation_uid,
        &profile_ref,
        request.provider,
        &request.profile_uid,
    )
    .unwrap_or_else(|error| panic!("race fence preparation: {error}")) else {
        panic!("race fence preparation did not produce a guard");
    };
    store
        .core
        .retain_fence(request.profile_uid.clone(), guard)
        .unwrap_or_else(|error| panic!("retain race fence: {error:?}"));
}

fn terminal(
    store: &mut super::ReadyStore,
    request: &crate::automation::contracts::IdentityLeaseRequest,
    status: LeaseStatus,
) -> (crate::automation::contracts::LeaseId, u64) {
    let authenticated_caller = caller();
    let authenticated_host = host();
    if status == LeaseStatus::Refused {
        let (lease_id, row_version) = begin(store, request, 100);
        let request_control = AuthenticatedRequestControl::new(
            &lease_id,
            row_version,
            &authenticated_caller,
            &authenticated_host,
        );
        let refused = store
            .refuse_requested(
                &request_control,
                NonCapacityRefusal::from_evaluation(
                    crate::automation::contracts::RefusalCode::ProfileNotReady,
                )
                .unwrap_or_else(|| panic!("terminal race refusal")),
                clock(store, "2026-08-22T10:00:03Z", 101).wall(),
            )
            .unwrap_or_else(|error| panic!("terminal race refuse: {error:?}"));
        return (
            lease_id,
            refused
                .successful_row_version()
                .unwrap_or_else(|| panic!("terminal race refused version")),
        );
    }
    let (lease_id, row_version) = activate(store, request);
    let lease_control = control(request, &authenticated_caller, &authenticated_host, 1);
    let next_version = match status {
        LeaseStatus::Closed => store
            .close_lease(
                &lease_id,
                row_version,
                &lease_control,
                LeaseReasonCode::Completed,
                &clock(store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("terminal race close: {error:?}"))
            .successful_row_version(),
        LeaseStatus::Revoked => store
            .revoke_by_service(
                &lease_id,
                row_version,
                LeaseReasonCode::PolicyRevoked,
                &clock(store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("terminal race revoke: {error:?}"))
            .successful_row_version(),
        LeaseStatus::Expired => store
            .enforce_expiration(
                &lease_id,
                row_version,
                &clock(store, "2026-08-22T10:15:02Z", 900_000_000_100),
            )
            .unwrap_or_else(|error| panic!("terminal race expire: {error:?}"))
            .successful_row_version(),
        _ => unreachable!(),
    };
    (
        lease_id,
        next_version.unwrap_or_else(|| panic!("terminal race {status:?} version")),
    )
}

fn nonterminal(
    store: &mut super::ReadyStore,
    request: &crate::automation::contracts::IdentityLeaseRequest,
    status: LeaseStatus,
) -> (crate::automation::contracts::LeaseId, u64) {
    let (lease_id, mut row_version) = activate(store, request);
    let authenticated_caller = caller();
    let authenticated_host = host();
    let lease_control = control(request, &authenticated_caller, &authenticated_host, 1);
    match status {
        LeaseStatus::Active => {}
        LeaseStatus::Renewing => {
            row_version = store
                .begin_renewal(
                    &lease_id,
                    row_version,
                    &lease_control,
                    &policy(request),
                    &clock(store, "2026-08-22T10:00:04Z", 102),
                )
                .unwrap_or_else(|error| panic!("replay renewing: {error:?}"))
                .successful_row_version()
                .unwrap_or_else(|| panic!("replay renewing row version"));
        }
        LeaseStatus::Error => {
            row_version = store
                .mark_error(
                    &lease_id,
                    row_version,
                    LeaseReasonCode::InternalError,
                    &clock(store, "2026-08-22T10:00:04Z", 102),
                )
                .unwrap_or_else(|error| panic!("replay error: {error:?}"))
                .successful_row_version()
                .unwrap_or_else(|| panic!("replay error row version"));
        }
        _ => unreachable!(),
    }
    (lease_id, row_version)
}

#[test]
fn txn2_exact_active_renewing_and_error_winners_never_expose_authority_without_resource() {
    for (index, status) in [
        LeaseStatus::Active,
        LeaseStatus::Renewing,
        LeaseStatus::Error,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FK{index}"));
        let (lease_id, mut row_version) = activate(&mut store, &request);
        let authenticated_caller = caller();
        let authenticated_host = host();
        let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
        if status == LeaseStatus::Renewing {
            let renewed = store
                .begin_renewal(
                    &lease_id,
                    row_version,
                    &lease_control,
                    &policy(&request),
                    &clock(&store, "2026-08-22T10:00:04Z", 102),
                )
                .unwrap_or_else(|error| panic!("race renewal: {error:?}"));
            row_version = renewed
                .successful_row_version()
                .unwrap_or_else(|| panic!("race renewing row version"));
        } else if status == LeaseStatus::Error {
            let errored = store
                .mark_error(
                    &lease_id,
                    row_version,
                    LeaseReasonCode::InternalError,
                    &clock(&store, "2026-08-22T10:00:04Z", 102),
                )
                .unwrap_or_else(|error| panic!("race error transition: {error:?}"));
            row_version = errored
                .successful_row_version()
                .unwrap_or_else(|| panic!("race error row version"));
        }
        let replay = replay_result(&store, &lease_id);
        assert_eq!(replay.row_version(), row_version);
        assert_eq!(replay.outcome().response().status, status);
        let before = graph(&store);
        store.core.release_resource(&lease_id);
        assert!(matches!(
            finish_acquire_second_phase(
                &mut store.core,
                &request,
                true,
                AcquireSecondPhase::Replay(replay),
            ),
            Err(StoreError::RecoveryRequired)
        ));
        assert_eq!(graph(&store), before, "{status:?}");
        assert!(
            store
                .core
                .fence_cleanup_deferred
                .contains(&request.profile_uid)
        );
        assert!(
            profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
                .unwrap_or_else(|error| panic!("race fence presence: {error}"))
        );
    }
}

#[test]
fn txn2_requested_cleanup_failure_never_replaces_conflict() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FK3");
    let (lease_id, _) = begin(&mut store, &request, 100);
    let before = graph(&store);
    let requested = replay_result(&store, &lease_id);
    let replay = finish_acquire_second_phase(
        &mut store.core,
        &request,
        true,
        AcquireSecondPhase::Replay(requested),
    )
    .unwrap_or_else(|error| panic!("safe requested replay: {error:?}"));
    assert_eq!(replay.outcome().response().status, LeaseStatus::Requested);
    assert_eq!(graph(&store), before);

    store
        .core
        .latch_profile_cleanup(request.profile_uid.clone());
    let requested = replay_result(&store, &lease_id);
    assert!(matches!(
        finish_acquire_second_phase(
            &mut store.core,
            &request,
            true,
            AcquireSecondPhase::Replay(requested),
        ),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(matches!(
        finish_acquire_second_phase(
            &mut store.core,
            &request,
            true,
            AcquireSecondPhase::Conflict,
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(graph(&store), before);
    assert!(
        profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
            .unwrap_or_else(|error| panic!("requested race fence: {error}"))
    );
    assert!(
        acquire_profile_lock(
            &fixture.paths.profile_resource_lock(&request.profile_uid),
            true,
        )
        .is_ok(),
        "REQUESTED retains no mutable-home resource"
    );
}

#[test]
fn txn2_terminal_exact_winners_replay_without_mutating_the_winner_graph() {
    for (index, status) in [
        LeaseStatus::Refused,
        LeaseStatus::Closed,
        LeaseStatus::Revoked,
        LeaseStatus::Expired,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FZ{index}"));
        let (lease_id, row_version) = terminal(&mut store, &request, status);
        let before = graph(&store);
        retain_created_fence(&mut store, &request);
        let replay = replay_result(&store, &lease_id);
        let replay = finish_acquire_second_phase(
            &mut store.core,
            &request,
            true,
            AcquireSecondPhase::Replay(replay),
        )
        .unwrap_or_else(|error| panic!("terminal race replay {status:?}: {error:?}"));
        assert!(replay.replayed());
        assert_eq!(replay.row_version(), row_version);
        assert_eq!(replay.outcome().response().status, status);
        assert_eq!(graph(&store), before, "{status:?}");
        assert!(
            !profile_automation_fence_presence(&fixture.paths, &request.profile_uid)
                .unwrap_or_else(|error| panic!("terminal replay marker: {error}"))
        );
    }
}

#[test]
fn txn2_terminal_cleanup_failure_returns_recovery_and_gates_later_replay() {
    let fixture = Fixture::new();
    let mut store = fixture.ready();
    let request = fixture.request("01ARZ3NDEKTSV4RRFFQ69G5FZ4");
    let (lease_id, _) = terminal(&mut store, &request, LeaseStatus::Refused);
    let before = graph(&store);
    retain_created_fence(&mut store, &request);
    std::fs::write(
        fixture.paths.profile_automation_fence(&request.profile_uid),
        b"invalid marker\n",
    )
    .unwrap_or_else(|error| panic!("tamper terminal race marker: {error}"));
    let replay = replay_result(&store, &lease_id);
    assert!(matches!(
        finish_acquire_second_phase(
            &mut store.core,
            &request,
            true,
            AcquireSecondPhase::Replay(replay),
        ),
        Err(StoreError::RecoveryRequired)
    ));
    assert_eq!(graph(&store), before);
    assert!(matches!(
        store.begin_acquire(
            &request,
            &caller(),
            &host(),
            &clock(&store, "2026-08-22T10:00:05Z", 103),
        ),
        Err(StoreError::RecoveryRequired)
    ));
    let profile_ref = request
        .profile_ref
        .as_str()
        .parse::<ProfileId>()
        .unwrap_or_else(|error| panic!("terminal race profile ref: {error:?}"));
    assert!(
        acquire_profile_lock(
            &fixture
                .paths
                .profile_lock(profile_ref.provider(), profile_ref.name()),
            false,
        )
        .is_err()
    );
    assert!(
        acquire_profile_lock(
            &fixture.paths.profile_lifecycle_lock(&request.profile_uid),
            true,
        )
        .is_err()
    );
}

#[test]
fn txn1_exact_requested_replay_requires_an_intact_retained_fence() {
    for tampered in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(if tampered {
            "01ARZ3NDEKTSV4RRFFQ69G5FY0"
        } else {
            "01ARZ3NDEKTSV4RRFFQ69G5FY1"
        });
        let _ = begin(&mut store, &request, 100);
        let before = graph(&store);
        if tampered {
            std::fs::write(
                fixture.paths.profile_automation_fence(&request.profile_uid),
                b"invalid marker\n",
            )
            .unwrap_or_else(|error| panic!("tamper requested replay marker: {error}"));
        } else {
            drop(store.core.profile_fences.remove(&request.profile_uid));
        }
        let replay_clock = clock(&store, "2026-08-22T10:00:04Z", 102);
        assert!(matches!(
            store.begin_acquire(&request, &caller(), &host(), &replay_clock),
            Err(StoreError::RecoveryRequired | StoreError::UnsafeStorage)
        ));
        assert_eq!(graph(&store), before);
    }
}

#[test]
fn txn1_exact_resolved_nonterminal_replay_requires_fence_and_resource() {
    for (index, status) in [
        LeaseStatus::Active,
        LeaseStatus::Renewing,
        LeaseStatus::Error,
    ]
    .into_iter()
    .enumerate()
    {
        for lose_fence in [false, true] {
            let fixture = Fixture::new();
            let mut store = fixture.ready();
            let request = fixture.request(&format!(
                "01ARZ3NDEKTSV4RRFFQ69G5F{}{}",
                if lose_fence { 'X' } else { 'W' },
                index
            ));
            let (lease_id, _) = nonterminal(&mut store, &request, status);
            let before = graph(&store);
            if lose_fence {
                drop(store.core.profile_fences.remove(&request.profile_uid));
            } else {
                store.core.release_resource(&lease_id);
            }
            let replay_clock = clock(&store, "2026-08-22T10:00:05Z", 103);
            assert!(matches!(
                store.begin_acquire(&request, &caller(), &host(), &replay_clock),
                Err(StoreError::RecoveryRequired)
            ));
            assert_eq!(graph(&store), before, "{status:?} fence={lose_fence}");
        }
    }
}
