use crate::config::{
    ProfileAutomationResourceAcquisition, ProfileAutomationResourceMode,
    acquire_profile_automation_resource,
};

use super::*;

fn retain_authority_resource(
    ready: &mut ReadyStore,
    request: &IdentityLeaseRequest,
    lease_id: &LeaseId,
) {
    let mode = ProfileAutomationResourceMode::Exclusive;
    let profile_ref = parsed(request.profile_ref.as_str());
    let acquired = {
        let fence = ready
            .core
            .fence(&request.profile_uid)
            .unwrap_or_else(|error| panic!("retained fence: {error:?}"));
        acquire_profile_automation_resource(
            &ready.core.paths,
            &ready.core.installation_uid,
            &profile_ref,
            &request.profile_uid,
            mode,
            fence,
        )
        .unwrap_or_else(|error| panic!("authority resource: {error:?}"))
    };
    let guard = match acquired {
        ProfileAutomationResourceAcquisition::Acquired(guard) => guard,
        ProfileAutomationResourceAcquisition::Busy => panic!("authority resource was busy"),
    };
    ready
        .core
        .retain_resource(lease_id.clone(), request.profile_uid.clone(), mode, guard)
        .unwrap_or_else(|error| panic!("retain authority resource: {error:?}"));
}

#[test]
fn replay_reconstructs_full_valid_response_for_all_eight_states() {
    for status in [
        LeaseStatus::Requested,
        LeaseStatus::Active,
        LeaseStatus::Renewing,
        LeaseStatus::Error,
        LeaseStatus::Closed,
        LeaseStatus::Revoked,
        LeaseStatus::Expired,
        LeaseStatus::Refused,
    ] {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut ready = fixture.ready();
        let lease_id = seed(&mut ready, &request);
        match status {
            LeaseStatus::Requested => {}
            LeaseStatus::Refused => {
                let caller = caller();
                let host = host();
                let control = AuthenticatedRequestControl::new(&lease_id, 1, &caller, &host);
                let _ = ready
                    .refuse_requested(
                        &control,
                        refusal(RefusalCode::ProfileNotReady),
                        &stamp("2026-08-22T10:00:03Z"),
                    )
                    .unwrap_or_else(|error| panic!("refuse: {error:?}"));
            }
            LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error => {
                resolved_status(ready.test_connection(), status);
                retain_authority_resource(&mut ready, &request, &lease_id);
            }
            LeaseStatus::Closed | LeaseStatus::Revoked | LeaseStatus::Expired => {
                resolved_status(ready.test_connection(), status);
            }
        }
        let changes_before = ready.test_connection().total_changes();
        let replay = ready
            .begin_acquire(&request, &caller(), &host(), &clock(&ready, 900))
            .unwrap_or_else(|error| panic!("replay {status:?}: {error:?}"));
        assert!(!format!("{replay:?}").contains("exec_"));
        assert!(replay.replayed());
        assert_eq!(ready.test_connection().total_changes(), changes_before);
        let response = replay.outcome().response();
        assert_eq!(response.status, status);
        assert_eq!(response.lease_id, lease_id);
        assert_eq!(response.tenant_id, request.tenant_id);
        assert_eq!(response.work_order_id, request.work_order_id);
        assert_eq!(response.run_id, request.run_id);
        assert_eq!(response.caller_subject, caller());
        assert_eq!(response.host_identity, host());
        assert_eq!(
            response.execution_handle.is_some(),
            matches!(status, LeaseStatus::Active | LeaseStatus::Renewing)
        );
        if matches!(status, LeaseStatus::Active | LeaseStatus::Renewing) {
            assert_eq!(
                response
                    .execution_handle
                    .as_ref()
                    .map(crate::automation::contracts::ExecutionHandle::as_str),
                Some("exec_00000000000000000000000000")
            );
        }
        response
            .validate()
            .unwrap_or_else(|error| panic!("response {status:?}: {error:?}"));
        let wire = serde_json::to_vec(response)
            .unwrap_or_else(|error| panic!("serialize {status:?}: {error}"));
        let decoded = serde_json::from_slice(&wire)
            .unwrap_or_else(|error| panic!("decode {status:?}: {error}"));
        assert_eq!(response, &decoded);
        assert_eq!(
            replay.outcome().issuance().service_generation(),
            ready.service_clock_generation()
        );
        assert!(matches!(
            (status, replay.outcome()),
            (
                LeaseStatus::Requested,
                PersistedAcquireOutcome::Requested { .. }
            ) | (
                LeaseStatus::Refused,
                PersistedAcquireOutcome::Refused { .. }
            ) | (
                LeaseStatus::Active
                    | LeaseStatus::Renewing
                    | LeaseStatus::Error
                    | LeaseStatus::Closed
                    | LeaseStatus::Revoked
                    | LeaseStatus::Expired,
                PersistedAcquireOutcome::Resolved { .. }
            )
        ));
        let second = ready
            .begin_acquire(&request, &caller(), &host(), &clock(&ready, 901))
            .unwrap_or_else(|error| panic!("second replay {status:?}: {error:?}"));
        assert_eq!(second, replay);
        assert_eq!(ready.test_connection().total_changes(), changes_before);
    }
}
