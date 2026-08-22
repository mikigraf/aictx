use std::num::NonZeroU32;

use crate::{
    automation::contracts::{
        AutomationAuthMode, CallerSubject, IdentityLeaseRequest, IsolationClassification,
    },
    model::{AutomationConcurrencyMode, SharedStateIsolationRequirement},
};

use super::{CapacityClaim, CapacityLimits, EffectivePolicy, PolicyRequirements};

/// Mechanical test construction only. This deliberately proves no policy,
/// controller-epoch, configuration-digest, or runtime-readiness freshness.
// Only supported-target store tests construct effective policies through this helper.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn effective_policy(
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &crate::automation::contracts::HostIdentity,
    mode: AutomationConcurrencyMode,
    isolation: IsolationClassification,
    shared: Option<SharedStateIsolationRequirement>,
    limits: [u32; 4],
) -> EffectivePolicy {
    let limit = |value| NonZeroU32::new(value).unwrap_or(NonZeroU32::MIN);
    EffectivePolicy {
        source_request_digest: request
            .authority_digest()
            .unwrap_or_else(|error| panic!("request digest: {error:?}")),
        client_request_id: request.client_request_id.clone(),
        tenant_id: request.tenant_id.clone(),
        work_order_id: request.work_order_id.clone(),
        work_order_digest: request.work_order_digest,
        run_id: request.run_id.clone(),
        attempt_id: request.attempt_id.clone(),
        role: request.role,
        provider: request.provider,
        profile_uid: request.profile_uid.clone(),
        profile_ref: request.profile_ref.clone(),
        repository: request.repository.clone(),
        workspace_id: request.workspace_id.clone(),
        environment: request.environment.clone(),
        caller_subject: caller.clone(),
        host_identity: host.clone(),
        auth_mode: AutomationAuthMode::ChatgptOauth,
        isolation,
        shared_state_isolation: shared,
        requested_ttl_seconds: request.requested_ttl_seconds.get(),
        maximum_ttl_seconds: request.work_order_authorization.maximum_ttl_seconds.get(),
        maximum_session_seconds: request
            .work_order_authorization
            .maximum_session_seconds
            .get(),
        signed_expires_at: request.work_order_authorization.expires_at.clone(),
        concurrency_mode: mode,
        requirements: PolicyRequirements {
            workload_identity: false,
            authentication_exception: false,
            isolation_exception: false,
        },
        capacity_claim: CapacityClaim {
            profile_uid: request.profile_uid.clone(),
            provider: request.provider,
            caller_subject: caller.clone(),
            host_identity: host.clone(),
            limits: CapacityLimits::new(
                limit(limits[0]),
                limit(limits[1]),
                limit(limits[2]),
                limit(limits[3]),
            ),
        },
    }
}
