use rusqlite::{Transaction, params};

use crate::automation::contracts::{CallerSubject, HostIdentity, IdentityLeaseRequest};

use crate::automation::store::{
    StoreError,
    records::{StoredTimestamp, role_label},
};

#[allow(clippy::too_many_arguments)]
pub(super) fn request(
    transaction: &Transaction<'_>,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    request_record_id: &str,
    canonical: &[u8],
    digest: &str,
    authorization_expiry: &StoredTimestamp<'_>,
    replay_retention: &StoredTimestamp<'_>,
    recorded_at: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO lease_requests (
                request_record_id, client_request_id, canonical_authority_digest,
                canonical_request, authenticated_caller, host_identity,
                authorization_expires_at_utc, authorization_expires_at_seconds,
                authorization_expires_at_nanos, replay_retain_until_utc,
                replay_retain_until_seconds, replay_retain_until_nanos,
                recorded_at_utc, recorded_at_seconds, recorded_at_nanos
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
             )",
            params![
                request_record_id,
                request.client_request_id.as_str(),
                digest,
                canonical,
                caller.as_str(),
                host.as_str(),
                authorization_expiry.wire,
                authorization_expiry.seconds,
                authorization_expiry.nanos,
                replay_retention.wire,
                replay_retention.seconds,
                replay_retention.nanos,
                recorded_at.wire,
                recorded_at.seconds,
                recorded_at.nanos
            ],
        )
        .map(|_| ())
        .map_err(|_| StoreError::DatabaseUnavailable)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn requested_lease(
    transaction: &Transaction<'_>,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    request_record_id: &str,
    lease_id: &str,
    service_generation: i64,
    issued_at: &StoredTimestamp<'_>,
    issued_monotonic: &[u8; 16],
) -> Result<(), StoreError> {
    let policy_digest = request.policy_digest.map(|value| value.to_string());
    let requested_ttl = i64::try_from(request.requested_ttl_seconds.get())
        .map_err(|_| StoreError::InvalidRequest)?;
    transaction
        .execute(
            "INSERT INTO leases (
                lease_id, request_record_id, service_generation, row_version,
                next_audit_sequence, status, recovery_state, quarantined,
                tenant_id, work_order_id, work_order_digest, run_id, attempt_id,
                role, provider, profile_uid, profile_ref, repository_id, workspace_id,
                environment, authenticated_caller, host_identity, requested_ttl_seconds,
                requested_policy_digest, issued_at_utc, issued_at_seconds, issued_at_nanos,
                issued_monotonic_nanos
             ) VALUES (
                ?1, ?2, ?3, 1, 2, 'REQUESTED', 'NONE', 0,
                ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
             )",
            params![
                lease_id,
                request_record_id,
                service_generation,
                request.tenant_id.as_str(),
                request.work_order_id.as_str(),
                request.work_order_digest.to_string(),
                request.run_id.as_str(),
                request.attempt_id.as_str(),
                role_label(request.role),
                request.provider.to_string(),
                request.profile_uid.as_str(),
                request.profile_ref.as_str(),
                request.repository.as_str(),
                request.workspace_id.as_str(),
                request.environment.as_str(),
                caller.as_str(),
                host.as_str(),
                requested_ttl,
                policy_digest,
                issued_at.wire,
                issued_at.seconds,
                issued_at.nanos,
                issued_monotonic.as_slice()
            ],
        )
        .map(|_| ())
        .map_err(|_| StoreError::DatabaseUnavailable)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn requested_audit(
    transaction: &Transaction<'_>,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    audit_id: &str,
    lease_id: &str,
    service_generation: i64,
    now: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller, host_identity
             ) VALUES (
                ?1, ?2, 1, ?3, 'lease.requested', 'recorded', 'REQUESTED', 'NONE', 0,
                ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21, ?22
             )",
            params![
                audit_id,
                lease_id,
                service_generation,
                now.wire,
                now.seconds,
                now.nanos,
                caller.as_str(),
                request.client_request_id.as_str(),
                request.tenant_id.as_str(),
                request.work_order_id.as_str(),
                request.work_order_digest.to_string(),
                request.run_id.as_str(),
                request.attempt_id.as_str(),
                role_label(request.role),
                request.provider.to_string(),
                request.profile_uid.as_str(),
                request.profile_ref.as_str(),
                request.repository.as_str(),
                request.workspace_id.as_str(),
                request.environment.as_str(),
                caller.as_str(),
                host.as_str()
            ],
        )
        .map(|_| ())
        .map_err(|_| StoreError::DatabaseUnavailable)
}
