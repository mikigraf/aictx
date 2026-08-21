use serde::Serialize;

use super::{
    request::{IdentityLeaseRequest, WorkOrderAuthorization},
    temporal::{DurationSeconds, MaximumTtlSeconds, RequestedTtlSeconds, UtcTimestamp},
    types::{
        AgentRole, AttemptId, ClientRequestId, DetachedSignature, EnvironmentName,
        IdentityLeaseRequestSchema, KeyId, ProfileRef, ProfileUid, Provider, RepositoryId, RunId,
        Sha256Digest, TenantId, WorkOrderAuthorizationSchema, WorkOrderId, WorkOrderProofAlgorithm,
        WorkspaceId,
    },
};

const SIGNATURE_DOMAIN: &[u8] = b"ctxlane.work-order-authorization/v1\0";

// All v1 string values are restricted to ASCII. Declaring keys in Unicode
// code-point order and using serde_json's compact string/integer encoding is
// therefore rigorously equivalent to RFC 8785 JCS for this closed schema.
#[derive(Serialize)]
struct UnsignedAuthorization<'a> {
    algorithm: WorkOrderProofAlgorithm,
    attempt_id: &'a AttemptId,
    client_request_id: &'a ClientRequestId,
    environment: &'a EnvironmentName,
    expires_at: &'a UtcTimestamp,
    key_id: &'a KeyId,
    maximum_session_seconds: DurationSeconds,
    maximum_ttl_seconds: MaximumTtlSeconds,
    not_before: &'a UtcTimestamp,
    profile_ref: &'a ProfileRef,
    profile_uid: &'a ProfileUid,
    provider: Provider,
    repository: &'a RepositoryId,
    role: AgentRole,
    run_id: &'a RunId,
    schema: WorkOrderAuthorizationSchema,
    tenant_id: &'a TenantId,
    work_order_digest: Sha256Digest,
    work_order_id: &'a WorkOrderId,
    workspace_id: &'a WorkspaceId,
}

#[derive(Serialize)]
struct SignedAuthorization<'a> {
    algorithm: WorkOrderProofAlgorithm,
    attempt_id: &'a AttemptId,
    client_request_id: &'a ClientRequestId,
    environment: &'a EnvironmentName,
    expires_at: &'a UtcTimestamp,
    key_id: &'a KeyId,
    maximum_session_seconds: DurationSeconds,
    maximum_ttl_seconds: MaximumTtlSeconds,
    not_before: &'a UtcTimestamp,
    profile_ref: &'a ProfileRef,
    profile_uid: &'a ProfileUid,
    provider: Provider,
    repository: &'a RepositoryId,
    role: AgentRole,
    run_id: &'a RunId,
    schema: WorkOrderAuthorizationSchema,
    signature: &'a DetachedSignature,
    tenant_id: &'a TenantId,
    work_order_digest: Sha256Digest,
    work_order_id: &'a WorkOrderId,
    workspace_id: &'a WorkspaceId,
}

impl<'a> From<&'a WorkOrderAuthorization> for UnsignedAuthorization<'a> {
    fn from(value: &'a WorkOrderAuthorization) -> Self {
        Self {
            algorithm: value.algorithm,
            attempt_id: &value.attempt_id,
            client_request_id: &value.client_request_id,
            environment: &value.environment,
            expires_at: &value.expires_at,
            key_id: &value.key_id,
            maximum_session_seconds: value.maximum_session_seconds,
            maximum_ttl_seconds: value.maximum_ttl_seconds,
            not_before: &value.not_before,
            profile_ref: &value.profile_ref,
            profile_uid: &value.profile_uid,
            provider: value.provider,
            repository: &value.repository,
            role: value.role,
            run_id: &value.run_id,
            schema: value.schema,
            tenant_id: &value.tenant_id,
            work_order_digest: value.work_order_digest,
            work_order_id: &value.work_order_id,
            workspace_id: &value.workspace_id,
        }
    }
}

impl<'a> From<&'a WorkOrderAuthorization> for SignedAuthorization<'a> {
    fn from(value: &'a WorkOrderAuthorization) -> Self {
        Self {
            algorithm: value.algorithm,
            attempt_id: &value.attempt_id,
            client_request_id: &value.client_request_id,
            environment: &value.environment,
            expires_at: &value.expires_at,
            key_id: &value.key_id,
            maximum_session_seconds: value.maximum_session_seconds,
            maximum_ttl_seconds: value.maximum_ttl_seconds,
            not_before: &value.not_before,
            profile_ref: &value.profile_ref,
            profile_uid: &value.profile_uid,
            provider: value.provider,
            repository: &value.repository,
            role: value.role,
            run_id: &value.run_id,
            schema: value.schema,
            signature: &value.signature,
            tenant_id: &value.tenant_id,
            work_order_digest: value.work_order_digest,
            work_order_id: &value.work_order_id,
            workspace_id: &value.workspace_id,
        }
    }
}

#[derive(Serialize)]
struct CanonicalRequest<'a> {
    attempt_id: &'a AttemptId,
    client_request_id: &'a ClientRequestId,
    environment: &'a EnvironmentName,
    policy_digest: Option<Sha256Digest>,
    profile_ref: &'a ProfileRef,
    profile_uid: &'a ProfileUid,
    provider: Provider,
    repository: &'a RepositoryId,
    requested_ttl_seconds: RequestedTtlSeconds,
    role: AgentRole,
    run_id: &'a RunId,
    schema: IdentityLeaseRequestSchema,
    tenant_id: &'a TenantId,
    work_order_authorization: SignedAuthorization<'a>,
    work_order_digest: Sha256Digest,
    work_order_id: &'a WorkOrderId,
    workspace_id: &'a WorkspaceId,
}

pub(super) fn authorization_signature_message(
    authorization: &WorkOrderAuthorization,
) -> Result<Vec<u8>, serde_json::Error> {
    let canonical = serde_json::to_vec(&UnsignedAuthorization::from(authorization))?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&canonical);
    Ok(message)
}

pub(super) fn request_json(request: &IdentityLeaseRequest) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&CanonicalRequest {
        attempt_id: &request.attempt_id,
        client_request_id: &request.client_request_id,
        environment: &request.environment,
        policy_digest: request.policy_digest,
        profile_ref: &request.profile_ref,
        profile_uid: &request.profile_uid,
        provider: request.provider,
        repository: &request.repository,
        requested_ttl_seconds: request.requested_ttl_seconds,
        role: request.role,
        run_id: &request.run_id,
        schema: request.schema,
        tenant_id: &request.tenant_id,
        work_order_authorization: SignedAuthorization::from(&request.work_order_authorization),
        work_order_digest: request.work_order_digest,
        work_order_id: &request.work_order_id,
        workspace_id: &request.workspace_id,
    })
}
