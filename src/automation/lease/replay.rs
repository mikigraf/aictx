use crate::automation::contracts::{
    AgentRole, AttemptId, AutomationErrorCode, CallerSubject, ClientRequestId,
    ContractEncodingError, HostIdentity, IdentityLeaseRequest, LeaseId, ProfileRef, ProfileUid,
    Provider, RepositoryId, RunId, Sha256Digest, TenantId, UtcTimestamp, WorkOrderId, WorkspaceId,
};

use super::{EnvironmentName, clock::later};

#[derive(Debug, Eq, PartialEq)]
pub struct LeaseBinding {
    pub(super) lease_id: LeaseId,
    pub(super) client_request_id: ClientRequestId,
    pub(super) authority_digest: Sha256Digest,
    pub(super) tenant_id: TenantId,
    pub(super) work_order_id: WorkOrderId,
    pub(super) work_order_digest: Sha256Digest,
    pub(super) run_id: RunId,
    pub(super) attempt_id: AttemptId,
    pub(super) role: AgentRole,
    pub(super) provider: Provider,
    pub(super) profile_uid: ProfileUid,
    pub(super) profile_ref: ProfileRef,
    pub(super) repository: RepositoryId,
    pub(super) workspace_id: WorkspaceId,
    pub(super) environment: EnvironmentName,
    pub(super) initial_requested_ttl_seconds: u64,
    pub(super) caller_subject: CallerSubject,
    pub(super) host_identity: HostIdentity,
    pub(super) signed_authorization_expires_at: UtcTimestamp,
}

impl LeaseBinding {
    pub fn from_request(
        lease_id: LeaseId,
        request: &IdentityLeaseRequest,
        caller_subject: CallerSubject,
        host_identity: HostIdentity,
    ) -> Result<Self, ContractEncodingError> {
        Ok(Self {
            lease_id,
            client_request_id: request.client_request_id.clone(),
            authority_digest: request.authority_digest()?,
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
            initial_requested_ttl_seconds: request.requested_ttl_seconds.get(),
            caller_subject,
            host_identity,
            signed_authorization_expires_at: request.work_order_authorization.expires_at.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBinding {
    pub(super) lease_id: LeaseId,
    pub(super) client_request_id: ClientRequestId,
    pub(super) authority_digest: Sha256Digest,
    pub(super) caller_subject: CallerSubject,
    pub(super) host_identity: HostIdentity,
    pub(super) signed_authorization_expires_at: UtcTimestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayDisposition {
    UnrelatedKey,
    ExactRetry(LeaseId),
    Conflict(AutomationErrorCode),
}

impl ReplayBinding {
    #[must_use]
    pub const fn signed_authorization_expires_at(&self) -> &UtcTimestamp {
        &self.signed_authorization_expires_at
    }

    #[must_use]
    pub fn retention_deadline(&self, local_horizon: &UtcTimestamp) -> UtcTimestamp {
        later(&self.signed_authorization_expires_at, local_horizon).clone()
    }

    #[must_use]
    pub fn compare(&self, candidate: &Self) -> ReplayDisposition {
        if self.client_request_id != candidate.client_request_id {
            ReplayDisposition::UnrelatedKey
        } else if self.authority_digest == candidate.authority_digest
            && self.caller_subject == candidate.caller_subject
            && self.host_identity == candidate.host_identity
        {
            ReplayDisposition::ExactRetry(self.lease_id.clone())
        } else {
            ReplayDisposition::Conflict(AutomationErrorCode::IdempotencyConflict)
        }
    }
}
