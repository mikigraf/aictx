use serde::{Deserialize, Serialize};

use super::{
    references::{CallerSubject, HostIdentity, PrincipalRef, WorkerIdentity, WorkspaceRef},
    temporal::{FencingGeneration, UtcTimestamp},
    types::{
        AgentRole, AttemptId, AutomationAuthMode, ContractValidationError, EnvironmentName,
        ExecutionHandle, IdentityLeaseSchema, IsolationClassification, LeaseId, LeaseReasonCode,
        LeaseStatus, ProfileRef, ProfileUid, Provider, RefusalCode, RepositoryId, RunId,
        Sha256Digest, TenantId, WorkOrderId, WorkspaceId,
    },
};

/// Non-secret lease attribution suitable for MCP, JSON output, and audit views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityLeaseResponse {
    pub schema: IdentityLeaseSchema,
    pub lease_id: LeaseId,
    pub status: LeaseStatus,
    pub tenant_id: TenantId,
    pub work_order_id: WorkOrderId,
    pub work_order_digest: Sha256Digest,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub role: AgentRole,
    pub provider: Provider,
    pub profile_uid: ProfileUid,
    pub profile_ref: ProfileRef,
    pub repository: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub environment: EnvironmentName,
    /// Derived from the authenticated transport, never request JSON.
    pub caller_subject: CallerSubject,
    pub host_identity: HostIdentity,
    pub worker_identity: Option<WorkerIdentity>,
    pub principal_ref: Option<PrincipalRef>,
    pub workspace_ref: Option<WorkspaceRef>,
    pub auth_mode: Option<AutomationAuthMode>,
    pub fencing_generation: Option<FencingGeneration>,
    pub issued_at: UtcTimestamp,
    pub expires_at: Option<UtcTimestamp>,
    pub maximum_expires_at: Option<UtcTimestamp>,
    /// Present only for an active or renewing lease.
    pub execution_handle: Option<ExecutionHandle>,
    pub isolation: Option<IsolationClassification>,
    /// Computed from operator policy, never copied from the request expectation.
    pub effective_policy_digest: Option<Sha256Digest>,
    pub refusal_code: Option<RefusalCode>,
    pub reason_code: Option<LeaseReasonCode>,
}

#[derive(Deserialize)]
struct RequiredNullable<T>(Option<T>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWire {
    schema: IdentityLeaseSchema,
    lease_id: LeaseId,
    status: LeaseStatus,
    tenant_id: TenantId,
    work_order_id: WorkOrderId,
    work_order_digest: Sha256Digest,
    run_id: RunId,
    attempt_id: AttemptId,
    role: AgentRole,
    provider: Provider,
    profile_uid: ProfileUid,
    profile_ref: ProfileRef,
    repository: RepositoryId,
    workspace_id: WorkspaceId,
    environment: EnvironmentName,
    caller_subject: CallerSubject,
    host_identity: HostIdentity,
    worker_identity: RequiredNullable<WorkerIdentity>,
    principal_ref: RequiredNullable<PrincipalRef>,
    workspace_ref: RequiredNullable<WorkspaceRef>,
    auth_mode: RequiredNullable<AutomationAuthMode>,
    fencing_generation: RequiredNullable<FencingGeneration>,
    issued_at: UtcTimestamp,
    expires_at: RequiredNullable<UtcTimestamp>,
    maximum_expires_at: RequiredNullable<UtcTimestamp>,
    execution_handle: RequiredNullable<ExecutionHandle>,
    isolation: RequiredNullable<IsolationClassification>,
    effective_policy_digest: RequiredNullable<Sha256Digest>,
    refusal_code: RequiredNullable<RefusalCode>,
    reason_code: RequiredNullable<LeaseReasonCode>,
}

#[derive(Serialize)]
struct ResponseWireRef<'a> {
    schema: IdentityLeaseSchema,
    lease_id: &'a LeaseId,
    status: LeaseStatus,
    tenant_id: &'a TenantId,
    work_order_id: &'a WorkOrderId,
    work_order_digest: Sha256Digest,
    run_id: &'a RunId,
    attempt_id: &'a AttemptId,
    role: AgentRole,
    provider: Provider,
    profile_uid: &'a ProfileUid,
    profile_ref: &'a ProfileRef,
    repository: &'a RepositoryId,
    workspace_id: &'a WorkspaceId,
    environment: &'a EnvironmentName,
    caller_subject: &'a CallerSubject,
    host_identity: &'a HostIdentity,
    worker_identity: &'a Option<WorkerIdentity>,
    principal_ref: &'a Option<PrincipalRef>,
    workspace_ref: &'a Option<WorkspaceRef>,
    auth_mode: &'a Option<AutomationAuthMode>,
    fencing_generation: &'a Option<FencingGeneration>,
    issued_at: &'a UtcTimestamp,
    expires_at: &'a Option<UtcTimestamp>,
    maximum_expires_at: &'a Option<UtcTimestamp>,
    execution_handle: &'a Option<ExecutionHandle>,
    isolation: &'a Option<IsolationClassification>,
    effective_policy_digest: &'a Option<Sha256Digest>,
    refusal_code: &'a Option<RefusalCode>,
    reason_code: &'a Option<LeaseReasonCode>,
}

impl IdentityLeaseResponse {
    /// Validate provider, time, resolution, handle, and reason-code invariants.
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.provider != self.profile_ref.provider() {
            return Err(ContractValidationError::ProviderProfileMismatch);
        }
        if self
            .workspace_ref
            .as_ref()
            .is_some_and(|workspace| !workspace.matches_provider(self.provider))
        {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "workspace_ref namespace does not match provider",
            ));
        }
        if self
            .auth_mode
            .is_some_and(|mode| !mode.supports_provider(self.provider))
        {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "auth_mode is not valid for provider",
            ));
        }
        match self.refusal_code {
            Some(RefusalCode::OrganizationMismatch) if self.provider != Provider::Claude => {
                return Err(ContractValidationError::InvalidResponseInvariant(
                    "organization-mismatch is only valid for Claude",
                ));
            }
            Some(RefusalCode::WorkspaceMismatch) if self.provider != Provider::Codex => {
                return Err(ContractValidationError::InvalidResponseInvariant(
                    "workspace-mismatch is only valid for Codex",
                ));
            }
            _ => {}
        }
        if self.execution_handle.is_some() != self.status.permits_execution_handle() {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "execution_handle must be present only for active or renewing leases",
            ));
        }
        if self.status.requires_resolution()
            && (self.principal_ref.is_none()
                || self.workspace_ref.is_none()
                || self.auth_mode.is_none()
                || self.isolation.is_none()
                || self.fencing_generation.is_none()
                || self.expires_at.is_none()
                || self.maximum_expires_at.is_none()
                || self.effective_policy_digest.is_none())
        {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "activated leases require resolved profile, identity, timing, and policy attribution",
            ));
        }
        if self.status.requires_resolution() {
            match self.isolation {
                Some(IsolationClassification::Unproven) => {
                    return Err(ContractValidationError::InvalidResponseInvariant(
                        "resolved leases require proven credential isolation",
                    ));
                }
                Some(IsolationClassification::CopiedCredentialDevelopment)
                    if self.environment.as_str() != "local-development"
                        && self.role != AgentRole::PrReviewer =>
                {
                    return Err(ContractValidationError::InvalidResponseInvariant(
                        "copied credentials are limited to local development or PR review",
                    ));
                }
                _ => {}
            }
        }
        if matches!(self.status, LeaseStatus::Requested | LeaseStatus::Refused)
            && (self.worker_identity.is_some()
                || self.fencing_generation.is_some()
                || self.expires_at.is_some()
                || self.maximum_expires_at.is_some()
                || self.effective_policy_digest.is_some()
                || self.principal_ref.is_some()
                || self.workspace_ref.is_some()
                || self.auth_mode.is_some()
                || self.isolation.is_some())
        {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "requested and refused leases cannot claim activated authority",
            ));
        }
        self.validate_timestamps()?;
        self.validate_codes()
    }

    fn validate_timestamps(&self) -> Result<(), ContractValidationError> {
        match (&self.expires_at, &self.maximum_expires_at) {
            (Some(expires_at), Some(maximum_expires_at)) => {
                if !self.issued_at.is_before(expires_at) {
                    return Err(ContractValidationError::InvalidResponseInvariant(
                        "issued_at must be earlier than expires_at",
                    ));
                }
                if maximum_expires_at.is_before(expires_at) {
                    return Err(ContractValidationError::InvalidResponseInvariant(
                        "expires_at must not exceed maximum_expires_at",
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ContractValidationError::InvalidResponseInvariant(
                    "expires_at and maximum_expires_at must be present together",
                ));
            }
        }
        Ok(())
    }

    fn validate_codes(&self) -> Result<(), ContractValidationError> {
        let valid = match self.status {
            LeaseStatus::Refused => self.refusal_code.is_some() && self.reason_code.is_none(),
            LeaseStatus::Closed => {
                self.refusal_code.is_none()
                    && self.reason_code.is_some_and(|reason| {
                        matches!(
                            reason,
                            LeaseReasonCode::Completed | LeaseReasonCode::WorkerFailed
                        )
                    })
            }
            LeaseStatus::Expired => {
                self.refusal_code.is_none()
                    && self.reason_code.is_some_and(|reason| {
                        matches!(
                            reason,
                            LeaseReasonCode::LeaseExpired | LeaseReasonCode::MaximumLifetimeReached
                        )
                    })
            }
            LeaseStatus::Revoked => {
                self.refusal_code.is_none()
                    && self.reason_code.is_some_and(|reason| {
                        matches!(
                            reason,
                            LeaseReasonCode::OperatorRevoked
                                | LeaseReasonCode::PolicyRevoked
                                | LeaseReasonCode::PrincipalMismatch
                                | LeaseReasonCode::HeartbeatLost
                                | LeaseReasonCode::ProcessUnverifiable
                                | LeaseReasonCode::GenerationSuperseded
                                | LeaseReasonCode::RenewalAcknowledgementFailed
                                | LeaseReasonCode::ServiceRecovery
                        )
                    })
            }
            LeaseStatus::Error => {
                self.refusal_code.is_none()
                    && self.reason_code.is_some_and(|reason| {
                        matches!(
                            reason,
                            LeaseReasonCode::ProcessUnverifiable
                                | LeaseReasonCode::ServiceRecovery
                                | LeaseReasonCode::InternalError
                        )
                    })
            }
            LeaseStatus::Requested | LeaseStatus::Active | LeaseStatus::Renewing => {
                self.refusal_code.is_none() && self.reason_code.is_none()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(ContractValidationError::InvalidResponseInvariant(
                "refusal_code and reason_code do not match lease status",
            ))
        }
    }

    fn wire_ref(&self) -> ResponseWireRef<'_> {
        ResponseWireRef {
            schema: self.schema,
            lease_id: &self.lease_id,
            status: self.status,
            tenant_id: &self.tenant_id,
            work_order_id: &self.work_order_id,
            work_order_digest: self.work_order_digest,
            run_id: &self.run_id,
            attempt_id: &self.attempt_id,
            role: self.role,
            provider: self.provider,
            profile_uid: &self.profile_uid,
            profile_ref: &self.profile_ref,
            repository: &self.repository,
            workspace_id: &self.workspace_id,
            environment: &self.environment,
            caller_subject: &self.caller_subject,
            host_identity: &self.host_identity,
            worker_identity: &self.worker_identity,
            principal_ref: &self.principal_ref,
            workspace_ref: &self.workspace_ref,
            auth_mode: &self.auth_mode,
            fencing_generation: &self.fencing_generation,
            issued_at: &self.issued_at,
            expires_at: &self.expires_at,
            maximum_expires_at: &self.maximum_expires_at,
            execution_handle: &self.execution_handle,
            isolation: &self.isolation,
            effective_policy_digest: &self.effective_policy_digest,
            refusal_code: &self.refusal_code,
            reason_code: &self.reason_code,
        }
    }
}

impl TryFrom<ResponseWire> for IdentityLeaseResponse {
    type Error = ContractValidationError;

    fn try_from(value: ResponseWire) -> Result<Self, Self::Error> {
        let response = Self {
            schema: value.schema,
            lease_id: value.lease_id,
            status: value.status,
            tenant_id: value.tenant_id,
            work_order_id: value.work_order_id,
            work_order_digest: value.work_order_digest,
            run_id: value.run_id,
            attempt_id: value.attempt_id,
            role: value.role,
            provider: value.provider,
            profile_uid: value.profile_uid,
            profile_ref: value.profile_ref,
            repository: value.repository,
            workspace_id: value.workspace_id,
            environment: value.environment,
            caller_subject: value.caller_subject,
            host_identity: value.host_identity,
            worker_identity: value.worker_identity.0,
            principal_ref: value.principal_ref.0,
            workspace_ref: value.workspace_ref.0,
            auth_mode: value.auth_mode.0,
            fencing_generation: value.fencing_generation.0,
            issued_at: value.issued_at,
            expires_at: value.expires_at.0,
            maximum_expires_at: value.maximum_expires_at.0,
            execution_handle: value.execution_handle.0,
            isolation: value.isolation.0,
            effective_policy_digest: value.effective_policy_digest.0,
            refusal_code: value.refusal_code.0,
            reason_code: value.reason_code.0,
        };
        response.validate()?;
        Ok(response)
    }
}

impl Serialize for IdentityLeaseResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        self.wire_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdentityLeaseResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ResponseWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}
