use serde::{Deserialize, Serialize};

use super::{
    canonical,
    temporal::{DurationSeconds, MaximumTtlSeconds, RequestedTtlSeconds, UtcTimestamp},
    types::{
        AgentRole, AttemptId, ClientRequestId, ContractEncodingError, ContractValidationError,
        DetachedSignature, EnvironmentName, IdentityLeaseRequestSchema, KeyId, ProfileRef,
        ProfileUid, Provider, RepositoryId, RunId, Sha256Digest, TenantId,
        WorkOrderAuthorizationSchema, WorkOrderId, WorkOrderProofAlgorithm, WorkspaceId,
    },
};

#[derive(Deserialize, Serialize)]
struct RequiredNullable<T>(Option<T>);

/// Signed maximum authority for one work order and agent role.
///
/// The signature covers every field except `signature`, including the schema,
/// algorithm, key ID, validity interval, and lifetime limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkOrderAuthorization {
    pub schema: WorkOrderAuthorizationSchema,
    pub algorithm: WorkOrderProofAlgorithm,
    pub key_id: KeyId,
    pub client_request_id: ClientRequestId,
    pub tenant_id: TenantId,
    pub work_order_id: WorkOrderId,
    pub work_order_digest: Sha256Digest,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub role: AgentRole,
    pub provider: Provider,
    pub profile_ref: ProfileRef,
    pub profile_uid: ProfileUid,
    pub repository: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub environment: EnvironmentName,
    pub not_before: UtcTimestamp,
    pub expires_at: UtcTimestamp,
    pub maximum_ttl_seconds: MaximumTtlSeconds,
    pub maximum_session_seconds: DurationSeconds,
    pub signature: DetachedSignature,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkOrderAuthorizationWire {
    schema: WorkOrderAuthorizationSchema,
    algorithm: WorkOrderProofAlgorithm,
    key_id: KeyId,
    client_request_id: ClientRequestId,
    tenant_id: TenantId,
    work_order_id: WorkOrderId,
    work_order_digest: Sha256Digest,
    run_id: RunId,
    attempt_id: AttemptId,
    role: AgentRole,
    provider: Provider,
    profile_ref: ProfileRef,
    profile_uid: ProfileUid,
    repository: RepositoryId,
    workspace_id: WorkspaceId,
    environment: EnvironmentName,
    not_before: UtcTimestamp,
    expires_at: UtcTimestamp,
    maximum_ttl_seconds: MaximumTtlSeconds,
    maximum_session_seconds: DurationSeconds,
    signature: DetachedSignature,
}

impl WorkOrderAuthorization {
    fn validate_structure(&self) -> Result<(), ContractValidationError> {
        if self.provider != self.profile_ref.provider() {
            return Err(ContractValidationError::ProviderProfileMismatch);
        }
        Ok(())
    }

    /// Validate contract shape, provider binding, validity ordering, and limits.
    ///
    /// This does not authenticate `signature` or `key_id`. A service must use
    /// [`Self::signature_message`] with an operator-configured Ed25519 key and
    /// apply caller and local policy before granting any authority.
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        self.validate_structure()?;
        if !self.not_before.is_before(&self.expires_at) {
            return Err(ContractValidationError::InvalidAuthorizationValidity);
        }
        if self.maximum_ttl_seconds.get() > self.maximum_session_seconds.get() {
            return Err(ContractValidationError::InvalidAuthorizationLimits);
        }
        if self
            .not_before
            .seconds_until(&self.expires_at)
            .is_none_or(|seconds| self.maximum_session_seconds.get() > seconds)
        {
            return Err(ContractValidationError::InvalidAuthorizationLimits);
        }
        Ok(())
    }

    /// Return the domain-separated bytes that Ed25519 signs.
    pub fn signature_message(&self) -> Result<Vec<u8>, ContractEncodingError> {
        self.validate_structure()?;
        Ok(canonical::authorization_signature_message(self)?)
    }

    fn wire(&self) -> WorkOrderAuthorizationWire {
        WorkOrderAuthorizationWire {
            schema: self.schema,
            algorithm: self.algorithm,
            key_id: self.key_id.clone(),
            client_request_id: self.client_request_id.clone(),
            tenant_id: self.tenant_id.clone(),
            work_order_id: self.work_order_id.clone(),
            work_order_digest: self.work_order_digest,
            run_id: self.run_id.clone(),
            attempt_id: self.attempt_id.clone(),
            role: self.role,
            provider: self.provider,
            profile_ref: self.profile_ref.clone(),
            profile_uid: self.profile_uid.clone(),
            repository: self.repository.clone(),
            workspace_id: self.workspace_id.clone(),
            environment: self.environment.clone(),
            not_before: self.not_before.clone(),
            expires_at: self.expires_at.clone(),
            maximum_ttl_seconds: self.maximum_ttl_seconds,
            maximum_session_seconds: self.maximum_session_seconds,
            signature: self.signature.clone(),
        }
    }
}

impl Serialize for WorkOrderAuthorization {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        self.wire().serialize(serializer)
    }
}

impl TryFrom<WorkOrderAuthorizationWire> for WorkOrderAuthorization {
    type Error = ContractValidationError;

    fn try_from(value: WorkOrderAuthorizationWire) -> Result<Self, Self::Error> {
        let authorization = Self {
            schema: value.schema,
            algorithm: value.algorithm,
            key_id: value.key_id,
            client_request_id: value.client_request_id,
            tenant_id: value.tenant_id,
            work_order_id: value.work_order_id,
            work_order_digest: value.work_order_digest,
            run_id: value.run_id,
            attempt_id: value.attempt_id,
            role: value.role,
            provider: value.provider,
            profile_ref: value.profile_ref,
            profile_uid: value.profile_uid,
            repository: value.repository,
            workspace_id: value.workspace_id,
            environment: value.environment,
            not_before: value.not_before,
            expires_at: value.expires_at,
            maximum_ttl_seconds: value.maximum_ttl_seconds,
            maximum_session_seconds: value.maximum_session_seconds,
            signature: value.signature,
        };
        authorization.validate_structure()?;
        Ok(authorization)
    }
}

impl<'de> Deserialize<'de> for WorkOrderAuthorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        WorkOrderAuthorizationWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

/// Versioned lease request supplied by an authenticated trusted controller.
///
/// Caller, UID, GID, host, worker, and process identities are absent by design.
/// The service derives them from its authenticated transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityLeaseRequest {
    pub schema: IdentityLeaseRequestSchema,
    pub client_request_id: ClientRequestId,
    pub tenant_id: TenantId,
    pub work_order_id: WorkOrderId,
    pub work_order_digest: Sha256Digest,
    pub work_order_authorization: WorkOrderAuthorization,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub role: AgentRole,
    pub provider: Provider,
    pub profile_ref: ProfileRef,
    pub profile_uid: ProfileUid,
    pub repository: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub environment: EnvironmentName,
    pub requested_ttl_seconds: RequestedTtlSeconds,
    /// An optional client equality expectation, never an authority grant.
    /// `None` means no consistency assertion. The service computes and
    /// enforces the effective digest; successfully resolved leases persist and
    /// return it, while requested and refused responses keep it absent.
    pub policy_digest: Option<Sha256Digest>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityLeaseRequestWire {
    schema: IdentityLeaseRequestSchema,
    client_request_id: ClientRequestId,
    tenant_id: TenantId,
    work_order_id: WorkOrderId,
    work_order_digest: Sha256Digest,
    work_order_authorization: WorkOrderAuthorization,
    run_id: RunId,
    attempt_id: AttemptId,
    role: AgentRole,
    provider: Provider,
    profile_ref: ProfileRef,
    profile_uid: ProfileUid,
    repository: RepositoryId,
    workspace_id: WorkspaceId,
    environment: EnvironmentName,
    requested_ttl_seconds: RequestedTtlSeconds,
    policy_digest: RequiredNullable<Sha256Digest>,
}

macro_rules! require_signed_match {
    ($request:expr, $field:ident) => {
        if $request.$field != $request.work_order_authorization.$field {
            return Err(ContractValidationError::WorkOrderAuthorizationMismatch {
                field: stringify!($field),
            });
        }
    };
}

impl IdentityLeaseRequest {
    fn validate_structure(&self) -> Result<(), ContractValidationError> {
        if self.provider != self.profile_ref.provider() {
            return Err(ContractValidationError::ProviderProfileMismatch);
        }
        self.work_order_authorization.validate_structure()
    }

    /// Validate contract-internal top-level/envelope equality and TTL limits.
    ///
    /// This method does not verify the Ed25519 signature, trust `key_id`,
    /// authenticate the caller, or apply local policy. It must never be used by
    /// itself to grant authority.
    pub fn validate_authorization_binding(&self) -> Result<(), ContractValidationError> {
        self.work_order_authorization.validate()?;
        self.validate_structure()?;
        require_signed_match!(self, client_request_id);
        require_signed_match!(self, tenant_id);
        require_signed_match!(self, work_order_id);
        require_signed_match!(self, work_order_digest);
        require_signed_match!(self, run_id);
        require_signed_match!(self, attempt_id);
        require_signed_match!(self, role);
        require_signed_match!(self, provider);
        require_signed_match!(self, profile_ref);
        require_signed_match!(self, profile_uid);
        require_signed_match!(self, repository);
        require_signed_match!(self, workspace_id);
        require_signed_match!(self, environment);
        if self.requested_ttl_seconds.get()
            > self.work_order_authorization.maximum_ttl_seconds.get()
            || self.requested_ttl_seconds.get()
                > self.work_order_authorization.maximum_session_seconds.get()
        {
            return Err(ContractValidationError::RequestedTtlExceedsAuthorization);
        }
        Ok(())
    }

    /// Validate contract binding and the half-open validity interval.
    ///
    /// The requested lease must fit wholly inside `[not_before, expires_at)`.
    /// A service derives `maximum_expires_at` as the earlier of signed
    /// `expires_at` and issue time plus maximum session. This method still does
    /// not verify the Ed25519 signature or configured key and is not sufficient
    /// to grant authority.
    pub fn validate_authorization(
        &self,
        now: &UtcTimestamp,
    ) -> Result<(), ContractValidationError> {
        self.validate_authorization_binding()?;
        if now.is_before(&self.work_order_authorization.not_before) {
            return Err(ContractValidationError::AuthorizationNotYetValid);
        }
        if !now.is_before(&self.work_order_authorization.expires_at) {
            return Err(ContractValidationError::AuthorizationExpired);
        }
        if now
            .seconds_until(&self.work_order_authorization.expires_at)
            .is_none_or(|remaining| self.requested_ttl_seconds.get() > remaining)
        {
            return Err(ContractValidationError::RequestedTtlExceedsAuthorizationValidity);
        }
        Ok(())
    }

    /// RFC 8785/JCS-compatible v1 bytes used for idempotency fingerprinting.
    ///
    /// Encoding and the contract-validation methods do not grant authority.
    /// The future service must also verify [`WorkOrderAuthorization::signature_message`]
    /// with the operator-configured key, authenticate the caller, and apply
    /// effective local policy.
    pub fn canonical_authority_json(&self) -> Result<Vec<u8>, ContractEncodingError> {
        self.validate_structure()?;
        Ok(canonical::request_json(self)?)
    }

    /// SHA-256 of every strict request field, including authorization signature.
    pub fn authority_digest(&self) -> Result<Sha256Digest, ContractEncodingError> {
        self.canonical_authority_json().map(Sha256Digest::hash)
    }

    fn wire(&self) -> IdentityLeaseRequestWire {
        IdentityLeaseRequestWire {
            schema: self.schema,
            client_request_id: self.client_request_id.clone(),
            tenant_id: self.tenant_id.clone(),
            work_order_id: self.work_order_id.clone(),
            work_order_digest: self.work_order_digest,
            work_order_authorization: self.work_order_authorization.clone(),
            run_id: self.run_id.clone(),
            attempt_id: self.attempt_id.clone(),
            role: self.role,
            provider: self.provider,
            profile_ref: self.profile_ref.clone(),
            profile_uid: self.profile_uid.clone(),
            repository: self.repository.clone(),
            workspace_id: self.workspace_id.clone(),
            environment: self.environment.clone(),
            requested_ttl_seconds: self.requested_ttl_seconds,
            policy_digest: RequiredNullable(self.policy_digest),
        }
    }
}

impl Serialize for IdentityLeaseRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate_authorization_binding()
            .map_err(serde::ser::Error::custom)?;
        self.wire().serialize(serializer)
    }
}

impl TryFrom<IdentityLeaseRequestWire> for IdentityLeaseRequest {
    type Error = ContractValidationError;

    fn try_from(value: IdentityLeaseRequestWire) -> Result<Self, Self::Error> {
        let request = Self {
            schema: value.schema,
            client_request_id: value.client_request_id,
            tenant_id: value.tenant_id,
            work_order_id: value.work_order_id,
            work_order_digest: value.work_order_digest,
            work_order_authorization: value.work_order_authorization,
            run_id: value.run_id,
            attempt_id: value.attempt_id,
            role: value.role,
            provider: value.provider,
            profile_ref: value.profile_ref,
            profile_uid: value.profile_uid,
            repository: value.repository,
            workspace_id: value.workspace_id,
            environment: value.environment,
            requested_ttl_seconds: value.requested_ttl_seconds,
            policy_digest: value.policy_digest.0,
        };
        request.validate_structure()?;
        Ok(request)
    }
}

impl<'de> Deserialize<'de> for IdentityLeaseRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        IdentityLeaseRequestWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}
