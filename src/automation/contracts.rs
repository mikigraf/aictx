//! Stable, secret-free wire types for the local automation identity plane.
//!
//! Request objects carry bounded authority metadata. Response objects expose
//! attribution and opaque routing handles, never provider credentials,
//! credential paths, reconstructed environments, vendor homes, or keyring
//! references.

mod canonical;
mod error_contract;
mod integer;
mod readiness;
mod references;
mod request;
mod response;
mod temporal;
mod types;

pub use error_contract::{
    AUTOMATION_ERROR_SCHEMA, AutomationError, AutomationErrorCode, AutomationErrorSchema,
    AutomationOperation,
};
pub use readiness::{
    AutomationReadiness, ProbeTimeoutMilliseconds, ReadinessCheck, ReadinessChecks,
    ReadinessReasonCode,
};
pub use references::{CallerSubject, HostIdentity, PrincipalRef, WorkerIdentity, WorkspaceRef};
pub use request::{IdentityLeaseRequest, WorkOrderAuthorization};
pub use response::IdentityLeaseResponse;
pub use temporal::{
    DurationSeconds, FencingGeneration, MaximumTtlSeconds, RequestedTtlSeconds, UtcTimestamp,
};
pub use types::{
    AgentRole, AttemptId, AutomationAuthMode, ClientRequestId, ContractEncodingError,
    ContractValidationError, DetachedSignature, EnvironmentName, ExecutionHandle,
    IDENTITY_LEASE_REQUEST_SCHEMA, IDENTITY_LEASE_SCHEMA, IdentityLeaseRequestSchema,
    IdentityLeaseSchema, IsolationClassification, KeyId, LeaseId, LeaseReasonCode, LeaseStatus,
    ProbeCost, ProfileRef, ProfileUid, Provider, READINESS_SCHEMA, ReadinessSchema,
    ReadinessStatus, RefusalCode, RepositoryId, RunId, Sha256Digest, TenantId,
    WORK_ORDER_AUTHORIZATION_SCHEMA, WorkOrderAuthorizationSchema, WorkOrderId,
    WorkOrderProofAlgorithm, WorkspaceId,
};

#[cfg(test)]
mod tests;
