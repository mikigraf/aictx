//! Opt-in durable storage for the automation lease service.
//!
//! Merely constructing or using ordinary metadata paths does not open this
//! store. The automation directory and database are touched only by
//! [`RecoveringStore::open`].

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod acquire_failure_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod acquire_race_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod activation;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod activation_failure_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod activation_lifecycle_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod capacity;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod capacity_dimension_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod control_precedence_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod fence;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod fence_contention_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod global_audit_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod guard_classification_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod ids;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod legacy_capacity_matrix_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod lifecycle;
mod lifecycle_types;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod load;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod load_parse;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod migrations;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod ownership;
mod records;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod recovery;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod recovery_contention_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod recovery_failure_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod recovery_mutation;
mod recovery_types;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod retained_history_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod retention;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod retention_failure_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod retention_gate_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod security;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod sqlite;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod test_support;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;

pub(crate) use records::BeginAcquireResult;
// Kept available on unsupported targets so the sealed service seam is source-compatible.
#[allow(unused_imports)]
pub(crate) use lifecycle_types::{
    AuthenticatedRequestControl, CapacityReleaseResult, CommittedMutation, PruneResult,
};
#[allow(unused_imports)]
pub(crate) use records::PersistedAcquireOutcome;
#[allow(unused_imports)]
pub(crate) use recovery_types::{
    RecoveryCursor, RecoveryMutationResult, RecoveryPage, RecoveryPageRequest,
};
use thiserror::Error;

use crate::automation::contracts::{
    AutomationError, AutomationErrorCode, AutomationErrorSchema, AutomationOperation,
    ClientRequestId, LeaseId,
};

/// Redacted, stable failure categories for the automation store boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum StoreError {
    #[error("automation lease storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("the automation lease service is already running")]
    ServiceBusy,
    #[error("automation storage permissions or ownership are unsafe")]
    UnsafeStorage,
    #[error("the automation lease database is unavailable")]
    DatabaseUnavailable,
    #[error("the automation lease database identity is invalid")]
    DatabaseIdentityMismatch,
    #[error("the automation lease database belongs to another installation")]
    InstallationMismatch,
    #[error("the automation lease database schema is newer than this build")]
    UnsupportedSchema,
    #[error("the automation lease database migration identity is invalid")]
    MigrationChecksumMismatch,
    #[error("the automation lease database failed an integrity check")]
    IntegrityCheckFailed,
    #[error("automation lease recovery is required before serving requests")]
    RecoveryRequired,
    #[error("the automation lease request is invalid")]
    InvalidRequest,
    #[error("the client request ID was already used for different authority")]
    IdempotencyConflict,
    #[error("operating-system randomness is unavailable")]
    EntropyUnavailable,
    #[error("could not allocate a unique automation identifier")]
    IdentifierCollision,
    #[error("the persisted lease cannot make that transition")]
    InvalidTransition,
    #[error("the persisted lease does not exist")]
    LeaseNotFound,
    #[error("the persisted lease changed concurrently")]
    ConcurrentMutation,
}

impl StoreError {
    pub(crate) fn acquire_automation_error(
        self,
        client_request_id: Option<ClientRequestId>,
    ) -> AutomationError {
        automation_error(
            self,
            AutomationOperation::LeaseAcquire,
            client_request_id,
            None,
        )
    }

    pub(crate) fn renew_automation_error(
        self,
        client_request_id: Option<ClientRequestId>,
        lease_id: &LeaseId,
    ) -> AutomationError {
        automation_error(
            self,
            AutomationOperation::LeaseRenew,
            client_request_id,
            Some(lease_id),
        )
    }

    pub(crate) fn revoke_automation_error(
        self,
        client_request_id: Option<ClientRequestId>,
        lease_id: &LeaseId,
    ) -> AutomationError {
        automation_error(
            self,
            AutomationOperation::LeaseRevoke,
            client_request_id,
            Some(lease_id),
        )
    }

    pub(crate) fn close_automation_error(
        self,
        client_request_id: Option<ClientRequestId>,
        lease_id: &LeaseId,
    ) -> AutomationError {
        automation_error(
            self,
            AutomationOperation::LeaseClose,
            client_request_id,
            Some(lease_id),
        )
    }
}

fn automation_error(
    error: StoreError,
    operation: AutomationOperation,
    client_request_id: Option<ClientRequestId>,
    syntactic_lease_id: Option<&LeaseId>,
) -> AutomationError {
    let code = match error {
        StoreError::UnsupportedPlatform => AutomationErrorCode::UnsupportedPlatform,
        StoreError::ServiceBusy | StoreError::RecoveryRequired => {
            AutomationErrorCode::ServiceRecovering
        }
        StoreError::DatabaseUnavailable | StoreError::ConcurrentMutation => {
            AutomationErrorCode::StoreUnavailable
        }
        StoreError::UnsupportedSchema => AutomationErrorCode::UnsupportedSchema,
        StoreError::InvalidRequest => AutomationErrorCode::InvalidRequest,
        StoreError::LeaseNotFound => AutomationErrorCode::CallerUnauthorized,
        StoreError::IdempotencyConflict if operation == AutomationOperation::LeaseAcquire => {
            AutomationErrorCode::IdempotencyConflict
        }
        StoreError::InvalidTransition
            if matches!(
                operation,
                AutomationOperation::LeaseRenew
                    | AutomationOperation::LeaseRevoke
                    | AutomationOperation::LeaseClose
            ) =>
        {
            AutomationErrorCode::LeaseNotActive
        }
        StoreError::DatabaseIdentityMismatch
        | StoreError::InstallationMismatch
        | StoreError::MigrationChecksumMismatch
        | StoreError::IntegrityCheckFailed
        | StoreError::UnsafeStorage
        | StoreError::EntropyUnavailable
        | StoreError::IdentifierCollision
        | StoreError::IdempotencyConflict
        | StoreError::InvalidTransition => AutomationErrorCode::InternalError,
    };
    let mut projected = AutomationError {
        schema: AutomationErrorSchema,
        operation,
        code,
        client_request_id,
        lease_id: syntactic_lease_id.cloned(),
    };
    if projected.validate().is_err() {
        projected.lease_id = None;
    }
    debug_assert!(projected.validate().is_ok());
    projected
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unused_imports)]
pub(crate) use sqlite::{ReadyStore, RecoveringStore};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(unused_imports)]
pub(crate) use unsupported::{ReadyStore, RecoveringStore};

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod audit_recovery_tests;
#[cfg(test)]
mod error_projection_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod lifecycle_failure_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod lifecycle_mutation_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod load_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod migration_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod mutation_oracle_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod policy_binding_store_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod recovery_tests;
#[cfg(test)]
mod retention_rule_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod retention_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod security_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod semantic_refusal_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod service_error_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;
