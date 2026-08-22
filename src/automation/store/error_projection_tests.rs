use core::{fmt::Debug, str::FromStr};

use crate::automation::contracts::{
    AutomationError, AutomationErrorCode, AutomationOperation, ClientRequestId, LeaseId,
};

use super::{CommittedMutation, StoreError};

const STORE_ERRORS: [StoreError; 17] = [
    StoreError::UnsupportedPlatform,
    StoreError::ServiceBusy,
    StoreError::UnsafeStorage,
    StoreError::DatabaseUnavailable,
    StoreError::DatabaseIdentityMismatch,
    StoreError::InstallationMismatch,
    StoreError::UnsupportedSchema,
    StoreError::MigrationChecksumMismatch,
    StoreError::IntegrityCheckFailed,
    StoreError::RecoveryRequired,
    StoreError::InvalidRequest,
    StoreError::IdempotencyConflict,
    StoreError::EntropyUnavailable,
    StoreError::IdentifierCollision,
    StoreError::InvalidTransition,
    StoreError::LeaseNotFound,
    StoreError::ConcurrentMutation,
];

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    value
        .parse()
        .unwrap_or_else(|error| panic!("parse {value}: {error:?}"))
}

fn assert_wire_valid(error: &AutomationError) {
    error
        .validate()
        .unwrap_or_else(|validation| panic!("invalid projection {error:?}: {validation:?}"));
    let wire = serde_json::to_vec(error)
        .unwrap_or_else(|encoding| panic!("encode projection: {encoding}"));
    let decoded: AutomationError = serde_json::from_slice(&wire)
        .unwrap_or_else(|encoding| panic!("decode projection: {encoding}"));
    assert_eq!(&decoded, error);
}

#[test]
fn every_store_error_projects_to_valid_operation_bound_wire_errors() {
    let request_id = parsed::<ClientRequestId>("01ARZ3NDEKTSV4RRFFQ69G5FA1");
    let lease_id = parsed::<LeaseId>("lease_01ARZ3NDEKTSV4RRFFQ69G5FA2");
    for error in STORE_ERRORS {
        let acquire = error.acquire_automation_error(Some(request_id.clone()));
        assert_eq!(acquire.operation, AutomationOperation::LeaseAcquire);
        assert_wire_valid(&acquire);

        for projected in [
            error.renew_automation_error(Some(request_id.clone()), &lease_id),
            error.revoke_automation_error(Some(request_id.clone()), &lease_id),
            error.close_automation_error(Some(request_id.clone()), &lease_id),
        ] {
            assert!(matches!(
                projected.operation,
                AutomationOperation::LeaseRenew
                    | AutomationOperation::LeaseRevoke
                    | AutomationOperation::LeaseClose
            ));
            assert_wire_valid(&projected);
        }
    }
}

#[test]
fn acquire_never_emits_a_lease_only_code_or_identifier() {
    let projected = StoreError::LeaseNotFound.acquire_automation_error(None);
    assert_eq!(projected.operation, AutomationOperation::LeaseAcquire);
    assert_eq!(projected.code, AutomationErrorCode::CallerUnauthorized);
    assert!(projected.lease_id.is_none());
    assert_wire_valid(&projected);
}

#[test]
fn common_errors_never_disclose_a_syntactic_lease_identifier() {
    let lease_id = parsed::<LeaseId>("lease_01ARZ3NDEKTSV4RRFFQ69G5FA2");
    for error in [
        StoreError::DatabaseUnavailable,
        StoreError::ConcurrentMutation,
        StoreError::IntegrityCheckFailed,
        StoreError::RecoveryRequired,
    ] {
        for projected in [
            error.renew_automation_error(None, &lease_id),
            error.revoke_automation_error(None, &lease_id),
            error.close_automation_error(None, &lease_id),
        ] {
            assert!(projected.lease_id.is_none());
            assert_wire_valid(&projected);
        }
    }
}

#[test]
fn authenticated_denial_is_operation_bound_and_discloses_no_lease() {
    let lease_id = parsed::<LeaseId>("lease_01ARZ3NDEKTSV4RRFFQ69G5FA2");
    for operation in [
        AutomationOperation::LeaseAcquire,
        AutomationOperation::LeaseRenew,
        AutomationOperation::LeaseRevoke,
        AutomationOperation::LeaseClose,
    ] {
        let denied = CommittedMutation::<()>::authentication_denied(operation);
        assert!(denied.successful_response().is_none());
        assert!(denied.successful_row_version().is_none());
        let error = denied
            .automation_error(None, &lease_id)
            .unwrap_or_else(|projection| panic!("project denial: {projection:?}"))
            .unwrap_or_else(|| panic!("denial omitted wire error"));
        assert_eq!(error.operation, operation);
        assert_eq!(error.code, AutomationErrorCode::CallerUnauthorized);
        assert!(error.lease_id.is_none());
        assert_wire_valid(&error);
    }
}
