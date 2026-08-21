use serde_json::{Value, json};

use super::{
    super::{
        AutomationError, AutomationErrorCode, AutomationErrorSchema, AutomationOperation,
        CallerSubject, LeaseId,
    },
    fixtures::{authorization, parsed, valid, wif_readiness},
};

fn common_error() -> AutomationError {
    AutomationError {
        schema: AutomationErrorSchema,
        operation: AutomationOperation::ProfileList,
        code: AutomationErrorCode::CallerUnauthenticated,
        client_request_id: None,
        lease_id: None,
    }
}

#[test]
fn automation_errors_are_strict_code_only_contracts() {
    let error = common_error();
    let encoded = valid(serde_json::to_vec(&error));
    assert_eq!(
        valid(serde_json::from_slice::<AutomationError>(&encoded)),
        error
    );

    let mut message: Value = valid(serde_json::from_slice(&encoded));
    message["message"] = json!("CREDENTIAL_CANARY_DO_NOT_LOG=/private/keyring");
    let parse_error = serde_json::from_value::<AutomationError>(message);
    assert!(parse_error.is_err());
    assert!(!format!("{parse_error:?}").contains("CREDENTIAL_CANARY_DO_NOT_LOG"));

    let mut retryable: Value = valid(serde_json::from_slice(&encoded));
    retryable["retryable"] = json!(true);
    assert!(serde_json::from_value::<AutomationError>(retryable).is_err());
}

#[test]
fn automation_error_operation_code_and_lease_id_are_one_closed_mapping() {
    let mut error = common_error();
    error.operation = AutomationOperation::LeaseRenew;
    error.code = AutomationErrorCode::GenerationMismatch;
    error.lease_id = Some(parsed("lease_01ARZ3NDEKTSV4RRFFQ69G5FB0"));
    assert!(serde_json::to_value(&error).is_ok());

    error.lease_id = None;
    assert!(serde_json::to_value(&error).is_err());

    error.operation = AutomationOperation::LeaseAcquire;
    error.code = AutomationErrorCode::ProfileNotReady;
    assert!(serde_json::to_value(&error).is_err());

    error.operation = AutomationOperation::ProfileReadiness;
    error.code = AutomationErrorCode::ProfileNotFound;
    assert!(serde_json::to_value(&error).is_ok());

    error.operation = AutomationOperation::ProfileList;
    assert!(serde_json::to_value(&error).is_err());

    error.operation = AutomationOperation::ServiceHealth;
    error.code = AutomationErrorCode::InternalError;
    error.lease_id = Some(parsed("lease_01ARZ3NDEKTSV4RRFFQ69G5FB0"));
    assert!(serde_json::to_value(&error).is_err());
}

#[test]
fn automation_error_requires_explicit_nullable_correlation_fields() {
    let base = valid(serde_json::to_value(common_error()));
    for field in ["client_request_id", "lease_id"] {
        let mut value = base.clone();
        let removed = value
            .as_object_mut()
            .and_then(|object| object.remove(field));
        assert!(removed.is_some());
        assert!(serde_json::from_value::<AutomationError>(value).is_err());
    }

    let mut major = base;
    major["schema"] = json!("ctxlane.automation-error/v2");
    assert!(serde_json::from_value::<AutomationError>(major).is_err());
}

#[test]
fn public_response_surfaces_do_not_accept_secret_or_path_bearing_values() {
    let canary = "CREDENTIAL_CANARY_DO_NOT_LOG=/Users/example/.config/keyring";
    assert!(CallerSubject::parse(format!("caller:{canary}")).is_err());

    let readiness = wif_readiness();
    assert!(!format!("{readiness:?}").contains(canary));
    assert!(!valid(serde_json::to_string(&readiness)).contains(canary));
    assert!(!format!("{:?}", common_error()).contains(canary));
    assert!(!valid(serde_json::to_string(&common_error())).contains(canary));

    let invalid_id = serde_json::from_value::<LeaseId>(json!(canary));
    assert!(invalid_id.is_err());
    assert!(!format!("{invalid_id:?}").contains(canary));
}

#[test]
fn signed_proof_is_redacted_from_debug_output() {
    let authorization = authorization();
    let signature = authorization.signature.as_str();
    assert!(!format!("{authorization:?}").contains(signature));
    assert_eq!(
        format!("{:?}", authorization.signature),
        "DetachedSignature([redacted])"
    );
}

#[test]
fn automation_error_matrix_is_exhaustive() {
    let lease_id: LeaseId = parsed("lease_01ARZ3NDEKTSV4RRFFQ69G5FB0");
    for operation in all_operations() {
        for code in all_error_codes() {
            for supplied_lease in [None, Some(lease_id.clone())] {
                let error = AutomationError {
                    schema: AutomationErrorSchema,
                    operation,
                    code,
                    client_request_id: None,
                    lease_id: supplied_lease.clone(),
                };
                let should_succeed = code_is_allowed(operation, code)
                    && supplied_lease.is_some() == code_requires_lease(operation, code);
                assert_eq!(
                    serde_json::to_value(&error).is_ok(),
                    should_succeed,
                    "unexpected mapping for {operation:?}/{code:?}/lease={}",
                    supplied_lease.is_some()
                );
            }
        }
    }
}

fn all_operations() -> [AutomationOperation; 10] {
    [
        AutomationOperation::ProfileList,
        AutomationOperation::ProfileReadiness,
        AutomationOperation::ProfileResolve,
        AutomationOperation::LeaseAcquire,
        AutomationOperation::LeaseInspect,
        AutomationOperation::LeaseRenew,
        AutomationOperation::LeaseRevoke,
        AutomationOperation::LeaseClose,
        AutomationOperation::ServiceHealth,
        AutomationOperation::ExecutionStart,
    ]
}

fn all_error_codes() -> [AutomationErrorCode; 37] {
    [
        AutomationErrorCode::InvalidRequest,
        AutomationErrorCode::UnsupportedSchema,
        AutomationErrorCode::CallerUnauthenticated,
        AutomationErrorCode::CallerUnauthorized,
        AutomationErrorCode::ProfileNotFound,
        AutomationErrorCode::ProviderMismatch,
        AutomationErrorCode::ProfileNotEligible,
        AutomationErrorCode::AuthenticationExceptionRequired,
        AutomationErrorCode::IsolationExceptionRequired,
        AutomationErrorCode::EnvironmentNotAllowed,
        AutomationErrorCode::RoleNotAllowed,
        AutomationErrorCode::CallerNotAllowed,
        AutomationErrorCode::RepositoryNotAllowed,
        AutomationErrorCode::ProfileNotReady,
        AutomationErrorCode::IdentityTokenStale,
        AutomationErrorCode::HarnessUntrusted,
        AutomationErrorCode::PrincipalUnverified,
        AutomationErrorCode::PrincipalMismatch,
        AutomationErrorCode::OrganizationMismatch,
        AutomationErrorCode::WorkspaceMismatch,
        AutomationErrorCode::IsolationUnproven,
        AutomationErrorCode::IdempotencyConflict,
        AutomationErrorCode::RateLimited,
        AutomationErrorCode::ServiceRecovering,
        AutomationErrorCode::UnsupportedPlatform,
        AutomationErrorCode::LeaseNotFound,
        AutomationErrorCode::LeaseNotActive,
        AutomationErrorCode::LeaseExpired,
        AutomationErrorCode::LeaseRevoked,
        AutomationErrorCode::GenerationMismatch,
        AutomationErrorCode::RunMismatch,
        AutomationErrorCode::RoleMismatch,
        AutomationErrorCode::TenantMismatch,
        AutomationErrorCode::HostMismatch,
        AutomationErrorCode::SessionLimitReached,
        AutomationErrorCode::StoreUnavailable,
        AutomationErrorCode::InternalError,
    ]
}

fn code_is_common(code: AutomationErrorCode) -> bool {
    matches!(
        code,
        AutomationErrorCode::InvalidRequest
            | AutomationErrorCode::UnsupportedSchema
            | AutomationErrorCode::CallerUnauthenticated
            | AutomationErrorCode::CallerUnauthorized
            | AutomationErrorCode::RateLimited
            | AutomationErrorCode::ServiceRecovering
            | AutomationErrorCode::UnsupportedPlatform
            | AutomationErrorCode::StoreUnavailable
            | AutomationErrorCode::InternalError
    )
}

fn code_is_allowed(operation: AutomationOperation, code: AutomationErrorCode) -> bool {
    if code_is_common(code) {
        return true;
    }
    match operation {
        AutomationOperation::ProfileList | AutomationOperation::ServiceHealth => false,
        AutomationOperation::ProfileReadiness => matches!(
            code,
            AutomationErrorCode::ProfileNotFound | AutomationErrorCode::ProviderMismatch
        ),
        AutomationOperation::ProfileResolve => matches!(
            code,
            AutomationErrorCode::ProfileNotFound
                | AutomationErrorCode::ProviderMismatch
                | AutomationErrorCode::ProfileNotEligible
                | AutomationErrorCode::AuthenticationExceptionRequired
                | AutomationErrorCode::IsolationExceptionRequired
                | AutomationErrorCode::EnvironmentNotAllowed
                | AutomationErrorCode::RoleNotAllowed
                | AutomationErrorCode::CallerNotAllowed
                | AutomationErrorCode::RepositoryNotAllowed
                | AutomationErrorCode::ProfileNotReady
                | AutomationErrorCode::IdentityTokenStale
                | AutomationErrorCode::HarnessUntrusted
                | AutomationErrorCode::PrincipalUnverified
                | AutomationErrorCode::PrincipalMismatch
                | AutomationErrorCode::OrganizationMismatch
                | AutomationErrorCode::WorkspaceMismatch
                | AutomationErrorCode::IsolationUnproven
        ),
        AutomationOperation::LeaseAcquire => code == AutomationErrorCode::IdempotencyConflict,
        AutomationOperation::LeaseInspect => code == AutomationErrorCode::LeaseNotFound,
        AutomationOperation::LeaseRenew => lease_mutation_code(code),
        AutomationOperation::LeaseRevoke => matches!(
            code,
            AutomationErrorCode::LeaseNotFound | AutomationErrorCode::LeaseNotActive
        ),
        AutomationOperation::LeaseClose => lease_close_code(code),
        AutomationOperation::ExecutionStart => {
            lease_mutation_code(code)
                || matches!(
                    code,
                    AutomationErrorCode::ProfileNotReady
                        | AutomationErrorCode::IdentityTokenStale
                        | AutomationErrorCode::HarnessUntrusted
                        | AutomationErrorCode::PrincipalUnverified
                        | AutomationErrorCode::PrincipalMismatch
                        | AutomationErrorCode::OrganizationMismatch
                        | AutomationErrorCode::WorkspaceMismatch
                        | AutomationErrorCode::IsolationUnproven
                )
        }
    }
}

fn lease_mutation_code(code: AutomationErrorCode) -> bool {
    matches!(
        code,
        AutomationErrorCode::LeaseNotFound
            | AutomationErrorCode::LeaseNotActive
            | AutomationErrorCode::LeaseExpired
            | AutomationErrorCode::LeaseRevoked
            | AutomationErrorCode::GenerationMismatch
            | AutomationErrorCode::RunMismatch
            | AutomationErrorCode::RoleMismatch
            | AutomationErrorCode::TenantMismatch
            | AutomationErrorCode::HostMismatch
            | AutomationErrorCode::SessionLimitReached
    )
}

fn lease_close_code(code: AutomationErrorCode) -> bool {
    lease_mutation_code(code) && code != AutomationErrorCode::SessionLimitReached
}

fn code_requires_lease(operation: AutomationOperation, code: AutomationErrorCode) -> bool {
    !code_is_common(code)
        && matches!(
            operation,
            AutomationOperation::LeaseInspect
                | AutomationOperation::LeaseRenew
                | AutomationOperation::LeaseRevoke
                | AutomationOperation::LeaseClose
                | AutomationOperation::ExecutionStart
        )
}
