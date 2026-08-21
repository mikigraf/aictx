use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use super::{
    super::{
        AgentRole, AutomationAuthMode, AutomationError, AutomationErrorCode, AutomationOperation,
        AutomationReadiness, IdentityLeaseRequest, IdentityLeaseResponse, IsolationClassification,
        LeaseReasonCode, LeaseStatus, ProbeCost, Provider, ReadinessReasonCode, ReadinessStatus,
        RefusalCode, WorkOrderAuthorization, WorkOrderProofAlgorithm,
    },
    fixtures::{active_response, authorization, request, valid, wif_readiness},
};

const AUTH_SCHEMA: &str =
    include_str!("../../../../schemas/ctxlane.work-order-authorization.v1.schema.json");
const REQUEST_SCHEMA: &str =
    include_str!("../../../../schemas/ctxlane.identity-lease-request.v1.schema.json");
const LEASE_SCHEMA: &str =
    include_str!("../../../../schemas/ctxlane.identity-lease.v1.schema.json");
const READINESS_SCHEMA: &str =
    include_str!("../../../../schemas/ctxlane.automation-readiness.v1.schema.json");
const ERROR_SCHEMA: &str =
    include_str!("../../../../schemas/ctxlane.automation-error.v1.schema.json");

fn schema(value: &str) -> Value {
    valid(serde_json::from_str(value))
}

fn strings(value: &Value, pointer: &str) -> BTreeSet<String> {
    match value.pointer(pointer).and_then(Value::as_array) {
        Some(values) => values
            .iter()
            .map(|value| match value.as_str() {
                Some(value) => value.to_owned(),
                None => panic!("{pointer} must contain only strings"),
            })
            .collect(),
        None => panic!("missing string array at {pointer}"),
    }
}

fn object_keys(value: &Value, pointer: &str) -> BTreeSet<String> {
    match value.pointer(pointer).and_then(Value::as_object) {
        Some(object) => object.keys().cloned().collect(),
        None => panic!("missing object at {pointer}"),
    }
}

fn wire_values<T: Serialize>(values: &[T]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| match valid(serde_json::to_value(value)).as_str() {
            Some(value) => value.to_owned(),
            None => panic!("enum must serialize as a string"),
        })
        .collect()
}

fn assert_root_shape_matches<T: Serialize>(document: &Value, fixture: &T) {
    assert_eq!(document["additionalProperties"], Value::Bool(false));
    let required = strings(document, "/required");
    let properties = object_keys(document, "/properties");
    assert_eq!(required, properties, "all v1 properties must be required");
    assert_eq!(
        object_keys(&valid(serde_json::to_value(fixture)), ""),
        properties,
        "Rust wire fields drifted from the published schema"
    );
}

#[test]
fn root_required_and_property_sets_match_rust_wires() {
    assert_root_shape_matches(&schema(AUTH_SCHEMA), &authorization());
    assert_root_shape_matches(&schema(REQUEST_SCHEMA), &request());
    assert_root_shape_matches(&schema(LEASE_SCHEMA), &active_response());
    assert_root_shape_matches(&schema(READINESS_SCHEMA), &wif_readiness());

    let error: AutomationError = valid(serde_json::from_str(include_str!(
        "../../../../schemas/examples/automation-error.v1.json"
    )));
    assert_root_shape_matches(&schema(ERROR_SCHEMA), &error);
}

#[test]
fn common_enums_match_published_schema_spellings_exactly() {
    let request_schema = schema(REQUEST_SCHEMA);
    assert_eq!(
        wire_values(&[
            AgentRole::Implementer,
            AgentRole::LocalReviewer,
            AgentRole::PrReviewer,
        ]),
        strings(&request_schema, "/properties/role/enum")
    );
    assert_eq!(
        wire_values(&[Provider::Claude, Provider::Codex]),
        strings(&request_schema, "/properties/provider/enum")
    );

    let lease_schema = schema(LEASE_SCHEMA);
    assert_eq!(
        wire_values(&[
            LeaseStatus::Requested,
            LeaseStatus::Active,
            LeaseStatus::Renewing,
            LeaseStatus::Closed,
            LeaseStatus::Revoked,
            LeaseStatus::Expired,
            LeaseStatus::Refused,
            LeaseStatus::Error,
        ]),
        strings(&lease_schema, "/properties/status/enum")
    );
    assert_eq!(
        wire_values(&[
            AutomationAuthMode::Wif,
            AutomationAuthMode::SubscriptionToken,
            AutomationAuthMode::ApiKey,
            AutomationAuthMode::ChatgptOauth,
            AutomationAuthMode::AccessToken,
        ]),
        strings(&lease_schema, "/$defs/authMode/enum")
    );
    assert_eq!(
        wire_values(&[
            IsolationClassification::CredentialIsolated,
            IsolationClassification::PerLeaseIsolated,
            IsolationClassification::CopiedCredentialDevelopment,
            IsolationClassification::Unproven,
        ]),
        strings(&lease_schema, "/$defs/isolation/enum")
    );
}

#[test]
fn refusal_and_lifecycle_reason_enums_match_schema_exactly() {
    let lease_schema = schema(LEASE_SCHEMA);
    assert_eq!(
        wire_values(&[
            RefusalCode::WorkOrderProofInvalid,
            RefusalCode::WorkOrderAuthorizationMismatch,
            RefusalCode::RequestedTtlNotAllowed,
            RefusalCode::PolicyDigestMismatch,
            RefusalCode::ProfileNotFound,
            RefusalCode::ProviderMismatch,
            RefusalCode::ProfileNotEligible,
            RefusalCode::AuthenticationExceptionRequired,
            RefusalCode::IsolationExceptionRequired,
            RefusalCode::EnvironmentNotAllowed,
            RefusalCode::RoleNotAllowed,
            RefusalCode::CallerNotAllowed,
            RefusalCode::RepositoryNotAllowed,
            RefusalCode::ProfileNotReady,
            RefusalCode::IdentityTokenStale,
            RefusalCode::HarnessUntrusted,
            RefusalCode::PrincipalUnverified,
            RefusalCode::PrincipalMismatch,
            RefusalCode::OrganizationMismatch,
            RefusalCode::WorkspaceMismatch,
            RefusalCode::IsolationUnproven,
            RefusalCode::CapacityExceeded,
        ]),
        strings(&lease_schema, "/$defs/refusalCode/enum")
    );
    assert_eq!(
        wire_values(&[
            LeaseReasonCode::Completed,
            LeaseReasonCode::WorkerFailed,
            LeaseReasonCode::OperatorRevoked,
            LeaseReasonCode::PolicyRevoked,
            LeaseReasonCode::PrincipalMismatch,
            LeaseReasonCode::LeaseExpired,
            LeaseReasonCode::MaximumLifetimeReached,
            LeaseReasonCode::HeartbeatLost,
            LeaseReasonCode::ProcessUnverifiable,
            LeaseReasonCode::GenerationSuperseded,
            LeaseReasonCode::RenewalAcknowledgementFailed,
            LeaseReasonCode::ServiceRecovery,
            LeaseReasonCode::InternalError,
        ]),
        strings(&lease_schema, "/$defs/reasonCode/enum")
    );
}

#[test]
fn readiness_enums_match_schema_exactly() {
    let readiness = schema(READINESS_SCHEMA);
    assert_eq!(
        wire_values(&[
            ReadinessStatus::Pass,
            ReadinessStatus::Warn,
            ReadinessStatus::Fail,
            ReadinessStatus::Unknown,
            ReadinessStatus::NotApplicable,
        ]),
        strings(&readiness, "/$defs/readinessCheck/properties/status/enum")
    );
    assert_eq!(
        wire_values(&[
            ReadinessReasonCode::NotApplicable,
            ReadinessReasonCode::MetadataInvalid,
            ReadinessReasonCode::CredentialSourceUnavailable,
            ReadinessReasonCode::IdentityTokenStale,
            ReadinessReasonCode::HarnessUntrusted,
            ReadinessReasonCode::PrincipalUnverified,
            ReadinessReasonCode::PrincipalMismatch,
            ReadinessReasonCode::ExpectedTenantUnverified,
            ReadinessReasonCode::OrganizationMismatch,
            ReadinessReasonCode::WorkspaceMismatch,
            ReadinessReasonCode::AutomationPolicyDenied,
            ReadinessReasonCode::AuthenticationExceptionRequired,
            ReadinessReasonCode::AuthenticationExceptionAcknowledged,
            ReadinessReasonCode::IsolationExceptionRequired,
            ReadinessReasonCode::IsolationExceptionAcknowledged,
            ReadinessReasonCode::IsolationUnproven,
            ReadinessReasonCode::ProbeNotRun,
            ReadinessReasonCode::ProbeFailed,
            ReadinessReasonCode::UnsupportedPlatform,
        ]),
        strings(&readiness, "/$defs/readinessReasonCode/enum")
    );
    assert_eq!(
        wire_values(&[
            ProbeCost::None,
            ProbeCost::ProviderRequestPossible,
            ProbeCost::ProviderRequestIncurred,
        ]),
        strings(&readiness, "/properties/probe_cost/enum")
    );
}

#[test]
fn automation_error_operation_and_code_enums_match_schema_exactly() {
    let error = schema(ERROR_SCHEMA);
    assert_eq!(
        wire_values(&[
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
        ]),
        strings(&error, "/properties/operation/enum")
    );
    assert_eq!(
        wire_values(&[
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
        ]),
        strings(&error, "/properties/code/enum")
    );
}

#[test]
fn proof_algorithm_is_the_published_singleton() {
    let auth = schema(AUTH_SCHEMA);
    assert_eq!(
        valid(serde_json::to_value(WorkOrderProofAlgorithm::Ed25519)),
        auth["properties"]["algorithm"]["const"]
    );
}

#[test]
fn every_published_contract_example_deserializes_to_its_rust_dto() {
    let _: WorkOrderAuthorization = valid(serde_json::from_str(include_str!(
        "../../../../schemas/examples/work-order-authorization.v1.json"
    )));
    let _: IdentityLeaseRequest = valid(serde_json::from_str(include_str!(
        "../../../../schemas/examples/identity-lease-request.v1.json"
    )));
    for example in [
        include_str!("../../../../schemas/examples/identity-lease-active.v1.json"),
        include_str!("../../../../schemas/examples/identity-lease-refused.v1.json"),
    ] {
        let _: IdentityLeaseResponse = valid(serde_json::from_str(example));
    }
    for example in [
        include_str!("../../../../schemas/examples/automation-readiness-ready.v1.json"),
        include_str!("../../../../schemas/examples/automation-readiness-not-ready.v1.json"),
        include_str!(
            "../../../../schemas/examples/automation-readiness-development-exception.v1.json"
        ),
    ] {
        let _: AutomationReadiness = valid(serde_json::from_str(example));
    }
    let _: AutomationError = valid(serde_json::from_str(include_str!(
        "../../../../schemas/examples/automation-error.v1.json"
    )));
}
