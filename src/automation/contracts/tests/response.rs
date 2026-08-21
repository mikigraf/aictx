use serde_json::{Value, json};

use super::{
    super::{
        AutomationAuthMode, IdentityLeaseResponse, LeaseReasonCode, LeaseStatus, Provider,
        RefusalCode,
    },
    fixtures::{active_response, parsed, refused_response, valid},
};

#[test]
fn active_requested_and_refused_responses_round_trip() {
    let active = active_response();
    let active_json = valid(serde_json::to_vec(&active));
    assert_eq!(
        valid(serde_json::from_slice::<IdentityLeaseResponse>(
            &active_json
        )),
        active
    );

    let refused = refused_response();
    let refused_json = valid(serde_json::to_vec(&refused));
    assert_eq!(
        valid(serde_json::from_slice::<IdentityLeaseResponse>(
            &refused_json
        )),
        refused
    );

    let mut requested = refused;
    requested.status = LeaseStatus::Requested;
    requested.refusal_code = None;
    let requested_json = valid(serde_json::to_vec(&requested));
    assert_eq!(
        valid(serde_json::from_slice::<IdentityLeaseResponse>(
            &requested_json
        )),
        requested
    );
}

#[test]
fn published_lease_examples_deserialize() {
    let active = include_str!("../../../../schemas/examples/identity-lease-active.v1.json");
    let refused = include_str!("../../../../schemas/examples/identity-lease-refused.v1.json");
    assert!(serde_json::from_str::<IdentityLeaseResponse>(active).is_ok());
    assert!(serde_json::from_str::<IdentityLeaseResponse>(refused).is_ok());
}

#[test]
fn required_nullable_fields_cannot_be_omitted_and_unknown_fields_are_refused() {
    let mut value = valid(serde_json::to_value(refused_response()));
    let removed = value
        .as_object_mut()
        .and_then(|object| object.remove("principal_ref"));
    assert!(removed.is_some());
    assert!(serde_json::from_value::<IdentityLeaseResponse>(value).is_err());

    let mut unknown = valid(serde_json::to_value(refused_response()));
    unknown["vendor_home"] = json!("/secret/path");
    assert!(serde_json::from_value::<IdentityLeaseResponse>(unknown).is_err());
}

#[test]
fn requested_and_refused_cannot_claim_runtime_authority() {
    let base = valid(serde_json::to_value(refused_response()));
    let claims = [
        ("worker_identity", json!("worker:automation-worker")),
        ("principal_ref", json!("service-account:automation-worker")),
        ("workspace_ref", json!("chatgpt-workspace:company")),
        ("auth_mode", json!("wif")),
        ("fencing_generation", json!(1)),
        ("expires_at", json!("2026-08-21T10:15:00Z")),
        ("maximum_expires_at", json!("2026-08-21T14:00:00Z")),
        ("isolation", json!("credential-isolated")),
        (
            "effective_policy_digest",
            json!("sha256:bb42590da6d8c5c0c0103b67572979c60d3c44a5a5a2cfa74f469e8cd7cf3d12"),
        ),
    ];
    for (field, claim) in claims {
        let mut value = base.clone();
        value[field] = claim;
        assert!(
            serde_json::from_value::<IdentityLeaseResponse>(value).is_err(),
            "refused response accepted {field}"
        );
    }

    let mut constructed = refused_response();
    constructed.auth_mode = Some(AutomationAuthMode::Wif);
    assert!(serde_json::to_value(&constructed).is_err());
}

#[test]
fn execution_handles_exist_only_while_active_or_renewing() {
    let mut active = active_response();
    active.execution_handle = None;
    assert!(serde_json::to_value(&active).is_err());

    let mut renewing = active_response();
    renewing.status = LeaseStatus::Renewing;
    assert!(serde_json::to_value(&renewing).is_ok());

    let mut closed = active_response();
    closed.status = LeaseStatus::Closed;
    closed.reason_code = Some(LeaseReasonCode::Completed);
    assert!(serde_json::to_value(&closed).is_err());
    closed.execution_handle = None;
    assert!(serde_json::to_value(&closed).is_ok());
}

#[test]
fn terminal_statuses_accept_only_their_closed_reason_sets() {
    let cases = [
        (
            LeaseStatus::Closed,
            LeaseReasonCode::Completed,
            LeaseReasonCode::LeaseExpired,
        ),
        (
            LeaseStatus::Expired,
            LeaseReasonCode::MaximumLifetimeReached,
            LeaseReasonCode::Completed,
        ),
        (
            LeaseStatus::Revoked,
            LeaseReasonCode::RenewalAcknowledgementFailed,
            LeaseReasonCode::InternalError,
        ),
        (
            LeaseStatus::Error,
            LeaseReasonCode::ServiceRecovery,
            LeaseReasonCode::OperatorRevoked,
        ),
    ];
    for (status, accepted, rejected) in cases {
        let mut response = active_response();
        response.status = status;
        response.execution_handle = None;
        response.reason_code = Some(accepted);
        assert!(
            serde_json::to_value(&response).is_ok(),
            "rejected {status:?}"
        );
        response.reason_code = Some(rejected);
        assert!(
            serde_json::to_value(&response).is_err(),
            "accepted {status:?}"
        );
    }

    let mut refused = refused_response();
    refused.refusal_code = None;
    assert!(serde_json::to_value(&refused).is_err());
    refused.refusal_code = Some(RefusalCode::WorkspaceMismatch);
    assert!(serde_json::to_value(&refused).is_ok());

    refused.refusal_code = Some(RefusalCode::OrganizationMismatch);
    assert!(serde_json::to_value(&refused).is_err());
    refused.provider = Provider::Claude;
    refused.profile_ref = parsed("claude:automation-production");
    assert!(serde_json::to_value(&refused).is_ok());
}

#[test]
fn provider_auth_and_workspace_attribution_must_agree() {
    let mut workspace = active_response();
    workspace.workspace_ref = Some(parsed("claude-organization:company"));
    assert!(serde_json::to_value(&workspace).is_err());

    let mut auth = active_response();
    auth.auth_mode = Some(AutomationAuthMode::SubscriptionToken);
    assert!(serde_json::to_value(&auth).is_err());

    let mut claude = active_response();
    claude.provider = Provider::Claude;
    claude.profile_ref = parsed("claude:automation-production");
    claude.workspace_ref = Some(parsed("claude-organization:company"));
    claude.auth_mode = Some(AutomationAuthMode::SubscriptionToken);
    assert!(serde_json::to_value(&claude).is_ok());
}

#[test]
fn resolved_leases_require_eligible_proven_isolation() {
    let mut unproven = active_response();
    unproven.isolation = Some(super::super::IsolationClassification::Unproven);
    assert!(serde_json::to_value(&unproven).is_err());

    let mut copied_production = active_response();
    copied_production.isolation =
        Some(super::super::IsolationClassification::CopiedCredentialDevelopment);
    assert!(serde_json::to_value(&copied_production).is_err());

    let mut copied_local = copied_production.clone();
    copied_local.environment = parsed("local-development");
    assert!(serde_json::to_value(&copied_local).is_ok());

    let mut copied_pr = copied_production;
    copied_pr.role = super::super::AgentRole::PrReviewer;
    assert!(serde_json::to_value(&copied_pr).is_ok());
}

#[test]
fn activated_timestamps_are_ordered_and_complete() {
    let mut equal = active_response();
    equal.expires_at = Some(equal.issued_at.clone());
    assert!(serde_json::to_value(&equal).is_err());

    let mut beyond_maximum = active_response();
    beyond_maximum.expires_at = Some(parsed("2026-08-21T14:00:01Z"));
    assert!(serde_json::to_value(&beyond_maximum).is_err());

    let mut incomplete = active_response();
    incomplete.maximum_expires_at = None;
    assert!(serde_json::to_value(&incomplete).is_err());
}

#[test]
fn malformed_status_combinations_fail_deserialization_too() {
    let mut value: Value = valid(serde_json::to_value(active_response()));
    value["status"] = json!("closed");
    value["execution_handle"] = Value::Null;
    value["reason_code"] = json!("lease-expired");
    assert!(serde_json::from_value::<IdentityLeaseResponse>(value).is_err());
}
