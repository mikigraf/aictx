use serde_json::{Value, json};

use super::{
    super::{
        AgentRole, AutomationAuthMode, AutomationReadiness, IsolationClassification, Provider,
        ReadinessReasonCode, ReadinessStatus,
    },
    fixtures::{check, local_non_wif_readiness, parsed, valid, wif_readiness},
};

#[test]
fn wif_and_local_non_wif_ready_results_round_trip() {
    for readiness in [wif_readiness(), local_non_wif_readiness()] {
        let encoded = valid(serde_json::to_vec(&readiness));
        assert_eq!(
            valid(serde_json::from_slice::<AutomationReadiness>(&encoded)),
            readiness
        );
    }
}

#[test]
fn nonlocal_non_wif_requires_an_explicit_authentication_exception() {
    let mut readiness = local_non_wif_readiness();
    readiness.environment = parsed("production");
    readiness.authentication_exception_acknowledged = true;
    readiness.checks.automation_policy_permits = check(
        ReadinessStatus::Warn,
        ReadinessReasonCode::AuthenticationExceptionAcknowledged,
    );
    assert!(readiness.validate().is_ok());

    readiness.authentication_exception_acknowledged = false;
    readiness.checks.automation_policy_permits = check(
        ReadinessStatus::Fail,
        ReadinessReasonCode::AuthenticationExceptionRequired,
    );
    readiness.ready = false;
    assert!(readiness.validate().is_ok());

    readiness.checks.automation_policy_permits = super::fixtures::pass();
    assert!(readiness.validate().is_err());
}

#[test]
fn copied_credentials_are_ready_only_in_the_explicit_narrow_scope() {
    let mut local = local_non_wif_readiness();
    local.isolation = IsolationClassification::CopiedCredentialDevelopment;
    local.isolation_exception_acknowledged = true;
    local.checks.credential_isolation_proven = check(
        ReadinessStatus::Warn,
        ReadinessReasonCode::IsolationExceptionAcknowledged,
    );
    assert!(local.validate().is_ok());

    let mut pr = local.clone();
    pr.environment = parsed("production");
    pr.role = AgentRole::PrReviewer;
    pr.authentication_exception_acknowledged = true;
    pr.checks.automation_policy_permits = check(
        ReadinessStatus::Warn,
        ReadinessReasonCode::AuthenticationExceptionAcknowledged,
    );
    assert!(pr.validate().is_ok());

    let mut production_implementer = pr;
    production_implementer.role = AgentRole::Implementer;
    production_implementer.ready = false;
    production_implementer.checks.automation_policy_permits = check(
        ReadinessStatus::Fail,
        ReadinessReasonCode::AutomationPolicyDenied,
    );
    assert!(production_implementer.validate().is_ok());

    production_implementer.checks.automation_policy_permits = check(
        ReadinessStatus::Warn,
        ReadinessReasonCode::AuthenticationExceptionAcknowledged,
    );
    assert!(production_implementer.validate().is_err());
}

#[test]
fn unproven_isolation_can_never_report_ready() {
    let mut readiness = wif_readiness();
    readiness.ready = false;
    readiness.isolation = IsolationClassification::Unproven;
    readiness.checks.credential_isolation_proven = check(
        ReadinessStatus::Fail,
        ReadinessReasonCode::IsolationUnproven,
    );
    assert!(readiness.validate().is_ok());

    readiness.ready = true;
    assert!(serde_json::to_value(&readiness).is_err());
    readiness.ready = false;
    readiness.isolation_exception_acknowledged = true;
    assert!(readiness.validate().is_err());
}

#[test]
fn readiness_status_reason_pairs_are_closed_per_check() {
    let mut readiness = wif_readiness();
    readiness.ready = false;
    readiness.checks.metadata_valid =
        check(ReadinessStatus::Warn, ReadinessReasonCode::MetadataInvalid);
    assert!(readiness.validate().is_err());

    readiness = wif_readiness();
    readiness.ready = false;
    readiness.checks.credential_source_available = check(
        ReadinessStatus::Unknown,
        ReadinessReasonCode::CredentialSourceUnavailable,
    );
    assert!(readiness.validate().is_err());

    readiness = wif_readiness();
    readiness.ready = false;
    readiness.checks.provider_principal_verified =
        check(ReadinessStatus::Warn, ReadinessReasonCode::ProbeFailed);
    assert!(readiness.validate().is_err());

    readiness = wif_readiness();
    readiness.ready = false;
    readiness.checks.provider_principal_verified =
        check(ReadinessStatus::Unknown, ReadinessReasonCode::ProbeNotRun);
    assert!(readiness.validate().is_ok());
}

#[test]
fn provider_auth_profile_and_tenant_evidence_must_agree() {
    let mut auth = wif_readiness();
    auth.auth_mode = AutomationAuthMode::SubscriptionToken;
    assert!(auth.validate().is_err());

    let mut profile = wif_readiness();
    profile.provider = Provider::Claude;
    assert!(profile.validate().is_err());

    let mut codex_organization = wif_readiness();
    codex_organization.ready = false;
    codex_organization.checks.expected_tenant_verified = check(
        ReadinessStatus::Fail,
        ReadinessReasonCode::OrganizationMismatch,
    );
    assert!(codex_organization.validate().is_err());

    let mut claude_workspace = wif_readiness();
    claude_workspace.provider = Provider::Claude;
    claude_workspace.profile_ref = parsed("claude:automation-production");
    claude_workspace.auth_mode = AutomationAuthMode::Wif;
    claude_workspace.ready = false;
    claude_workspace.checks.expected_tenant_verified = check(
        ReadinessStatus::Fail,
        ReadinessReasonCode::WorkspaceMismatch,
    );
    assert!(claude_workspace.validate().is_err());
}

#[test]
fn timestamps_probe_mode_and_ready_flag_are_validated_before_serialization() {
    let mut interactive = wif_readiness();
    interactive.probe_interactive = true;
    assert!(serde_json::to_value(&interactive).is_err());

    let mut stale = wif_readiness();
    stale.valid_until = stale.checked_at.clone();
    assert!(serde_json::to_value(&stale).is_err());

    let mut dishonest = wif_readiness();
    dishonest.ready = false;
    assert!(serde_json::to_value(&dishonest).is_err());
}

#[test]
fn readiness_wire_is_closed_and_requires_all_eight_named_checks() {
    let base = valid(serde_json::to_value(wif_readiness()));

    let mut unknown = base.clone();
    unknown["checks"]["credential-path-safe"] = json!({
        "status": "pass",
        "reason_code": null
    });
    assert!(serde_json::from_value::<AutomationReadiness>(unknown).is_err());

    let mut missing = base.clone();
    let removed = missing["checks"]
        .as_object_mut()
        .and_then(|checks| checks.remove("metadata-valid"));
    assert!(removed.is_some());
    assert!(serde_json::from_value::<AutomationReadiness>(missing).is_err());

    let mut missing_reason = base;
    let removed = missing_reason["checks"]["metadata-valid"]
        .as_object_mut()
        .and_then(|check| check.remove("reason_code"));
    assert!(removed.is_some());
    assert!(serde_json::from_value::<AutomationReadiness>(missing_reason).is_err());
}

#[test]
fn malformed_readiness_json_cannot_bypass_cross_field_rules() {
    let mut value: Value = valid(serde_json::to_value(wif_readiness()));
    value["auth_mode"] = json!("chatgpt-oauth");
    assert!(serde_json::from_value::<AutomationReadiness>(value).is_err());
}
