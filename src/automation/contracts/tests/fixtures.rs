use std::{fmt::Debug, str::FromStr};

use super::super::*;

pub(super) fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    match value.parse() {
        Ok(value) => value,
        Err(error) => panic!("test value must parse: {error:?}"),
    }
}

pub(super) fn valid<T, E>(result: Result<T, E>) -> T
where
    E: Debug,
{
    match result {
        Ok(value) => value,
        Err(error) => panic!("test fixture must be valid: {error:?}"),
    }
}

pub(super) fn authorization() -> WorkOrderAuthorization {
    WorkOrderAuthorization {
        schema: WorkOrderAuthorizationSchema,
        algorithm: WorkOrderProofAlgorithm::Ed25519,
        key_id: parsed("key-controller-2026-08"),
        client_request_id: parsed("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        tenant_id: parsed("tenant-acme"),
        work_order_id: parsed("wo_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        work_order_digest: parsed(
            "sha256:a36dbc1704725260b0896399529c16a86acabb6849bb1c9abeb251d7ffd16e6c",
        ),
        run_id: parsed("run_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        attempt_id: parsed("attempt_01"),
        role: AgentRole::Implementer,
        provider: Provider::Codex,
        profile_ref: parsed("codex:automation-production"),
        profile_uid: parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        repository: parsed("github:acme/payments"),
        workspace_id: parsed("workspace_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        environment: parsed("production"),
        not_before: parsed("2026-08-21T10:00:00Z"),
        expires_at: parsed("2026-08-21T14:00:00Z"),
        maximum_ttl_seconds: valid(MaximumTtlSeconds::from_seconds(900)),
        maximum_session_seconds: valid(DurationSeconds::from_seconds(14_400)),
        signature: valid(DetachedSignature::parse(
            "jLtlv6wVNme_sIhGEIcT25hnhY4YrkAwOolb60L22TWa9DRkudNgfEAxrBSrCm3YXjvFIRsujAKizOeO7wjrAw",
        )),
    }
}

pub(super) fn request() -> IdentityLeaseRequest {
    let work_order_authorization = authorization();
    IdentityLeaseRequest {
        schema: IdentityLeaseRequestSchema,
        client_request_id: parsed("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        tenant_id: work_order_authorization.tenant_id.clone(),
        work_order_id: work_order_authorization.work_order_id.clone(),
        work_order_digest: work_order_authorization.work_order_digest,
        run_id: work_order_authorization.run_id.clone(),
        attempt_id: work_order_authorization.attempt_id.clone(),
        role: work_order_authorization.role,
        provider: work_order_authorization.provider,
        profile_ref: work_order_authorization.profile_ref.clone(),
        profile_uid: work_order_authorization.profile_uid.clone(),
        repository: work_order_authorization.repository.clone(),
        workspace_id: work_order_authorization.workspace_id.clone(),
        environment: work_order_authorization.environment.clone(),
        requested_ttl_seconds: valid(RequestedTtlSeconds::from_seconds(900)),
        policy_digest: None,
        work_order_authorization,
    }
}

pub(super) fn active_response() -> IdentityLeaseResponse {
    IdentityLeaseResponse {
        schema: IdentityLeaseSchema,
        lease_id: parsed("lease_01ARZ3NDEKTSV4RRFFQ69G5FB0"),
        status: LeaseStatus::Active,
        tenant_id: parsed("tenant-acme"),
        work_order_id: parsed("wo_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        work_order_digest: parsed(
            "sha256:a36dbc1704725260b0896399529c16a86acabb6849bb1c9abeb251d7ffd16e6c",
        ),
        run_id: parsed("run_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        attempt_id: parsed("attempt_01"),
        role: AgentRole::Implementer,
        provider: Provider::Codex,
        profile_uid: parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        profile_ref: parsed("codex:automation-production"),
        repository: parsed("github:acme/payments"),
        workspace_id: parsed("workspace_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        environment: parsed("production"),
        caller_subject: parsed("caller:local-controller"),
        host_identity: parsed("host:runner-01"),
        worker_identity: Some(parsed("worker:controller-01")),
        principal_ref: Some(parsed("service-account:automation-worker")),
        workspace_ref: Some(parsed("chatgpt-workspace:ws_automation_prod")),
        auth_mode: Some(AutomationAuthMode::Wif),
        fencing_generation: Some(valid(FencingGeneration::from_value(1))),
        issued_at: parsed("2026-08-21T10:00:00Z"),
        expires_at: Some(parsed("2026-08-21T10:15:00Z")),
        maximum_expires_at: Some(parsed("2026-08-21T14:00:00Z")),
        execution_handle: Some(parsed("exec_01ARZ3NDEKTSV4RRFFQ69G5FB1")),
        isolation: Some(IsolationClassification::CredentialIsolated),
        effective_policy_digest: Some(parsed(
            "sha256:bb42590da6d8c5c0c0103b67572979c60d3c44a5a5a2cfa74f469e8cd7cf3d12",
        )),
        refusal_code: None,
        reason_code: None,
    }
}

pub(super) fn refused_response() -> IdentityLeaseResponse {
    let mut response = active_response();
    response.status = LeaseStatus::Refused;
    response.worker_identity = None;
    response.principal_ref = None;
    response.workspace_ref = None;
    response.auth_mode = None;
    response.fencing_generation = None;
    response.expires_at = None;
    response.maximum_expires_at = None;
    response.execution_handle = None;
    response.isolation = None;
    response.effective_policy_digest = None;
    response.refusal_code = Some(RefusalCode::ProfileNotReady);
    response
}

pub(super) fn pass() -> ReadinessCheck {
    ReadinessCheck {
        status: ReadinessStatus::Pass,
        reason_code: None,
    }
}

pub(super) fn check(status: ReadinessStatus, reason_code: ReadinessReasonCode) -> ReadinessCheck {
    ReadinessCheck {
        status,
        reason_code: Some(reason_code),
    }
}

pub(super) fn passing_checks() -> ReadinessChecks {
    ReadinessChecks {
        metadata_valid: pass(),
        credential_source_available: pass(),
        identity_token_current: pass(),
        harness_trusted: pass(),
        provider_principal_verified: pass(),
        expected_tenant_verified: pass(),
        automation_policy_permits: pass(),
        credential_isolation_proven: pass(),
    }
}

pub(super) fn wif_readiness() -> AutomationReadiness {
    AutomationReadiness {
        schema: ReadinessSchema,
        profile_uid: parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        profile_ref: parsed("codex:automation-production"),
        provider: Provider::Codex,
        environment: parsed("production"),
        role: AgentRole::Implementer,
        auth_mode: AutomationAuthMode::Wif,
        ready: true,
        isolation: IsolationClassification::CredentialIsolated,
        authentication_exception_acknowledged: false,
        isolation_exception_acknowledged: false,
        probe_cost: ProbeCost::ProviderRequestIncurred,
        probe_timeout_milliseconds: valid(ProbeTimeoutMilliseconds::from_value(5_000)),
        probe_interactive: false,
        checked_at: parsed("2026-08-21T10:00:00Z"),
        valid_until: parsed("2026-08-21T10:05:00Z"),
        checks: passing_checks(),
    }
}

pub(super) fn local_non_wif_readiness() -> AutomationReadiness {
    let mut readiness = wif_readiness();
    readiness.environment = parsed("local-development");
    readiness.auth_mode = AutomationAuthMode::ChatgptOauth;
    readiness.checks.identity_token_current = check(
        ReadinessStatus::NotApplicable,
        ReadinessReasonCode::NotApplicable,
    );
    readiness
}
