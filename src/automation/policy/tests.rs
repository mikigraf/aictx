use std::{collections::BTreeSet, fmt::Debug, num::NonZeroU32, str::FromStr};

use super::*;

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    value.parse().unwrap_or_else(|error| panic!("{error:?}"))
}

fn limits(profile: u32, provider: u32, caller: u32, host: u32) -> CapacityLimits {
    CapacityLimits::new(
        NonZeroU32::new(profile).unwrap_or(NonZeroU32::MIN),
        NonZeroU32::new(provider).unwrap_or(NonZeroU32::MIN),
        NonZeroU32::new(caller).unwrap_or(NonZeroU32::MIN),
        NonZeroU32::new(host).unwrap_or(NonZeroU32::MIN),
    )
}

fn baseline() -> EffectivePolicy {
    EffectivePolicy {
        source_request_digest: parsed(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        client_request_id: parsed("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        tenant_id: parsed("tenant-one"),
        work_order_id: parsed("wo_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        work_order_digest: parsed(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        run_id: parsed("run_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        attempt_id: parsed("attempt-one"),
        role: AgentRole::Implementer,
        provider: Provider::Claude,
        profile_uid: parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        profile_ref: parsed("claude:one"),
        repository: parsed("github:acme/one"),
        workspace_id: parsed("workspace-one"),
        environment: parsed("production"),
        caller_subject: parsed("caller:one"),
        host_identity: parsed("host:one"),
        auth_mode: AutomationAuthMode::Wif,
        isolation: IsolationClassification::CredentialIsolated,
        shared_state_isolation: None,
        requested_ttl_seconds: 60,
        maximum_ttl_seconds: 120,
        maximum_session_seconds: 600,
        signed_expires_at: valid_timestamp("2026-08-21T10:10:00Z"),
        concurrency_mode: AutomationConcurrencyMode::Exclusive,
        requirements: PolicyRequirements {
            workload_identity: true,
            authentication_exception: false,
            isolation_exception: false,
        },
        capacity_claim: CapacityClaim {
            profile_uid: parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            provider: Provider::Claude,
            caller_subject: parsed("caller:one"),
            host_identity: parsed("host:one"),
            limits: limits(1, 2, 3, 4),
        },
    }
}

fn valid_timestamp(value: &str) -> UtcTimestamp {
    UtcTimestamp::parse(value).unwrap_or_else(|error| panic!("{error:?}"))
}

#[test]
fn effective_digest_changes_for_every_effective_authority_and_limit_field() {
    let baseline = baseline();
    let digest = baseline.digest();
    let mut variants = Vec::new();
    macro_rules! change {
        ($field:ident, $value:expr) => {{
            let mut value = baseline.clone();
            value.$field = $value;
            variants.push(value);
        }};
    }
    change!(client_request_id, parsed("01ARZ3NDEKTSV4RRFFQ69G5FB0"));
    change!(tenant_id, parsed("tenant-two"));
    change!(work_order_id, parsed("wo_01ARZ3NDEKTSV4RRFFQ69G5FB0"));
    change!(
        work_order_digest,
        parsed("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
    );
    change!(run_id, parsed("run_01ARZ3NDEKTSV4RRFFQ69G5FB0"));
    change!(attempt_id, parsed("attempt-two"));
    change!(role, AgentRole::LocalReviewer);
    change!(provider, Provider::Codex);
    change!(profile_uid, parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FB0"));
    change!(profile_ref, parsed("claude:two"));
    change!(repository, parsed("github:acme/two"));
    change!(workspace_id, parsed("workspace-two"));
    change!(environment, parsed("staging"));
    change!(caller_subject, parsed("caller:two"));
    change!(host_identity, parsed("host:two"));
    change!(auth_mode, AutomationAuthMode::ApiKey);
    change!(isolation, IsolationClassification::PerLeaseIsolated);
    change!(
        shared_state_isolation,
        Some(SharedStateIsolationRequirement::Stateless)
    );
    change!(requested_ttl_seconds, 61);
    change!(maximum_ttl_seconds, 121);
    change!(maximum_session_seconds, 601);
    change!(signed_expires_at, valid_timestamp("2026-08-21T10:10:01Z"));
    change!(concurrency_mode, AutomationConcurrencyMode::Shared);
    for index in 0..3 {
        let mut value = baseline.clone();
        match index {
            0 => value.requirements.workload_identity = false,
            1 => value.requirements.authentication_exception = true,
            _ => value.requirements.isolation_exception = true,
        }
        variants.push(value);
    }
    for index in 0..8 {
        let mut value = baseline.clone();
        match index {
            0 => value.capacity_claim.profile_uid = parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FB1"),
            1 => value.capacity_claim.provider = Provider::Codex,
            2 => value.capacity_claim.caller_subject = parsed("caller:claim-two"),
            3 => value.capacity_claim.host_identity = parsed("host:claim-two"),
            4 => value.capacity_claim.limits = limits(2, 2, 3, 4),
            5 => value.capacity_claim.limits = limits(1, 3, 3, 4),
            6 => value.capacity_claim.limits = limits(1, 2, 4, 4),
            _ => value.capacity_claim.limits = limits(1, 2, 3, 5),
        }
        variants.push(value);
    }
    assert_eq!(variants.len(), 34);
    for variant in variants {
        assert_ne!(variant.digest(), digest);
    }

    let mut replay_only = baseline;
    replay_only.source_request_digest =
        parsed("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    assert_eq!(replay_only.digest(), digest);
}

#[test]
fn shared_resource_mode_accepts_only_the_two_proven_isolation_pairs() {
    for (isolation, shared, accepted) in [
        (
            IsolationClassification::CredentialIsolated,
            Some(SharedStateIsolationRequirement::Stateless),
            true,
        ),
        (
            IsolationClassification::PerLeaseIsolated,
            Some(SharedStateIsolationRequirement::PerLeaseIsolated),
            true,
        ),
        (
            IsolationClassification::CopiedCredentialDevelopment,
            Some(SharedStateIsolationRequirement::Stateless),
            false,
        ),
        (
            IsolationClassification::Unproven,
            Some(SharedStateIsolationRequirement::Stateless),
            false,
        ),
        (IsolationClassification::CredentialIsolated, None, false),
    ] {
        assert_eq!(valid_shared_resource_isolation(isolation, shared), accepted);
        let mut policy = baseline();
        policy.concurrency_mode = AutomationConcurrencyMode::Shared;
        policy.isolation = isolation;
        policy.shared_state_isolation = shared;
        assert_eq!(policy.resource_isolation_is_consistent(), accepted);
    }
}

#[test]
fn copied_credentials_are_refused_for_shared_local_and_pr_exception_shapes() {
    for (environment, role) in [
        ("local-development", AgentRole::Implementer),
        ("production", AgentRole::PrReviewer),
    ] {
        let mut request: IdentityLeaseRequest = serde_json::from_str(include_str!(
            "../../../schemas/examples/identity-lease-request.v1.json"
        ))
        .unwrap_or_else(|error| panic!("request fixture: {error}"));
        request.environment = parsed(environment);
        request.work_order_authorization.environment = request.environment.clone();
        request.role = role;
        request.work_order_authorization.role = role;
        let caller = parsed::<CallerSubject>("caller:local-controller");
        let host = parsed::<HostIdentity>("host:runner-01");
        let profile = ProfilePolicy {
            profile_uid: request.profile_uid.clone(),
            profile_ref: request.profile_ref.clone(),
            provider: request.provider,
            auth_mode: AutomationAuthMode::ChatgptOauth,
            eligible: true,
            environments: BTreeSet::from([request.environment.clone()]),
            roles: vec![request.role],
            caller_subjects: BTreeSet::from([caller.clone()]),
            maximum_ttl_seconds: request.work_order_authorization.maximum_ttl_seconds,
            maximum_session_seconds: request.work_order_authorization.maximum_session_seconds,
            maximum_concurrent_leases: NonZeroU32::MIN,
            concurrency_mode: AutomationConcurrencyMode::Shared,
            shared_state_isolation_requirement: Some(SharedStateIsolationRequirement::Stateless),
            requirements: PolicyRequirements {
                workload_identity: false,
                authentication_exception: true,
                isolation_exception: true,
            },
        };
        let controller = ControllerPolicy {
            profile_uids: AllowScope::Any,
            providers: AllowScope::Any,
            environments: AllowScope::Any,
            roles: AllowScope::Any,
            caller_subjects: AllowScope::Any,
            repositories: AllowScope::Any,
            maximum_ttl_seconds: request.work_order_authorization.maximum_ttl_seconds,
            maximum_session_seconds: request.work_order_authorization.maximum_session_seconds,
            capacity: limits(1, 1, 1, 1),
            allow_authentication_exception: true,
            allow_isolation_exception: true,
        };
        let now = valid_timestamp("2026-08-21T10:01:00Z");
        assert_eq!(
            evaluate_policy(&PolicyEvaluation {
                request: &request,
                profile: &profile,
                controller: &controller,
                caller_subject: &caller,
                host_identity: &host,
                authorization_proof: AuthorizationProof::Verified,
                readiness: RuntimeReadiness::Ready {
                    isolation: IsolationClassification::CopiedCredentialDevelopment,
                    shared_state_isolation: Some(SharedStateIsolationRequirement::Stateless),
                },
                capacity_usage: CapacityUsage::default(),
                now: &now,
            }),
            PolicyDecision::Refused(RefusalCode::IsolationUnproven),
            "{environment} {role:?}"
        );
    }
}
