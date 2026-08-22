use std::{collections::BTreeSet, fmt::Debug, num::NonZeroU32, path::PathBuf, str::FromStr};

use ctxlane::{
    automation::{
        contracts::{
            AgentRole, AttemptId, AutomationAuthMode, AutomationError, AutomationErrorCode,
            AutomationErrorSchema, AutomationOperation, CallerSubject, ClientRequestId,
            DetachedSignature, DurationSeconds, EnvironmentName, ExecutionHandle,
            FencingGeneration, HostIdentity, IdentityLeaseRequest, IdentityLeaseRequestSchema,
            IsolationClassification, KeyId, LeaseId, LeaseReasonCode, LeaseStatus,
            MaximumTtlSeconds, PrincipalRef, ProfileRef, RefusalCode, RepositoryId,
            RequestedTtlSeconds, RunId, Sha256Digest, TenantId, UtcTimestamp,
            WorkOrderAuthorization, WorkOrderAuthorizationSchema, WorkOrderId,
            WorkOrderProofAlgorithm, WorkerIdentity, WorkspaceId, WorkspaceRef,
        },
        lease::{
            ClockSample, Lease, LeaseBinding, LeaseControl, LeaseDomainError, LeaseResolution,
            MonotonicMoment, ReplayDisposition, ServiceClockGeneration,
        },
        policy::{
            AllowScope, AuthorizationProof, CapacityLimits, CapacityUsage, ControllerPolicy,
            EffectivePolicy, PolicyDecision, PolicyEvaluation, ProfilePolicy, ReadinessDenial,
            RuntimeReadiness, evaluate_policy,
        },
    },
    model::{
        AutomationConcurrencyMode, AutomationPolicy, AutomationRole, BillingDomain, ClaudeAuth,
        ClaudeWifConfig, Config, Name, Profile, ProfileId, ProfileUid, Provider,
    },
};

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    value
        .parse()
        .unwrap_or_else(|error| panic!("parse {value}: {error:?}"))
}

fn valid<T, E: Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| panic!("fixture: {error:?}"))
}

fn timestamp(value: &str) -> UtcTimestamp {
    valid(UtcTimestamp::parse(value))
}
fn generation(value: u64) -> FencingGeneration {
    valid(FencingGeneration::from_value(value))
}

fn nz(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap_or(NonZeroU32::MIN)
}
#[cfg(not(windows))]
fn fixture_path(leaf: &str) -> PathBuf {
    PathBuf::from("/tmp").join(leaf)
}
#[cfg(windows)]
fn fixture_path(leaf: &str) -> PathBuf {
    PathBuf::from(r"C:\ctxlane").join(leaf)
}

#[derive(Clone)]
struct Fixture {
    config: Config,
    profile_id: ProfileId,
    request: IdentityLeaseRequest,
    controller: ControllerPolicy,
    caller: CallerSubject,
    host: HostIdentity,
    now: UtcTimestamp,
}

impl Fixture {
    fn new() -> Self {
        let mut config = valid(Config::new());
        let profile_id = ProfileId::new(Provider::Claude, valid(Name::parse("automation-prod")));
        let state_dir = fixture_path("p-automation-prod");
        let immutable_uid = valid(ProfileUid::for_state_dir(
            &config.installation_uid,
            Provider::Claude,
            &state_dir,
        ));
        let automation = AutomationPolicy {
            eligible: true,
            environments: BTreeSet::from(["production".to_owned()]),
            roles: BTreeSet::from([AutomationRole::Implementer]),
            caller_subjects: BTreeSet::from(["caller:local-controller".to_owned()]),
            lease_ttl_seconds: 120,
            max_session_seconds: 600,
            max_concurrent_leases: 1,
            concurrency_mode: AutomationConcurrencyMode::Exclusive,
            shared_state_isolation_requirement: None,
            require_workload_identity: true,
            authentication_exception_acknowledged: false,
            isolation_exception_acknowledged: false,
        };
        config.profiles.insert(
            profile_id.clone(),
            Profile::Claude {
                profile_uid: immutable_uid.clone(),
                billing_domain: BillingDomain::AnthropicApi,
                auth: ClaudeAuth::Wif,
                state_dir,
                secret_ref: None,
                account_hint: None,
                expected_organization: Some("org-production".to_owned()),
                wif: Some(ClaudeWifConfig {
                    organization_id: "org-production".to_owned(),
                    federation_rule_id: "rule-production".to_owned(),
                    service_account_id: "service-production".to_owned(),
                    workspace_id: None,
                    identity_token_file: fixture_path("identity-token"),
                }),
                automation,
            },
        );
        valid(config.validate());
        let authorization = WorkOrderAuthorization {
            schema: WorkOrderAuthorizationSchema,
            algorithm: WorkOrderProofAlgorithm::Ed25519,
            key_id: parsed::<KeyId>("key-controller-2026-08"),
            client_request_id: parsed::<ClientRequestId>("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            tenant_id: parsed::<TenantId>("tenant-acme"),
            work_order_id: parsed::<WorkOrderId>("wo_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            work_order_digest: parsed::<Sha256Digest>(
                "sha256:a36dbc1704725260b0896399529c16a86acabb6849bb1c9abeb251d7ffd16e6c",
            ),
            run_id: parsed::<RunId>("run_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            attempt_id: parsed::<AttemptId>("attempt_01"),
            role: AgentRole::Implementer,
            provider: Provider::Claude,
            profile_ref: valid(ProfileRef::parse(profile_id.to_string())),
            profile_uid: immutable_uid.clone(),
            repository: valid(RepositoryId::parse("github:acme/payments")),
            workspace_id: parsed::<WorkspaceId>("workspace_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            environment: parsed::<EnvironmentName>("production"),
            not_before: timestamp("2026-08-21T09:59:00Z"),
            expires_at: timestamp("2026-08-21T10:10:00Z"),
            maximum_ttl_seconds: valid(MaximumTtlSeconds::from_seconds(120)),
            maximum_session_seconds: valid(DurationSeconds::from_seconds(600)),
            signature: valid(DetachedSignature::parse(
                "jLtlv6wVNme_sIhGEIcT25hnhY4YrkAwOolb60L22TWa9DRkudNgfEAxrBSrCm3YXjvFIRsujAKizOeO7wjrAw",
            )),
        };
        let request = IdentityLeaseRequest {
            schema: IdentityLeaseRequestSchema,
            client_request_id: authorization.client_request_id.clone(),
            tenant_id: authorization.tenant_id.clone(),
            work_order_id: authorization.work_order_id.clone(),
            work_order_digest: authorization.work_order_digest,
            run_id: authorization.run_id.clone(),
            attempt_id: authorization.attempt_id.clone(),
            role: authorization.role,
            provider: authorization.provider,
            profile_ref: authorization.profile_ref.clone(),
            profile_uid: authorization.profile_uid.clone(),
            repository: authorization.repository.clone(),
            workspace_id: authorization.workspace_id.clone(),
            environment: authorization.environment.clone(),
            requested_ttl_seconds: valid(RequestedTtlSeconds::from_seconds(60)),
            policy_digest: None,
            work_order_authorization: authorization,
        };
        Self {
            config,
            profile_id,
            request,
            controller: ControllerPolicy {
                profile_uids: AllowScope::Any,
                providers: AllowScope::Any,
                environments: AllowScope::Any,
                roles: AllowScope::Any,
                caller_subjects: AllowScope::Any,
                repositories: AllowScope::Any,
                maximum_ttl_seconds: valid(MaximumTtlSeconds::from_seconds(120)),
                maximum_session_seconds: valid(DurationSeconds::from_seconds(600)),
                capacity: CapacityLimits::new(nz(1), nz(2), nz(3), nz(4)),
                allow_authentication_exception: false,
                allow_isolation_exception: false,
            },
            caller: parsed("caller:local-controller"),
            host: parsed("host:runner-01"),
            now: timestamp("2026-08-21T10:00:00Z"),
        }
    }

    fn profile_policy(&self) -> ProfilePolicy {
        valid(ProfilePolicy::from_config(&self.config, &self.profile_id))
    }

    fn automation_mut(&mut self) -> &mut AutomationPolicy {
        match self.config.profiles.get_mut(&self.profile_id) {
            Some(Profile::Claude { automation, .. }) => automation,
            _ => panic!("claude fixture profile"),
        }
    }

    fn decision(&self, usage: CapacityUsage, readiness: RuntimeReadiness) -> PolicyDecision {
        let profile = self.profile_policy();
        evaluate_policy(&PolicyEvaluation {
            request: &self.request,
            profile: &profile,
            controller: &self.controller,
            caller_subject: &self.caller,
            host_identity: &self.host,
            authorization_proof: AuthorizationProof::Verified,
            readiness,
            capacity_usage: usage,
            now: &self.now,
        })
    }

    fn policy(&self) -> EffectivePolicy {
        match self.decision(CapacityUsage::default(), ready()) {
            PolicyDecision::Permitted(policy) => *policy,
            PolicyDecision::Refused(code) => panic!("unexpected refusal: {code:?}"),
        }
    }
}

fn ready() -> RuntimeReadiness {
    RuntimeReadiness::Ready {
        isolation: IsolationClassification::CredentialIsolated,
        shared_state_isolation: None,
    }
}
fn refused(decision: PolicyDecision) -> RefusalCode {
    match decision {
        PolicyDecision::Refused(code) => code,
        PolicyDecision::Permitted(policy) => panic!("unexpected policy {}", policy.digest()),
    }
}

fn sample(wall: &str, seconds: u64) -> ClockSample {
    ClockSample::new(
        timestamp(wall),
        MonotonicMoment::from_nanoseconds(u128::from(seconds) * 1_000_000_000),
        ServiceClockGeneration::from_value(1),
    )
}

fn resolution() -> LeaseResolution {
    LeaseResolution {
        execution_handle: parsed::<ExecutionHandle>("exec_01ARZ3NDEKTSV4RRFFQ69G5FB1"),
        worker_identity: Some(parsed::<WorkerIdentity>("worker:controller-01")),
        principal_ref: parsed::<PrincipalRef>("service-account:automation-worker"),
        workspace_ref: parsed::<WorkspaceRef>("claude-organization:org-production"),
        auth_mode: AutomationAuthMode::Wif,
        isolation: IsolationClassification::CredentialIsolated,
    }
}
fn requested_lease(fixture: &Fixture) -> Lease {
    let binding = valid(LeaseBinding::from_request(
        parsed::<LeaseId>("lease_01ARZ3NDEKTSV4RRFFQ69G5FB0"),
        &fixture.request,
        fixture.caller.clone(),
        fixture.host.clone(),
    ));
    Lease::requested(binding, sample("2026-08-21T10:00:00Z", 1_000))
}

fn active_lease(fixture: &Fixture, policy: &EffectivePolicy) -> Lease {
    let mut lease = requested_lease(fixture);
    valid(lease.activate(policy, resolution(), &sample("2026-08-21T10:00:00Z", 1_000)));
    lease
}

fn control(fixture: &Fixture, value: u64) -> LeaseControl<'_> {
    LeaseControl {
        caller_subject: &fixture.caller,
        tenant_id: &fixture.request.tenant_id,
        run_id: &fixture.request.run_id,
        role: fixture.request.role,
        host_identity: &fixture.host,
        fencing_generation: generation(value),
    }
}

#[test]
fn public_api_evaluates_before_constructing_authority_and_active_requires_a_handle() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    assert_eq!(policy.capacity_claim().limits().profile(), 1);
    let mut lease = active_lease(&fixture, &policy);
    assert_eq!(lease.status(), LeaseStatus::Active);
    assert_eq!(lease.fencing_generation(), Some(generation(1)));
    assert!(lease.execution_handle().is_some());
    assert_eq!(
        valid(lease.authorize_launch(
            &control(&fixture, 1),
            &policy,
            &sample("2026-08-21T10:00:01Z", 1_001),
        )),
        parsed("exec_01ARZ3NDEKTSV4RRFFQ69G5FB1")
    );
}

#[test]
fn policy_exact_binding_denials_and_readiness_codes_are_stable() {
    let baseline = Fixture::new();
    let cases = [
        ReadinessDenial::ProfileNotReady,
        ReadinessDenial::IdentityTokenStale,
        ReadinessDenial::HarnessUntrusted,
        ReadinessDenial::PrincipalUnverified,
        ReadinessDenial::PrincipalMismatch,
        ReadinessDenial::OrganizationMismatch,
        ReadinessDenial::WorkspaceMismatch,
        ReadinessDenial::IsolationUnproven,
    ];
    for denial in cases {
        assert_eq!(
            refused(baseline.decision(CapacityUsage::default(), RuntimeReadiness::Denied(denial))),
            denial.refusal_code()
        );
    }
    let mut provider = baseline.clone();
    provider.request.provider = Provider::Codex;
    provider.request.profile_ref = valid(ProfileRef::parse("codex:automation-prod"));
    assert_eq!(
        refused(provider.decision(CapacityUsage::default(), ready())),
        RefusalCode::WorkOrderAuthorizationMismatch
    );
    let mut uid = baseline.clone();
    uid.request.profile_uid = valid(ProfileUid::parse("profile_01ARZ3NDEKTSV4RRFFQ69G5FB2"));
    uid.request.work_order_authorization.profile_uid = uid.request.profile_uid.clone();
    assert_eq!(
        refused(uid.decision(CapacityUsage::default(), ready())),
        RefusalCode::ProfileNotFound
    );
    let mut alias = baseline.clone();
    alias.request.profile_ref = valid(ProfileRef::parse("claude:other"));
    alias.request.work_order_authorization.profile_ref = alias.request.profile_ref.clone();
    assert_eq!(
        refused(alias.decision(CapacityUsage::default(), ready())),
        RefusalCode::ProfileNotFound
    );
}

#[test]
fn profile_request_and_controller_intersection_can_only_narrow() {
    let baseline = Fixture::new();
    let mut profile = baseline.clone();
    profile.automation_mut().eligible = false;
    assert_eq!(
        refused(profile.decision(CapacityUsage::default(), ready())),
        RefusalCode::ProfileNotEligible
    );
    profile = baseline.clone();
    profile.automation_mut().environments.clear();
    assert!(ProfilePolicy::from_config(&profile.config, &profile.profile_id).is_err());
    profile = baseline.clone();
    profile.automation_mut().lease_ttl_seconds = 59;
    assert_eq!(
        refused(profile.decision(CapacityUsage::default(), ready())),
        RefusalCode::RequestedTtlNotAllowed
    );

    let mut request = baseline.clone();
    request.request.environment = parsed("staging");
    request.request.work_order_authorization.environment = request.request.environment.clone();
    assert_eq!(
        refused(request.decision(CapacityUsage::default(), ready())),
        RefusalCode::EnvironmentNotAllowed
    );
    request = baseline.clone();
    request.request.role = AgentRole::LocalReviewer;
    request.request.work_order_authorization.role = request.request.role;
    assert_eq!(
        refused(request.decision(CapacityUsage::default(), ready())),
        RefusalCode::RoleNotAllowed
    );
    request = baseline.clone();
    request.request.requested_ttl_seconds = valid(RequestedTtlSeconds::from_seconds(121));
    assert_eq!(
        refused(request.decision(CapacityUsage::default(), ready())),
        RefusalCode::RequestedTtlNotAllowed
    );

    let mut controller = baseline.clone();
    controller.controller.profile_uids = AllowScope::Only(vec![valid(ProfileUid::parse(
        "profile_01ARZ3NDEKTSV4RRFFQ69G5FB4",
    ))]);
    assert_eq!(
        refused(controller.decision(CapacityUsage::default(), ready())),
        RefusalCode::ProfileNotEligible
    );
    controller = baseline.clone();
    controller.controller.providers = AllowScope::Only(vec![Provider::Codex]);
    assert_eq!(
        refused(controller.decision(CapacityUsage::default(), ready())),
        RefusalCode::ProviderMismatch
    );
    controller = baseline.clone();
    controller.controller.environments = AllowScope::Only(vec![parsed("staging")]);
    assert_eq!(
        refused(controller.decision(CapacityUsage::default(), ready())),
        RefusalCode::EnvironmentNotAllowed
    );
    controller = baseline.clone();
    controller.controller.roles = AllowScope::Only(vec![AgentRole::LocalReviewer]);
    assert_eq!(
        refused(controller.decision(CapacityUsage::default(), ready())),
        RefusalCode::RoleNotAllowed
    );
    controller = baseline.clone();
    controller.controller.caller_subjects = AllowScope::Only(vec![parsed("caller:other")]);
    assert_eq!(
        refused(controller.decision(CapacityUsage::default(), ready())),
        RefusalCode::CallerNotAllowed
    );
    controller = baseline.clone();
    controller.controller.repositories =
        AllowScope::Only(vec![valid(RepositoryId::parse("github:acme/other"))]);
    assert_eq!(
        refused(controller.decision(CapacityUsage::default(), ready())),
        RefusalCode::RepositoryNotAllowed
    );
    controller = baseline.clone();
    controller.controller.maximum_ttl_seconds = valid(MaximumTtlSeconds::from_seconds(59));
    assert_eq!(
        refused(controller.decision(CapacityUsage::default(), ready())),
        RefusalCode::RequestedTtlNotAllowed
    );
    controller = baseline.clone();
    controller.controller.maximum_session_seconds = valid(DurationSeconds::from_seconds(59));
    assert_eq!(
        refused(controller.decision(CapacityUsage::default(), ready())),
        RefusalCode::RequestedTtlNotAllowed
    );
}
#[test]
fn policy_digest_precondition_precedes_all_four_capacity_dimensions() {
    let mut fixture = Fixture::new();
    fixture.request.policy_digest = Some(parsed(
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ));
    for usage in [
        CapacityUsage {
            profile: 1,
            ..CapacityUsage::default()
        },
        CapacityUsage {
            provider: 2,
            ..CapacityUsage::default()
        },
        CapacityUsage {
            caller: 3,
            ..CapacityUsage::default()
        },
        CapacityUsage {
            host: 4,
            ..CapacityUsage::default()
        },
    ] {
        assert_eq!(
            refused(fixture.decision(usage, ready())),
            RefusalCode::PolicyDigestMismatch
        );
    }
    fixture.request.policy_digest = None;
    for usage in [
        CapacityUsage {
            profile: 1,
            ..CapacityUsage::default()
        },
        CapacityUsage {
            provider: 2,
            ..CapacityUsage::default()
        },
        CapacityUsage {
            caller: 3,
            ..CapacityUsage::default()
        },
        CapacityUsage {
            host: 4,
            ..CapacityUsage::default()
        },
    ] {
        assert_eq!(
            refused(fixture.decision(usage, ready())),
            RefusalCode::CapacityExceeded
        );
    }
}

#[test]
fn copied_and_shared_isolation_never_upgrade_unproven_evidence() {
    let fixture = Fixture::new();
    assert_eq!(
        refused(fixture.decision(
            CapacityUsage::default(),
            RuntimeReadiness::Ready {
                isolation: IsolationClassification::Unproven,
                shared_state_isolation: None,
            },
        )),
        RefusalCode::IsolationUnproven
    );
    assert_eq!(
        refused(fixture.decision(
            CapacityUsage::default(),
            RuntimeReadiness::Ready {
                isolation: IsolationClassification::CopiedCredentialDevelopment,
                shared_state_isolation: None,
            },
        )),
        RefusalCode::IsolationUnproven
    );

    let mut local = Fixture::new();
    let Profile::Claude { automation, .. } = local
        .config
        .profiles
        .get_mut(&local.profile_id)
        .unwrap_or_else(|| panic!("profile"))
    else {
        panic!("claude profile")
    };
    automation.environments = BTreeSet::from(["local-development".to_owned()]);
    automation.isolation_exception_acknowledged = true;
    local.request.environment = parsed("local-development");
    local.request.work_order_authorization.environment = local.request.environment.clone();
    local.controller.allow_isolation_exception = true;
    assert!(matches!(
        local.decision(
            CapacityUsage::default(),
            RuntimeReadiness::Ready {
                isolation: IsolationClassification::CopiedCredentialDevelopment,
                shared_state_isolation: None,
            }
        ),
        PolicyDecision::Permitted(_)
    ));
}

#[test]
fn lifecycle_fences_renewal_and_enforces_acknowledgement() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let renewed = valid(policy.for_renewal_ttl(valid(RequestedTtlSeconds::from_seconds(90))));
    let mut lease = active_lease(&fixture, &policy);
    let next = valid(lease.begin_renewal(
        &control(&fixture, 1),
        &renewed,
        &sample("2026-08-21T10:00:30Z", 1_030),
    ));
    assert_eq!(next, generation(2));
    assert_eq!(lease.status(), LeaseStatus::Renewing);
    assert!(lease.execution_handle().is_some());
    let fenced = lease.authorize_launch(
        &control(&fixture, 1),
        &renewed,
        &sample("2026-08-21T10:00:31Z", 1_031),
    );
    assert_eq!(
        fenced
            .as_ref()
            .map_err(|error| { error.automation_code(AutomationOperation::ExecutionStart) }),
        Err(AutomationErrorCode::LeaseNotActive)
    );
    valid(lease.acknowledge_renewal(
        &control(&fixture, next.get()),
        &sample("2026-08-21T10:00:31Z", 1_031),
    ));
    assert_eq!(lease.status(), LeaseStatus::Active);
    assert_eq!(lease.effective_policy_digest(), Some(renewed.digest()));
    assert_eq!(
        lease.authorize_launch(
            &control(&fixture, 1),
            &renewed,
            &sample("2026-08-21T10:00:32Z", 1_032),
        ),
        Err(LeaseDomainError::GenerationMismatch)
    );

    let mut mismatch = active_lease(&fixture, &policy);
    valid(mismatch.begin_renewal(
        &control(&fixture, 1),
        &renewed,
        &sample("2026-08-21T10:00:30Z", 1_030),
    ));
    assert_eq!(
        mismatch.acknowledge_renewal(
            &control(&fixture, 1),
            &sample("2026-08-21T10:00:31Z", 1_031),
        ),
        Err(LeaseDomainError::GenerationMismatch)
    );
    assert_eq!(mismatch.status(), LeaseStatus::Revoked);
    assert_eq!(
        mismatch.reason_code(),
        Some(LeaseReasonCode::RenewalAcknowledgementFailed)
    );

    let mut late = active_lease(&fixture, &policy);
    valid(late.begin_renewal(
        &control(&fixture, 1),
        &renewed,
        &sample("2026-08-21T10:00:30Z", 1_030),
    ));
    assert!(valid(
        late.enforce_deadlines(&sample("2026-08-21T10:01:00Z", 1_060))
    ));
    assert_eq!(late.status(), LeaseStatus::Revoked);
}

#[test]
fn lifecycle_reasons_terminal_immutability_and_clock_boundaries_are_exact() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    for reason in [LeaseReasonCode::Completed, LeaseReasonCode::WorkerFailed] {
        let mut lease = active_lease(&fixture, &policy);
        valid(lease.close(
            &control(&fixture, 1),
            reason,
            &sample("2026-08-21T10:00:01Z", 1_001),
        ));
        assert_eq!(lease.status(), LeaseStatus::Closed);
        assert_eq!(lease.reason_code(), Some(reason));
        assert!(lease.execution_handle().is_none());
        assert!(lease.refuse(RefusalCode::ProfileNotReady).is_err());
    }
    for reason in [
        LeaseReasonCode::OperatorRevoked,
        LeaseReasonCode::PolicyRevoked,
        LeaseReasonCode::PrincipalMismatch,
        LeaseReasonCode::HeartbeatLost,
        LeaseReasonCode::ProcessUnverifiable,
        LeaseReasonCode::GenerationSuperseded,
        LeaseReasonCode::RenewalAcknowledgementFailed,
        LeaseReasonCode::ServiceRecovery,
    ] {
        let mut lease = active_lease(&fixture, &policy);
        valid(lease.revoke(reason));
        assert_eq!(lease.status(), LeaseStatus::Revoked);
        assert_eq!(lease.reason_code(), Some(reason));
        assert_eq!(lease.revoke(reason), Err(LeaseDomainError::LeaseNotActive));
    }
    for reason in [
        LeaseReasonCode::ProcessUnverifiable,
        LeaseReasonCode::ServiceRecovery,
        LeaseReasonCode::InternalError,
    ] {
        let mut lease = active_lease(&fixture, &policy);
        valid(lease.mark_error(reason));
        assert_eq!(lease.status(), LeaseStatus::Error);
        valid(lease.revoke(LeaseReasonCode::ServiceRecovery));
    }
    let mut refused_lease = requested_lease(&fixture);
    valid(refused_lease.refuse(RefusalCode::ProfileNotReady));
    assert_eq!(refused_lease.status(), LeaseStatus::Refused);
    assert_eq!(
        refused_lease.refusal_code(),
        Some(RefusalCode::ProfileNotReady)
    );
    assert!(
        refused_lease
            .activate(
                &policy,
                resolution(),
                &sample("2026-08-21T10:00:00Z", 1_000)
            )
            .is_err()
    );

    let mut interval = active_lease(&fixture, &policy);
    assert!(valid(
        interval.enforce_deadlines(&sample("2026-08-21T10:01:00Z", 1_060))
    ));
    assert_eq!(interval.reason_code(), Some(LeaseReasonCode::LeaseExpired));

    let mut bounded = Fixture::new();
    bounded.request.work_order_authorization.expires_at = timestamp("2026-08-21T10:01:00Z");
    bounded
        .request
        .work_order_authorization
        .maximum_session_seconds = valid(DurationSeconds::from_seconds(60));
    bounded.request.work_order_authorization.maximum_ttl_seconds =
        valid(MaximumTtlSeconds::from_seconds(60));
    let bounded_policy = bounded.policy();
    let mut maximum = active_lease(&bounded, &bounded_policy);
    assert!(valid(
        maximum.enforce_deadlines(&sample("2026-08-21T10:01:00Z", 1_060))
    ));
    assert_eq!(
        maximum.reason_code(),
        Some(LeaseReasonCode::MaximumLifetimeReached)
    );

    let mut rollback = requested_lease(&fixture);
    assert_eq!(
        rollback.activate(
            &policy,
            resolution(),
            &sample("2026-08-21T09:59:59Z", 1_001),
        ),
        Err(LeaseDomainError::ClockBeforeIssuance)
    );
}

#[test]
fn replay_binding_is_global_to_request_caller_and_host_and_retention_never_shortens() {
    let fixture = Fixture::new();
    let lease = requested_lease(&fixture);
    let original = lease.replay_binding();
    assert!(matches!(
        original.compare(&original),
        ReplayDisposition::ExactRetry(_)
    ));
    let mut changed = fixture.clone();
    changed.caller = parsed("caller:other-controller");
    let caller = requested_lease(&changed).replay_binding();
    assert_eq!(
        original.compare(&caller),
        ReplayDisposition::Conflict(AutomationErrorCode::IdempotencyConflict)
    );
    changed = fixture.clone();
    changed.host = parsed("host:runner-02");
    assert_eq!(
        original.compare(&requested_lease(&changed).replay_binding()),
        ReplayDisposition::Conflict(AutomationErrorCode::IdempotencyConflict)
    );
    changed = fixture.clone();
    changed.request.client_request_id = parsed("01ARZ3NDEKTSV4RRFFQ69G5FB3");
    assert_eq!(
        original.compare(&requested_lease(&changed).replay_binding()),
        ReplayDisposition::UnrelatedKey
    );
    assert_eq!(
        original.retention_deadline(&timestamp("2026-08-21T10:05:00Z")),
        timestamp("2026-08-21T10:10:00Z")
    );
    assert_eq!(
        original.retention_deadline(&timestamp("2026-08-28T10:00:00Z")),
        timestamp("2026-08-28T10:00:00Z")
    );
}
#[test]
fn operation_aware_error_mapping_always_builds_a_valid_wire_error() {
    let operations = [
        AutomationOperation::LeaseRenew,
        AutomationOperation::LeaseRevoke,
        AutomationOperation::LeaseClose,
        AutomationOperation::ExecutionStart,
    ];
    let errors = [
        LeaseDomainError::LeaseNotActive,
        LeaseDomainError::LeaseExpired,
        LeaseDomainError::LeaseRevoked,
        LeaseDomainError::CallerUnauthorized,
        LeaseDomainError::GenerationMismatch,
        LeaseDomainError::SessionLimitReached,
        LeaseDomainError::TenantMismatch,
        LeaseDomainError::RunMismatch,
        LeaseDomainError::RoleMismatch,
        LeaseDomainError::HostMismatch,
        LeaseDomainError::PolicyBindingMismatch,
        LeaseDomainError::ClockBeforeIssuance,
        LeaseDomainError::ClockGenerationMismatch,
        LeaseDomainError::MonotonicRegression,
        LeaseDomainError::ClockOverflow,
        LeaseDomainError::InvalidReason {
            status: LeaseStatus::Closed,
            reason: LeaseReasonCode::InternalError,
        },
    ];
    for operation in operations {
        for error in &errors {
            let wire = AutomationError {
                schema: AutomationErrorSchema,
                operation,
                code: error.automation_code(operation),
                client_request_id: None,
                lease_id: if matches!(
                    error.automation_code(operation),
                    AutomationErrorCode::InvalidRequest
                        | AutomationErrorCode::CallerUnauthorized
                        | AutomationErrorCode::InternalError
                ) {
                    None
                } else {
                    Some(parsed("lease_01ARZ3NDEKTSV4RRFFQ69G5FB0"))
                },
            };
            valid(wire.validate());
        }
    }
}

#[path = "automation_domain/issuance.rs"]
mod issuance;
#[path = "automation_domain/no_widening.rs"]
mod no_widening;
