use super::*;

fn exact_controller_scopes(fixture: &mut Fixture) {
    fixture.controller.profile_uids = AllowScope::Only(vec![fixture.request.profile_uid.clone()]);
    fixture.controller.providers = AllowScope::Only(vec![fixture.request.provider]);
    fixture.controller.environments = AllowScope::Only(vec![fixture.request.environment.clone()]);
    fixture.controller.roles = AllowScope::Only(vec![fixture.request.role]);
    fixture.controller.caller_subjects = AllowScope::Only(vec![fixture.caller.clone()]);
    fixture.controller.repositories = AllowScope::Only(vec![fixture.request.repository.clone()]);
}

fn api_key_profile(fixture: &mut Fixture) {
    let Some(Profile::Claude {
        auth,
        secret_ref,
        wif,
        automation,
        ..
    }) = fixture.config.profiles.get_mut(&fixture.profile_id)
    else {
        panic!("claude profile")
    };
    *auth = ClaudeAuth::ApiKey;
    *secret_ref = Some("keyring://ctxlane/automation-test".to_owned());
    *wif = None;
    automation.require_workload_identity = false;
}

#[test]
fn every_single_field_scope_or_ceiling_widening_leaves_this_lease_unchanged() {
    let mut baseline = Fixture::new();
    exact_controller_scopes(&mut baseline);
    let expected = baseline.policy().digest();
    let mut variants = Vec::new();
    macro_rules! widen_controller {
        ($field:ident, $value:expr) => {{
            let mut value = baseline.clone();
            value.controller.$field = $value;
            variants.push(value);
        }};
    }
    widen_controller!(profile_uids, AllowScope::Any);
    widen_controller!(providers, AllowScope::Any);
    widen_controller!(environments, AllowScope::Any);
    widen_controller!(roles, AllowScope::Any);
    widen_controller!(caller_subjects, AllowScope::Any);
    widen_controller!(repositories, AllowScope::Any);

    for mutation in ["environment", "role", "caller"] {
        let mut value = baseline.clone();
        match mutation {
            "environment" => {
                value
                    .automation_mut()
                    .environments
                    .insert("staging".to_owned());
            }
            "role" => {
                value
                    .automation_mut()
                    .roles
                    .insert(AutomationRole::LocalReviewer);
            }
            _ => {
                value
                    .automation_mut()
                    .caller_subjects
                    .insert("caller:other".to_owned());
            }
        }
        variants.push(value);
    }
    let mut value = baseline.clone();
    value.automation_mut().lease_ttl_seconds = 300;
    variants.push(value);
    let mut value = baseline.clone();
    value.automation_mut().max_session_seconds = 900;
    variants.push(value);
    let mut value = baseline.clone();
    value.request.work_order_authorization.maximum_ttl_seconds =
        valid(MaximumTtlSeconds::from_seconds(300));
    variants.push(value);
    let mut value = baseline.clone();
    value
        .request
        .work_order_authorization
        .maximum_session_seconds = valid(DurationSeconds::from_seconds(660));
    variants.push(value);
    widen_controller!(
        maximum_ttl_seconds,
        valid(MaximumTtlSeconds::from_seconds(300))
    );
    widen_controller!(
        maximum_session_seconds,
        valid(DurationSeconds::from_seconds(900))
    );
    widen_controller!(capacity, CapacityLimits::new(nz(9), nz(2), nz(3), nz(4)));

    assert_eq!(variants.len(), 16);
    for (index, variant) in variants.into_iter().enumerate() {
        let policy = match variant.decision(CapacityUsage::default(), ready()) {
            PolicyDecision::Permitted(policy) => policy,
            PolicyDecision::Refused(code) => panic!("widening case {index} refused: {code:?}"),
        };
        assert_eq!(policy.digest(), expected, "widening case {index}");
    }
}

#[test]
fn non_wif_authentication_exception_is_two_sided_and_local_development_is_narrow() {
    let mut production = Fixture::new();
    api_key_profile(&mut production);
    production
        .automation_mut()
        .authentication_exception_acknowledged = true;
    assert_eq!(
        refused(production.decision(CapacityUsage::default(), ready())),
        RefusalCode::AuthenticationExceptionRequired
    );
    production.controller.allow_authentication_exception = true;
    assert!(matches!(
        production.decision(CapacityUsage::default(), ready()),
        PolicyDecision::Permitted(_)
    ));
    let projection = format!("{:?}", production.profile_policy());
    assert!(!projection.contains("keyring://") && !projection.contains("identity-token"));

    let mut local = Fixture::new();
    api_key_profile(&mut local);
    local.automation_mut().environments = BTreeSet::from(["local-development".to_owned()]);
    local.request.environment = parsed("local-development");
    local.request.work_order_authorization.environment = local.request.environment.clone();
    assert!(matches!(
        local.decision(CapacityUsage::default(), ready()),
        PolicyDecision::Permitted(_)
    ));
}

#[test]
fn proof_provider_and_copied_isolation_refusals_remain_distinct() {
    let fixture = Fixture::new();
    let profile = fixture.profile_policy();
    assert_eq!(
        refused(evaluate_policy(&PolicyEvaluation {
            request: &fixture.request,
            profile: &profile,
            controller: &fixture.controller,
            caller_subject: &fixture.caller,
            host_identity: &fixture.host,
            authorization_proof: AuthorizationProof::Invalid,
            readiness: ready(),
            capacity_usage: CapacityUsage::default(),
            now: &fixture.now,
        })),
        RefusalCode::WorkOrderProofInvalid
    );

    let mut provider = fixture.clone();
    provider.request.provider = Provider::Codex;
    provider.request.work_order_authorization.provider = Provider::Codex;
    provider.request.profile_ref = valid(ProfileRef::parse("codex:automation-prod"));
    provider.request.work_order_authorization.profile_ref = provider.request.profile_ref.clone();
    assert_eq!(
        refused(provider.decision(CapacityUsage::default(), ready())),
        RefusalCode::ProviderMismatch
    );

    let mut local = Fixture::new();
    local.automation_mut().environments = BTreeSet::from(["local-development".to_owned()]);
    local.request.environment = parsed("local-development");
    local.request.work_order_authorization.environment = local.request.environment.clone();
    let copied = RuntimeReadiness::Ready {
        isolation: IsolationClassification::CopiedCredentialDevelopment,
        shared_state_isolation: None,
    };
    assert_eq!(
        refused(local.decision(CapacityUsage::default(), copied)),
        RefusalCode::IsolationExceptionRequired
    );
    local.automation_mut().isolation_exception_acknowledged = true;
    assert_eq!(
        refused(local.decision(CapacityUsage::default(), copied)),
        RefusalCode::IsolationExceptionRequired
    );
    local.controller.allow_isolation_exception = true;
    assert!(matches!(
        local.decision(CapacityUsage::default(), copied),
        PolicyDecision::Permitted(_)
    ));

    let mut reviewer = Fixture::new();
    reviewer.automation_mut().roles = BTreeSet::from([AutomationRole::PrReviewer]);
    reviewer.automation_mut().isolation_exception_acknowledged = true;
    reviewer.request.role = AgentRole::PrReviewer;
    reviewer.request.work_order_authorization.role = AgentRole::PrReviewer;
    reviewer.controller.allow_isolation_exception = true;
    assert!(matches!(
        reviewer.decision(CapacityUsage::default(), copied),
        PolicyDecision::Permitted(_)
    ));
    assert_eq!(
        refused(reviewer.decision(
            CapacityUsage::default(),
            RuntimeReadiness::Ready {
                isolation: IsolationClassification::Unproven,
                shared_state_isolation: None,
            },
        )),
        RefusalCode::IsolationUnproven
    );
}

#[test]
fn shared_concurrency_requires_the_exact_proven_isolation_shape() {
    use ctxlane::model::SharedStateIsolationRequirement::{PerLeaseIsolated, Stateless};

    let mut shared = Fixture::new();
    let automation = shared.automation_mut();
    automation.concurrency_mode = AutomationConcurrencyMode::Shared;
    automation.max_concurrent_leases = 2;
    automation.shared_state_isolation_requirement = Some(Stateless);
    shared.controller.capacity = CapacityLimits::new(nz(2), nz(2), nz(3), nz(4));
    assert_eq!(
        refused(shared.decision(CapacityUsage::default(), ready())),
        RefusalCode::IsolationUnproven
    );
    assert!(matches!(
        shared.decision(
            CapacityUsage::default(),
            RuntimeReadiness::Ready {
                isolation: IsolationClassification::CredentialIsolated,
                shared_state_isolation: Some(Stateless),
            },
        ),
        PolicyDecision::Permitted(_)
    ));

    shared.automation_mut().shared_state_isolation_requirement = Some(PerLeaseIsolated);
    assert_eq!(
        refused(shared.decision(
            CapacityUsage::default(),
            RuntimeReadiness::Ready {
                isolation: IsolationClassification::CredentialIsolated,
                shared_state_isolation: Some(PerLeaseIsolated),
            },
        )),
        RefusalCode::IsolationUnproven
    );
    assert!(matches!(
        shared.decision(
            CapacityUsage::default(),
            RuntimeReadiness::Ready {
                isolation: IsolationClassification::PerLeaseIsolated,
                shared_state_isolation: Some(PerLeaseIsolated),
            },
        ),
        PolicyDecision::Permitted(_)
    ));
}
