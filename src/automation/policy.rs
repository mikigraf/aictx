//! Pure, controller-neutral policy intersection for identity leases.
//!
//! This module performs no I/O and grants no authority by itself. A service
//! must authenticate the caller, verify the signed work order, obtain current
//! readiness evidence, and atomically persist any returned capacity claim.

use std::{collections::BTreeSet, num::NonZeroU32};

use crate::model::{
    AutomationConcurrencyMode, AutomationRole, Config, Profile, ProfileId,
    SharedStateIsolationRequirement,
};

use super::contracts::{
    AgentRole, AttemptId, AutomationAuthMode, CallerSubject, ClientRequestId,
    ContractValidationError, DurationSeconds, EnvironmentName, HostIdentity, IdentityLeaseRequest,
    IsolationClassification, MaximumTtlSeconds, ProfileRef, ProfileUid, Provider, RefusalCode,
    RepositoryId, RunId, Sha256Digest, TenantId, UtcTimestamp, WorkOrderId, WorkspaceId,
};

const EFFECTIVE_POLICY_DOMAIN: &[u8] = b"ctxlane.effective-policy/v1\0";

/// An explicit controller allow-scope. `Any` adds no authority; it merely
/// leaves the narrower profile and signed-work-order constraints unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowScope<T> {
    Any,
    Only(Vec<T>),
}

impl<T: PartialEq> AllowScope<T> {
    #[must_use]
    pub fn permits(&self, value: &T) -> bool {
        match self {
            Self::Any => true,
            Self::Only(values) => values.contains(value),
        }
    }
}

/// Non-zero capacity ceilings for each required accounting dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityLimits {
    profile: NonZeroU32,
    provider: NonZeroU32,
    caller: NonZeroU32,
    host: NonZeroU32,
}

impl CapacityLimits {
    #[must_use]
    pub const fn new(
        profile: NonZeroU32,
        provider: NonZeroU32,
        caller: NonZeroU32,
        host: NonZeroU32,
    ) -> Self {
        Self {
            profile,
            provider,
            caller,
            host,
        }
    }

    #[must_use]
    pub const fn profile(self) -> u32 {
        self.profile.get()
    }

    #[must_use]
    pub const fn provider(self) -> u32 {
        self.provider.get()
    }

    #[must_use]
    pub const fn caller(self) -> u32 {
        self.caller.get()
    }

    #[must_use]
    pub const fn host(self) -> u32 {
        self.host.get()
    }
}

/// Counts read under the future store transaction. This type never persists
/// or synchronizes them; the store must check and claim atomically.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapacityUsage {
    pub profile: u32,
    pub provider: u32,
    pub caller: u32,
    pub host: u32,
}

/// Exact keys and limits which a future transaction must claim together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityClaim {
    pub(crate) profile_uid: ProfileUid,
    pub(crate) provider: Provider,
    pub(crate) caller_subject: CallerSubject,
    pub(crate) host_identity: HostIdentity,
    pub(crate) limits: CapacityLimits,
}

impl CapacityClaim {
    #[must_use]
    pub const fn profile_uid(&self) -> &ProfileUid {
        &self.profile_uid
    }

    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    #[must_use]
    pub const fn caller_subject(&self) -> &CallerSubject {
        &self.caller_subject
    }

    #[must_use]
    pub const fn host_identity(&self) -> &HostIdentity {
        &self.host_identity
    }

    #[must_use]
    pub const fn permits(&self, usage: CapacityUsage) -> bool {
        usage.profile < self.limits.profile()
            && usage.provider < self.limits.provider()
            && usage.caller < self.limits.caller()
            && usage.host < self.limits.host()
    }

    #[must_use]
    pub const fn limits(&self) -> CapacityLimits {
        self.limits
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyRequirements {
    workload_identity: bool,
    authentication_exception: bool,
    isolation_exception: bool,
}

/// Safe profile-owned inputs extracted from validated global metadata.
/// No path, credential reference, WIF metadata, or free-form account hint is
/// retained in this domain value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePolicy {
    profile_uid: ProfileUid,
    profile_ref: ProfileRef,
    provider: Provider,
    auth_mode: AutomationAuthMode,
    eligible: bool,
    environments: BTreeSet<EnvironmentName>,
    roles: Vec<AgentRole>,
    caller_subjects: BTreeSet<CallerSubject>,
    maximum_ttl_seconds: MaximumTtlSeconds,
    maximum_session_seconds: DurationSeconds,
    maximum_concurrent_leases: NonZeroU32,
    concurrency_mode: AutomationConcurrencyMode,
    shared_state_isolation_requirement: Option<SharedStateIsolationRequirement>,
    requirements: PolicyRequirements,
}

impl ProfilePolicy {
    /// Validate global metadata, resolve the exact profile, and retain only
    /// non-secret policy and immutable identity fields.
    pub fn from_config(
        config: &Config,
        profile_ref: &ProfileId,
    ) -> Result<Self, ContractValidationError> {
        if !config.is_authoritative() {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "projected legacy metadata cannot authorize automation",
            ));
        }
        config.validate().map_err(|_| {
            ContractValidationError::InvalidResponseInvariant(
                "global metadata must be valid before policy extraction",
            )
        })?;
        let profile = config.profiles.get(profile_ref).ok_or(
            ContractValidationError::InvalidResponseInvariant(
                "profile must exist in validated global metadata",
            ),
        )?;
        Self::from_profile(profile_ref, profile)
    }

    fn from_profile(
        profile_ref: &ProfileId,
        profile: &Profile,
    ) -> Result<Self, ContractValidationError> {
        if profile_ref.provider() != profile.provider() {
            return Err(ContractValidationError::ProviderProfileMismatch);
        }
        let automation = profile.automation();
        let auth_mode = profile_auth_mode(profile);
        automation
            .validate(profile_ref, auth_mode == AutomationAuthMode::Wif)
            .map_err(|_| {
                ContractValidationError::InvalidResponseInvariant(
                    "profile automation policy must be validated before extraction",
                )
            })?;
        let environments = automation
            .environments
            .iter()
            .map(|value| EnvironmentName::parse(value.clone()))
            .collect::<Result<_, _>>()?;
        let caller_subjects = automation
            .caller_subjects
            .iter()
            .map(|value| CallerSubject::parse(value.clone()))
            .collect::<Result<_, _>>()?;
        let maximum_concurrent_leases = NonZeroU32::new(automation.max_concurrent_leases).ok_or(
            ContractValidationError::InvalidResponseInvariant("profile capacity must be non-zero"),
        )?;
        Ok(Self {
            profile_uid: profile.profile_uid().clone(),
            profile_ref: ProfileRef::parse(profile_ref.to_string())?,
            provider: profile.provider(),
            auth_mode,
            eligible: automation.eligible,
            environments,
            roles: automation
                .roles
                .iter()
                .copied()
                .map(contract_role)
                .collect(),
            caller_subjects,
            maximum_ttl_seconds: MaximumTtlSeconds::from_seconds(u64::from(
                automation.lease_ttl_seconds,
            ))?,
            maximum_session_seconds: DurationSeconds::from_seconds(u64::from(
                automation.max_session_seconds,
            ))?,
            maximum_concurrent_leases,
            concurrency_mode: automation.concurrency_mode,
            shared_state_isolation_requirement: automation.shared_state_isolation_requirement,
            requirements: PolicyRequirements {
                workload_identity: automation.require_workload_identity,
                authentication_exception: automation.authentication_exception_acknowledged,
                isolation_exception: automation.isolation_exception_acknowledged,
            },
        })
    }
}

fn profile_auth_mode(profile: &Profile) -> AutomationAuthMode {
    match profile {
        Profile::Claude { auth, .. } => match auth {
            crate::model::ClaudeAuth::SubscriptionToken => AutomationAuthMode::SubscriptionToken,
            crate::model::ClaudeAuth::ApiKey => AutomationAuthMode::ApiKey,
            crate::model::ClaudeAuth::Wif => AutomationAuthMode::Wif,
        },
        Profile::Codex { auth, .. } => match auth {
            crate::model::CodexAuth::Wif => AutomationAuthMode::Wif,
            crate::model::CodexAuth::ChatgptOauth => AutomationAuthMode::ChatgptOauth,
            crate::model::CodexAuth::ApiKey => AutomationAuthMode::ApiKey,
            crate::model::CodexAuth::AccessToken => AutomationAuthMode::AccessToken,
        },
    }
}

const fn contract_role(role: AutomationRole) -> AgentRole {
    match role {
        AutomationRole::Implementer => AgentRole::Implementer,
        AutomationRole::LocalReviewer => AgentRole::LocalReviewer,
        AutomationRole::PrReviewer => AgentRole::PrReviewer,
    }
}

/// Operator-owned controller constraints. Every scope can only narrow the
/// exact request already authorized by the profile and signed work order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerPolicy {
    pub profile_uids: AllowScope<ProfileUid>,
    pub providers: AllowScope<Provider>,
    pub environments: AllowScope<EnvironmentName>,
    pub roles: AllowScope<AgentRole>,
    pub caller_subjects: AllowScope<CallerSubject>,
    pub repositories: AllowScope<RepositoryId>,
    pub maximum_ttl_seconds: MaximumTtlSeconds,
    pub maximum_session_seconds: DurationSeconds,
    pub capacity: CapacityLimits,
    pub allow_authentication_exception: bool,
    pub allow_isolation_exception: bool,
}

/// Signature-verification result supplied by the future trusted service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationProof {
    Verified,
    Invalid,
}

/// Stable readiness failures that can become durable acquisition refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessDenial {
    ProfileNotReady,
    IdentityTokenStale,
    HarnessUntrusted,
    PrincipalUnverified,
    PrincipalMismatch,
    OrganizationMismatch,
    WorkspaceMismatch,
    IsolationUnproven,
}

impl ReadinessDenial {
    #[must_use]
    pub const fn refusal_code(self) -> RefusalCode {
        match self {
            Self::ProfileNotReady => RefusalCode::ProfileNotReady,
            Self::IdentityTokenStale => RefusalCode::IdentityTokenStale,
            Self::HarnessUntrusted => RefusalCode::HarnessUntrusted,
            Self::PrincipalUnverified => RefusalCode::PrincipalUnverified,
            Self::PrincipalMismatch => RefusalCode::PrincipalMismatch,
            Self::OrganizationMismatch => RefusalCode::OrganizationMismatch,
            Self::WorkspaceMismatch => RefusalCode::WorkspaceMismatch,
            Self::IsolationUnproven => RefusalCode::IsolationUnproven,
        }
    }
}

/// Current runtime proof, separate from persisted profile intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeReadiness {
    Ready {
        isolation: IsolationClassification,
        shared_state_isolation: Option<SharedStateIsolationRequirement>,
    },
    Denied(ReadinessDenial),
}

/// All pure inputs needed for one acquisition decision.
pub struct PolicyEvaluation<'a> {
    pub request: &'a IdentityLeaseRequest,
    pub profile: &'a ProfilePolicy,
    pub controller: &'a ControllerPolicy,
    pub caller_subject: &'a CallerSubject,
    pub host_identity: &'a HostIdentity,
    pub authorization_proof: AuthorizationProof,
    pub readiness: RuntimeReadiness,
    pub capacity_usage: CapacityUsage,
    pub now: &'a UtcTimestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Permitted(Box<EffectivePolicy>),
    Refused(RefusalCode),
}

/// Exact, narrowed authority. Its digest covers every field in this value and
/// is independent of map ordering, controller product, active context, or
/// directory binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectivePolicy {
    // Replay/binding evidence, deliberately excluded from `digest` because the
    // request itself may carry an effective-policy equality expectation.
    pub(crate) source_request_digest: Sha256Digest,
    pub(crate) client_request_id: ClientRequestId,
    pub(crate) tenant_id: TenantId,
    pub(crate) work_order_id: WorkOrderId,
    pub(crate) work_order_digest: Sha256Digest,
    pub(crate) run_id: RunId,
    pub(crate) attempt_id: AttemptId,
    pub(crate) role: AgentRole,
    pub(crate) provider: Provider,
    pub(crate) profile_uid: ProfileUid,
    pub(crate) profile_ref: ProfileRef,
    pub(crate) repository: RepositoryId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) environment: EnvironmentName,
    pub(crate) caller_subject: CallerSubject,
    pub(crate) host_identity: HostIdentity,
    pub(crate) auth_mode: AutomationAuthMode,
    pub(crate) isolation: IsolationClassification,
    pub(crate) shared_state_isolation: Option<SharedStateIsolationRequirement>,
    pub(crate) requested_ttl_seconds: u64,
    pub(crate) maximum_ttl_seconds: u64,
    pub(crate) maximum_session_seconds: u64,
    pub(crate) signed_expires_at: UtcTimestamp,
    pub(crate) concurrency_mode: AutomationConcurrencyMode,
    requirements: PolicyRequirements,
    pub(crate) capacity_claim: CapacityClaim,
}

impl EffectivePolicy {
    #[must_use]
    pub const fn capacity_claim(&self) -> &CapacityClaim {
        &self.capacity_claim
    }

    #[must_use]
    pub const fn maximum_ttl_seconds(&self) -> u64 {
        self.maximum_ttl_seconds
    }

    #[must_use]
    pub const fn maximum_session_seconds(&self) -> u64 {
        self.maximum_session_seconds
    }

    /// Derive a renewal policy from already evaluated authority. The renewal
    /// interval may use, but never exceed, the effective TTL/session ceilings.
    /// Callers must start from a fresh evaluation; this method does not establish
    /// profile, controller, proof, or readiness freshness.
    pub fn for_renewal_ttl(
        &self,
        requested_ttl: super::contracts::RequestedTtlSeconds,
    ) -> Result<Self, RefusalCode> {
        if requested_ttl.get() > self.maximum_ttl_seconds
            || requested_ttl.get() > self.maximum_session_seconds
        {
            return Err(RefusalCode::RequestedTtlNotAllowed);
        }
        let mut renewed = self.clone();
        renewed.requested_ttl_seconds = requested_ttl.get();
        Ok(renewed)
    }

    /// Versioned, domain-separated digest over every effective field.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        let mut encoded = EFFECTIVE_POLICY_DOMAIN.to_vec();
        macro_rules! text_field {
            ($name:literal, $value:expr) => {
                append_field(&mut encoded, $name, ($value).as_bytes());
            };
        }
        text_field!("client_request_id", self.client_request_id.as_str());
        text_field!("tenant_id", self.tenant_id.as_str());
        text_field!("work_order_id", self.work_order_id.as_str());
        text_field!("work_order_digest", &self.work_order_digest.to_string());
        text_field!("run_id", self.run_id.as_str());
        text_field!("attempt_id", self.attempt_id.as_str());
        text_field!("role", role_label(self.role));
        text_field!("provider", &self.provider.to_string());
        text_field!("profile_uid", self.profile_uid.as_str());
        text_field!("profile_ref", self.profile_ref.as_str());
        text_field!("repository", self.repository.as_str());
        text_field!("workspace_id", self.workspace_id.as_str());
        text_field!("environment", self.environment.as_str());
        text_field!("caller_subject", self.caller_subject.as_str());
        text_field!("host_identity", self.host_identity.as_str());
        text_field!("auth_mode", auth_label(self.auth_mode));
        text_field!("isolation", isolation_label(self.isolation));
        text_field!(
            "shared_state_isolation",
            shared_isolation_label(self.shared_state_isolation)
        );
        number_field(
            &mut encoded,
            "requested_ttl_seconds",
            self.requested_ttl_seconds,
        );
        number_field(
            &mut encoded,
            "maximum_ttl_seconds",
            self.maximum_ttl_seconds,
        );
        number_field(
            &mut encoded,
            "maximum_session_seconds",
            self.maximum_session_seconds,
        );
        text_field!("signed_expires_at", self.signed_expires_at.as_str());
        text_field!("concurrency_mode", concurrency_label(self.concurrency_mode));
        bool_field(
            &mut encoded,
            "require_workload_identity",
            self.requirements.workload_identity,
        );
        bool_field(
            &mut encoded,
            "authentication_exception_acknowledged",
            self.requirements.authentication_exception,
        );
        bool_field(
            &mut encoded,
            "isolation_exception_acknowledged",
            self.requirements.isolation_exception,
        );
        text_field!(
            "capacity_profile_uid",
            self.capacity_claim.profile_uid.as_str()
        );
        text_field!(
            "capacity_provider_key",
            &self.capacity_claim.provider.to_string()
        );
        text_field!(
            "capacity_caller_subject",
            self.capacity_claim.caller_subject.as_str()
        );
        text_field!(
            "capacity_host_identity",
            self.capacity_claim.host_identity.as_str()
        );
        number_field(
            &mut encoded,
            "capacity_profile_limit",
            u64::from(self.capacity_claim.limits.profile()),
        );
        number_field(
            &mut encoded,
            "capacity_provider_limit",
            u64::from(self.capacity_claim.limits.provider()),
        );
        number_field(
            &mut encoded,
            "capacity_caller_limit",
            u64::from(self.capacity_claim.limits.caller()),
        );
        number_field(
            &mut encoded,
            "capacity_host_limit",
            u64::from(self.capacity_claim.limits.host()),
        );
        Sha256Digest::hash(encoded)
    }
}

/// Intersect profile, signed request, authenticated-controller, readiness, and
/// capacity constraints. All denials are durable lease refusal codes.
#[must_use]
pub fn evaluate_policy(input: &PolicyEvaluation<'_>) -> PolicyDecision {
    let refuse = |code| PolicyDecision::Refused(code);
    if input.authorization_proof == AuthorizationProof::Invalid {
        return refuse(RefusalCode::WorkOrderProofInvalid);
    }
    if let Err(error) = input.request.validate_authorization(input.now) {
        return refuse(refusal_for_contract_error(&error));
    }
    let Ok(source_request_digest) = input.request.authority_digest() else {
        return refuse(RefusalCode::WorkOrderProofInvalid);
    };
    let request = input.request;
    let profile = input.profile;
    if request.provider != profile.provider
        || request.profile_ref.provider() != profile.provider
        || !input.controller.providers.permits(&request.provider)
    {
        return refuse(RefusalCode::ProviderMismatch);
    }
    if request.profile_uid != profile.profile_uid || request.profile_ref != profile.profile_ref {
        return refuse(RefusalCode::ProfileNotFound);
    }
    if !profile.eligible || !input.controller.profile_uids.permits(&profile.profile_uid) {
        return refuse(RefusalCode::ProfileNotEligible);
    }
    if !profile.environments.contains(&request.environment)
        || !input.controller.environments.permits(&request.environment)
    {
        return refuse(RefusalCode::EnvironmentNotAllowed);
    }
    if !profile.roles.contains(&request.role) || !input.controller.roles.permits(&request.role) {
        return refuse(RefusalCode::RoleNotAllowed);
    }
    if !profile.caller_subjects.contains(input.caller_subject)
        || !input
            .controller
            .caller_subjects
            .permits(input.caller_subject)
    {
        return refuse(RefusalCode::CallerNotAllowed);
    }
    if !input.controller.repositories.permits(&request.repository) {
        return refuse(RefusalCode::RepositoryNotAllowed);
    }
    let non_wif = profile.auth_mode != AutomationAuthMode::Wif;
    let non_local = request.environment.as_str() != "local-development";
    if non_wif
        && (profile.requirements.workload_identity || non_local)
        && (!profile.requirements.authentication_exception
            || !input.controller.allow_authentication_exception)
    {
        return refuse(RefusalCode::AuthenticationExceptionRequired);
    }
    let (isolation, shared_state_isolation) = match input.readiness {
        RuntimeReadiness::Denied(denial) => return refuse(denial.refusal_code()),
        RuntimeReadiness::Ready {
            isolation,
            shared_state_isolation,
        } => (isolation, shared_state_isolation),
    };
    if isolation == IsolationClassification::Unproven {
        return refuse(RefusalCode::IsolationUnproven);
    }
    if isolation == IsolationClassification::CopiedCredentialDevelopment {
        if non_local && request.role != AgentRole::PrReviewer {
            return refuse(RefusalCode::IsolationUnproven);
        }
        if !profile.requirements.isolation_exception || !input.controller.allow_isolation_exception
        {
            return refuse(RefusalCode::IsolationExceptionRequired);
        }
    }
    match profile.concurrency_mode {
        AutomationConcurrencyMode::Exclusive if shared_state_isolation.is_some() => {
            return refuse(RefusalCode::IsolationUnproven);
        }
        AutomationConcurrencyMode::Shared => {
            if shared_state_isolation != profile.shared_state_isolation_requirement
                || (shared_state_isolation
                    == Some(SharedStateIsolationRequirement::PerLeaseIsolated)
                    && isolation != IsolationClassification::PerLeaseIsolated)
            {
                return refuse(RefusalCode::IsolationUnproven);
            }
        }
        AutomationConcurrencyMode::Exclusive => {}
    }

    let maximum_ttl_seconds = request
        .work_order_authorization
        .maximum_ttl_seconds
        .get()
        .min(profile.maximum_ttl_seconds.get())
        .min(input.controller.maximum_ttl_seconds.get());
    let maximum_session_seconds = request
        .work_order_authorization
        .maximum_session_seconds
        .get()
        .min(profile.maximum_session_seconds.get())
        .min(input.controller.maximum_session_seconds.get());
    if request.requested_ttl_seconds.get() > maximum_ttl_seconds
        || request.requested_ttl_seconds.get() > maximum_session_seconds
    {
        return refuse(RefusalCode::RequestedTtlNotAllowed);
    }
    let profile_limit = profile
        .maximum_concurrent_leases
        .get()
        .min(input.controller.capacity.profile());
    let limits = CapacityLimits::new(
        NonZeroU32::new(profile_limit).unwrap_or(NonZeroU32::MIN),
        input.controller.capacity.provider,
        input.controller.capacity.caller,
        input.controller.capacity.host,
    );
    let capacity_claim = CapacityClaim {
        profile_uid: profile.profile_uid.clone(),
        provider: profile.provider,
        caller_subject: input.caller_subject.clone(),
        host_identity: input.host_identity.clone(),
        limits,
    };
    let effective = EffectivePolicy {
        source_request_digest,
        client_request_id: request.client_request_id.clone(),
        tenant_id: request.tenant_id.clone(),
        work_order_id: request.work_order_id.clone(),
        work_order_digest: request.work_order_digest,
        run_id: request.run_id.clone(),
        attempt_id: request.attempt_id.clone(),
        role: request.role,
        provider: request.provider,
        profile_uid: request.profile_uid.clone(),
        profile_ref: request.profile_ref.clone(),
        repository: request.repository.clone(),
        workspace_id: request.workspace_id.clone(),
        environment: request.environment.clone(),
        caller_subject: input.caller_subject.clone(),
        host_identity: input.host_identity.clone(),
        auth_mode: profile.auth_mode,
        isolation,
        shared_state_isolation,
        requested_ttl_seconds: request.requested_ttl_seconds.get(),
        maximum_ttl_seconds,
        maximum_session_seconds,
        signed_expires_at: request.work_order_authorization.expires_at.clone(),
        concurrency_mode: profile.concurrency_mode,
        requirements: profile.requirements,
        capacity_claim,
    };
    if request
        .policy_digest
        .is_some_and(|expected| expected != effective.digest())
    {
        return refuse(RefusalCode::PolicyDigestMismatch);
    }
    if !effective.capacity_claim.permits(input.capacity_usage) {
        return refuse(RefusalCode::CapacityExceeded);
    }
    PolicyDecision::Permitted(Box::new(effective))
}

/// Stable mapping for semantic failures after strict request decoding.
#[must_use]
pub const fn refusal_for_contract_error(error: &ContractValidationError) -> RefusalCode {
    match error {
        ContractValidationError::WorkOrderAuthorizationMismatch { .. } => {
            RefusalCode::WorkOrderAuthorizationMismatch
        }
        ContractValidationError::RequestedTtlExceedsAuthorization
        | ContractValidationError::RequestedTtlExceedsAuthorizationValidity
        | ContractValidationError::InvalidRequestedTtl => RefusalCode::RequestedTtlNotAllowed,
        ContractValidationError::ProviderProfileMismatch => RefusalCode::ProviderMismatch,
        _ => RefusalCode::WorkOrderProofInvalid,
    }
}

fn append_field(output: &mut Vec<u8>, name: &str, value: &[u8]) {
    output.extend_from_slice(&u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(value);
}

fn number_field(output: &mut Vec<u8>, name: &str, value: u64) {
    append_field(output, name, &value.to_be_bytes());
}

fn bool_field(output: &mut Vec<u8>, name: &str, value: bool) {
    append_field(output, name, &[u8::from(value)]);
}

const fn role_label(value: AgentRole) -> &'static str {
    match value {
        AgentRole::Implementer => "implementer",
        AgentRole::LocalReviewer => "local-reviewer",
        AgentRole::PrReviewer => "pr-reviewer",
    }
}

const fn auth_label(value: AutomationAuthMode) -> &'static str {
    match value {
        AutomationAuthMode::Wif => "wif",
        AutomationAuthMode::SubscriptionToken => "subscription-token",
        AutomationAuthMode::ApiKey => "api-key",
        AutomationAuthMode::ChatgptOauth => "chatgpt-oauth",
        AutomationAuthMode::AccessToken => "access-token",
    }
}

const fn isolation_label(value: IsolationClassification) -> &'static str {
    match value {
        IsolationClassification::CredentialIsolated => "credential-isolated",
        IsolationClassification::PerLeaseIsolated => "per-lease-isolated",
        IsolationClassification::CopiedCredentialDevelopment => "copied-credential-development",
        IsolationClassification::Unproven => "unproven",
    }
}

const fn shared_isolation_label(value: Option<SharedStateIsolationRequirement>) -> &'static str {
    match value {
        None => "none",
        Some(SharedStateIsolationRequirement::Stateless) => "stateless",
        Some(SharedStateIsolationRequirement::PerLeaseIsolated) => "per-lease-isolated",
    }
}

const fn concurrency_label(value: AutomationConcurrencyMode) -> &'static str {
    match value {
        AutomationConcurrencyMode::Exclusive => "exclusive",
        AutomationConcurrencyMode::Shared => "shared",
    }
}

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;
