use serde::{Deserialize, Serialize};

use super::{
    integer::deserialize_bounded_u64,
    temporal::UtcTimestamp,
    types::{
        AgentRole, AutomationAuthMode, ContractValidationError, EnvironmentName,
        IsolationClassification, ProbeCost, ProfileRef, ProfileUid, Provider, ReadinessSchema,
        ReadinessStatus,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessReasonCode {
    NotApplicable,
    MetadataInvalid,
    CredentialSourceUnavailable,
    IdentityTokenStale,
    HarnessUntrusted,
    PrincipalUnverified,
    PrincipalMismatch,
    ExpectedTenantUnverified,
    OrganizationMismatch,
    WorkspaceMismatch,
    AutomationPolicyDenied,
    AuthenticationExceptionRequired,
    AuthenticationExceptionAcknowledged,
    IsolationExceptionRequired,
    IsolationExceptionAcknowledged,
    IsolationUnproven,
    ProbeNotRun,
    ProbeFailed,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProbeTimeoutMilliseconds(u32);

impl ProbeTimeoutMilliseconds {
    pub fn from_value(value: u32) -> Result<Self, ContractValidationError> {
        if (1..=30_000).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ContractValidationError::InvalidResponseInvariant(
                "probe timeout must be between 1 and 30000 milliseconds",
            ))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Serialize for ProbeTimeoutMilliseconds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.get())
    }
}

impl<'de> Deserialize<'de> for ProbeTimeoutMilliseconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = deserialize_bounded_u64(deserializer, 1, 30_000)?;
        let value = u32::try_from(value).map_err(serde::de::Error::custom)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize, Serialize)]
struct RequiredNullable<T>(Option<T>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessCheck {
    pub status: ReadinessStatus,
    pub reason_code: Option<ReadinessReasonCode>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessCheckWire {
    status: ReadinessStatus,
    reason_code: RequiredNullable<ReadinessReasonCode>,
}

impl ReadinessCheck {
    fn validate(&self) -> Result<(), ContractValidationError> {
        let valid = match self.status {
            ReadinessStatus::Pass => self.reason_code.is_none(),
            ReadinessStatus::NotApplicable => {
                self.reason_code == Some(ReadinessReasonCode::NotApplicable)
            }
            ReadinessStatus::Warn | ReadinessStatus::Fail | ReadinessStatus::Unknown => {
                self.reason_code.is_some()
                    && self.reason_code != Some(ReadinessReasonCode::NotApplicable)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(ContractValidationError::InvalidResponseInvariant(
                "readiness status and reason_code are inconsistent",
            ))
        }
    }
}

impl Serialize for ReadinessCheck {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        ReadinessCheckWire {
            status: self.status,
            reason_code: RequiredNullable(self.reason_code),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReadinessCheck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ReadinessCheckWire::deserialize(deserializer)?;
        let check = Self {
            status: wire.status,
            reason_code: wire.reason_code.0,
        };
        check.validate().map_err(serde::de::Error::custom)?;
        Ok(check)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessChecks {
    #[serde(rename = "metadata-valid")]
    pub metadata_valid: ReadinessCheck,
    #[serde(rename = "credential-source-available")]
    pub credential_source_available: ReadinessCheck,
    #[serde(rename = "identity-token-current")]
    pub identity_token_current: ReadinessCheck,
    #[serde(rename = "harness-trusted")]
    pub harness_trusted: ReadinessCheck,
    #[serde(rename = "provider-principal-verified")]
    pub provider_principal_verified: ReadinessCheck,
    #[serde(rename = "expected-tenant-verified")]
    pub expected_tenant_verified: ReadinessCheck,
    #[serde(rename = "automation-policy-permits")]
    pub automation_policy_permits: ReadinessCheck,
    #[serde(rename = "credential-isolation-proven")]
    pub credential_isolation_proven: ReadinessCheck,
}

impl ReadinessChecks {
    fn validate(&self) -> Result<(), ContractValidationError> {
        validate_check(
            &self.metadata_valid,
            &[
                (ReadinessStatus::Pass, None),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::MetadataInvalid),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::UnsupportedPlatform),
                ),
            ],
        )?;
        validate_check(
            &self.credential_source_available,
            &[
                (ReadinessStatus::Pass, None),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::CredentialSourceUnavailable),
                ),
            ],
        )?;
        validate_check(
            &self.identity_token_current,
            &[
                (ReadinessStatus::Pass, None),
                (
                    ReadinessStatus::NotApplicable,
                    Some(ReadinessReasonCode::NotApplicable),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::IdentityTokenStale),
                ),
            ],
        )?;
        validate_check(
            &self.harness_trusted,
            &[
                (ReadinessStatus::Pass, None),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::HarnessUntrusted),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::UnsupportedPlatform),
                ),
            ],
        )?;
        validate_check(
            &self.provider_principal_verified,
            &[
                (ReadinessStatus::Pass, None),
                (
                    ReadinessStatus::Unknown,
                    Some(ReadinessReasonCode::PrincipalUnverified),
                ),
                (
                    ReadinessStatus::Unknown,
                    Some(ReadinessReasonCode::ProbeNotRun),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::PrincipalMismatch),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::ProbeFailed),
                ),
            ],
        )?;
        validate_check(
            &self.expected_tenant_verified,
            &[
                (ReadinessStatus::Pass, None),
                (
                    ReadinessStatus::Unknown,
                    Some(ReadinessReasonCode::ExpectedTenantUnverified),
                ),
                (
                    ReadinessStatus::Unknown,
                    Some(ReadinessReasonCode::ProbeNotRun),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::OrganizationMismatch),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::WorkspaceMismatch),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::ProbeFailed),
                ),
            ],
        )?;
        validate_check(
            &self.automation_policy_permits,
            &[
                (ReadinessStatus::Pass, None),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::AutomationPolicyDenied),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::AuthenticationExceptionRequired),
                ),
                (
                    ReadinessStatus::Warn,
                    Some(ReadinessReasonCode::AuthenticationExceptionAcknowledged),
                ),
            ],
        )?;
        validate_check(
            &self.credential_isolation_proven,
            &[
                (ReadinessStatus::Pass, None),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::IsolationUnproven),
                ),
                (
                    ReadinessStatus::Fail,
                    Some(ReadinessReasonCode::IsolationExceptionRequired),
                ),
                (
                    ReadinessStatus::Warn,
                    Some(ReadinessReasonCode::IsolationExceptionAcknowledged),
                ),
            ],
        )
    }

    fn static_core_passes(&self) -> bool {
        [
            &self.metadata_valid,
            &self.credential_source_available,
            &self.harness_trusted,
            &self.provider_principal_verified,
            &self.expected_tenant_verified,
        ]
        .into_iter()
        .all(|check| check.status == ReadinessStatus::Pass)
    }
}

fn validate_check(
    check: &ReadinessCheck,
    allowed: &[(ReadinessStatus, Option<ReadinessReasonCode>)],
) -> Result<(), ContractValidationError> {
    check.validate()?;
    if !allowed.contains(&(check.status, check.reason_code)) {
        return Err(ContractValidationError::InvalidResponseInvariant(
            "readiness status and reason_code are not valid for this check",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)] // Closed wire contract has independent evidence flags.
pub struct AutomationReadiness {
    pub schema: ReadinessSchema,
    pub profile_uid: ProfileUid,
    pub profile_ref: ProfileRef,
    pub provider: Provider,
    pub environment: EnvironmentName,
    pub role: AgentRole,
    pub auth_mode: AutomationAuthMode,
    pub ready: bool,
    pub isolation: IsolationClassification,
    pub authentication_exception_acknowledged: bool,
    pub isolation_exception_acknowledged: bool,
    pub probe_cost: ProbeCost,
    pub probe_timeout_milliseconds: ProbeTimeoutMilliseconds,
    pub probe_interactive: bool,
    pub checked_at: UtcTimestamp,
    pub valid_until: UtcTimestamp,
    pub checks: ReadinessChecks,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Mirrors the closed public contract exactly.
struct ReadinessWire {
    schema: ReadinessSchema,
    profile_uid: ProfileUid,
    profile_ref: ProfileRef,
    provider: Provider,
    environment: EnvironmentName,
    role: AgentRole,
    auth_mode: AutomationAuthMode,
    ready: bool,
    isolation: IsolationClassification,
    authentication_exception_acknowledged: bool,
    isolation_exception_acknowledged: bool,
    probe_cost: ProbeCost,
    probe_timeout_milliseconds: ProbeTimeoutMilliseconds,
    probe_interactive: bool,
    checked_at: UtcTimestamp,
    valid_until: UtcTimestamp,
    checks: ReadinessChecks,
}

impl AutomationReadiness {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.provider != self.profile_ref.provider()
            || !self.auth_mode.supports_provider(self.provider)
        {
            return Err(ContractValidationError::ProviderProfileMismatch);
        }
        if self.probe_interactive {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "automation readiness probes must be non-interactive",
            ));
        }
        if !self.checked_at.is_before(&self.valid_until) {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "checked_at must be earlier than valid_until",
            ));
        }
        self.checks.validate()?;
        self.validate_provider_attribution()?;
        self.validate_authentication_state()?;
        self.validate_isolation_state()?;
        self.validate_copied_credential_scope()?;
        let eligible = self.checks.static_core_passes()
            && self.authentication_ready()
            && self.isolation_ready();
        if self.ready != eligible {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "ready does not match the readiness evidence",
            ));
        }
        Ok(())
    }

    fn validate_provider_attribution(&self) -> Result<(), ContractValidationError> {
        match self.checks.expected_tenant_verified.reason_code {
            Some(ReadinessReasonCode::OrganizationMismatch)
                if self.provider != Provider::Claude =>
            {
                Err(ContractValidationError::InvalidResponseInvariant(
                    "organization-mismatch is only valid for Claude",
                ))
            }
            Some(ReadinessReasonCode::WorkspaceMismatch) if self.provider != Provider::Codex => {
                Err(ContractValidationError::InvalidResponseInvariant(
                    "workspace-mismatch is only valid for Codex",
                ))
            }
            _ => Ok(()),
        }
    }

    fn validate_authentication_state(&self) -> Result<(), ContractValidationError> {
        let token = &self.checks.identity_token_current;
        let policy = &self.checks.automation_policy_permits;
        let token_passes = check_is(token, ReadinessStatus::Pass, None);
        let token_is_stale = check_is(
            token,
            ReadinessStatus::Fail,
            Some(ReadinessReasonCode::IdentityTokenStale),
        );
        let token_is_not_applicable = check_is(
            token,
            ReadinessStatus::NotApplicable,
            Some(ReadinessReasonCode::NotApplicable),
        );
        let policy_passes = check_is(policy, ReadinessStatus::Pass, None);
        let policy_denied = check_is(
            policy,
            ReadinessStatus::Fail,
            Some(ReadinessReasonCode::AutomationPolicyDenied),
        );
        let exception_required = check_is(
            policy,
            ReadinessStatus::Fail,
            Some(ReadinessReasonCode::AuthenticationExceptionRequired),
        );
        let exception_acknowledged = check_is(
            policy,
            ReadinessStatus::Warn,
            Some(ReadinessReasonCode::AuthenticationExceptionAcknowledged),
        );

        let valid = if self.auth_mode == AutomationAuthMode::Wif {
            !self.authentication_exception_acknowledged
                && (token_passes || token_is_stale)
                && (policy_passes || policy_denied)
        } else if self.environment.as_str() == "local-development" {
            !self.authentication_exception_acknowledged
                && token_is_not_applicable
                && (policy_passes || policy_denied)
        } else if self.authentication_exception_acknowledged {
            token_is_not_applicable && (exception_acknowledged || policy_denied)
        } else {
            token_is_not_applicable && (exception_required || policy_denied)
        };

        if valid {
            Ok(())
        } else {
            Err(ContractValidationError::InvalidResponseInvariant(
                "authentication readiness evidence is inconsistent with auth mode, environment, or exception acknowledgement",
            ))
        }
    }

    fn validate_isolation_state(&self) -> Result<(), ContractValidationError> {
        let check = &self.checks.credential_isolation_proven;
        let valid = match self.isolation {
            IsolationClassification::CredentialIsolated
            | IsolationClassification::PerLeaseIsolated => {
                !self.isolation_exception_acknowledged
                    && check_is(check, ReadinessStatus::Pass, None)
            }
            IsolationClassification::CopiedCredentialDevelopment => {
                if self.isolation_exception_acknowledged {
                    check_is(
                        check,
                        ReadinessStatus::Warn,
                        Some(ReadinessReasonCode::IsolationExceptionAcknowledged),
                    )
                } else {
                    check_is(
                        check,
                        ReadinessStatus::Fail,
                        Some(ReadinessReasonCode::IsolationExceptionRequired),
                    )
                }
            }
            IsolationClassification::Unproven => {
                !self.isolation_exception_acknowledged
                    && check_is(
                        check,
                        ReadinessStatus::Fail,
                        Some(ReadinessReasonCode::IsolationUnproven),
                    )
            }
        };

        if valid {
            Ok(())
        } else {
            Err(ContractValidationError::InvalidResponseInvariant(
                "isolation readiness evidence is inconsistent with isolation classification or exception acknowledgement",
            ))
        }
    }

    fn validate_copied_credential_scope(&self) -> Result<(), ContractValidationError> {
        let copied_is_allowed =
            self.environment.as_str() == "local-development" || self.role == AgentRole::PrReviewer;
        if self.isolation == IsolationClassification::CopiedCredentialDevelopment
            && !copied_is_allowed
            && !check_is(
                &self.checks.automation_policy_permits,
                ReadinessStatus::Fail,
                Some(ReadinessReasonCode::AutomationPolicyDenied),
            )
        {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "copied credentials outside local development or PR review must be denied by policy",
            ));
        }
        Ok(())
    }

    fn authentication_ready(&self) -> bool {
        if self.auth_mode == AutomationAuthMode::Wif {
            !self.authentication_exception_acknowledged
                && check_is(
                    &self.checks.identity_token_current,
                    ReadinessStatus::Pass,
                    None,
                )
                && check_is(
                    &self.checks.automation_policy_permits,
                    ReadinessStatus::Pass,
                    None,
                )
        } else if self.environment.as_str() == "local-development" {
            !self.authentication_exception_acknowledged
                && check_is(
                    &self.checks.identity_token_current,
                    ReadinessStatus::NotApplicable,
                    Some(ReadinessReasonCode::NotApplicable),
                )
                && check_is(
                    &self.checks.automation_policy_permits,
                    ReadinessStatus::Pass,
                    None,
                )
        } else {
            self.authentication_exception_acknowledged
                && check_is(
                    &self.checks.identity_token_current,
                    ReadinessStatus::NotApplicable,
                    Some(ReadinessReasonCode::NotApplicable),
                )
                && check_is(
                    &self.checks.automation_policy_permits,
                    ReadinessStatus::Warn,
                    Some(ReadinessReasonCode::AuthenticationExceptionAcknowledged),
                )
        }
    }

    fn isolation_ready(&self) -> bool {
        let check = &self.checks.credential_isolation_proven;
        match self.isolation {
            IsolationClassification::CredentialIsolated
            | IsolationClassification::PerLeaseIsolated => {
                !self.isolation_exception_acknowledged
                    && check.status == ReadinessStatus::Pass
                    && check.reason_code.is_none()
            }
            IsolationClassification::CopiedCredentialDevelopment => {
                self.isolation_exception_acknowledged
                    && check.status == ReadinessStatus::Warn
                    && check.reason_code
                        == Some(ReadinessReasonCode::IsolationExceptionAcknowledged)
                    && (self.environment.as_str() == "local-development"
                        || self.role == AgentRole::PrReviewer)
            }
            IsolationClassification::Unproven => false,
        }
    }

    fn wire(&self) -> ReadinessWire {
        ReadinessWire {
            schema: self.schema,
            profile_uid: self.profile_uid.clone(),
            profile_ref: self.profile_ref.clone(),
            provider: self.provider,
            environment: self.environment.clone(),
            role: self.role,
            auth_mode: self.auth_mode,
            ready: self.ready,
            isolation: self.isolation,
            authentication_exception_acknowledged: self.authentication_exception_acknowledged,
            isolation_exception_acknowledged: self.isolation_exception_acknowledged,
            probe_cost: self.probe_cost,
            probe_timeout_milliseconds: self.probe_timeout_milliseconds,
            probe_interactive: self.probe_interactive,
            checked_at: self.checked_at.clone(),
            valid_until: self.valid_until.clone(),
            checks: self.checks.clone(),
        }
    }
}

fn check_is(
    check: &ReadinessCheck,
    status: ReadinessStatus,
    reason_code: Option<ReadinessReasonCode>,
) -> bool {
    check.status == status && check.reason_code == reason_code
}

impl TryFrom<ReadinessWire> for AutomationReadiness {
    type Error = ContractValidationError;

    fn try_from(value: ReadinessWire) -> Result<Self, Self::Error> {
        let readiness = Self {
            schema: value.schema,
            profile_uid: value.profile_uid,
            profile_ref: value.profile_ref,
            provider: value.provider,
            environment: value.environment,
            role: value.role,
            auth_mode: value.auth_mode,
            ready: value.ready,
            isolation: value.isolation,
            authentication_exception_acknowledged: value.authentication_exception_acknowledged,
            isolation_exception_acknowledged: value.isolation_exception_acknowledged,
            probe_cost: value.probe_cost,
            probe_timeout_milliseconds: value.probe_timeout_milliseconds,
            probe_interactive: value.probe_interactive,
            checked_at: value.checked_at,
            valid_until: value.valid_until,
            checks: value.checks,
        };
        readiness.validate()?;
        Ok(readiness)
    }
}

impl Serialize for AutomationReadiness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        self.wire().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AutomationReadiness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ReadinessWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}
