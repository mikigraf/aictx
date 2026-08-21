use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

use super::{ProfileId, ProfileUid, Provider};

const MAX_TTL_SECONDS: u32 = 86_400;
const MAX_SESSION_SECONDS: u32 = 604_800;
const MAX_CONCURRENT_LEASES: u32 = 64;
const MAX_ENVIRONMENTS: usize = 32;
const MAX_CALLER_SUBJECTS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutomationRole {
    Implementer,
    LocalReviewer,
    PrReviewer,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutomationConcurrencyMode {
    #[default]
    Exclusive,
    Shared,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SharedStateIsolationRequirement {
    Stateless,
    PerLeaseIsolated,
}

/// Operator-owned limits for unattended use of one profile.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationPolicy {
    pub eligible: bool,
    pub environments: BTreeSet<String>,
    pub roles: BTreeSet<AutomationRole>,
    pub caller_subjects: BTreeSet<String>,
    pub lease_ttl_seconds: u32,
    pub max_session_seconds: u32,
    pub max_concurrent_leases: u32,
    pub concurrency_mode: AutomationConcurrencyMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Required runtime isolation shape. This is policy, never proof that isolation exists.
    pub shared_state_isolation_requirement: Option<SharedStateIsolationRequirement>,
    pub require_workload_identity: bool,
    pub authentication_exception_acknowledged: bool,
    pub isolation_exception_acknowledged: bool,
}

/// Secret-free profile metadata safe for future automation control surfaces.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationProfileView {
    pub profile_uid: ProfileUid,
    pub profile_ref: ProfileId,
    pub provider: Provider,
    pub auth_mode: String,
    pub eligible: bool,
    pub environment_count: usize,
    pub roles: BTreeSet<AutomationRole>,
    pub caller_subject_count: usize,
    pub lease_ttl_seconds: u32,
    pub max_session_seconds: u32,
    pub max_concurrent_leases: u32,
    pub concurrency_mode: AutomationConcurrencyMode,
    pub shared_state_isolation_requirement: Option<SharedStateIsolationRequirement>,
    pub require_workload_identity: bool,
    pub authentication_exception_acknowledged: bool,
    pub isolation_exception_acknowledged: bool,
}

impl Default for AutomationPolicy {
    fn default() -> Self {
        Self {
            eligible: false,
            environments: BTreeSet::new(),
            roles: BTreeSet::new(),
            caller_subjects: BTreeSet::new(),
            lease_ttl_seconds: 900,
            max_session_seconds: 14_400,
            max_concurrent_leases: 1,
            concurrency_mode: AutomationConcurrencyMode::Exclusive,
            shared_state_isolation_requirement: None,
            require_workload_identity: true,
            authentication_exception_acknowledged: false,
            isolation_exception_acknowledged: false,
        }
    }
}

impl AutomationPolicy {
    pub(crate) fn validate(&self, id: &ProfileId, is_wif: bool) -> Result<()> {
        if !(1..=MAX_TTL_SECONDS).contains(&self.lease_ttl_seconds) {
            return Err(invalid(id, "lease_ttl_seconds must be between 1 and 86400"));
        }
        if self.max_session_seconds < self.lease_ttl_seconds
            || self.max_session_seconds > MAX_SESSION_SECONDS
        {
            return Err(invalid(
                id,
                "max_session_seconds must be at least lease_ttl_seconds and at most 604800",
            ));
        }
        if !(1..=MAX_CONCURRENT_LEASES).contains(&self.max_concurrent_leases) {
            return Err(invalid(
                id,
                "max_concurrent_leases must be between 1 and 64",
            ));
        }
        if self.environments.len() > MAX_ENVIRONMENTS {
            return Err(invalid(id, "environments may contain at most 32 entries"));
        }
        if self.caller_subjects.len() > MAX_CALLER_SUBJECTS {
            return Err(invalid(
                id,
                "caller_subjects may contain at most 64 entries",
            ));
        }
        for value in &self.environments {
            validate_label(id, "environment", value)?;
        }
        for value in &self.caller_subjects {
            validate_caller_subject(id, value)?;
        }
        match self.concurrency_mode {
            AutomationConcurrencyMode::Exclusive => {
                if self.max_concurrent_leases != 1
                    || self.shared_state_isolation_requirement.is_some()
                {
                    return Err(invalid(
                        id,
                        "exclusive concurrency requires one lease and no shared-state isolation claim",
                    ));
                }
            }
            AutomationConcurrencyMode::Shared => {
                if self.max_concurrent_leases < 2
                    || self.shared_state_isolation_requirement.is_none()
                {
                    return Err(invalid(
                        id,
                        "shared concurrency requires at least two leases and stateless or per-lease-isolated state",
                    ));
                }
            }
        }
        if is_wif && self.authentication_exception_acknowledged {
            return Err(invalid(
                id,
                "a WIF profile cannot declare a non-WIF authentication exception",
            ));
        }
        if self.require_workload_identity && self.authentication_exception_acknowledged {
            return Err(invalid(
                id,
                "require_workload_identity conflicts with the non-WIF authentication exception",
            ));
        }
        let has_nonlocal_environment = self
            .environments
            .iter()
            .any(|environment| environment != "local-development");
        let has_nonreview_role = self
            .roles
            .iter()
            .any(|role| *role != AutomationRole::PrReviewer);
        if self.isolation_exception_acknowledged && has_nonlocal_environment && has_nonreview_role {
            return Err(invalid(
                id,
                "isolation exception permits only local-development or pr-reviewer scope",
            ));
        }
        if !self.eligible {
            return Ok(());
        }
        if self.environments.is_empty() || self.roles.is_empty() || self.caller_subjects.is_empty()
        {
            return Err(invalid(
                id,
                "eligible automation requires environments, roles, and caller_subjects",
            ));
        }
        if self.require_workload_identity && !is_wif {
            return Err(invalid(
                id,
                "eligible automation requires WIF unless workload identity is disabled explicitly",
            ));
        }
        if !is_wif && has_nonlocal_environment && !self.authentication_exception_acknowledged {
            return Err(invalid(
                id,
                "non-WIF automation outside local-development requires the dedicated authentication exception",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for AutomationPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AutomationPolicy")
            .field("eligible", &self.eligible)
            .field("environment_count", &self.environments.len())
            .field("roles", &self.roles)
            .field("caller_subject_count", &self.caller_subjects.len())
            .field("lease_ttl_seconds", &self.lease_ttl_seconds)
            .field("max_session_seconds", &self.max_session_seconds)
            .field("max_concurrent_leases", &self.max_concurrent_leases)
            .field("concurrency_mode", &self.concurrency_mode)
            .field(
                "shared_state_isolation_requirement",
                &self.shared_state_isolation_requirement,
            )
            .field("require_workload_identity", &self.require_workload_identity)
            .field(
                "authentication_exception_acknowledged",
                &self.authentication_exception_acknowledged,
            )
            .field(
                "isolation_exception_acknowledged",
                &self.isolation_exception_acknowledged,
            )
            .finish()
    }
}

fn validate_label(id: &ProfileId, kind: &str, value: &str) -> Result<()> {
    if valid_environment_label(value) {
        Ok(())
    } else {
        Err(invalid(
            id,
            &format!("{kind} must be a 1-128 character log-safe identifier"),
        ))
    }
}

pub(super) fn valid_environment_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'+')
        })
}

fn validate_caller_subject(id: &ProfileId, value: &str) -> Result<()> {
    let Some(suffix) = value.strip_prefix("caller:") else {
        return Err(invalid(
            id,
            "caller subject must use the normalized `caller:<id>` form",
        ));
    };
    let valid = !suffix.is_empty()
        && suffix.len() <= 128
        && suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(invalid(
            id,
            "caller subject must use the normalized `caller:<id>` form",
        ))
    }
}

fn invalid(id: &ProfileId, reason: &str) -> Error {
    Error::InvalidConfig(format!("profile `{id}` automation policy {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> ProfileId {
        "codex:automation"
            .parse()
            .unwrap_or_else(|error| panic!("profile ID: {error}"))
    }

    fn eligible() -> AutomationPolicy {
        AutomationPolicy {
            eligible: true,
            environments: BTreeSet::from(["production".to_owned()]),
            roles: BTreeSet::from([AutomationRole::Implementer]),
            caller_subjects: BTreeSet::from(["caller:controller".to_owned()]),
            ..AutomationPolicy::default()
        }
    }

    #[test]
    fn existing_profile_default_is_disabled_and_exclusive() {
        let policy = AutomationPolicy::default();
        assert!(!policy.eligible);
        assert_eq!(policy.max_concurrent_leases, 1);
        assert_eq!(
            policy.concurrency_mode,
            AutomationConcurrencyMode::Exclusive
        );
        assert!(policy.validate(&id(), false).is_ok());
    }

    #[test]
    fn eligible_non_wif_production_requires_the_visible_exception() {
        let mut policy = eligible();
        policy.require_workload_identity = false;
        assert!(policy.validate(&id(), false).is_err());
        policy.authentication_exception_acknowledged = true;
        assert!(policy.validate(&id(), false).is_ok());
        assert!(format!("{policy:?}").contains("authentication_exception_acknowledged: true"));
    }

    #[test]
    fn shared_concurrency_requires_an_explicit_isolation_shape() {
        let mut policy = AutomationPolicy {
            concurrency_mode: AutomationConcurrencyMode::Shared,
            max_concurrent_leases: 4,
            ..AutomationPolicy::default()
        };
        assert!(policy.validate(&id(), true).is_err());
        policy.shared_state_isolation_requirement =
            Some(SharedStateIsolationRequirement::PerLeaseIsolated);
        assert!(policy.validate(&id(), true).is_ok());
    }

    #[test]
    fn copied_credential_exception_is_independent_and_narrowly_scoped() {
        let mut policy = eligible();
        policy.isolation_exception_acknowledged = true;
        assert!(policy.validate(&id(), true).is_err());
        policy.roles = BTreeSet::from([AutomationRole::PrReviewer]);
        assert!(policy.validate(&id(), true).is_ok());

        policy.roles = BTreeSet::from([AutomationRole::Implementer]);
        policy.environments = BTreeSet::from(["local-development".to_owned()]);
        assert!(policy.validate(&id(), true).is_ok());
    }

    #[test]
    fn policy_cardinalities_and_lifetimes_are_bounded() {
        let mut policy = AutomationPolicy {
            max_session_seconds: MAX_SESSION_SECONDS + 1,
            ..AutomationPolicy::default()
        };
        assert!(policy.validate(&id(), false).is_err());
        policy.max_session_seconds = 14_400;
        policy.max_concurrent_leases = MAX_CONCURRENT_LEASES + 1;
        assert!(policy.validate(&id(), false).is_err());
        policy.max_concurrent_leases = 1;
        policy.environments = (0..=MAX_ENVIRONMENTS)
            .map(|index| format!("env{index}"))
            .collect();
        assert!(policy.validate(&id(), false).is_err());
        policy.environments.clear();
        policy.caller_subjects = (0..=MAX_CALLER_SUBJECTS)
            .map(|index| format!("caller:service{index}"))
            .collect();
        assert!(policy.validate(&id(), false).is_err());
    }

    #[test]
    fn caller_and_role_wire_grammars_match_phase_zero_contracts() {
        for value in ["caller:controller", "caller:A_b.c-1"] {
            assert!(validate_caller_subject(&id(), value).is_ok());
            assert!(crate::automation::contracts::CallerSubject::parse(value.to_owned()).is_ok());
        }
        for value in ["foo", "caller:a:b", "caller:a+b", "caller:a@b"] {
            assert!(validate_caller_subject(&id(), value).is_err());
            assert!(crate::automation::contracts::CallerSubject::parse(value.to_owned()).is_err());
        }
        let model = [
            AutomationRole::Implementer,
            AutomationRole::LocalReviewer,
            AutomationRole::PrReviewer,
        ];
        let contract = [
            crate::automation::contracts::AgentRole::Implementer,
            crate::automation::contracts::AgentRole::LocalReviewer,
            crate::automation::contracts::AgentRole::PrReviewer,
        ];
        let model_json =
            serde_json::to_value(model).unwrap_or_else(|error| panic!("serialize roles: {error}"));
        let contract_json = serde_json::to_value(contract)
            .unwrap_or_else(|error| panic!("serialize contract roles: {error}"));
        assert_eq!(model_json, contract_json);
    }
}
