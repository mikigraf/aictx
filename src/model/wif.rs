use std::{collections::BTreeMap, fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

use super::{ProfileId, automation::valid_environment_label};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeWifConfig {
    pub organization_id: String,
    pub federation_rule_id: String,
    pub service_account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub identity_token_file: PathBuf,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodexWifConfig {
    pub federation_rule_id: String,
    pub identity_token_file: PathBuf,
    pub expected_workspace: String,
    pub expected_principal: String,
    pub allowed_environments: std::collections::BTreeSet<String>,
    pub allowed_workload_labels: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_identity_context: Option<WorkloadIdentityContext>,
    pub minimum_codex_version: String,
}

/// Optional non-authoritative attribution passed to the official Codex CLI.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentityContext {
    pub instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub labels: BTreeMap<String, String>,
}

impl ClaudeWifConfig {
    pub(super) fn validate(&self, id: &ProfileId) -> Result<()> {
        for (field, value) in [
            ("organization_id", self.organization_id.as_str()),
            ("federation_rule_id", self.federation_rule_id.as_str()),
            ("service_account_id", self.service_account_id.as_str()),
        ] {
            validate_metadata(id, field, value)?;
        }
        if let Some(workspace) = self.workspace_id.as_deref() {
            validate_metadata(id, "workspace_id", workspace)?;
        }
        validate_token_path_shape(id, &self.identity_token_file)
    }

    pub(crate) fn validate_enrollment(&self, id: &ProfileId) -> Result<()> {
        self.validate(id)?;
        validate_wif_token_location(id, &self.identity_token_file)
    }
}

impl CodexWifConfig {
    pub(super) fn validate(&self, id: &ProfileId) -> Result<()> {
        validate_federation_rule(id, &self.federation_rule_id)?;
        validate_normalized_reference(
            id,
            "expected_workspace",
            &self.expected_workspace,
            &["chatgpt-workspace"],
        )?;
        validate_normalized_reference(
            id,
            "expected_principal",
            &self.expected_principal,
            &["user", "service-account"],
        )?;
        if self.allowed_environments.is_empty() || self.allowed_environments.len() > 32 {
            return Err(invalid(
                id,
                "allowed_environments must contain between one and 32 environments",
            ));
        }
        for environment in &self.allowed_environments {
            if !valid_environment_label(environment) {
                return Err(invalid(
                    id,
                    "allowed environment must match the automation environment grammar",
                ));
            }
        }
        if self.allowed_workload_labels.len() > 32 {
            return Err(invalid(
                id,
                "allowed_workload_labels may contain at most 32 labels",
            ));
        }
        for (key, value) in &self.allowed_workload_labels {
            validate_context_key(id, "workload label key", key)?;
            validate_context_value(id, "workload label value", value, 256)?;
        }
        if let Some(context) = &self.workload_identity_context {
            context.validate(id)?;
        }
        validate_codex_version(id, &self.minimum_codex_version)?;
        validate_token_path_shape(id, &self.identity_token_file)
    }

    pub(crate) fn validate_enrollment(&self, id: &ProfileId) -> Result<()> {
        self.validate(id)?;
        validate_wif_token_location(id, &self.identity_token_file)
    }
}

impl WorkloadIdentityContext {
    fn validate(&self, id: &ProfileId) -> Result<()> {
        validate_context_value(id, "workload context instance_id", &self.instance_id, 128)?;
        if let Some(display_name) = self.display_name.as_deref() {
            validate_context_value(id, "workload context display_name", display_name, 128)?;
        }
        if self.labels.len() > 8 {
            return Err(invalid(
                id,
                "workload context may contain at most eight labels",
            ));
        }
        for (key, value) in &self.labels {
            validate_context_key(id, "workload context label key", key)?;
            validate_context_value(id, "workload context label value", value, 256)?;
        }
        let encoded = serde_json::to_vec(self).map_err(|_| {
            invalid(
                id,
                "workload context could not be encoded with its closed schema",
            )
        })?;
        if encoded.len() > 1_024 {
            return Err(invalid(
                id,
                "workload context encoded size must not exceed 1024 bytes",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ClaudeWifConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaudeWifConfig")
            .field("organization_id", &"[redacted]")
            .field("federation_rule_id", &"[redacted]")
            .field("service_account_id", &"[redacted]")
            .field("workspace_id_present", &self.workspace_id.is_some())
            .field("identity_token_file", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for CodexWifConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexWifConfig")
            .field("federation_rule_id", &"[redacted]")
            .field("identity_token_file", &"[redacted]")
            .field("expected_workspace", &"[redacted]")
            .field("expected_principal", &"[redacted]")
            .field(
                "allowed_environment_count",
                &self.allowed_environments.len(),
            )
            .field(
                "allowed_workload_label_count",
                &self.allowed_workload_labels.len(),
            )
            .field(
                "workload_identity_context_present",
                &self.workload_identity_context.is_some(),
            )
            .field("minimum_codex_version", &self.minimum_codex_version)
            .finish()
    }
}

fn validate_token_path_shape(id: &ProfileId, path: &std::path::Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.to_str().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || path
            .as_os_str()
            .to_string_lossy()
            .chars()
            .any(char::is_control)
    {
        return Err(invalid(
            id,
            "identity_token_file must be an absolute path without relative or control components",
        ));
    }
    Ok(())
}

/// Check the enrollment-time repository boundary before any token-file stat or read.
///
/// Runtime consumers must still canonicalize and re-check the actual workspace,
/// ownership, mode, file type, freshness, and the validation-to-open race.
pub(crate) fn validate_wif_token_location(id: &ProfileId, path: &std::path::Path) -> Result<()> {
    if path
        .ancestors()
        .any(|ancestor| ancestor.join(".git").exists())
    {
        return Err(invalid(
            id,
            "identity_token_file must remain outside Git worktrees",
        ));
    }
    Ok(())
}

fn validate_codex_version(id: &ProfileId, value: &str) -> Result<()> {
    let components = value
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok();
    let valid = components.as_deref().is_some_and(|components| {
        components.len() == 3
            && components
                .iter()
                .map(u32::to_string)
                .zip(value.split('.'))
                .all(|(canonical, original)| canonical == original)
            && (components[0], components[1], components[2]) >= (0, 148, 0)
    });
    if valid {
        Ok(())
    } else {
        Err(invalid(
            id,
            "minimum_codex_version must be canonical x.y.z and at least 0.148.0",
        ))
    }
}

fn validate_normalized_reference(
    id: &ProfileId,
    field: &str,
    value: &str,
    namespaces: &[&str],
) -> Result<()> {
    let Some((namespace, suffix)) = value.split_once(':') else {
        return Err(invalid(
            id,
            &format!("{field} is not a normalized reference"),
        ));
    };
    let suffix_is_valid = !suffix.is_empty()
        && suffix.len() <= 128
        && suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !namespaces.contains(&namespace) || suffix.contains(':') || !suffix_is_valid {
        return Err(invalid(
            id,
            &format!("{field} is not a normalized reference"),
        ));
    }
    Ok(())
}

fn validate_metadata(id: &ProfileId, field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(invalid(
            id,
            &format!("{field} must be 1-512 trimmed characters without controls"),
        ))
    } else {
        Ok(())
    }
}

fn validate_context_key(id: &ProfileId, field: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(invalid(
            id,
            &format!("{field} must be a 1-64 character normalized key"),
        ))
    }
}

fn validate_context_value(id: &ProfileId, field: &str, value: &str, max: usize) -> Result<()> {
    if valid_context_value(value, max) {
        Ok(())
    } else {
        Err(invalid(
            id,
            &format!("{field} must be a 1-{max} character normalized value"),
        ))
    }
}

fn valid_context_value(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn validate_federation_rule(id: &ProfileId, value: &str) -> Result<()> {
    let suffix = value.strip_prefix("idpm_");
    let valid = suffix.is_some_and(|suffix| {
        !suffix.is_empty()
            && value.len() <= 128
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    });
    if valid {
        Ok(())
    } else {
        Err(invalid(
            id,
            "federation_rule_id must use the normalized `idpm_...` form",
        ))
    }
}

fn invalid(id: &ProfileId, reason: &str) -> Error {
    Error::InvalidConfig(format!("WIF profile `{id}` {reason}"))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    fn id() -> ProfileId {
        "codex:automation"
            .parse()
            .unwrap_or_else(|error| panic!("profile ID: {error}"))
    }

    fn codex() -> CodexWifConfig {
        CodexWifConfig {
            federation_rule_id: "idpm_production".to_owned(),
            identity_token_file: absolute_test_token(),
            expected_workspace: "chatgpt-workspace:managed".to_owned(),
            expected_principal: "service-account:factory".to_owned(),
            allowed_environments: BTreeSet::from(["production".to_owned()]),
            allowed_workload_labels: BTreeMap::from([("pool".to_owned(), "trusted".to_owned())]),
            workload_identity_context: Some(WorkloadIdentityContext {
                instance_id: "controller-01".to_owned(),
                display_name: Some("Local-controller".to_owned()),
                labels: BTreeMap::from([("pool".to_owned(), "trusted".to_owned())]),
            }),
            minimum_codex_version: "0.148.0".to_owned(),
        }
    }

    fn absolute_test_token() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\ctxlane\identity.jwt")
        } else {
            PathBuf::from("/run/ctxlane/identity.jwt")
        }
    }

    #[test]
    fn codex_metadata_is_strict_and_debug_is_redacted() {
        let config = codex();
        assert!(config.validate(&id()).is_ok());
        let debug = format!("{config:?}");
        let token_path = config.identity_token_file.display().to_string();
        for private in [
            "idpm_production",
            &token_path,
            "chatgpt-workspace:managed",
            "service-account:factory",
            "controller-01",
            "Local-controller",
        ] {
            assert!(!debug.contains(private));
        }
    }

    #[test]
    fn codex_requires_supported_version_and_normalized_expectations() {
        let mut config = codex();
        config.minimum_codex_version = "0.147.9".to_owned();
        assert!(config.validate(&id()).is_err());
        config.minimum_codex_version = "0.148.0".to_owned();
        config.expected_principal = "raw/backend/principal".to_owned();
        assert!(config.validate(&id()).is_err());

        let mut config = codex();
        config.allowed_environments = BTreeSet::from(["prod+gpu".to_owned()]);
        assert!(config.validate(&id()).is_ok());
        config.allowed_environments = BTreeSet::from(["prod/eu".to_owned()]);
        assert!(config.validate(&id()).is_err());
    }

    #[test]
    fn workload_context_is_bounded_and_closed() {
        let mut config = codex();
        let context = config
            .workload_identity_context
            .as_mut()
            .unwrap_or_else(|| panic!("fixture context"));
        context.labels = (0..9)
            .map(|index| (format!("key{index}"), "value".to_owned()))
            .collect();
        assert!(config.validate(&id()).is_err());

        let mut config = codex();
        config
            .workload_identity_context
            .as_mut()
            .unwrap_or_else(|| panic!("fixture context"))
            .display_name = Some("Production-worker:01/@primary".to_owned());
        assert!(config.validate(&id()).is_ok());
        for invalid in ["Production worker", " leading", "trailing ", "line\nbreak"] {
            config
                .workload_identity_context
                .as_mut()
                .unwrap_or_else(|| panic!("fixture context"))
                .display_name = Some(invalid.to_owned());
            assert!(config.validate(&id()).is_err());
        }
    }
}
