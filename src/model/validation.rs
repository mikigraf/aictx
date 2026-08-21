use std::{collections::BTreeSet, path::Path};

use crate::{Error, Result};

use super::{
    BillingDomain, ClaudeAuth, CodexAuth, CodexCredentialStore, Config, Profile, ProfileId,
    ProfileUid, Provider, SCHEMA_VERSION,
};

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.version != SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported schema version {}; this build supports version {SCHEMA_VERSION}",
                self.version
            )));
        }
        if self.settings.telemetry {
            return Err(Error::InvalidConfig(
                "telemetry must remain disabled; ctxlane does not implement telemetry".to_owned(),
            ));
        }
        for (provider, binary) in [
            ("claude", &self.binaries.claude),
            ("codex", &self.binaries.codex),
        ] {
            validate_persisted_path(&format!("{provider} binary"), binary)?;
            if binary.as_os_str().is_empty()
                || (!binary.is_absolute() && binary.components().count() != 1)
            {
                return Err(Error::InvalidConfig(format!(
                    "{provider} binary must be an absolute path or a bare executable name"
                )));
            }
            if binary.is_absolute() {
                reject_relative_components(&format!("{provider} binary"), binary)?;
            }
        }

        let mut profile_names = BTreeSet::new();
        let mut profile_uids = BTreeSet::new();
        let mut state_dirs = BTreeSet::new();
        for (id, profile) in &self.profiles {
            if !profile_names.insert((id.provider(), id.name().as_str().to_ascii_lowercase())) {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` collides with another same-provider profile name after ASCII case folding"
                )));
            }
            if id.provider() != profile.provider() {
                return Err(Error::InvalidConfig(format!(
                    "profile key `{id}` does not match provider `{}`",
                    profile.provider()
                )));
            }
            if !profile.state_dir().is_absolute() {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` state_dir must be absolute"
                )));
            }
            validate_persisted_path(&format!("profile `{id}` state_dir"), profile.state_dir())?;
            if profile.state_dir().components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            }) {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` state_dir must not contain `.` or `..` components"
                )));
            }
            let state_dir = profile.state_dir().to_str().ok_or_else(|| {
                Error::InvalidConfig(format!("profile `{id}` state_dir must be valid UTF-8"))
            })?;
            if !state_dirs.insert(state_dir.to_ascii_lowercase()) {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` shares or ASCII-case-fold aliases mutable state directory {} with another profile",
                    profile.state_dir().display()
                )));
            }
            let expected_uid = ProfileUid::for_state_dir(
                &self.installation_uid,
                id.provider(),
                profile.state_dir(),
            )?;
            if profile.profile_uid() != &expected_uid {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` profile_uid does not match its immutable provider state identity"
                )));
            }
            if !profile_uids.insert(profile.profile_uid().clone()) {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` reuses immutable profile_uid `{}`",
                    profile.profile_uid()
                )));
            }
            if self.retired_profile_uids.contains(profile.profile_uid()) {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` reuses retired profile_uid `{}`",
                    profile.profile_uid()
                )));
            }
            validate_profile(id, profile)?;
        }

        for (name, context) in &self.contexts {
            if context.claude.is_none() && context.codex.is_none() {
                return Err(Error::InvalidConfig(format!(
                    "context `{name}` must reference at least one profile"
                )));
            }
            for (provider, profile_id) in [
                (Provider::Claude, context.claude.as_ref()),
                (Provider::Codex, context.codex.as_ref()),
            ] {
                if let Some(profile_id) = profile_id {
                    if profile_id.provider() != provider {
                        return Err(Error::InvalidConfig(format!(
                            "context `{name}` has a {provider} slot pointing to `{profile_id}`"
                        )));
                    }
                    if !self.profiles.contains_key(profile_id) {
                        return Err(Error::InvalidConfig(format!(
                            "context `{name}` references missing profile `{profile_id}`"
                        )));
                    }
                }
            }
        }

        if let Some(default) = &self.default_context
            && !self.contexts.contains_key(default)
        {
            return Err(Error::InvalidConfig(format!(
                "default context `{default}` does not exist"
            )));
        }

        let mut binding_paths = BTreeSet::new();
        for binding in &self.bindings {
            validate_persisted_path("binding path", &binding.path)?;
            if !binding.path.is_absolute() {
                return Err(Error::InvalidConfig(format!(
                    "binding path {} must be absolute",
                    binding.path.display()
                )));
            }
            reject_relative_components("binding path", &binding.path)?;
            if !binding_paths.insert(binding.path.clone()) {
                return Err(Error::InvalidConfig(format!(
                    "duplicate binding for {}",
                    binding.path.display()
                )));
            }
            if !self.contexts.contains_key(&binding.context) {
                return Err(Error::InvalidConfig(format!(
                    "binding {} references missing context `{}`",
                    binding.path.display(),
                    binding.context
                )));
            }
        }

        Ok(())
    }
}

fn validate_profile(id: &ProfileId, profile: &Profile) -> Result<()> {
    profile
        .automation()
        .validate(id, profile.auth_label() == "wif")?;
    match profile {
        Profile::Claude {
            billing_domain,
            auth,
            secret_ref,
            account_hint,
            expected_organization,
            wif,
            ..
        } => {
            validate_optional_persisted_metadata(id, "account_hint", account_hint.as_deref())?;
            validate_optional_persisted_metadata(
                id,
                "expected_organization",
                expected_organization.as_deref(),
            )?;
            let expected_billing = match auth {
                ClaudeAuth::SubscriptionToken => BillingDomain::ClaudeSubscription,
                ClaudeAuth::ApiKey | ClaudeAuth::Wif => BillingDomain::AnthropicApi,
            };
            if *billing_domain != expected_billing {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` auth `{auth}` requires billing domain `{expected_billing}`"
                )));
            }
            match auth {
                ClaudeAuth::SubscriptionToken | ClaudeAuth::ApiKey => {
                    validate_secret_ref(id, secret_ref.as_deref())?;
                    if wif.is_some() {
                        return Err(Error::InvalidConfig(format!(
                            "profile `{id}` has WIF metadata but does not use WIF"
                        )));
                    }
                }
                ClaudeAuth::Wif => {
                    if secret_ref.is_some() {
                        return Err(Error::InvalidConfig(format!(
                            "WIF profile `{id}` must not persist a static secret"
                        )));
                    }
                    let wif = wif.as_ref().ok_or_else(|| {
                        Error::InvalidConfig(format!("WIF profile `{id}` is missing WIF metadata"))
                    })?;
                    wif.validate(id)?;
                }
            }
        }
        Profile::Codex {
            billing_domain,
            auth,
            secret_ref,
            account_hint,
            expected_workspace_id,
            credential_store,
            trusted_runners_only,
            wif,
            ..
        } => {
            validate_optional_persisted_metadata(id, "account_hint", account_hint.as_deref())?;
            validate_optional_persisted_metadata(
                id,
                "expected_workspace_id",
                expected_workspace_id.as_deref(),
            )?;
            let expected_billing = match auth {
                CodexAuth::Wif | CodexAuth::ChatgptOauth | CodexAuth::AccessToken => {
                    BillingDomain::ChatgptSubscription
                }
                CodexAuth::ApiKey => BillingDomain::OpenaiApi,
            };
            if *billing_domain != expected_billing {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` auth `{auth}` requires billing domain `{expected_billing}`"
                )));
            }
            match auth {
                CodexAuth::ChatgptOauth => {
                    if secret_ref.is_some() {
                        return Err(Error::InvalidConfig(format!(
                            "ChatGPT OAuth profile `{id}` must leave credentials vendor-managed"
                        )));
                    }
                    if wif.is_some() {
                        return Err(Error::InvalidConfig(format!(
                            "profile `{id}` has WIF metadata but does not use WIF"
                        )));
                    }
                }
                CodexAuth::ApiKey | CodexAuth::AccessToken => {
                    validate_secret_ref(id, secret_ref.as_deref())?;
                    if wif.is_some() {
                        return Err(Error::InvalidConfig(format!(
                            "profile `{id}` has WIF metadata but does not use WIF"
                        )));
                    }
                }
                CodexAuth::Wif => {
                    if secret_ref.is_some() {
                        return Err(Error::InvalidConfig(format!(
                            "WIF profile `{id}` must not persist a static secret"
                        )));
                    }
                    let wif = wif.as_ref().ok_or_else(|| {
                        Error::InvalidConfig(format!("WIF profile `{id}` is missing WIF metadata"))
                    })?;
                    if expected_workspace_id.is_some() {
                        return Err(Error::InvalidConfig(format!(
                            "Codex WIF profile `{id}` must keep the verified workspace only in WIF metadata"
                        )));
                    }
                    if *credential_store != CodexCredentialStore::File || *trusted_runners_only {
                        return Err(Error::InvalidConfig(format!(
                            "Codex WIF profile `{id}` must use the inert file credential-store default and leave trusted_runners_only disabled"
                        )));
                    }
                    wif.validate(id)?;
                }
            }
            if *auth == CodexAuth::AccessToken {
                if expected_workspace_id.as_deref().is_none_or(str::is_empty) {
                    return Err(Error::InvalidConfig(format!(
                        "Codex access-token profile `{id}` requires expected_workspace_id"
                    )));
                }
                if !trusted_runners_only {
                    return Err(Error::InvalidConfig(format!(
                        "Codex access-token profile `{id}` must set trusted_runners_only"
                    )));
                }
            }
            if *auth == CodexAuth::ApiKey && expected_workspace_id.is_some() {
                return Err(Error::InvalidConfig(format!(
                    "Codex API-key profile `{id}` must not set expected_workspace_id"
                )));
            }
        }
    }
    Ok(())
}

fn validate_optional_persisted_metadata(
    id: &ProfileId,
    field: &str,
    value: Option<&str>,
) -> Result<()> {
    if let Some(value) = value {
        validate_persisted_metadata(&format!("profile `{id}` {field}"), value)?;
    }
    Ok(())
}

fn validate_persisted_metadata(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Error::InvalidConfig(format!(
            "{label} must be 1-512 trimmed characters and contain no control characters"
        )));
    }
    Ok(())
}

fn validate_persisted_path(label: &str, path: &Path) -> Result<()> {
    if path
        .as_os_str()
        .to_string_lossy()
        .chars()
        .any(char::is_control)
    {
        return Err(Error::InvalidConfig(format!(
            "{label} must contain no control characters"
        )));
    }
    Ok(())
}

fn reject_relative_components(label: &str, path: &Path) -> Result<()> {
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(Error::InvalidConfig(format!(
            "{label} must not contain `.` or `..` components"
        )));
    }
    Ok(())
}

fn validate_secret_ref(id: &ProfileId, secret_ref: Option<&str>) -> Result<()> {
    let secret_ref = secret_ref.ok_or_else(|| {
        Error::InvalidConfig(format!("profile `{id}` requires a secret reference"))
    })?;
    if secret_ref.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(format!(
            "profile `{id}` secret_ref contains a forbidden control character"
        )));
    }
    if let Some(rest) = secret_ref.strip_prefix("keyring://") {
        let Some((service, account)) = rest.split_once('/') else {
            return Err(Error::InvalidConfig(format!(
                "profile `{id}` has an invalid keyring secret_ref"
            )));
        };
        if service.is_empty() || account.is_empty() || account.contains('/') {
            return Err(Error::InvalidConfig(format!(
                "profile `{id}` has an invalid keyring secret_ref"
            )));
        }
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "profile `{id}` secret_ref must use `keyring://service/account`"
    )))
}
