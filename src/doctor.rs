use std::{env, path::Path};

use crate::{
    config::{AppPaths, validate_secure_directory},
    model::{CodexAuth, Config, Profile, Provider},
    runner::{
        is_blocked_key, resolve_vendor_binary, validate_claude_settings, validate_codex_settings,
        vendor_version,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckLevel {
    Pass,
    Warning,
    Failure,
}

impl CheckLevel {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warning => "WARN",
            Self::Failure => "FAIL",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Check {
    pub level: CheckLevel,
    pub name: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct DoctorReport {
    pub checks: Vec<Check>,
}

impl DoctorReport {
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.level == CheckLevel::Failure)
    }

    fn push(&mut self, level: CheckLevel, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            level,
            name: name.into(),
            detail: detail.into(),
        });
    }
}

#[must_use]
pub fn inspect(
    config: &Config,
    paths: &AppPaths,
    cwd: &Path,
    provider_filter: Option<Provider>,
) -> DoctorReport {
    let mut report = DoctorReport::default();

    match config.validate() {
        Ok(()) => report.push(
            CheckLevel::Pass,
            "metadata",
            "schema and references are valid",
        ),
        Err(error) => report.push(CheckLevel::Failure, "metadata", error.to_string()),
    }
    match paths.validate_layout() {
        Ok(()) => report.push(
            CheckLevel::Pass,
            "permissions",
            if cfg!(unix) {
                "application directories are current-user-owned, owner-only, and not symlinked"
            } else {
                "application directories exist and are not symlinked; qualify Windows ACLs separately"
            },
        ),
        Err(error) => report.push(CheckLevel::Failure, "permissions", error.to_string()),
    }

    let mut inherited = env::vars_os()
        .filter_map(|(name, _)| is_blocked_key(&name).then(|| name.to_string_lossy().into_owned()))
        .collect::<Vec<_>>();
    inherited.sort();
    if inherited.is_empty() {
        report.push(
            CheckLevel::Pass,
            "parent environment",
            "no competing vendor credential or endpoint selectors are set",
        );
    } else {
        report.push(
            CheckLevel::Warning,
            "parent environment",
            format!(
                "aictx will remove these variables from vendor children: {}",
                inherited.join(", ")
            ),
        );
    }

    for provider in [Provider::Claude, Provider::Codex] {
        if provider_filter.is_some_and(|filter| filter != provider) {
            continue;
        }
        match resolve_vendor_binary(config, provider) {
            Ok(path) => match vendor_version(config, provider) {
                Ok(version) => report.push(
                    CheckLevel::Pass,
                    format!("{provider} binary"),
                    format!("{} ({version})", path.display()),
                ),
                Err(error) => report.push(
                    CheckLevel::Failure,
                    format!("{provider} binary"),
                    error.to_string(),
                ),
            },
            Err(error) => report.push(
                CheckLevel::Failure,
                format!("{provider} binary"),
                error.to_string(),
            ),
        }
    }

    if needs_keyring(config, provider_filter) {
        match keyring::Entry::store_status() {
            Ok(()) => report.push(
                CheckLevel::Pass,
                "OS keyring",
                "native credential store initialized successfully",
            ),
            Err(error) => report.push(CheckLevel::Failure, "OS keyring", error.to_string()),
        }
    }
    for (profile_id, profile) in &config.profiles {
        if provider_filter.is_some_and(|filter| filter != profile.provider()) {
            continue;
        }
        match validate_secure_directory(profile.state_dir()) {
            Ok(()) => report.push(
                CheckLevel::Pass,
                format!("{profile_id} state"),
                profile.state_dir().display().to_string(),
            ),
            Err(error) => report.push(
                CheckLevel::Failure,
                format!("{profile_id} state"),
                error.to_string(),
            ),
        }

        if profile.provider() == Provider::Claude {
            match validate_claude_settings(profile.state_dir(), cwd) {
                Ok(()) => report.push(
                    CheckLevel::Pass,
                    format!("{profile_id} settings"),
                    "no competing credential helpers or endpoint overrides detected",
                ),
                Err(error) => report.push(
                    CheckLevel::Failure,
                    format!("{profile_id} settings"),
                    error.to_string(),
                ),
            }
        }

        if profile.provider() == Provider::Codex {
            match validate_codex_settings(profile.state_dir(), cwd) {
                Ok(()) => report.push(
                    CheckLevel::Pass,
                    format!("{profile_id} settings"),
                    "no custom credential routes or repository command hooks detected",
                ),
                Err(error) => report.push(
                    CheckLevel::Failure,
                    format!("{profile_id} settings"),
                    error.to_string(),
                ),
            }
        }

        if let Profile::Codex {
            auth,
            expected_workspace_id,
            credential_store,
            ..
        } = profile
        {
            if matches!(auth, CodexAuth::ChatgptOauth | CodexAuth::AccessToken)
                && expected_workspace_id.is_none()
            {
                report.push(
                    CheckLevel::Warning,
                    format!("{profile_id} workspace"),
                    "workspace is not pinned; status will report identity as unverified",
                );
            } else if let Some(workspace) = expected_workspace_id {
                report.push(
                    CheckLevel::Pass,
                    format!("{profile_id} workspace"),
                    format!("forced workspace configured (…{})", suffix(workspace)),
                );
            }
            if *credential_store != crate::model::CodexCredentialStore::File {
                report.push(
                    CheckLevel::Warning,
                    format!("{profile_id} credential store"),
                    "keyring/auto isolation remains vendor-defined; file mode gives the strongest CODEX_HOME separation",
                );
            }
        }
    }

    report
}

fn needs_keyring(config: &Config, provider_filter: Option<Provider>) -> bool {
    config
        .profiles
        .values()
        .filter(|profile| provider_filter.is_none_or(|filter| filter == profile.provider()))
        .filter_map(Profile::secret_ref)
        .any(|reference| reference.starts_with("keyring://"))
}

fn suffix(value: &str) -> String {
    value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::model::{BillingDomain, ClaudeAuth, CodexCredentialStore, ProfileId};

    use super::*;

    #[test]
    fn provider_filter_limits_keyring_diagnostics() {
        let mut config = Config::default();
        let profile_id: ProfileId = "claude:work"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
        config.profiles.insert(
            profile_id,
            Profile::Claude {
                billing_domain: BillingDomain::AnthropicApi,
                auth: ClaudeAuth::ApiKey,
                state_dir: PathBuf::from("unused-test-state"),
                secret_ref: Some("keyring://aictx/claude-work".to_owned()),
                account_hint: None,
                expected_organization: None,
                wif: None,
            },
        );
        let codex_id: ProfileId = "codex:work"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
        config.profiles.insert(
            codex_id,
            Profile::Codex {
                billing_domain: BillingDomain::ChatgptSubscription,
                auth: CodexAuth::ChatgptOauth,
                state_dir: PathBuf::from("unused-test-state-2"),
                secret_ref: None,
                account_hint: None,
                expected_workspace_id: None,
                credential_store: CodexCredentialStore::File,
                trusted_runners_only: false,
            },
        );

        assert!(needs_keyring(&config, None));
        assert!(needs_keyring(&config, Some(Provider::Claude)));
        assert!(!needs_keyring(&config, Some(Provider::Codex)));
    }
}
