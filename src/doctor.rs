use std::{env, path::Path};

use serde::Serialize;

use crate::{
    config::{
        AppPaths, acquire_ordered_profile_locks, ensure_profile_automation_unfenced,
        validate_secure_directory, validate_sensitive_file,
    },
    model::{ClaudeAuth, CodexAuth, Config, Profile, Provider, validate_wif_token_location},
    runner::{
        is_blocked_key, resolve_vendor_binary, validate_claude_settings, validate_codex_settings,
        vendor_version,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
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

#[derive(Clone, Debug, Serialize)]
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

    pub(crate) fn push(
        &mut self,
        level: CheckLevel,
        name: impl Into<String>,
        detail: impl Into<String>,
    ) {
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
                "ctxlane will remove these variables from vendor children: {}",
                inherited.join(", ")
            ),
        );
    }

    if !config
        .profiles
        .values()
        .any(|profile| provider_filter.is_none_or(|filter| filter == profile.provider()))
    {
        let name = provider_filter.map_or_else(
            || "profiles".to_owned(),
            |provider| format!("{provider} profiles"),
        );
        let detail = provider_filter.map_or_else(
            || "no profiles are configured; run `ctxlane profile add --help`".to_owned(),
            |provider| {
                format!("no {provider} profiles are configured; run `ctxlane profile add --help`")
            },
        );
        report.push(CheckLevel::Failure, name, detail);
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
        append_automation_policy(&mut report, profile_id, profile);
        if matches!(
            profile,
            Profile::Codex {
                auth: CodexAuth::Wif,
                ..
            }
        ) {
            report.push(
                CheckLevel::Failure,
                format!("{profile_id} native WIF runtime"),
                "Codex WIF enrollment is stored, but native runtime qualification is unavailable in this release",
            );
            continue;
        }
        let alias_path = paths.profile_lock(profile.provider(), profile_id.name());
        let lifecycle_path = paths.profile_lifecycle_lock(profile.profile_uid());
        let resource_path = paths.profile_resource_lock(profile.profile_uid());
        let _profile_locks = match acquire_ordered_profile_locks([
            (alias_path, false),
            (lifecycle_path, false),
            (resource_path, true),
        ]) {
            Ok(locks) => locks,
            Err(error) => {
                report.push(
                    CheckLevel::Failure,
                    format!("{profile_id} state isolation"),
                    error.to_string(),
                );
                continue;
            }
        };
        if let Err(error) = ensure_profile_automation_unfenced(paths, profile.profile_uid()) {
            report.push(
                CheckLevel::Failure,
                format!("{profile_id} state isolation"),
                error.to_string(),
            );
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

        if let Profile::Claude {
            auth: ClaudeAuth::Wif,
            wif: Some(wif),
            ..
        } = profile
        {
            match validate_wif_token_location(profile_id, &wif.identity_token_file)
                .and_then(|()| validate_sensitive_file(&wif.identity_token_file))
            {
                Ok(()) => report.push(
                    CheckLevel::Pass,
                    format!("{profile_id} identity source"),
                    "private WIF identity-token file is available",
                ),
                Err(error) => report.push(
                    CheckLevel::Failure,
                    format!("{profile_id} identity source"),
                    error.to_string(),
                ),
            }
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

fn append_automation_policy(
    report: &mut DoctorReport,
    profile_id: &crate::model::ProfileId,
    profile: &Profile,
) {
    let policy = profile.automation();
    if policy.eligible {
        report.push(
            CheckLevel::Warning,
            format!("{profile_id} automation policy"),
            format!(
                "eligible metadata is configured for {} environment(s), {} role(s), and {} caller(s); automation runtime is not available in this release, so this is not a readiness result",
                policy.environments.len(),
                policy.roles.len(),
                policy.caller_subjects.len()
            ),
        );
    } else {
        report.push(
            CheckLevel::Pass,
            format!("{profile_id} automation policy"),
            "disabled; this profile is not automation-eligible",
        );
    }
    if policy.authentication_exception_acknowledged {
        report.push(
            CheckLevel::Warning,
            format!("{profile_id} authentication exception"),
            "a dedicated non-WIF authentication exception is acknowledged in local operator policy",
        );
    }
    if policy.isolation_exception_acknowledged {
        report.push(
            CheckLevel::Warning,
            format!("{profile_id} isolation exception"),
            "a copied-credential isolation exception is acknowledged in local operator policy",
        );
    }
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
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::PathBuf,
    };

    use crate::model::{
        AutomationPolicy, BillingDomain, ClaudeAuth, CodexCredentialStore, CodexWifConfig,
        ProfileId, ProfileUid,
    };

    use super::*;

    fn uid(index: u32) -> ProfileUid {
        ProfileUid::parse(format!("profile_{index:026}"))
            .unwrap_or_else(|error| panic!("profile UID: {error}"))
    }

    #[test]
    fn provider_filter_limits_keyring_diagnostics() {
        let mut config = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
        let profile_id: ProfileId = "claude:work"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
        config.profiles.insert(
            profile_id,
            Profile::Claude {
                profile_uid: uid(1),
                billing_domain: BillingDomain::AnthropicApi,
                auth: ClaudeAuth::ApiKey,
                state_dir: PathBuf::from("unused-test-state"),
                secret_ref: Some("keyring://ctxlane/claude-work".to_owned()),
                account_hint: None,
                expected_organization: None,
                wif: None,
                automation: AutomationPolicy::default(),
            },
        );
        let codex_id: ProfileId = "codex:work"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
        config.profiles.insert(
            codex_id,
            Profile::Codex {
                profile_uid: uid(2),
                billing_domain: BillingDomain::ChatgptSubscription,
                auth: CodexAuth::ChatgptOauth,
                state_dir: PathBuf::from("unused-test-state-2"),
                secret_ref: None,
                account_hint: None,
                expected_workspace_id: None,
                credential_store: CodexCredentialStore::File,
                trusted_runners_only: false,
                wif: None,
                automation: AutomationPolicy::default(),
            },
        );

        assert!(needs_keyring(&config, None));
        assert!(needs_keyring(&config, Some(Provider::Claude)));
        assert!(!needs_keyring(&config, Some(Provider::Codex)));
    }

    #[test]
    fn codex_wif_is_explicitly_unqualified_without_exposing_enrollment_metadata() {
        let mut config = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
        let profile_id: ProfileId = "codex:factory"
            .parse()
            .unwrap_or_else(|error| panic!("profile: {error}"));
        config.profiles.insert(
            profile_id,
            Profile::Codex {
                profile_uid: uid(3),
                billing_domain: BillingDomain::ChatgptSubscription,
                auth: CodexAuth::Wif,
                state_dir: PathBuf::from("/private/CREDENTIAL_CANARY_state"),
                secret_ref: None,
                account_hint: None,
                expected_workspace_id: None,
                credential_store: CodexCredentialStore::File,
                trusted_runners_only: false,
                wif: Some(CodexWifConfig {
                    federation_rule_id: "idpm_CREDENTIAL_CANARY_rule".to_owned(),
                    identity_token_file: PathBuf::from("/private/CREDENTIAL_CANARY_token"),
                    expected_workspace: "chatgpt-workspace:CREDENTIAL_CANARY".to_owned(),
                    expected_principal: "service-account:CREDENTIAL_CANARY".to_owned(),
                    allowed_environments: BTreeSet::from(["production".to_owned()]),
                    allowed_workload_labels: BTreeMap::new(),
                    workload_identity_context: None,
                    minimum_codex_version: "0.148.0".to_owned(),
                }),
                automation: AutomationPolicy::default(),
            },
        );
        let paths = AppPaths::for_root(PathBuf::from("/tmp/ctxlane-doctor-wif"));
        let report = inspect(&config, &paths, Path::new("/tmp"), Some(Provider::Codex));
        let rendered = serde_json::to_string(&report.checks)
            .unwrap_or_else(|error| panic!("serialize report: {error}"));
        assert!(rendered.contains("native WIF runtime"));
        assert!(rendered.contains("qualification is unavailable"));
        assert!(!rendered.contains("CREDENTIAL_CANARY"));
        assert!(report.has_failures());
    }

    #[test]
    fn automation_policy_reports_only_counts_and_explicit_exception_classes() {
        let profile_id: ProfileId = "codex:factory"
            .parse()
            .unwrap_or_else(|error| panic!("profile: {error}"));
        let automation = AutomationPolicy {
            eligible: true,
            environments: BTreeSet::from([
                "local-development".to_owned(),
                "CREDENTIAL_CANARY_ENVIRONMENT".to_owned(),
            ]),
            roles: BTreeSet::from([crate::model::AutomationRole::PrReviewer]),
            caller_subjects: BTreeSet::from([
                "caller:CREDENTIAL_CANARY_CALLER".to_owned(),
                "caller:local-controller".to_owned(),
            ]),
            require_workload_identity: false,
            authentication_exception_acknowledged: true,
            isolation_exception_acknowledged: true,
            ..AutomationPolicy::default()
        };
        let profile = Profile::Codex {
            profile_uid: uid(4),
            billing_domain: BillingDomain::ChatgptSubscription,
            auth: CodexAuth::ChatgptOauth,
            state_dir: PathBuf::from("unused-test-state"),
            secret_ref: None,
            account_hint: None,
            expected_workspace_id: None,
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: false,
            wif: None,
            automation,
        };
        let mut report = DoctorReport::default();
        append_automation_policy(&mut report, &profile_id, &profile);
        assert_eq!(report.checks.len(), 3);
        assert_eq!(report.checks[0].level, CheckLevel::Warning);
        assert!(report.checks[0].detail.contains("2 environment(s)"));
        assert!(report.checks[0].detail.contains("1 role(s)"));
        assert!(report.checks[0].detail.contains("2 caller(s)"));
        assert!(report.checks[0].detail.contains("not a readiness result"));
        assert_eq!(
            report.checks[1].name,
            "codex:factory authentication exception"
        );
        assert_eq!(report.checks[2].name, "codex:factory isolation exception");
        let rendered = serde_json::to_string(&report.checks)
            .unwrap_or_else(|error| panic!("serialize checks: {error}"));
        assert!(!rendered.contains("CREDENTIAL_CANARY"));
    }
}
