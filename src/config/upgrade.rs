use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    model::{
        AutomationPolicy, BillingDomain, BinaryConfig, Binding, CONFIG_SCHEMA_VERSION, ClaudeAuth,
        ClaudeWifConfig, CodexAuth, CodexCredentialStore, Config, Context, InstallationUid, Name,
        Profile, ProfileId, ProfileUid, Settings,
    },
};

use super::AppPaths;

#[derive(Debug)]
pub(super) struct DecodedConfig {
    pub(super) config: Config,
    pub(super) migrated: bool,
}

#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigV1 {
    version: u32,
    #[serde(default)]
    default_context: Option<Name>,
    #[serde(default)]
    settings: SettingsV1,
    #[serde(default)]
    binaries: BinaryConfigV1,
    #[serde(default)]
    profiles: BTreeMap<ProfileId, ProfileV1>,
    #[serde(default)]
    contexts: BTreeMap<Name, ContextV1>,
    #[serde(default)]
    bindings: Vec<BindingV1>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "provider", rename_all = "lowercase", deny_unknown_fields)]
enum ProfileV1 {
    Claude {
        billing_domain: BillingDomainV1,
        auth: ClaudeAuthV1,
        state_dir: PathBuf,
        #[serde(default)]
        secret_ref: Option<String>,
        #[serde(default)]
        account_hint: Option<String>,
        #[serde(default)]
        expected_organization: Option<String>,
        #[serde(default)]
        wif: Option<ClaudeWifConfigV1>,
    },
    Codex {
        billing_domain: BillingDomainV1,
        auth: CodexAuthV1,
        state_dir: PathBuf,
        #[serde(default)]
        secret_ref: Option<String>,
        #[serde(default)]
        account_hint: Option<String>,
        #[serde(default)]
        expected_workspace_id: Option<String>,
        #[serde(default)]
        credential_store: CodexCredentialStoreV1,
        #[serde(default)]
        trusted_runners_only: bool,
    },
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CodexAuthV1 {
    ChatgptOauth,
    ApiKey,
    AccessToken,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ClaudeAuthV1 {
    SubscriptionToken,
    ApiKey,
    Wif,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BillingDomainV1 {
    ClaudeSubscription,
    AnthropicApi,
    ChatgptSubscription,
    OpenaiApi,
}

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CodexCredentialStoreV1 {
    #[default]
    File,
    Keyring,
    Auto,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaudeWifConfigV1 {
    organization_id: String,
    federation_rule_id: String,
    service_account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workspace_id: Option<String>,
    identity_token_file: PathBuf,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContextV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claude: Option<ProfileId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codex: Option<ProfileId>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingV1 {
    path: PathBuf,
    context: Name,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SettingsV1 {
    #[serde(default = "enabled_v1")]
    require_billing_confirmation_on_change: bool,
    #[serde(default = "enabled_v1")]
    show_run_banner: bool,
    #[serde(default)]
    telemetry: bool,
}

const fn enabled_v1() -> bool {
    true
}

impl Default for SettingsV1 {
    fn default() -> Self {
        Self {
            require_billing_confirmation_on_change: true,
            show_run_banner: true,
            telemetry: false,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BinaryConfigV1 {
    claude: PathBuf,
    codex: PathBuf,
}

impl Default for BinaryConfigV1 {
    fn default() -> Self {
        Self {
            claude: PathBuf::from("claude"),
            codex: PathBuf::from("codex"),
        }
    }
}

pub(super) fn decode(path: &Path, text: &str) -> Result<DecodedConfig> {
    decode_with_installation_uid(path, text, None)
}

pub(super) fn decode_with_installation_uid(
    path: &Path,
    text: &str,
    installation_uid: Option<InstallationUid>,
) -> Result<DecodedConfig> {
    let probe: VersionProbe = parse(path, text)?;
    match probe.version {
        1 => upgrade_v1(path, text, installation_uid),
        CONFIG_SCHEMA_VERSION => {
            let config: Config = parse(path, text)?;
            if installation_uid
                .as_ref()
                .is_some_and(|expected| expected != &config.installation_uid)
            {
                return Err(Error::PolicyRefused(
                    "migration journal installation identity does not match the v2 source configuration"
                        .to_owned(),
                ));
            }
            Ok(DecodedConfig {
                config,
                migrated: false,
            })
        }
        version => Err(Error::InvalidConfig(format!(
            "unsupported schema version {version}; this build supports versions 1 and {CONFIG_SCHEMA_VERSION}"
        ))),
    }
}

/// Reconstruct the exact configuration bytes written by the pre-v2 migrator.
///
/// This is intentionally limited to verified-journal recovery. It preserves
/// the frozen schema-v1 wire and rewrites only the old name-derived managed
/// state locations.
pub(crate) fn expected_legacy_v1_target_config(
    source_path: &Path,
    source_text: &str,
    target: &AppPaths,
) -> Result<Vec<u8>> {
    let mut legacy: ConfigV1 = parse(source_path, source_text)?;
    if legacy.version != 1 {
        return Err(Error::InvalidConfig(
            "legacy configuration must use schema version 1".to_owned(),
        ));
    }
    for (id, profile) in &mut legacy.profiles {
        let state_dir = target.profile_state_dir(id.provider(), id.name());
        match profile {
            ProfileV1::Claude {
                state_dir: current, ..
            }
            | ProfileV1::Codex {
                state_dir: current, ..
            } => *current = state_dir,
        }
    }
    let text = toml::to_string_pretty(&legacy)?;
    Ok(format!("{text}\n").into_bytes())
}

fn upgrade_v1(
    path: &Path,
    text: &str,
    installation_uid: Option<InstallationUid>,
) -> Result<DecodedConfig> {
    let legacy: ConfigV1 = parse(path, text)?;
    if legacy.version != 1 {
        return Err(Error::InvalidConfig(
            "legacy configuration must use schema version 1".to_owned(),
        ));
    }

    let installation_uid = installation_uid.map_or_else(InstallationUid::generate, Ok)?;
    let mut config = Config::with_installation_uid(installation_uid);
    config.default_context = legacy.default_context;
    config.settings = legacy.settings.into();
    config.binaries = legacy.binaries.into();
    config.contexts = legacy
        .contexts
        .into_iter()
        .map(|(name, context)| (name, context.into()))
        .collect();
    config.bindings = legacy.bindings.into_iter().map(Into::into).collect();
    for (id, profile) in legacy.profiles {
        let state_dir = profile.state_dir().to_path_buf();
        let uid = ProfileUid::for_state_dir(&config.installation_uid, id.provider(), &state_dir)?;
        config.profiles.insert(id, profile.upgrade(uid));
    }
    config.mark_projected_legacy();
    Ok(DecodedConfig {
        config,
        migrated: true,
    })
}

impl ProfileV1 {
    fn state_dir(&self) -> &Path {
        match self {
            Self::Claude { state_dir, .. } | Self::Codex { state_dir, .. } => state_dir,
        }
    }

    fn upgrade(self, profile_uid: ProfileUid) -> Profile {
        match self {
            Self::Claude {
                billing_domain,
                auth,
                state_dir,
                secret_ref,
                account_hint,
                expected_organization,
                wif,
            } => Profile::Claude {
                profile_uid,
                billing_domain: billing_domain.into(),
                auth: auth.into(),
                state_dir,
                secret_ref,
                account_hint,
                expected_organization,
                wif: wif.map(Into::into),
                automation: AutomationPolicy::default(),
            },
            Self::Codex {
                billing_domain,
                auth,
                state_dir,
                secret_ref,
                account_hint,
                expected_workspace_id,
                credential_store,
                trusted_runners_only,
            } => Profile::Codex {
                profile_uid,
                billing_domain: billing_domain.into(),
                auth: match auth {
                    CodexAuthV1::ChatgptOauth => CodexAuth::ChatgptOauth,
                    CodexAuthV1::ApiKey => CodexAuth::ApiKey,
                    CodexAuthV1::AccessToken => CodexAuth::AccessToken,
                },
                state_dir,
                secret_ref,
                account_hint,
                expected_workspace_id,
                credential_store: credential_store.into(),
                trusted_runners_only,
                wif: None,
                automation: AutomationPolicy::default(),
            },
        }
    }
}

impl From<SettingsV1> for Settings {
    fn from(value: SettingsV1) -> Self {
        Self {
            require_billing_confirmation_on_change: value.require_billing_confirmation_on_change,
            show_run_banner: value.show_run_banner,
            telemetry: value.telemetry,
        }
    }
}

impl From<BinaryConfigV1> for BinaryConfig {
    fn from(value: BinaryConfigV1) -> Self {
        Self {
            claude: value.claude,
            codex: value.codex,
        }
    }
}

impl From<ContextV1> for Context {
    fn from(value: ContextV1) -> Self {
        Self {
            claude: value.claude,
            codex: value.codex,
        }
    }
}

impl From<BindingV1> for Binding {
    fn from(value: BindingV1) -> Self {
        Self {
            path: value.path,
            context: value.context,
        }
    }
}

impl From<ClaudeWifConfigV1> for ClaudeWifConfig {
    fn from(value: ClaudeWifConfigV1) -> Self {
        Self {
            organization_id: value.organization_id,
            federation_rule_id: value.federation_rule_id,
            service_account_id: value.service_account_id,
            identity_token_file: value.identity_token_file,
            workspace_id: value.workspace_id,
        }
    }
}

impl From<BillingDomainV1> for BillingDomain {
    fn from(value: BillingDomainV1) -> Self {
        match value {
            BillingDomainV1::ClaudeSubscription => Self::ClaudeSubscription,
            BillingDomainV1::AnthropicApi => Self::AnthropicApi,
            BillingDomainV1::ChatgptSubscription => Self::ChatgptSubscription,
            BillingDomainV1::OpenaiApi => Self::OpenaiApi,
        }
    }
}

impl From<ClaudeAuthV1> for ClaudeAuth {
    fn from(value: ClaudeAuthV1) -> Self {
        match value {
            ClaudeAuthV1::SubscriptionToken => Self::SubscriptionToken,
            ClaudeAuthV1::ApiKey => Self::ApiKey,
            ClaudeAuthV1::Wif => Self::Wif,
        }
    }
}

impl From<CodexCredentialStoreV1> for CodexCredentialStore {
    fn from(value: CodexCredentialStoreV1) -> Self {
        match value {
            CodexCredentialStoreV1::File => Self::File,
            CodexCredentialStoreV1::Keyring => Self::Keyring,
            CodexCredentialStoreV1::Auto => Self::Auto,
        }
    }
}

fn parse<T: for<'de> Deserialize<'de>>(path: &Path, text: &str) -> Result<T> {
    toml::from_str(text).map_err(|_| {
        Error::InvalidConfig(format!(
            "failed to parse configuration in {}; parser details and input were redacted",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_profile_upgrades_disabled_with_stable_uid() {
        let text = r#"
version = 1

[profiles."codex:personal"]
provider = "codex"
billing_domain = "chatgpt-subscription"
auth = "chatgpt-oauth"
state_dir = "/tmp/ctxlane/vendor-state/codex/personal"
credential_store = "file"
trusted_runners_only = false
"#;
        let path = Path::new("/tmp/config.toml");
        let first = decode(path, text).unwrap_or_else(|error| panic!("upgrade: {error}"));
        assert!(first.migrated);
        assert!(!first.config.is_authoritative());
        let profile = first
            .config
            .profiles
            .values()
            .next()
            .unwrap_or_else(|| panic!("profile"));
        assert!(!profile.automation().eligible);
        assert!(first.config.retired_profile_uids.is_empty());
    }

    #[test]
    fn legacy_unknown_fields_are_rejected() {
        let error = match decode(
            Path::new("/tmp/config.toml"),
            "version = 1\nunexpected = true\n",
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("legacy unknown field must be rejected"),
        };
        assert!(error.contains("parser details and input were redacted"));
        assert!(!error.contains("unexpected"));
    }

    #[test]
    fn legacy_nested_objects_reject_v2_field_smuggling() {
        for text in [
            "version = 1\n[settings]\nfuture_policy = true\n",
            r#"
version = 1
[profiles."codex:personal"]
provider = "codex"
billing_domain = "chatgpt-subscription"
auth = "chatgpt-oauth"
state_dir = "/tmp/ctxlane/vendor-state/codex/personal"
credential_store = "file"
trusted_runners_only = false
profile_uid = "profile_00000000000000000000000001"
"#,
        ] {
            let error = match decode(Path::new("/tmp/config.toml"), text) {
                Err(error) => error.to_string(),
                Ok(_) => panic!("legacy nested v2 field must be rejected"),
            };
            assert!(error.contains("parser details and input were redacted"));
        }
    }
}
