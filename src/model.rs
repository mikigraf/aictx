use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

mod automation;
mod profile_uid;
mod validation;
mod wif;

pub use automation::{
    AutomationConcurrencyMode, AutomationPolicy, AutomationProfileView, AutomationRole,
    SharedStateIsolationRequirement,
};
pub use profile_uid::{InstallationUid, ProfileUid};
pub(crate) use wif::validate_wif_token_location;
pub use wif::{ClaudeWifConfig, CodexWifConfig, WorkloadIdentityContext};

/// Current persisted configuration schema.
pub const CONFIG_SCHEMA_VERSION: u32 = 2;
/// Current mutable-state schema. Configuration migration does not rewrite it.
pub const STATE_SCHEMA_VERSION: u32 = 1;
/// Compatibility alias for callers which refer to the configuration schema.
pub const SCHEMA_VERSION: u32 = CONFIG_SCHEMA_VERSION;
/// Compatibility alias for the original Claude WIF metadata name.
pub type WifConfig = ClaudeWifConfig;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Name(String);

impl Name {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric);

        if !valid {
            return Err(Error::InvalidInput(format!(
                "name `{value}` must be 1-64 ASCII letters, digits, `-`, or `_`, and start with a letter or digit"
            )));
        }

        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Name {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, ValueEnum,
)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lower")]
pub enum Provider {
    Claude,
    Codex,
}

impl fmt::Display for Provider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileId {
    provider: Provider,
    name: Name,
}

impl ProfileId {
    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    #[must_use]
    pub const fn name(&self) -> &Name {
        &self.name
    }

    #[must_use]
    pub const fn new(provider: Provider, name: Name) -> Self {
        Self { provider, name }
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.provider, self.name)
    }
}

impl FromStr for ProfileId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let (provider, name) = value.split_once(':').ok_or_else(|| {
            Error::InvalidInput(format!(
                "profile ID `{value}` must have the form `claude:name` or `codex:name`"
            ))
        })?;
        if name.contains(':') {
            return Err(Error::InvalidInput(format!(
                "profile ID `{value}` contains too many `:` separators"
            )));
        }
        let provider = match provider {
            "claude" => Provider::Claude,
            "codex" => Provider::Codex,
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown provider in profile ID `{value}`"
                )));
            }
        };
        Ok(Self::new(provider, Name::parse(name)?))
    }
}

impl Serialize for ProfileId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProfileId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum AuthArg {
    Subscription,
    SubscriptionToken,
    ApiKey,
    Wif,
    ChatgptOauth,
    AccessToken,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaudeAuth {
    SubscriptionToken,
    ApiKey,
    Wif,
}

impl fmt::Display for ClaudeAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SubscriptionToken => "subscription-token",
            Self::ApiKey => "api-key",
            Self::Wif => "wif",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodexAuth {
    Wif,
    ChatgptOauth,
    ApiKey,
    AccessToken,
}

impl fmt::Display for CodexAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Wif => "wif",
            Self::ChatgptOauth => "chatgpt-oauth",
            Self::ApiKey => "api-key",
            Self::AccessToken => "access-token",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BillingDomain {
    ClaudeSubscription,
    AnthropicApi,
    ChatgptSubscription,
    OpenaiApi,
}

impl fmt::Display for BillingDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClaudeSubscription => "Claude subscription",
            Self::AnthropicApi => "Anthropic API",
            Self::ChatgptSubscription => "ChatGPT subscription/workspace",
            Self::OpenaiApi => "OpenAI API",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum CodexCredentialStore {
    #[default]
    File,
    Keyring,
    Auto,
}

impl fmt::Display for CodexCredentialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::File => "file",
            Self::Keyring => "keyring",
            Self::Auto => "auto",
        })
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "provider", rename_all = "lowercase", deny_unknown_fields)]
pub enum Profile {
    Claude {
        profile_uid: ProfileUid,
        billing_domain: BillingDomain,
        auth: ClaudeAuth,
        state_dir: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        account_hint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_organization: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wif: Option<ClaudeWifConfig>,
        automation: AutomationPolicy,
    },
    Codex {
        profile_uid: ProfileUid,
        billing_domain: BillingDomain,
        auth: CodexAuth,
        state_dir: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        account_hint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_workspace_id: Option<String>,
        #[serde(default)]
        credential_store: CodexCredentialStore,
        #[serde(default)]
        trusted_runners_only: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        wif: Option<CodexWifConfig>,
        automation: AutomationPolicy,
    },
}

impl Profile {
    #[must_use]
    pub const fn profile_uid(&self) -> &ProfileUid {
        match self {
            Self::Claude { profile_uid, .. } | Self::Codex { profile_uid, .. } => profile_uid,
        }
    }

    #[must_use]
    pub const fn provider(&self) -> Provider {
        match self {
            Self::Claude { .. } => Provider::Claude,
            Self::Codex { .. } => Provider::Codex,
        }
    }

    #[must_use]
    pub const fn billing_domain(&self) -> BillingDomain {
        match self {
            Self::Claude { billing_domain, .. } | Self::Codex { billing_domain, .. } => {
                *billing_domain
            }
        }
    }

    #[must_use]
    pub fn auth_label(&self) -> String {
        match self {
            Self::Claude { auth, .. } => auth.to_string(),
            Self::Codex { auth, .. } => auth.to_string(),
        }
    }

    #[must_use]
    pub fn state_dir(&self) -> &Path {
        match self {
            Self::Claude { state_dir, .. } | Self::Codex { state_dir, .. } => state_dir.as_path(),
        }
    }

    #[must_use]
    pub fn secret_ref(&self) -> Option<&str> {
        match self {
            Self::Claude { secret_ref, .. } | Self::Codex { secret_ref, .. } => {
                secret_ref.as_deref()
            }
        }
    }

    #[must_use]
    pub fn account_hint(&self) -> Option<&str> {
        match self {
            Self::Claude { account_hint, .. } | Self::Codex { account_hint, .. } => {
                account_hint.as_deref()
            }
        }
    }

    #[must_use]
    pub const fn automation(&self) -> &AutomationPolicy {
        match self {
            Self::Claude { automation, .. } | Self::Codex { automation, .. } => automation,
        }
    }

    pub const fn automation_mut(&mut self) -> &mut AutomationPolicy {
        match self {
            Self::Claude { automation, .. } | Self::Codex { automation, .. } => automation,
        }
    }

    #[must_use]
    pub fn automation_view(&self, id: &ProfileId) -> AutomationProfileView {
        let policy = self.automation();
        AutomationProfileView {
            profile_uid: self.profile_uid().clone(),
            profile_ref: id.clone(),
            provider: self.provider(),
            auth_mode: self.auth_label(),
            eligible: policy.eligible,
            environment_count: policy.environments.len(),
            roles: policy.roles.clone(),
            caller_subject_count: policy.caller_subjects.len(),
            lease_ttl_seconds: policy.lease_ttl_seconds,
            max_session_seconds: policy.max_session_seconds,
            max_concurrent_leases: policy.max_concurrent_leases,
            concurrency_mode: policy.concurrency_mode,
            shared_state_isolation_requirement: policy.shared_state_isolation_requirement,
            require_workload_identity: policy.require_workload_identity,
            authentication_exception_acknowledged: policy.authentication_exception_acknowledged,
            isolation_exception_acknowledged: policy.isolation_exception_acknowledged,
        }
    }

    #[must_use]
    pub const fn requires_static_secret(&self) -> bool {
        matches!(
            self,
            Self::Claude {
                auth: ClaudeAuth::SubscriptionToken | ClaudeAuth::ApiKey,
                ..
            } | Self::Codex {
                auth: CodexAuth::ApiKey | CodexAuth::AccessToken,
                ..
            }
        )
    }

    #[must_use]
    pub fn expected_workspace_id(&self) -> Option<&str> {
        match self {
            Self::Codex {
                expected_workspace_id,
                ..
            } => expected_workspace_id.as_deref(),
            Self::Claude { .. } => None,
        }
    }

    #[must_use]
    pub fn expected_organization(&self) -> Option<&str> {
        match self {
            Self::Claude {
                expected_organization,
                ..
            } => expected_organization.as_deref(),
            Self::Codex { .. } => None,
        }
    }
}

impl fmt::Debug for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("Profile");
        debug
            .field("profile_uid", self.profile_uid())
            .field("provider", &self.provider())
            .field("billing_domain", &self.billing_domain())
            .field("auth", &self.auth_label())
            .field("state_dir", &"[redacted]")
            .field("secret_ref_present", &self.secret_ref().is_some())
            .field("account_hint_present", &self.account_hint().is_some())
            .field("automation", self.automation());
        match self {
            Self::Claude {
                expected_organization,
                wif,
                ..
            } => {
                debug
                    .field(
                        "expected_organization_present",
                        &expected_organization.is_some(),
                    )
                    .field("wif", wif);
            }
            Self::Codex {
                expected_workspace_id,
                credential_store,
                trusted_runners_only,
                wif,
                ..
            } => {
                debug
                    .field(
                        "expected_workspace_present",
                        &expected_workspace_id.is_some(),
                    )
                    .field("credential_store", credential_store)
                    .field("trusted_runners_only", trusted_runners_only)
                    .field("wif", wif);
            }
        }
        debug.finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude: Option<ProfileId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex: Option<ProfileId>,
}

impl Context {
    #[must_use]
    pub const fn profile(&self, provider: Provider) -> Option<&ProfileId> {
        match provider {
            Provider::Claude => self.claude.as_ref(),
            Provider::Codex => self.codex.as_ref(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub path: PathBuf,
    pub context: Name,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "enabled")]
    pub require_billing_confirmation_on_change: bool,
    #[serde(default = "enabled")]
    pub show_run_banner: bool,
    #[serde(default)]
    pub telemetry: bool,
}

const fn enabled() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            require_billing_confirmation_on_change: true,
            show_run_banner: true,
            telemetry: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryConfig {
    pub claude: PathBuf,
    pub codex: PathBuf,
}

impl Default for BinaryConfig {
    fn default() -> Self {
        Self {
            claude: PathBuf::from("claude"),
            codex: PathBuf::from("codex"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub installation_uid: InstallationUid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_context: Option<Name>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub binaries: BinaryConfig,
    #[serde(default)]
    pub profiles: BTreeMap<ProfileId, Profile>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub retired_profile_uids: BTreeSet<ProfileUid>,
    #[serde(default)]
    pub contexts: BTreeMap<Name, Context>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    #[serde(skip)]
    authority: ConfigAuthority,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConfigAuthority {
    #[default]
    Persisted,
    ProjectedLegacy,
}

impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self::with_installation_uid(InstallationUid::generate()?))
    }

    pub(crate) fn with_installation_uid(installation_uid: InstallationUid) -> Self {
        Self {
            version: CONFIG_SCHEMA_VERSION,
            installation_uid,
            default_context: None,
            settings: Settings::default(),
            binaries: BinaryConfig::default(),
            profiles: BTreeMap::new(),
            retired_profile_uids: BTreeSet::new(),
            contexts: BTreeMap::new(),
            bindings: Vec::new(),
            authority: ConfigAuthority::Persisted,
        }
    }

    #[must_use]
    pub const fn authority(&self) -> ConfigAuthority {
        self.authority
    }

    #[must_use]
    pub const fn is_authoritative(&self) -> bool {
        matches!(self.authority, ConfigAuthority::Persisted)
    }

    pub(crate) const fn mark_projected_legacy(&mut self) {
        self.authority = ConfigAuthority::ProjectedLegacy;
    }

    pub(crate) const fn mark_persisted(&mut self) {
        self.authority = ConfigAuthority::Persisted;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutableState {
    #[serde(default = "schema_version")]
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_context: Option<Name>,
}

impl Default for MutableState {
    fn default() -> Self {
        Self {
            version: STATE_SCHEMA_VERSION,
            current_context: None,
        }
    }
}

const fn schema_version() -> u32 {
    STATE_SCHEMA_VERSION
}

impl MutableState {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.version != STATE_SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported state schema version {}",
                self.version
            )));
        }
        if let Some(context) = &self.current_context
            && !config.contexts.contains_key(context)
        {
            return Err(Error::InvalidConfig(format!(
                "active context `{context}` no longer exists"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "model/tests.rs"]
mod tests;
