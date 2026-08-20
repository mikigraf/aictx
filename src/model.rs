use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const SCHEMA_VERSION: u32 = 1;

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
    ChatgptOauth,
    ApiKey,
    AccessToken,
}

impl fmt::Display for CodexAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WifConfig {
    pub organization_id: String,
    pub federation_rule_id: String,
    pub service_account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub identity_token_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "provider", rename_all = "lowercase", deny_unknown_fields)]
pub enum Profile {
    Claude {
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
        wif: Option<WifConfig>,
    },
    Codex {
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
    },
}

impl Profile {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_context: Option<Name>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub binaries: BinaryConfig,
    #[serde(default)]
    pub profiles: BTreeMap<ProfileId, Profile>,
    #[serde(default)]
    pub contexts: BTreeMap<Name, Context>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            default_context: None,
            settings: Settings::default(),
            binaries: BinaryConfig::default(),
            profiles: BTreeMap::new(),
            contexts: BTreeMap::new(),
            bindings: Vec::new(),
        }
    }
}

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
                "telemetry must remain disabled; aictx does not implement telemetry".to_owned(),
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
            if !state_dirs.insert(profile.state_dir().to_string_lossy().to_ascii_lowercase()) {
                return Err(Error::InvalidConfig(format!(
                    "profile `{id}` shares or ASCII-case-fold aliases mutable state directory {} with another profile",
                    profile.state_dir().display()
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
                    for (field, value) in [
                        ("organization_id", wif.organization_id.as_str()),
                        ("federation_rule_id", wif.federation_rule_id.as_str()),
                        ("service_account_id", wif.service_account_id.as_str()),
                    ] {
                        validate_persisted_metadata(&format!("WIF profile `{id}` {field}"), value)?;
                    }
                    if let Some(workspace) = wif.workspace_id.as_deref() {
                        validate_persisted_metadata(
                            &format!("WIF profile `{id}` workspace_id"),
                            workspace,
                        )?;
                    }
                    validate_persisted_path(
                        &format!("WIF profile `{id}` identity_token_file"),
                        &wif.identity_token_file,
                    )?;
                    if !wif.identity_token_file.is_absolute() {
                        return Err(Error::InvalidConfig(format!(
                            "WIF profile `{id}` identity_token_file must be absolute"
                        )));
                    }
                    reject_relative_components(
                        &format!("WIF profile `{id}` identity_token_file"),
                        &wif.identity_token_file,
                    )?;
                }
            }
        }
        Profile::Codex {
            billing_domain,
            auth,
            secret_ref,
            account_hint,
            expected_workspace_id,
            trusted_runners_only,
            ..
        } => {
            validate_optional_persisted_metadata(id, "account_hint", account_hint.as_deref())?;
            validate_optional_persisted_metadata(
                id,
                "expected_workspace_id",
                expected_workspace_id.as_deref(),
            )?;
            let expected_billing = match auth {
                CodexAuth::ChatgptOauth | CodexAuth::AccessToken => {
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
                }
                CodexAuth::ApiKey | CodexAuth::AccessToken => {
                    validate_secret_ref(id, secret_ref.as_deref())?;
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
            version: SCHEMA_VERSION,
            current_context: None,
        }
    }
}

const fn schema_version() -> u32 {
    SCHEMA_VERSION
}

impl MutableState {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.version != SCHEMA_VERSION {
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
mod tests {
    use super::*;

    #[test]
    fn names_are_path_safe() {
        assert!(Name::parse("work-2").is_ok());
        assert!(Name::parse("../work").is_err());
        assert!(Name::parse("with space").is_err());
        assert!(Name::parse("").is_err());
    }

    #[test]
    fn profile_ids_round_trip() {
        let parsed: ProfileId = "claude:personal".parse().unwrap_or_else(|error| {
            panic!("valid profile ID should parse: {error}");
        });
        assert_eq!(parsed.provider(), Provider::Claude);
        assert_eq!(parsed.name().as_str(), "personal");
        assert_eq!(parsed.to_string(), "claude:personal");
    }

    #[test]
    fn default_config_round_trips() {
        let config = Config::default();
        let text = toml::to_string_pretty(&config).unwrap_or_else(|error| {
            panic!("default config should serialize: {error}");
        });
        let decoded: Config = toml::from_str(&text).unwrap_or_else(|error| {
            panic!("default config should deserialize: {error}");
        });
        assert_eq!(decoded, config);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn profile_names_and_state_directories_are_ascii_case_fold_unique() {
        let root = std::env::temp_dir().join("aictx-model-case-fold-test");
        let profile = |state_dir: PathBuf| Profile::Codex {
            billing_domain: BillingDomain::ChatgptSubscription,
            auth: CodexAuth::ChatgptOauth,
            state_dir,
            secret_ref: None,
            account_hint: None,
            expected_workspace_id: None,
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: false,
        };

        let mut names = Config::default();
        names.profiles.insert(
            ProfileId::new(
                Provider::Codex,
                Name::parse("Work").unwrap_or_else(|error| panic!("name: {error}")),
            ),
            profile(root.join("Work")),
        );
        names.profiles.insert(
            ProfileId::new(
                Provider::Codex,
                Name::parse("work").unwrap_or_else(|error| panic!("name: {error}")),
            ),
            profile(root.join("work-elsewhere")),
        );
        let name_error = match names.validate() {
            Err(error) => error.to_string(),
            Ok(()) => panic!("case-folded profile names should be rejected"),
        };
        assert!(name_error.contains("ASCII case folding"));

        let mut directories = Config::default();
        directories.profiles.insert(
            ProfileId::new(
                Provider::Codex,
                Name::parse("first").unwrap_or_else(|error| panic!("name: {error}")),
            ),
            profile(root.join("VendorState")),
        );
        directories.profiles.insert(
            ProfileId::new(
                Provider::Codex,
                Name::parse("second").unwrap_or_else(|error| panic!("name: {error}")),
            ),
            profile(root.join("vendorstate")),
        );
        let directory_error = match directories.validate() {
            Err(error) => error.to_string(),
            Ok(()) => panic!("case-folded state directories should be rejected"),
        };
        assert!(directory_error.contains("ASCII-case-fold aliases"));
    }

    #[test]
    fn persisted_metadata_and_paths_reject_control_characters() {
        let root = std::env::temp_dir().join("aictx-model-control-test");
        let profile_id = ProfileId::new(
            Provider::Codex,
            Name::parse("work").unwrap_or_else(|error| panic!("name: {error}")),
        );
        let mut config = Config::default();
        config.profiles.insert(
            profile_id,
            Profile::Codex {
                billing_domain: BillingDomain::ChatgptSubscription,
                auth: CodexAuth::ChatgptOauth,
                state_dir: root.join("state"),
                secret_ref: None,
                account_hint: Some("visible\nterminal-control".to_owned()),
                expected_workspace_id: None,
                credential_store: CodexCredentialStore::File,
                trusted_runners_only: false,
            },
        );
        let Err(error) = config.validate() else {
            panic!("control characters in persisted profile metadata should be rejected");
        };
        assert!(error.to_string().contains("control characters"));

        let mut config = Config::default();
        config.binaries.codex = root.join("codex\u{1b}[31m");
        let Err(error) = config.validate() else {
            panic!("control characters in persisted paths should be rejected");
        };
        assert!(error.to_string().contains("control characters"));
    }
}
