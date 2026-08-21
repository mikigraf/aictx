use std::path::PathBuf;

use thiserror::Error;

use crate::model::{ProfileId, Provider};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRecovery {
    Login,
    ClaudeSetupToken,
    ClaudeWif,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("ctxlane is not initialized")]
    NotInitialized,

    #[error("profile not found: {0}")]
    ProfileNotFound(String),

    #[error("context not found: {0}")]
    ContextNotFound(String),

    #[error("credential unavailable for {profile}: {reason}")]
    CredentialUnavailable { profile: String, reason: String },

    #[error("credential unavailable for {profile}: {reason}")]
    SelectedCredentialUnavailable {
        profile: ProfileId,
        reason: String,
        recovery: CredentialRecovery,
    },

    #[error("credential expired for {0}")]
    CredentialExpired(String),

    #[error("identity does not match the configured organization or workspace: {0}")]
    IdentityMismatch(String),

    #[error("interaction required: {0}")]
    InteractionRequired(String),

    #[error("security policy refused execution: {0}")]
    PolicyRefused(String),

    #[error("vendor CLI is unavailable or incompatible: {0}")]
    VendorIncompatible(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("configuration is busy; another ctxlane process is updating it")]
    ConfigBusy,

    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("terminal UI failed: {0}")]
    Terminal(#[source] std::io::Error),

    #[error("failed to parse TOML metadata in {path}: {source}")]
    ParseToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("failed to serialize TOML metadata: {0}")]
    SerializeToml(#[from] toml::ser::Error),

    #[error("credential store error: {0}")]
    CredentialStore(String),

    #[error("failed to start {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{program} terminated before accepting the credential")]
    CredentialPipe { program: String },

    #[error("operation cancelled")]
    Cancelled,

    #[error("operation interrupted")]
    Interrupted(u8),
}

impl Error {
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::ProfileNotFound(_) | Self::ContextNotFound(_) => 10,
            Self::CredentialUnavailable { .. }
            | Self::SelectedCredentialUnavailable { .. }
            | Self::CredentialStore(_) => 11,
            Self::CredentialExpired(_) => 12,
            Self::IdentityMismatch(_) => 13,
            Self::InteractionRequired(_) => 14,
            Self::PolicyRefused(_) => 15,
            Self::VendorIncompatible(_) | Self::Spawn { .. } => 16,
            Self::Interrupted(exit_code) => *exit_code,
            Self::NotInitialized
            | Self::InvalidInput(_)
            | Self::InvalidConfig(_)
            | Self::ConfigBusy
            | Self::ReadFile { .. }
            | Self::WriteFile { .. }
            | Self::CreateDir { .. }
            | Self::Terminal(_)
            | Self::ParseToml { .. }
            | Self::SerializeToml(_)
            | Self::CredentialPipe { .. }
            | Self::Cancelled => 2,
        }
    }

    /// Return a short recovery action for errors that a user can address.
    #[must_use]
    pub fn hint(&self) -> Option<String> {
        let hint = match self {
            Self::NotInitialized => {
                "Run `ctxlane init` to create the local metadata store.".to_owned()
            }
            Self::ProfileNotFound(_) => {
                "Run `ctxlane profile list` to see the configured profile IDs.".to_owned()
            }
            Self::ContextNotFound(_) => {
                "Run `ctxlane context list` to see the configured context names.".to_owned()
            }
            Self::CredentialUnavailable { profile, .. } | Self::CredentialExpired(profile) => {
                login_hint(profile)
            }
            Self::SelectedCredentialUnavailable {
                profile, recovery, ..
            } => selected_credential_hint(profile, *recovery),
            Self::IdentityMismatch(_) => {
                "Run `ctxlane profile show <provider:name>`, verify the expected organization or workspace, then log in again."
                    .to_owned()
            }
            Self::InteractionRequired(_) => {
                "Retry from an interactive terminal without `--non-interactive`, or use an automation-safe authentication mode."
                    .to_owned()
            }
            Self::PolicyRefused(_) => {
                "Correct the reported unsafe setting, path, or argument, then retry.".to_owned()
            }
            Self::VendorIncompatible(_) | Self::Spawn { .. } | Self::CredentialPipe { .. } => {
                "Install or update the official vendor CLI, verify its path, then run `ctxlane doctor`."
                    .to_owned()
            }
            Self::InvalidInput(_) => {
                "Run the command with `--help` and correct the reported value.".to_owned()
            }
            Self::InvalidConfig(_) | Self::ParseToml { .. } | Self::SerializeToml(_) => {
                "Run `ctxlane doctor` and fix the reported local metadata problem.".to_owned()
            }
            Self::ConfigBusy => {
                "Wait for the other `ctxlane` process to finish, then retry.".to_owned()
            }
            Self::ReadFile { .. } | Self::WriteFile { .. } | Self::CreateDir { .. } => {
                "Check the reported path and permissions, then run `ctxlane doctor`.".to_owned()
            }
            Self::Terminal(_) => "Retry from an interactive terminal.".to_owned(),
            Self::CredentialStore(_) => {
                "Unlock the OS keyring and retry. If the error continues, run `ctxlane doctor`."
                    .to_owned()
            }
            Self::Cancelled | Self::Interrupted(_) => return None,
        };
        Some(hint)
    }

    /// Render the complete CLI error without emitting terminal control characters.
    #[must_use]
    pub fn render_for_terminal(&self) -> String {
        let mut output = format!("ctxlane: {}", terminal_safe(&self.primary_message()));
        if let Some(hint) = self.hint() {
            output.push_str("\nHint: ");
            output.push_str(&terminal_safe(&hint));
        }
        output
    }

    fn primary_message(&self) -> String {
        match self {
            Self::CredentialUnavailable {
                profile, reason, ..
            } if profile.parse::<ProfileId>().is_err() => {
                format!("credential unavailable: {reason}")
            }
            _ => self.to_string(),
        }
    }

    pub(crate) fn for_selected_credential(
        self,
        profile: &ProfileId,
        recovery: CredentialRecovery,
    ) -> Self {
        match self {
            Self::CredentialUnavailable { reason, .. } => Self::SelectedCredentialUnavailable {
                profile: profile.clone(),
                reason,
                recovery,
            },
            error => error,
        }
    }
}

fn selected_credential_hint(profile: &ProfileId, recovery: CredentialRecovery) -> String {
    match recovery {
        CredentialRecovery::Login => {
            format!("Run `ctxlane login {profile}` to store or refresh this credential.")
        }
        CredentialRecovery::ClaudeSetupToken
            if profile.provider() == Provider::Claude && profile.name().as_str() == "personal" =>
        {
            "Run `ctxlane login claude:personal --generate` to create and store a new Claude setup token. You can also repair the default personal setup with `ctxlane init --guided`."
                .to_owned()
        }
        CredentialRecovery::ClaudeSetupToken => {
            format!(
                "Run `ctxlane login {profile} --generate` to create and store a new Claude setup token."
            )
        }
        CredentialRecovery::ClaudeWif => {
            format!(
                "Run `ctxlane profile show {profile}`, verify its configured WIF identity-token file, then try again."
            )
        }
    }
}

fn login_hint(profile: &str) -> String {
    if profile.parse::<ProfileId>().is_ok() {
        format!("Run `ctxlane login {profile}` to store or refresh this credential.")
    } else {
        "Run `ctxlane login <provider:name>` for the affected profile, then try again.".to_owned()
    }
}

fn terminal_safe(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(value: &str) -> ProfileId {
        value
            .parse()
            .unwrap_or_else(|error| panic!("parse test profile: {error}"))
    }

    #[test]
    fn selected_claude_subscription_hints_use_the_safe_profile_id() {
        let opaque_handle = "private-keyring-account-canary";
        let missing = Error::CredentialUnavailable {
            profile: format!("keyring account {opaque_handle}"),
            reason: "no credential is stored".to_owned(),
        };
        let rendered = missing
            .for_selected_credential(
                &profile("claude:work"),
                CredentialRecovery::ClaudeSetupToken,
            )
            .render_for_terminal();

        assert!(rendered.contains("credential unavailable for claude:work"));
        assert!(rendered.contains("`ctxlane login claude:work --generate`"));
        assert!(!rendered.contains(opaque_handle));
    }

    #[test]
    fn personal_claude_subscription_uses_the_guided_recovery_flow() {
        let rendered = Error::CredentialUnavailable {
            profile: "OS keyring".to_owned(),
            reason: "stored credential is empty".to_owned(),
        }
        .for_selected_credential(
            &profile("claude:personal"),
            CredentialRecovery::ClaudeSetupToken,
        )
        .render_for_terminal();

        assert!(rendered.contains("credential unavailable for claude:personal"));
        assert!(rendered.contains("`ctxlane login claude:personal --generate`"));
        assert!(rendered.contains("`ctxlane init --guided`"));
        assert!(!rendered.contains("OS keyring"));
    }

    #[test]
    fn selected_api_credentials_use_exact_login_without_generation() {
        let error = Error::CredentialUnavailable {
            profile: "OS keyring".to_owned(),
            reason: "no credential is stored".to_owned(),
        }
        .for_selected_credential(&profile("codex:work"), CredentialRecovery::Login);
        let rendered = error.render_for_terminal();

        assert_eq!(error.exit_code(), 11);
        assert!(rendered.contains("credential unavailable for codex:work"));
        assert!(rendered.contains("`ctxlane login codex:work`"));
        assert!(!rendered.contains("--generate"));
    }
}
