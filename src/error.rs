use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("aictx is not initialized; run `aictx init` first")]
    NotInitialized,

    #[error("profile not found: {0}")]
    ProfileNotFound(String),

    #[error("context not found: {0}")]
    ContextNotFound(String),

    #[error("credential unavailable for {profile}: {reason}")]
    CredentialUnavailable { profile: String, reason: String },

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

    #[error("configuration is busy; another aictx process is updating it")]
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
}

impl Error {
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::ProfileNotFound(_) | Self::ContextNotFound(_) => 10,
            Self::CredentialUnavailable { .. } | Self::CredentialStore(_) => 11,
            Self::CredentialExpired(_) => 12,
            Self::IdentityMismatch(_) => 13,
            Self::InteractionRequired(_) => 14,
            Self::PolicyRefused(_) => 15,
            Self::VendorIncompatible(_) | Self::Spawn { .. } => 16,
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
}
