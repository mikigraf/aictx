use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use crate::model::Provider;

pub const IDENTITY_LEASE_REQUEST_SCHEMA: &str = "ctxlane.identity-lease-request/v1";
pub const IDENTITY_LEASE_SCHEMA: &str = "ctxlane.identity-lease/v1";
pub const WORK_ORDER_AUTHORIZATION_SCHEMA: &str = "ctxlane.work-order-authorization/v1";
pub const READINESS_SCHEMA: &str = "ctxlane.automation-readiness/v1";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractValidationError {
    #[error("invalid {kind}; expected a non-secret, log-safe identifier")]
    InvalidIdentifier { kind: &'static str },

    #[error("invalid SHA-256 digest; expected `sha256:` and 64 lowercase hexadecimal digits")]
    InvalidSha256Digest,

    #[error("invalid Ed25519 signature encoding")]
    InvalidEd25519Signature,

    #[error("invalid UTC timestamp; expected a real RFC 3339 calendar date with a `Z` offset")]
    InvalidUtcTimestamp,

    #[error("requested TTL must be between 1 and 86400 seconds")]
    InvalidRequestedTtl,

    #[error("maximum TTL must be between 1 and 86400 seconds")]
    InvalidMaximumTtl,

    #[error("duration must be between 1 and 4294967295 seconds")]
    InvalidDuration,

    #[error("fencing generation must be between 1 and 9007199254740991")]
    InvalidFencingGeneration,

    #[error("signed work-order `not_before` must be earlier than `expires_at`")]
    InvalidAuthorizationValidity,

    #[error(
        "signed lifetime limits are inconsistent or exceed the authorization validity interval"
    )]
    InvalidAuthorizationLimits,

    #[error("request field `{field}` does not match its signed work-order authorization")]
    WorkOrderAuthorizationMismatch { field: &'static str },

    #[error("requested TTL exceeds the signed work-order maximum")]
    RequestedTtlExceedsAuthorization,

    #[error("requested TTL would outlive the signed work-order validity interval")]
    RequestedTtlExceedsAuthorizationValidity,

    #[error("signed work-order authorization is not valid yet")]
    AuthorizationNotYetValid,

    #[error("signed work-order authorization has expired")]
    AuthorizationExpired,

    #[error("profile reference provider does not match the provider field")]
    ProviderProfileMismatch,

    #[error("invalid identity-lease response invariant: {0}")]
    InvalidResponseInvariant(&'static str),
}

/// Failure to validate or canonically encode an authority-bearing contract.
#[derive(Debug, Error)]
pub enum ContractEncodingError {
    #[error(transparent)]
    Validation(#[from] ContractValidationError),

    #[error("failed to encode canonical JSON: {0}")]
    Json(#[from] serde_json::Error),
}

macro_rules! fixed_schema {
    ($name:ident, $value:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
        pub struct $name;

        impl $name {
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                $value
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str($value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if String::deserialize(deserializer)? == $value {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(concat!(
                        "unsupported ",
                        $description
                    )))
                }
            }
        }
    };
}

fixed_schema!(
    IdentityLeaseRequestSchema,
    IDENTITY_LEASE_REQUEST_SCHEMA,
    "identity-lease request schema; expected v1"
);
fixed_schema!(
    IdentityLeaseSchema,
    IDENTITY_LEASE_SCHEMA,
    "identity-lease response schema; expected v1"
);
fixed_schema!(
    WorkOrderAuthorizationSchema,
    WORK_ORDER_AUTHORIZATION_SCHEMA,
    "work-order authorization schema; expected v1"
);
fixed_schema!(
    ReadinessSchema,
    READINESS_SCHEMA,
    "automation readiness schema; expected v1"
);

fn valid_safe_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'+')
        })
}

macro_rules! safe_id {
    ($name:ident, $kind:literal, $maximum:expr) => {
        #[doc = concat!("A validated, non-secret ", $kind, " safe for logs.")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ContractValidationError> {
                let value = value.into();
                if valid_safe_id(&value, $maximum) {
                    Ok(Self(value))
                } else {
                    Err(ContractValidationError::InvalidIdentifier { kind: $kind })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ContractValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

safe_id!(ClientRequestId, "client request ID", 128);
safe_id!(TenantId, "tenant ID", 128);
safe_id!(WorkOrderId, "work-order ID", 128);
safe_id!(RunId, "run ID", 128);
safe_id!(AttemptId, "attempt ID", 128);
safe_id!(WorkspaceId, "workspace ID", 128);
safe_id!(EnvironmentName, "environment name", 128);
safe_id!(KeyId, "work-order signing key ID", 128);

/// A namespaced logical repository identity, never a filesystem path.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryId(String);

impl RepositoryId {
    /// Parse `namespace:segment[/segment...]` with no empty or traversal segment.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractValidationError> {
        let value = value.into();
        let valid = value.len() <= 256
            && value
                .split_once(':')
                .is_some_and(|(namespace, repository)| {
                    valid_repository_segment(namespace, 64)
                        && !repository.is_empty()
                        && repository.split('/').all(|segment| {
                            !matches!(segment, "" | "." | "..")
                                && valid_repository_segment(segment, 128)
                        })
                });
        if valid {
            Ok(Self(value))
        } else {
            Err(ContractValidationError::InvalidIdentifier {
                kind: "repository identity",
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_repository_segment(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'+')
        })
}

impl fmt::Debug for RepositoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RepositoryId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for RepositoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RepositoryId {
    type Err = ContractValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for RepositoryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RepositoryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn valid_crockford_ulid(value: &str, prefix: &str) -> bool {
    let Some(ulid) = value.strip_prefix(prefix) else {
        return false;
    };
    ulid.len() == 26
        && ulid
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b'0'..=b'7'))
        && ulid.bytes().skip(1).all(|byte| {
            byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'
                )
        })
}

macro_rules! service_id {
    ($name:ident, $kind:literal, $prefix:literal) => {
        #[doc = concat!("A typed opaque ", $kind, " containing a Crockford ULID-shaped value.")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ContractValidationError> {
                let value = value.into();
                if valid_crockford_ulid(&value, $prefix) {
                    Ok(Self(value))
                } else {
                    Err(ContractValidationError::InvalidIdentifier { kind: $kind })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ContractValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

service_id!(LeaseId, "lease ID", "lease_");
service_id!(ProfileUid, "profile UID", "profile_");
service_id!(ExecutionHandle, "execution handle", "exec_");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileRef {
    provider: Provider,
    value: String,
}

impl ProfileRef {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractValidationError> {
        let value = value.into();
        let Some((provider, name)) = value.split_once(':') else {
            return Err(ContractValidationError::InvalidIdentifier {
                kind: "profile reference",
            });
        };
        let provider = match provider {
            "claude" => Provider::Claude,
            "codex" => Provider::Codex,
            _ => {
                return Err(ContractValidationError::InvalidIdentifier {
                    kind: "profile reference",
                });
            }
        };
        let valid_name = !name.is_empty()
            && name.len() <= 64
            && name
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if !valid_name {
            return Err(ContractValidationError::InvalidIdentifier {
                kind: "profile reference",
            });
        }
        Ok(Self { provider, value })
    }

    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for ProfileRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProfileRef")
            .field(&self.value)
            .finish()
    }
}

impl fmt::Display for ProfileRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl FromStr for ProfileRef {
    type Err = ContractValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for ProfileRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.value)
    }
}

impl<'de> Deserialize<'de> for ProfileRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    #[must_use]
    pub fn hash(value: impl AsRef<[u8]>) -> Self {
        let output = Sha256::digest(value.as_ref());
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&output);
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn encoded(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(71);
        value.push_str("sha256:");
        for byte in self.0 {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        value
    }
}

impl FromStr for Sha256Digest {
    type Err = ContractValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(ContractValidationError::InvalidSha256Digest);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ContractValidationError::InvalidSha256Digest);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(pair[0]).ok_or(ContractValidationError::InvalidSha256Digest)?;
            let low = decode_hex(pair[1]).ok_or(ContractValidationError::InvalidSha256Digest)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.encoded())
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encoded())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encoded())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkOrderProofAlgorithm {
    Ed25519,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DetachedSignature(String);

impl DetachedSignature {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractValidationError> {
        let value = value.into();
        let valid = value.len() == 86
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && value
                .as_bytes()
                .last()
                .is_some_and(|byte| matches!(byte, b'A' | b'Q' | b'g' | b'w'));
        if valid {
            Ok(Self(value))
        } else {
            Err(ContractValidationError::InvalidEd25519Signature)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DetachedSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DetachedSignature([redacted])")
    }
}

impl Serialize for DetachedSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DetachedSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentRole {
    Implementer,
    LocalReviewer,
    PrReviewer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseStatus {
    Requested,
    Active,
    Renewing,
    Closed,
    Revoked,
    Expired,
    Refused,
    Error,
}

impl LeaseStatus {
    pub(super) const fn permits_execution_handle(self) -> bool {
        matches!(self, Self::Active | Self::Renewing)
    }

    pub(super) const fn requires_resolution(self) -> bool {
        matches!(
            self,
            Self::Active
                | Self::Renewing
                | Self::Closed
                | Self::Revoked
                | Self::Expired
                | Self::Error
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationClassification {
    CredentialIsolated,
    PerLeaseIsolated,
    CopiedCredentialDevelopment,
    Unproven,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessStatus {
    Pass,
    Warn,
    Fail,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeCost {
    None,
    ProviderRequestPossible,
    ProviderRequestIncurred,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutomationAuthMode {
    Wif,
    SubscriptionToken,
    ApiKey,
    ChatgptOauth,
    AccessToken,
}

impl AutomationAuthMode {
    #[must_use]
    pub const fn supports_provider(self, provider: Provider) -> bool {
        match provider {
            Provider::Claude => {
                matches!(self, Self::Wif | Self::SubscriptionToken | Self::ApiKey)
            }
            Provider::Codex => matches!(
                self,
                Self::Wif | Self::ChatgptOauth | Self::ApiKey | Self::AccessToken
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalCode {
    WorkOrderProofInvalid,
    WorkOrderAuthorizationMismatch,
    RequestedTtlNotAllowed,
    PolicyDigestMismatch,
    ProfileNotFound,
    ProviderMismatch,
    ProfileNotEligible,
    AuthenticationExceptionRequired,
    IsolationExceptionRequired,
    EnvironmentNotAllowed,
    RoleNotAllowed,
    CallerNotAllowed,
    RepositoryNotAllowed,
    ProfileNotReady,
    IdentityTokenStale,
    HarnessUntrusted,
    PrincipalUnverified,
    PrincipalMismatch,
    OrganizationMismatch,
    WorkspaceMismatch,
    IsolationUnproven,
    CapacityExceeded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseReasonCode {
    Completed,
    WorkerFailed,
    OperatorRevoked,
    PolicyRevoked,
    PrincipalMismatch,
    LeaseExpired,
    MaximumLifetimeReached,
    HeartbeatLost,
    ProcessUnverifiable,
    GenerationSuperseded,
    RenewalAcknowledgementFailed,
    ServiceRecovery,
    InternalError,
}
