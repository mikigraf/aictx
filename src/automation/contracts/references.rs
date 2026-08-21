use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use super::types::{ContractValidationError, Provider};

fn valid_reference(value: &str, prefixes: &[&str]) -> bool {
    let Some((prefix, suffix)) = value.split_once(':') else {
        return false;
    };
    prefixes.contains(&prefix)
        && !suffix.contains(':')
        && !suffix.is_empty()
        && suffix.len() <= 128
        && suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

macro_rules! typed_reference {
    ($name:ident, $kind:literal, [$($prefix:literal),+ $(,)?]) => {
        #[doc = concat!("A typed, normalized ", $kind, " safe for public output.")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ContractValidationError> {
                let value = value.into();
                if valid_reference(&value, &[$($prefix),+]) {
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
                formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
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
                Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

typed_reference!(CallerSubject, "caller subject", ["caller"]);
typed_reference!(HostIdentity, "host identity", ["host"]);
typed_reference!(WorkerIdentity, "worker identity", ["worker"]);
typed_reference!(
    PrincipalRef,
    "provider principal reference",
    ["user", "service-account"]
);
typed_reference!(
    WorkspaceRef,
    "provider tenant reference",
    ["claude-organization", "chatgpt-workspace"]
);

impl WorkspaceRef {
    #[must_use]
    pub fn matches_provider(&self, provider: Provider) -> bool {
        match provider {
            Provider::Claude => self.0.starts_with("claude-organization:"),
            Provider::Codex => self.0.starts_with("chatgpt-workspace:"),
        }
    }
}
