use std::{fmt, path::Path, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

use super::{Name, Provider};

const INSTALLATION_PREFIX: &str = "installation_";
const PROFILE_PREFIX: &str = "profile_";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DERIVATION_DOMAIN: &[u8] = b"ctxlane.profile-uid/v1\0";

/// An immutable, non-secret identity for one installed metadata store.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InstallationUid(String);

impl InstallationUid {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| {
            Error::InvalidConfig(
                "operating-system randomness is unavailable; refusing to create an installation identity"
                    .to_owned(),
            )
        })?;
        Ok(Self(format!(
            "{INSTALLATION_PREFIX}{}",
            encode_crockford(bytes)
        )))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        parse_uid(value.into(), INSTALLATION_PREFIX, "installation_uid").map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An immutable, non-secret profile identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileUid(String);

impl ProfileUid {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        parse_uid(value.into(), PROFILE_PREFIX, "profile_uid").map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derive a stable UID from an immutable managed storage identity.
    pub fn for_state_dir(
        installation_uid: &InstallationUid,
        provider: Provider,
        state_dir: &Path,
    ) -> Result<Self> {
        let state_leaf = state_dir
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "profile state_dir must have a valid UTF-8 leaf before deriving profile_uid"
                        .to_owned(),
                )
            })?;
        Name::parse(state_leaf).map_err(|_| {
            Error::InvalidConfig(
                "profile state_dir leaf must use the canonical managed-name grammar".to_owned(),
            )
        })?;
        let mut hasher = Sha256::new();
        hasher.update(DERIVATION_DOMAIN);
        hasher.update(installation_uid.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(provider.to_string().as_bytes());
        hasher.update([0]);
        // Managed state leaves are case-folded identities on supported filesystems. Hash the
        // same canonical form so a case-only spelling cannot bypass a retired UID tombstone.
        hasher.update(state_leaf.to_ascii_lowercase().as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Ok(Self(format!("{PROFILE_PREFIX}{}", encode_crockford(bytes))))
    }
}

fn parse_uid(value: String, prefix: &str, field: &str) -> Result<String> {
    let Some(encoded) = value.strip_prefix(prefix) else {
        return Err(invalid_uid(field, prefix));
    };
    let valid = encoded.len() == 26
        && encoded
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b'0'..=b'7'))
        && encoded.bytes().skip(1).all(|byte| {
            byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'
                )
        });
    if valid {
        Ok(value)
    } else {
        Err(invalid_uid(field, prefix))
    }
}

fn encode_crockford(bytes: [u8; 16]) -> String {
    let mut value = u128::from_be_bytes(bytes);
    let mut encoded = [b'0'; 26];
    for byte in encoded.iter_mut().rev() {
        *byte = CROCKFORD[(value & 0x1f) as usize];
        value >>= 5;
    }
    encoded.into_iter().map(char::from).collect()
}

fn invalid_uid(field: &str, prefix: &str) -> Error {
    Error::InvalidConfig(format!(
        "{field} must use `{prefix}` followed by a canonical 128-bit Crockford identifier"
    ))
}

macro_rules! string_wire {
    ($name:ident) => {
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
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_wire!(InstallationUid);
string_wire!(ProfileUid);

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn derived_uid_is_canonical_stable_and_storage_bound() {
        let installation = InstallationUid::parse("installation_01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap_or_else(|error| panic!("installation UID: {error}"));
        let other_installation = InstallationUid::parse("installation_01ARZ3NDEKTSV4RRFFQ69G5FB0")
            .unwrap_or_else(|error| panic!("installation UID: {error}"));
        let first = ProfileUid::for_state_dir(
            &installation,
            Provider::Codex,
            Path::new("/managed/codex/p-one"),
        )
        .unwrap_or_else(|error| panic!("derive UID: {error}"));
        let same = ProfileUid::for_state_dir(
            &installation,
            Provider::Codex,
            Path::new("/rebased/codex/p-one"),
        )
        .unwrap_or_else(|error| panic!("derive UID: {error}"));
        let case_alias = ProfileUid::for_state_dir(
            &installation,
            Provider::Codex,
            Path::new("/rebased/codex/P-ONE"),
        )
        .unwrap_or_else(|error| panic!("derive case-folded UID: {error}"));
        let other = ProfileUid::for_state_dir(
            &other_installation,
            Provider::Codex,
            Path::new("/managed/codex/p-one"),
        )
        .unwrap_or_else(|error| panic!("derive UID: {error}"));
        let other_provider = ProfileUid::for_state_dir(
            &installation,
            Provider::Claude,
            Path::new("/managed/claude/p-one"),
        )
        .unwrap_or_else(|error| panic!("derive provider UID: {error}"));
        let other_leaf = ProfileUid::for_state_dir(
            &installation,
            Provider::Codex,
            Path::new("/managed/codex/p-two"),
        )
        .unwrap_or_else(|error| panic!("derive leaf UID: {error}"));
        assert_eq!(first, same);
        assert_eq!(first, case_alias);
        assert_ne!(first, other);
        assert_ne!(first, other_provider);
        assert_ne!(first, other_leaf);
        assert!(ProfileUid::parse(first.to_string()).is_ok());
    }

    #[test]
    fn uid_parser_rejects_overflow_aliases_and_noncanonical_characters() {
        assert!(ProfileUid::parse("profile_71ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());
        for invalid in [
            "profile_81ARZ3NDEKTSV4RRFFQ69G5FAV",
            "profile_01ARZ3NDEKTSV4RRFFQ69G5FAI",
            "profile_01arz3ndektsv4rrffq69g5fav",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ] {
            assert!(ProfileUid::parse(invalid).is_err(), "accepted {invalid}");
        }
    }
}
