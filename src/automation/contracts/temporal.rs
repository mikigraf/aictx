use std::{fmt, num::NonZeroU64, str::FromStr};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{integer::deserialize_bounded_u64, types::ContractValidationError};

macro_rules! positive_seconds {
    ($name:ident, $error:expr, $maximum:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name(NonZeroU64);

        impl $name {
            pub fn from_seconds(value: u64) -> Result<Self, ContractValidationError> {
                let Some(value) = NonZeroU64::new(value) else {
                    return Err($error);
                };
                if $maximum.is_some_and(|maximum| value.get() > maximum) {
                    return Err($error);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_u64(self.get())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let maximum = $maximum.unwrap_or(u64::MAX);
                Self::from_seconds(deserialize_bounded_u64(deserializer, 1, maximum)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

positive_seconds!(
    RequestedTtlSeconds,
    ContractValidationError::InvalidRequestedTtl,
    Some(86_400)
);
positive_seconds!(
    MaximumTtlSeconds,
    ContractValidationError::InvalidMaximumTtl,
    Some(86_400)
);
positive_seconds!(
    DurationSeconds,
    ContractValidationError::InvalidDuration,
    Some(u64::from(u32::MAX))
);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FencingGeneration(NonZeroU64);

impl FencingGeneration {
    pub const MAXIMUM: u64 = 9_007_199_254_740_991;

    pub fn from_value(value: u64) -> Result<Self, ContractValidationError> {
        let Some(value) = NonZeroU64::new(value) else {
            return Err(ContractValidationError::InvalidFencingGeneration);
        };
        if value.get() > Self::MAXIMUM {
            return Err(ContractValidationError::InvalidFencingGeneration);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl Serialize for FencingGeneration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for FencingGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::from_value(deserialize_bounded_u64(deserializer, 1, Self::MAXIMUM)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct UtcTimestamp {
    wire: String,
    instant: OffsetDateTime,
}

impl UtcTimestamp {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractValidationError> {
        let wire = value.into();
        if !canonical_utc_shape(&wire) {
            return Err(ContractValidationError::InvalidUtcTimestamp);
        }
        let instant = OffsetDateTime::parse(&wire, &Rfc3339)
            .map_err(|_| ContractValidationError::InvalidUtcTimestamp)?;
        if instant.offset() != UtcOffset::UTC {
            return Err(ContractValidationError::InvalidUtcTimestamp);
        }
        Ok(Self { wire, instant })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.wire
    }

    #[must_use]
    pub fn is_before(&self, other: &Self) -> bool {
        self.instant < other.instant
    }

    #[must_use]
    pub fn is_after(&self, other: &Self) -> bool {
        self.instant > other.instant
    }

    pub(super) fn seconds_until(&self, other: &Self) -> Option<u64> {
        u64::try_from((other.instant - self.instant).whole_seconds()).ok()
    }
}

fn canonical_utc_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes.last() != Some(&b'Z')
        || !bytes[0..4].iter().all(u8::is_ascii_digit)
        || &bytes[0..4] == b"0000"
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
        || !bytes[11..13].iter().all(u8::is_ascii_digit)
        || !bytes[14..16].iter().all(u8::is_ascii_digit)
        || !bytes[17..19].iter().all(u8::is_ascii_digit)
        || (bytes[17] == b'6' && bytes[18] == b'0')
    {
        return false;
    }
    let suffix = &bytes[19..bytes.len() - 1];
    suffix.is_empty()
        || (suffix.len() >= 2
            && suffix.len() <= 10
            && suffix[0] == b'.'
            && suffix[1..].iter().all(u8::is_ascii_digit))
}

impl fmt::Debug for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UtcTimestamp")
            .field(&self.wire)
            .finish()
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.wire)
    }
}

impl FromStr for UtcTimestamp {
    type Err = ContractValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.wire)
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
