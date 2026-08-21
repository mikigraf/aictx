use std::time::Duration;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::LeaseDomainError;
use crate::automation::contracts::UtcTimestamp;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Opaque elapsed-runtime time from one local monotonic clock epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMoment(u128);

impl MonotonicMoment {
    #[must_use]
    pub fn from_duration_since_epoch(value: Duration) -> Self {
        Self(value.as_nanos())
    }

    #[must_use]
    pub const fn from_nanoseconds(value: u128) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_nanoseconds(self) -> u128 {
        self.0
    }

    pub(super) fn checked_add_nanoseconds(self, value: u128) -> Option<Self> {
        self.0.checked_add(value).map(Self)
    }

    pub(super) fn checked_add_seconds(self, value: u64) -> Option<Self> {
        self.checked_add_nanoseconds(u128::from(value) * NANOS_PER_SECOND)
    }
}

/// One wall/monotonic observation from the same service clock sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockSample {
    pub(super) wall: UtcTimestamp,
    pub(super) monotonic: MonotonicMoment,
}

impl ClockSample {
    #[must_use]
    pub const fn new(wall: UtcTimestamp, monotonic: MonotonicMoment) -> Self {
        Self { wall, monotonic }
    }

    #[must_use]
    pub const fn wall(&self) -> &UtcTimestamp {
        &self.wall
    }

    #[must_use]
    pub const fn monotonic(&self) -> MonotonicMoment {
        self.monotonic
    }
}

pub(super) fn add_seconds(
    value: &UtcTimestamp,
    seconds: u64,
) -> Result<UtcTimestamp, LeaseDomainError> {
    let seconds = i64::try_from(seconds).map_err(|_| LeaseDomainError::ClockOverflow)?;
    let instant = parse_wall(value)?
        .checked_add(time::Duration::seconds(seconds))
        .ok_or(LeaseDomainError::ClockOverflow)?;
    UtcTimestamp::parse(canonical_utc(instant)).map_err(|_| LeaseDomainError::ClockOverflow)
}

pub(super) fn wall_nanoseconds_between(
    earlier: &UtcTimestamp,
    later: &UtcTimestamp,
) -> Result<u128, LeaseDomainError> {
    let difference = parse_wall(later)? - parse_wall(earlier)?;
    u128::try_from(difference.whole_nanoseconds()).map_err(|_| LeaseDomainError::ClockOverflow)
}

pub(super) fn earlier<'a>(left: &'a UtcTimestamp, right: &'a UtcTimestamp) -> &'a UtcTimestamp {
    if left.is_before(right) { left } else { right }
}

pub(super) fn later<'a>(left: &'a UtcTimestamp, right: &'a UtcTimestamp) -> &'a UtcTimestamp {
    if left.is_before(right) { right } else { left }
}

pub(super) fn deadline_reached(
    now: &ClockSample,
    wall: &UtcTimestamp,
    monotonic: MonotonicMoment,
) -> bool {
    !now.wall.is_before(wall) || now.monotonic >= monotonic
}

fn parse_wall(value: &UtcTimestamp) -> Result<OffsetDateTime, LeaseDomainError> {
    OffsetDateTime::parse(value.as_str(), &Rfc3339).map_err(|_| LeaseDomainError::ClockOverflow)
}

fn canonical_utc(value: OffsetDateTime) -> String {
    let mut output = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    );
    let nanos = value.nanosecond();
    if nanos != 0 {
        let fraction = format!("{nanos:09}");
        output.push('.');
        output.push_str(fraction.trim_end_matches('0'));
    }
    output.push('Z');
    output
}
