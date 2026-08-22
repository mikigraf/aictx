use crate::automation::contracts::UtcTimestamp;

use super::records::replay_retain_until;

fn stamp(value: &str) -> UtcTimestamp {
    value
        .parse()
        .unwrap_or_else(|error| panic!("parse {value}: {error:?}"))
}

#[test]
fn local_seven_day_horizon_wins_with_fractional_precision() {
    let retained = replay_retain_until(
        &stamp("2026-08-22T10:00:02.123456789Z"),
        &stamp("2026-08-23T14:00:00Z"),
    )
    .unwrap_or_else(|error| panic!("retention: {error:?}"));
    assert_eq!(retained.as_str(), "2026-08-29T10:00:02.123456789Z");
}

#[test]
fn later_signed_expiry_is_retained_exactly() {
    let retained = replay_retain_until(
        &stamp("2026-08-22T10:00:02Z"),
        &stamp("2026-09-30T12:34:56.987654321Z"),
    )
    .unwrap_or_else(|error| panic!("retention: {error:?}"));
    assert_eq!(retained.as_str(), "2026-09-30T12:34:56.987654321Z");
}

#[test]
fn equal_horizons_remain_canonical_and_exact() {
    let retained = replay_retain_until(
        &stamp("2026-08-22T10:00:02.000000001Z"),
        &stamp("2026-08-29T10:00:02.000000001Z"),
    )
    .unwrap_or_else(|error| panic!("retention: {error:?}"));
    assert_eq!(retained.as_str(), "2026-08-29T10:00:02.000000001Z");
}
