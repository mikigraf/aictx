use rusqlite::{OptionalExtension, Transaction};

use crate::automation::{
    contracts::{CallerSubject, LeaseId},
    lease::ServiceClockGeneration,
};

use super::StoreError;

/// Compare only the raw caller column before any status, authority, request,
/// clock, process, or audit reconstruction. Missing and non-owner rows are
/// deliberately indistinguishable.
pub(super) fn caller_matches(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    caller: &CallerSubject,
) -> Result<bool, StoreError> {
    let caller_bytes = transaction
        .query_row(
            "SELECT CAST(l.authenticated_caller AS BLOB),
                    CAST(r.authenticated_caller AS BLOB)
             FROM leases l
             JOIN lease_requests r ON r.request_record_id = l.request_record_id
             WHERE l.lease_id = ?1",
            [lease_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                ))
            },
        )
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let expected = caller.as_str().as_bytes();
    Ok(matches!(
        caller_bytes,
        Some((Some(ref lease), Some(ref request)))
            if lease.as_slice() == expected && request.as_slice() == expected && lease == request
    ))
}

/// The sole foreign-caller mutation exception is an exact acknowledgement of
/// the current generation's unresolved RENEWING transition. Raw casts keep a
/// corrupt foreign row on the common denial path unless every gate is exact.
pub(super) fn foreign_exact_renewing_ack(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    expected_row_version: u64,
    generation: ServiceClockGeneration,
) -> Result<bool, StoreError> {
    if expected_row_version == 0 {
        return Ok(false);
    }
    let raw = transaction
        .query_row(
            "SELECT CAST(status AS TEXT), CAST(row_version AS INTEGER),
                    CAST(service_generation AS INTEGER), CAST(recovery_state AS TEXT),
                    CAST(quarantined AS INTEGER)
             FROM leases WHERE lease_id = ?1",
            [lease_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let Some((status, row_version, origin, recovery, quarantined)) = raw else {
        return Ok(false);
    };
    let expected = i64::try_from(expected_row_version).ok();
    let current = i64::try_from(generation.get()).ok();
    Ok(status.as_deref() == Some("RENEWING")
        && row_version == expected
        && origin == current
        && recovery.as_deref() == Some("NONE")
        && quarantined == Some(0))
}
