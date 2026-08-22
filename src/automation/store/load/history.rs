use std::num::NonZeroU64;

use rusqlite::{Row, Transaction};

use crate::automation::{
    contracts::{ExecutionHandle, LeaseId, WorkerIdentity},
    lease::{LeaseSnapshot, ServiceClockGeneration},
};

use crate::automation::store::{
    StoreError,
    load_parse::{
        OptionalRawTimestamp, RawTimestamp, optional_timestamp, parse_fencing, parse_generation,
        required_timestamp,
    },
};

use super::LoadedLease;

pub(super) fn validate(
    transaction: &Transaction<'_>,
    loaded: &LoadedLease,
) -> Result<(), StoreError> {
    validate_capacity(transaction, loaded.snapshot.lease_id())?;
    validate_exited_processes(
        transaction,
        loaded.snapshot.lease_id(),
        &loaded.snapshot,
        loaded.origin_generation,
    )
}

fn validate_capacity(transaction: &Transaction<'_>, lease_id: &LeaseId) -> Result<(), StoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT state, reserved_at_utc, reserved_at_seconds, reserved_at_nanos,
                    released_at_utc, released_at_seconds, released_at_nanos
             FROM capacity_reservations WHERE lease_id = ?1 ORDER BY reservation_id",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let rows = statement
        .query_map([lease_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                required_timestamp(row, 1)?,
                optional_timestamp(row, 4)?,
            ))
        })
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    for (state, reserved_at, released_at) in rows {
        reserved_at.validate()?;
        let released_at = released_at.validate()?;
        if (state == "RELEASED") != released_at.is_some()
            || !matches!(
                state.as_str(),
                "HELD" | "RELEASED" | "QUARANTINED" | "RECOVERY_REQUIRED"
            )
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
    }
    Ok(())
}

fn validate_exited_processes(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    snapshot: &LeaseSnapshot,
    lease_generation: ServiceClockGeneration,
) -> Result<(), StoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT process_id, service_generation, process_id_number, process_identity,
                    execution_handle, worker_identity, observed_fencing_generation,
                    launch_intent_at_utc, launch_intent_at_seconds, launch_intent_at_nanos,
                    started_at_utc, started_at_seconds, started_at_nanos,
                    stop_requested_at_utc, stop_requested_at_seconds,
                    stop_requested_at_nanos, ended_at_utc, ended_at_seconds,
                    ended_at_nanos, exit_code
             FROM lease_processes
             WHERE lease_id = ?1 AND state = 'EXITED' ORDER BY process_id",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let rows = statement
        .query_map([lease_id.as_str()], RawExitedProcess::from_row)
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    for row in rows {
        row.validate(snapshot, lease_generation)?;
    }
    Ok(())
}

struct RawExitedProcess {
    process_id: String,
    service_generation: i64,
    process_id_number: Option<i64>,
    process_identity: Option<String>,
    execution_handle: String,
    worker_identity: Option<String>,
    observed_fencing_generation: Option<i64>,
    launch_intent_at: RawTimestamp,
    started_at: OptionalRawTimestamp,
    stop_requested_at: OptionalRawTimestamp,
    ended_at: OptionalRawTimestamp,
    exit_code: Option<i64>,
}

impl RawExitedProcess {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            process_id: row.get(0)?,
            service_generation: row.get(1)?,
            process_id_number: row.get(2)?,
            process_identity: row.get(3)?,
            execution_handle: row.get(4)?,
            worker_identity: row.get(5)?,
            observed_fencing_generation: row.get(6)?,
            launch_intent_at: required_timestamp(row, 7)?,
            started_at: optional_timestamp(row, 10)?,
            stop_requested_at: optional_timestamp(row, 13)?,
            ended_at: optional_timestamp(row, 16)?,
            exit_code: row.get(19)?,
        })
    }

    fn validate(
        self,
        snapshot: &LeaseSnapshot,
        lease_generation: ServiceClockGeneration,
    ) -> Result<(), StoreError> {
        if !valid_process_id(&self.process_id)
            || parse_generation(self.service_generation)? != lease_generation
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let process_id_number = self
            .process_id_number
            .map(|value| {
                u64::try_from(value)
                    .ok()
                    .and_then(NonZeroU64::new)
                    .ok_or(StoreError::IntegrityCheckFailed)
            })
            .transpose()?;
        if process_id_number.is_some() != self.process_identity.is_some()
            || self.process_identity.as_ref().is_some_and(|value| {
                value.contains('\0') || !(1..=256).contains(&value.chars().count())
            })
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let execution_handle = self
            .execution_handle
            .parse::<ExecutionHandle>()
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let worker_identity = self
            .worker_identity
            .as_deref()
            .map(str::parse::<WorkerIdentity>)
            .transpose()
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        snapshot
            .validate_process_binding(
                lease_generation,
                &execution_handle,
                worker_identity.as_ref(),
                parse_fencing(self.observed_fencing_generation)?,
            )
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        self.launch_intent_at.validate()?;
        if self.started_at.validate()?.is_none() || self.ended_at.validate()?.is_none() {
            return Err(StoreError::IntegrityCheckFailed);
        }
        self.stop_requested_at.validate()?;
        let _ = self.exit_code;
        Ok(())
    }
}

fn valid_process_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 34
        && bytes.starts_with(b"process_")
        && matches!(bytes[8], b'0'..=b'7')
        && bytes[8..].iter().all(|byte| {
            matches!(
                byte,
                b'0'..=b'9'
                    | b'A'..=b'H'
                    | b'J'
                    | b'K'
                    | b'M'
                    | b'N'
                    | b'P'..=b'T'
                    | b'V'..=b'Z'
            )
        })
}
