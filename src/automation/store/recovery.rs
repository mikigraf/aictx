use std::num::{NonZeroU32, NonZeroU64};

use rusqlite::{Row, Transaction, params};

use crate::automation::{
    contracts::{ExecutionHandle, FencingGeneration, LeaseId, WorkerIdentity},
    lease::{LeaseSnapshot, ServiceClockGeneration},
};

use super::{
    StoreError,
    load::{self, LoadedLease, audit::ProcessAuditProjection},
    load_parse::{
        OptionalRawTimestamp, RawTimestamp, RecoveryState, optional_timestamp, required_timestamp,
    },
    recovery_types::{
        CapacityDimension, CapacityEvidence, CapacityState, ProcessEvidence, ProcessState,
        RecoveryCandidate, RecoveryCursor, RecoveryLeaseState, RecoveryPage, RecoveryPageRequest,
    },
};

pub(super) fn enumerate(
    transaction: &Transaction<'_>,
    current_generation: ServiceClockGeneration,
    page: &RecoveryPageRequest,
) -> Result<RecoveryPage, StoreError> {
    let after = page.after.as_ref().map_or("", |cursor| cursor.0.as_str());
    let query_limit = i64::from(page.limit) + 1;
    let mut statement = transaction
        .prepare(
            "SELECT l.lease_id
             FROM leases l
             WHERE l.lease_id > ?1
               AND (
                    l.status IN ('REQUESTED', 'ACTIVE', 'RENEWING', 'ERROR')
                    OR l.recovery_state <> 'NONE'
                    OR l.quarantined = 1
                    OR EXISTS(
                        SELECT 1 FROM capacity_reservations c
                        WHERE c.lease_id = l.lease_id AND c.state <> 'RELEASED'
                    )
                    OR EXISTS(
                        SELECT 1 FROM lease_processes p
                        WHERE p.lease_id = l.lease_id AND p.state <> 'EXITED'
                    )
               )
             ORDER BY l.lease_id
             LIMIT ?2",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let mut lease_ids = statement
        .query_map(params![after, query_limit], |row| row.get::<_, String>(0))
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let has_more = lease_ids.len() > usize::from(page.limit);
    if has_more {
        lease_ids.pop();
    }
    let mut candidates = Vec::with_capacity(lease_ids.len());
    for lease_id in lease_ids {
        let loaded =
            load::lease_by_id(transaction, &lease_id)?.ok_or(StoreError::IntegrityCheckFailed)?;
        candidates.push(build_candidate(transaction, current_generation, loaded)?);
    }
    let next_cursor = if has_more {
        candidates
            .last()
            .map(|candidate| RecoveryCursor(candidate.lease_id.clone()))
    } else {
        None
    };
    Ok(RecoveryPage {
        candidates,
        next_cursor,
    })
}

fn build_candidate(
    transaction: &Transaction<'_>,
    current_generation: ServiceClockGeneration,
    loaded: LoadedLease,
) -> Result<RecoveryCandidate, StoreError> {
    let lease_id = loaded
        .lease
        .identity_response()
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .lease_id;
    let processes = process_evidence(
        transaction,
        &lease_id,
        &loaded.snapshot,
        loaded.origin_generation,
        &loaded.process_audit,
    )?;
    Ok(RecoveryCandidate {
        status: loaded.lease.status(),
        recovery_state: match loaded.recovery_state {
            RecoveryState::None => RecoveryLeaseState::None,
            RecoveryState::Required => RecoveryLeaseState::Required,
            RecoveryState::Reconciling => RecoveryLeaseState::Reconciling,
        },
        quarantined: loaded.quarantined,
        origin_generation: loaded.origin_generation,
        current_generation,
        lease_row_version: loaded.row_version,
        clock_row_version: loaded.clock_row_version,
        capacity: capacity_evidence(transaction, &lease_id)?,
        processes,
        snapshot: loaded.snapshot,
        lease_id,
    })
}

fn capacity_evidence(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
) -> Result<Vec<CapacityEvidence>, StoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT state, capacity_dimension, capacity_limit, slot
             FROM capacity_reservations
             WHERE lease_id = ?1 AND state <> 'RELEASED'
             ORDER BY capacity_dimension, reservation_id",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    statement
        .query_map([lease_id.as_str()], |row| {
            let state = row.get::<_, String>(0)?;
            let dimension = row.get::<_, String>(1)?;
            let limit = row.get::<_, i64>(2)?;
            let slot = row.get::<_, i64>(3)?;
            Ok((state, dimension, limit, slot))
        })
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .map(|row| {
            let (state, dimension, limit, slot) =
                row.map_err(|_| StoreError::IntegrityCheckFailed)?;
            Ok(CapacityEvidence {
                state: parse_capacity_state(&state)?,
                dimension: parse_capacity_dimension(&dimension)?,
                limit: u32::try_from(limit)
                    .ok()
                    .and_then(NonZeroU32::new)
                    .ok_or(StoreError::IntegrityCheckFailed)?,
                slot: u64::try_from(slot)
                    .ok()
                    .and_then(NonZeroU64::new)
                    .ok_or(StoreError::IntegrityCheckFailed)?,
            })
        })
        .collect()
}

fn process_evidence(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    snapshot: &LeaseSnapshot,
    lease_generation: ServiceClockGeneration,
    process_audit: &ProcessAuditProjection,
) -> Result<Vec<ProcessEvidence>, StoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT process_id, state, service_generation, process_id_number,
                    process_identity, execution_handle, worker_identity,
                    observed_fencing_generation,
                    launch_intent_at_utc, launch_intent_at_seconds, launch_intent_at_nanos,
                    started_at_utc, started_at_seconds, started_at_nanos,
                    stop_requested_at_utc, stop_requested_at_seconds,
                    stop_requested_at_nanos,
                    ended_at_utc, ended_at_seconds, ended_at_nanos, exit_code
             FROM lease_processes
             WHERE lease_id = ?1 AND state <> 'EXITED'
             ORDER BY process_id",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let evidence = statement
        .query_map([lease_id.as_str()], RawProcess::from_row)
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .map(|row| {
            row.map_err(|_| StoreError::IntegrityCheckFailed)?
                .validate(snapshot, lease_generation)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if process_evidence_matches_audit(&evidence, process_audit) {
        Ok(evidence)
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

pub(super) fn validate_live_process_evidence(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    snapshot: &LeaseSnapshot,
    lease_generation: ServiceClockGeneration,
    process_audit: &ProcessAuditProjection,
) -> Result<(), StoreError> {
    process_evidence(
        transaction,
        lease_id,
        snapshot,
        lease_generation,
        process_audit,
    )
    .map(|_| ())
}

fn process_evidence_matches_audit(
    evidence: &[ProcessEvidence],
    audit: &ProcessAuditProjection,
) -> bool {
    match (audit, evidence) {
        (ProcessAuditProjection::None, []) => true,
        (
            ProcessAuditProjection::LaunchIntent {
                launch_intent_at,
                observed_fence,
            },
            [process],
        ) => {
            process.launch_intent_at == *launch_intent_at
                && process.started_at.is_none()
                && process.observed_fencing_generation.get() == *observed_fence
                && matches!(
                    process.state,
                    ProcessState::LaunchIntent
                        | ProcessState::Starting
                        | ProcessState::Quarantined
                        | ProcessState::RecoveryRequired
                )
        }
        (
            ProcessAuditProjection::Started {
                launch_intent_at,
                started_at,
                observed_fence,
            },
            [process],
        ) => {
            process.launch_intent_at == *launch_intent_at
                && process.started_at.as_ref() == Some(started_at)
                && process.observed_fencing_generation.get() == *observed_fence
                && matches!(
                    process.state,
                    ProcessState::Running
                        | ProcessState::Stopping
                        | ProcessState::Quarantined
                        | ProcessState::RecoveryRequired
                )
        }
        _ => false,
    }
}

struct RawProcess {
    process_record_id: String,
    state: String,
    service_generation: i64,
    process_id_number: Option<i64>,
    process_identity: Option<String>,
    execution_handle: String,
    worker_identity: Option<String>,
    observed_fencing_generation: i64,
    launch_intent_at: RawTimestamp,
    started_at: OptionalRawTimestamp,
    stop_requested_at: OptionalRawTimestamp,
    ended_at: OptionalRawTimestamp,
    exit_code: Option<i64>,
}

impl RawProcess {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            process_record_id: row.get(0)?,
            state: row.get(1)?,
            service_generation: row.get(2)?,
            process_id_number: row.get(3)?,
            process_identity: row.get(4)?,
            execution_handle: row.get(5)?,
            worker_identity: row.get(6)?,
            observed_fencing_generation: row.get(7)?,
            launch_intent_at: required_timestamp(row, 8)?,
            started_at: optional_timestamp(row, 11)?,
            stop_requested_at: optional_timestamp(row, 14)?,
            ended_at: optional_timestamp(row, 17)?,
            exit_code: row.get(20)?,
        })
    }

    fn validate(
        self,
        snapshot: &LeaseSnapshot,
        lease_generation: ServiceClockGeneration,
    ) -> Result<ProcessEvidence, StoreError> {
        if !valid_process_record_id(&self.process_record_id) {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let state = parse_process_state(&self.state)?;
        let origin_generation = parse_generation(self.service_generation)?;
        if origin_generation != lease_generation {
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
        if self.process_identity.as_ref().is_some_and(|value| {
            value.contains('\0') || !(1..=256).contains(&value.chars().count())
        }) {
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
        let observed_fencing_generation = parse_fencing(self.observed_fencing_generation)?;
        snapshot
            .validate_process_binding(
                origin_generation,
                &execution_handle,
                worker_identity.as_ref(),
                observed_fencing_generation,
            )
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let launch_intent_at = self.launch_intent_at.validate()?;
        let started_at = self.started_at.validate()?;
        let stop_requested_at = self.stop_requested_at.validate()?;
        let ended_at = self.ended_at.validate()?;
        if ended_at.is_some() || self.exit_code.is_some() {
            return Err(StoreError::IntegrityCheckFailed);
        }
        validate_process_state(
            state,
            &ProcessShape {
                process_id: process_id_number,
                process_identity: self.process_identity.as_deref(),
                started_at: started_at.as_ref(),
                stop_requested_at: stop_requested_at.as_ref(),
            },
        )?;
        Ok(ProcessEvidence {
            process_record_id: self.process_record_id,
            state,
            origin_generation,
            process_id_number,
            process_identity: self.process_identity,
            execution_handle,
            worker_identity,
            observed_fencing_generation,
            launch_intent_at,
            started_at,
            stop_requested_at,
            ended_at,
            exit_code: self.exit_code,
        })
    }
}

fn valid_process_record_id(value: &str) -> bool {
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

struct ProcessShape<'a> {
    process_id: Option<NonZeroU64>,
    process_identity: Option<&'a str>,
    started_at: Option<&'a crate::automation::contracts::UtcTimestamp>,
    stop_requested_at: Option<&'a crate::automation::contracts::UtcTimestamp>,
}

fn validate_process_state(state: ProcessState, shape: &ProcessShape<'_>) -> Result<(), StoreError> {
    let has_process_id = shape.process_id.is_some();
    let has_process_identity = shape.process_identity.is_some();
    let has_started_at = shape.started_at.is_some();
    let has_stop_requested_at = shape.stop_requested_at.is_some();
    let valid = match state {
        ProcessState::LaunchIntent => {
            !has_process_id && !has_process_identity && !has_started_at && !has_stop_requested_at
        }
        ProcessState::Starting => {
            has_process_id == has_process_identity && !has_started_at && !has_stop_requested_at
        }
        ProcessState::Running => {
            has_process_id && has_process_identity && has_started_at && !has_stop_requested_at
        }
        ProcessState::Stopping => {
            has_process_id && has_process_identity && has_started_at && has_stop_requested_at
        }
        // These states intentionally retain partial observations for a future
        // terminal-only reconciler.
        ProcessState::Quarantined | ProcessState::RecoveryRequired => true,
    };
    if valid {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

fn parse_capacity_state(value: &str) -> Result<CapacityState, StoreError> {
    Ok(match value {
        "HELD" => CapacityState::Held,
        "QUARANTINED" => CapacityState::Quarantined,
        "RECOVERY_REQUIRED" => CapacityState::RecoveryRequired,
        _ => return Err(StoreError::IntegrityCheckFailed),
    })
}

fn parse_capacity_dimension(value: &str) -> Result<CapacityDimension, StoreError> {
    Ok(match value {
        "provider" => CapacityDimension::Provider,
        "profile" => CapacityDimension::Profile,
        "caller" => CapacityDimension::Caller,
        "host" => CapacityDimension::Host,
        _ => return Err(StoreError::IntegrityCheckFailed),
    })
}

fn parse_process_state(value: &str) -> Result<ProcessState, StoreError> {
    Ok(match value {
        "LAUNCH_INTENT" => ProcessState::LaunchIntent,
        "STARTING" => ProcessState::Starting,
        "RUNNING" => ProcessState::Running,
        "STOPPING" => ProcessState::Stopping,
        "QUARANTINED" => ProcessState::Quarantined,
        "RECOVERY_REQUIRED" => ProcessState::RecoveryRequired,
        _ => return Err(StoreError::IntegrityCheckFailed),
    })
}

fn parse_generation(value: i64) -> Result<ServiceClockGeneration, StoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=FencingGeneration::MAXIMUM).contains(value))
        .map(ServiceClockGeneration::from_value)
        .ok_or(StoreError::IntegrityCheckFailed)
}

fn parse_fencing(value: i64) -> Result<FencingGeneration, StoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| FencingGeneration::from_value(value).ok())
        .ok_or(StoreError::IntegrityCheckFailed)
}
