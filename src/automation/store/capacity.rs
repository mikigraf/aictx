use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::automation::{
    contracts::{LeaseId, ProfileUid, UtcTimestamp},
    policy::CapacityClaim,
};

use super::{
    CapacityReleaseResult, ReadyStore, StoreError,
    ids::{CAPACITY_PREFIX, allocate_id},
    lifecycle_types::terminal_status,
    load,
    records::StoredTimestamp,
};

struct Dimension {
    label: &'static str,
    key: String,
    limit: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReservationGraph {
    None,
    Held,
    Released,
    Quarantined,
    RecoveryRequired,
}

pub(super) fn claim(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    claim: &CapacityClaim,
    now: &UtcTimestamp,
) -> Result<bool, StoreError> {
    validate_claim_binding(transaction, lease_id, claim)?;
    if reservation_graph(transaction, lease_id)? != ReservationGraph::None {
        return Err(StoreError::IntegrityCheckFailed);
    }
    let Some((dimensions, slots)) = reservation_plan(transaction, claim)? else {
        return Ok(false);
    };
    let timestamp = StoredTimestamp::from_utc(now)?;
    for (dimension, slot) in dimensions.iter().zip(slots) {
        let reservation_id = allocate_id(
            transaction,
            CAPACITY_PREFIX,
            "SELECT EXISTS(SELECT 1 FROM capacity_reservations WHERE reservation_id = ?1)",
        )?;
        let inserted = transaction
            .execute(
                "INSERT INTO capacity_reservations (
                    reservation_id, lease_id, provider, profile_uid,
                    authenticated_caller, host_identity, tenant_id,
                    capacity_dimension, capacity_key, capacity_limit, slot, state,
                    reserved_at_utc, reserved_at_seconds, reserved_at_nanos
                 ) SELECT
                    ?1, l.lease_id, l.provider, l.profile_uid, l.authenticated_caller,
                    l.host_identity, l.tenant_id, ?2, ?3, ?4, ?5, 'HELD', ?6, ?7, ?8
                 FROM leases l WHERE l.lease_id = ?9",
                params![
                    reservation_id,
                    dimension.label,
                    dimension.key.as_str(),
                    i64::from(dimension.limit),
                    slot,
                    timestamp.wire,
                    timestamp.seconds,
                    timestamp.nanos,
                    lease_id.as_str(),
                ],
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if inserted != 1 {
            return Err(StoreError::ConcurrentMutation);
        }
    }
    if reservation_graph(transaction, lease_id)? != ReservationGraph::Held {
        return Err(StoreError::IntegrityCheckFailed);
    }
    Ok(true)
}

pub(super) fn available(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    claim: &CapacityClaim,
) -> Result<bool, StoreError> {
    validate_claim_binding(transaction, lease_id, claim)?;
    if reservation_graph(transaction, lease_id)? != ReservationGraph::None {
        return Err(StoreError::IntegrityCheckFailed);
    }
    reservation_plan(transaction, claim).map(|plan| plan.is_some())
}

pub(super) fn held_claim_matches(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    claim: &CapacityClaim,
) -> Result<bool, StoreError> {
    if reservation_graph(transaction, lease_id)? != ReservationGraph::Held {
        return Err(StoreError::IntegrityCheckFailed);
    }
    let limits = claim.limits();
    let matching: i64 = transaction
        .query_row(
            "SELECT count(*) FROM capacity_reservations
             WHERE lease_id = ?1 AND state = 'HELD' AND (
                (capacity_dimension = 'profile' AND capacity_key = ?2 AND capacity_limit = ?3)
                OR (capacity_dimension = 'provider' AND capacity_key = ?4 AND capacity_limit = ?5)
                OR (capacity_dimension = 'caller' AND capacity_key = ?6 AND capacity_limit = ?7)
                OR (capacity_dimension = 'host' AND capacity_key = ?8 AND capacity_limit = ?9))",
            params![
                lease_id.as_str(),
                claim.profile_uid().as_str(),
                i64::from(limits.profile()),
                claim.provider().to_string(),
                i64::from(limits.provider()),
                claim.caller_subject().as_str(),
                i64::from(limits.caller()),
                claim.host_identity().as_str(),
                i64::from(limits.host()),
            ],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    Ok(matching == 4)
}

type ReservationPlan = ([Dimension; 4], [i64; 4]);

fn reservation_plan(
    transaction: &Transaction<'_>,
    claim: &CapacityClaim,
) -> Result<Option<ReservationPlan>, StoreError> {
    let limits = claim.limits();
    let dimensions = [
        Dimension {
            label: "profile",
            key: claim.profile_uid().as_str().to_owned(),
            limit: limits.profile(),
        },
        Dimension {
            label: "provider",
            key: claim.provider().to_string(),
            limit: limits.provider(),
        },
        Dimension {
            label: "caller",
            key: claim.caller_subject().as_str().to_owned(),
            limit: limits.caller(),
        },
        Dimension {
            label: "host",
            key: claim.host_identity().as_str().to_owned(),
            limit: limits.host(),
        },
    ];
    let mut slots = [0_i64; 4];
    for (index, dimension) in dimensions.iter().enumerate() {
        let usage: i64 = transaction
            .query_row(
                "SELECT count(*) FROM capacity_reservations
                 WHERE capacity_dimension = ?1 AND capacity_key = ?2 AND state <> 'RELEASED'",
                params![dimension.label, dimension.key.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if usage < 0
            || u64::try_from(usage).map_err(|_| StoreError::IntegrityCheckFailed)?
                >= u64::from(dimension.limit)
        {
            return Ok(None);
        }
        slots[index] = first_available_slot(transaction, dimension)?
            .ok_or(StoreError::IntegrityCheckFailed)?;
    }

    Ok(Some((dimensions, slots)))
}

fn first_available_slot(
    transaction: &Transaction<'_>,
    dimension: &Dimension,
) -> Result<Option<i64>, StoreError> {
    transaction
        .query_row(
            "SELECT candidate FROM (
                SELECT 1 AS candidate
                WHERE NOT EXISTS (
                    SELECT 1 FROM capacity_reservations
                    WHERE capacity_dimension = ?1 AND capacity_key = ?2
                      AND slot = 1 AND state <> 'RELEASED'
                )
                UNION ALL
                SELECT current.slot + 1 AS candidate
                FROM capacity_reservations current
                WHERE current.capacity_dimension = ?1 AND current.capacity_key = ?2
                  AND current.state <> 'RELEASED' AND current.slot < ?3
                  AND NOT EXISTS (
                    SELECT 1 FROM capacity_reservations following
                    WHERE following.capacity_dimension = ?1 AND following.capacity_key = ?2
                      AND following.slot = current.slot + 1 AND following.state <> 'RELEASED'
                )
             ) ORDER BY candidate LIMIT 1",
            params![
                dimension.label,
                dimension.key.as_str(),
                i64::from(dimension.limit)
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::DatabaseUnavailable)
}

fn validate_claim_binding(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    claim: &CapacityClaim,
) -> Result<(), StoreError> {
    let valid: bool = transaction
        .query_row(
            "SELECT profile_uid = ?2 AND provider = ?3
                    AND authenticated_caller = ?4 AND host_identity = ?5
             FROM leases WHERE lease_id = ?1 AND status = 'REQUESTED'
               AND recovery_state = 'NONE' AND quarantined = 0",
            params![
                lease_id.as_str(),
                claim.profile_uid().as_str(),
                claim.provider().to_string(),
                claim.caller_subject().as_str(),
                claim.host_identity().as_str(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::DatabaseUnavailable)?
        .unwrap_or(false);
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidTransition)
    }
}

pub(super) fn release_if_resolved(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    now: &UtcTimestamp,
) -> Result<u64, StoreError> {
    let graph = reservation_graph(transaction, lease_id)?;
    let releasable: bool = transaction
        .query_row(
            "SELECT status IN ('CLOSED', 'REVOKED', 'EXPIRED', 'REFUSED')
                    AND recovery_state = 'NONE' AND quarantined = 0
                    AND NOT EXISTS (
                        SELECT 1 FROM lease_processes
                        WHERE lease_id = leases.lease_id AND state <> 'EXITED'
                    )
             FROM leases WHERE lease_id = ?1",
            [lease_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::DatabaseUnavailable)?
        .ok_or(StoreError::InvalidTransition)?;
    if !releasable {
        return Ok(0);
    }
    match graph {
        ReservationGraph::None
        | ReservationGraph::Released
        | ReservationGraph::Quarantined
        | ReservationGraph::RecoveryRequired => return Ok(0),
        ReservationGraph::Held => {}
    }
    let timestamp = StoredTimestamp::from_utc(now)?;
    let changed = transaction
        .execute(
            "UPDATE capacity_reservations
             SET state = 'RELEASED', released_at_utc = ?1,
                 released_at_seconds = ?2, released_at_nanos = ?3
             WHERE lease_id = ?4 AND state = 'HELD'",
            params![
                timestamp.wire,
                timestamp.seconds,
                timestamp.nanos,
                lease_id.as_str(),
            ],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    let changed = u64::try_from(changed).map_err(|_| StoreError::IntegrityCheckFailed)?;
    if !matches!(changed, 0 | 4) {
        return Err(StoreError::IntegrityCheckFailed);
    }
    Ok(changed)
}

/// Recovery-only release for legacy partial/mixed live graphs. The caller has
/// already terminalized the old-generation lease and proven there is no live
/// process or lease-level recovery/quarantine state in the same transaction.
pub(super) fn release_recovery_if_resolved(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    now: &UtcTimestamp,
) -> Result<u64, StoreError> {
    let releasable: bool = transaction
        .query_row(
            "SELECT status IN ('CLOSED', 'REVOKED', 'EXPIRED', 'REFUSED')
                    AND recovery_state = 'NONE' AND quarantined = 0
                    AND NOT EXISTS (
                        SELECT 1 FROM lease_processes
                        WHERE lease_id = leases.lease_id AND state <> 'EXITED'
                    )
             FROM leases WHERE lease_id = ?1",
            [lease_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::DatabaseUnavailable)?
        .ok_or(StoreError::InvalidTransition)?;
    if !releasable {
        return Err(StoreError::RecoveryRequired);
    }
    let timestamp = StoredTimestamp::from_utc(now)?;
    let changed = transaction
        .execute(
            "UPDATE capacity_reservations
             SET state = 'RELEASED', released_at_utc = ?1,
                 released_at_seconds = ?2, released_at_nanos = ?3
             WHERE lease_id = ?4 AND state <> 'RELEASED'",
            params![
                timestamp.wire,
                timestamp.seconds,
                timestamp.nanos,
                lease_id.as_str(),
            ],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    u64::try_from(changed).map_err(|_| StoreError::IntegrityCheckFailed)
}

fn reservation_graph(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
) -> Result<ReservationGraph, StoreError> {
    let (total, distinct, held, released, quarantined, recovery): (i64, i64, i64, i64, i64, i64) =
        transaction
            .query_row(
                "SELECT
                count(*),
                count(DISTINCT capacity_dimension),
                count(*) FILTER (WHERE state = 'HELD'),
                count(*) FILTER (WHERE state = 'RELEASED'),
                count(*) FILTER (WHERE state = 'QUARANTINED'),
                count(*) FILTER (WHERE state = 'RECOVERY_REQUIRED')
             FROM capacity_reservations WHERE lease_id = ?1",
                [lease_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if total == 0 && distinct == 0 {
        return Ok(ReservationGraph::None);
    }
    if total != 4 || distinct != 4 {
        return Err(StoreError::IntegrityCheckFailed);
    }
    match (held, released, quarantined, recovery) {
        (4, 0, 0, 0) => Ok(ReservationGraph::Held),
        (0, 4, 0, 0) => Ok(ReservationGraph::Released),
        (0, 0, 4, 0) => Ok(ReservationGraph::Quarantined),
        (0, 0, 0, 4) => Ok(ReservationGraph::RecoveryRequired),
        _ => Err(StoreError::IntegrityCheckFailed),
    }
}

impl ReadyStore {
    pub(in crate::automation::store) fn release_terminal_capacity(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        now: &UtcTimestamp,
    ) -> Result<CapacityReleaseResult, StoreError> {
        let generation = self.core.service_generation;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let loaded =
            load::lease_by_id(&transaction, lease_id.as_str())?.ok_or(StoreError::LeaseNotFound)?;
        if loaded.origin_generation != generation
            || !terminal_status(loaded.lease.status())
            || expected_row_version == 0
            || loaded.row_version != expected_row_version
        {
            return Err(StoreError::ConcurrentMutation);
        }
        let graph = reservation_graph(&transaction, lease_id)?;
        if matches!(graph, ReservationGraph::None | ReservationGraph::Released) {
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            let result = CapacityReleaseResult::new(
                0,
                loaded.row_version,
                loaded.snapshot.profile_uid().clone(),
            );
            return Ok(complete_release_cleanup(&mut self.core, lease_id, result));
        }
        let released = release_if_resolved(&transaction, lease_id, now)?;
        if released == 0 {
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            let result = CapacityReleaseResult::new(
                0,
                loaded.row_version,
                loaded.snapshot.profile_uid().clone(),
            );
            return Ok(complete_release_cleanup(&mut self.core, lease_id, result));
        }
        let new_version = loaded
            .row_version
            .checked_add(1)
            .ok_or(StoreError::ConcurrentMutation)?;
        let changed = transaction
            .execute(
                "UPDATE leases SET row_version = ?1
                 WHERE lease_id = ?2 AND row_version = ?3",
                params![
                    i64::try_from(new_version).map_err(|_| StoreError::IntegrityCheckFailed)?,
                    lease_id.as_str(),
                    i64::try_from(expected_row_version)
                        .map_err(|_| StoreError::IntegrityCheckFailed)?,
                ],
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if changed != 1 {
            return Err(StoreError::ConcurrentMutation);
        }
        let profile_uid = loaded.snapshot.profile_uid().clone();
        if transaction.commit().is_err() {
            self.core.latch_profile_cleanup(profile_uid.clone());
            return Err(StoreError::DatabaseUnavailable);
        }
        let result = CapacityReleaseResult::new(released, new_version, profile_uid);
        Ok(complete_release_cleanup(&mut self.core, lease_id, result))
    }
}

fn complete_release_cleanup(
    core: &mut super::sqlite::StoreCore,
    lease_id: &LeaseId,
    mut result: CapacityReleaseResult,
) -> CapacityReleaseResult {
    let profile_uid = result.profile_uid().clone();
    if let Err(error) = core.post_terminal_cleanup(lease_id, &profile_uid) {
        core.latch_cleanup_failure(profile_uid.clone(), error);
        result.mark_cleanup_deferred();
    }
    result
}

pub(super) fn profile_has_blocking_state(
    transaction: &Transaction<'_>,
    profile_uid: &ProfileUid,
) -> Result<bool, StoreError> {
    transaction
        .query_row(
            "SELECT
                EXISTS(SELECT 1 FROM leases
                    WHERE profile_uid = ?1
                      AND (status IN ('REQUESTED', 'ACTIVE', 'RENEWING', 'ERROR')
                           OR recovery_state <> 'NONE' OR quarantined = 1))
                OR EXISTS(
                    SELECT 1 FROM capacity_reservations c JOIN leases l USING (lease_id)
                    WHERE l.profile_uid = ?1 AND c.state <> 'RELEASED'
                )
                OR EXISTS(
                    SELECT 1 FROM lease_processes p JOIN leases l USING (lease_id)
                    WHERE l.profile_uid = ?1 AND p.state <> 'EXITED'
                )",
            [profile_uid.as_str()],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::DatabaseUnavailable)
}
