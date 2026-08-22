use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::automation::contracts::UtcTimestamp;

use super::{
    PruneResult, ReadyStore, StoreError,
    ids::{AUDIT_PREFIX, allocate_id},
    load,
    records::{StoredTimestamp, audit_retention_cutoff},
};

struct Candidate {
    lease_id: String,
    request_record_id: String,
}

#[derive(Clone)]
struct EventTime {
    wire: String,
    seconds: i64,
    nanos: i64,
}

#[derive(Default)]
struct EventRange {
    oldest: Option<EventTime>,
    newest: Option<EventTime>,
}

impl EventRange {
    fn include(&mut self, value: EventTime) {
        let key = (value.seconds, value.nanos, value.wire.as_str());
        if self
            .oldest
            .as_ref()
            .is_none_or(|oldest| key < (oldest.seconds, oldest.nanos, oldest.wire.as_str()))
        {
            self.oldest = Some(value.clone());
        }
        if self
            .newest
            .as_ref()
            .is_none_or(|newest| key > (newest.seconds, newest.nanos, newest.wire.as_str()))
        {
            self.newest = Some(value);
        }
    }
}

impl ReadyStore {
    /// Delete only history that is past both the seven-day audit cutoff and
    /// the request's independently persisted replay-retention deadline.
    pub(in crate::automation::store) fn prune_retained(
        &mut self,
        now: &UtcTimestamp,
    ) -> Result<PruneResult, StoreError> {
        if self.core.has_cleanup_deferred() {
            return Err(StoreError::RecoveryRequired);
        }
        let event_at = StoredTimestamp::from_utc(now)?;
        let cutoff = audit_retention_cutoff(now)?;
        let cutoff = StoredTimestamp::from_utc(&cutoff)?;
        let generation = i64::try_from(self.core.service_generation.get())
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        load::validate_all_leases(&transaction)?;
        let candidates = candidates(&transaction, &event_at, &cutoff)?;
        let mut event_range = EventRange::default();

        let old_global = event_range_for(
            &transaction,
            "lease_id IS NULL \
             AND (event_at_seconds < ?1 OR (event_at_seconds = ?1 AND event_at_nanos <= ?2))",
            params![cutoff.seconds, cutoff.nanos],
        )?;
        if let Some(value) = old_global.oldest {
            event_range.include(value);
        }
        if let Some(value) = old_global.newest {
            event_range.include(value);
        }
        let deleted_global = transaction
            .execute(
                "DELETE FROM audit_events
                 WHERE lease_id IS NULL
                   AND (event_at_seconds < ?1
                        OR (event_at_seconds = ?1 AND event_at_nanos <= ?2))",
                params![cutoff.seconds, cutoff.nanos],
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;

        let mut requests = 0_u64;
        let mut leases = 0_u64;
        let mut reservations = 0_u64;
        let mut processes = 0_u64;
        let mut events = count(deleted_global)?;
        for candidate in candidates {
            let range = event_range_for(&transaction, "lease_id = ?1", [&candidate.lease_id])?;
            if let Some(value) = range.oldest {
                event_range.include(value);
            }
            if let Some(value) = range.newest {
                event_range.include(value);
            }
            events = events
                .checked_add(count(delete_for_lease(
                    &transaction,
                    "audit_events",
                    &candidate.lease_id,
                )?)?)
                .ok_or(StoreError::IntegrityCheckFailed)?;
            processes = processes
                .checked_add(count(delete_for_lease(
                    &transaction,
                    "lease_processes",
                    &candidate.lease_id,
                )?)?)
                .ok_or(StoreError::IntegrityCheckFailed)?;
            reservations = reservations
                .checked_add(count(delete_for_lease(
                    &transaction,
                    "capacity_reservations",
                    &candidate.lease_id,
                )?)?)
                .ok_or(StoreError::IntegrityCheckFailed)?;
            let deleted_lease = transaction
                .execute(
                    "DELETE FROM leases WHERE lease_id = ?1",
                    [&candidate.lease_id],
                )
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            if deleted_lease != 1 {
                return Err(StoreError::ConcurrentMutation);
            }
            leases = leases
                .checked_add(1)
                .ok_or(StoreError::IntegrityCheckFailed)?;
            let deleted_request = transaction
                .execute(
                    "DELETE FROM lease_requests WHERE request_record_id = ?1",
                    [&candidate.request_record_id],
                )
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            if deleted_request != 1 {
                return Err(StoreError::IntegrityCheckFailed);
            }
            requests = requests
                .checked_add(1)
                .ok_or(StoreError::IntegrityCheckFailed)?;
        }
        let result = PruneResult::new(requests, leases, reservations, processes, events);
        if result.changed() {
            insert_pruned_audit(
                &transaction,
                generation,
                &event_at,
                &cutoff,
                result,
                &event_range,
            )?;
        }
        if transaction.commit().is_err() {
            self.core.durability_uncertain = true;
            return Err(StoreError::DatabaseUnavailable);
        }
        Ok(result)
    }
}

fn candidates(
    transaction: &Transaction<'_>,
    now: &StoredTimestamp<'_>,
    cutoff: &StoredTimestamp<'_>,
) -> Result<Vec<Candidate>, StoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT l.lease_id, l.request_record_id
             FROM leases l JOIN lease_requests r USING (request_record_id)
             WHERE l.status IN ('CLOSED', 'REVOKED', 'EXPIRED', 'REFUSED')
               AND l.recovery_state = 'NONE' AND l.quarantined = 0
               AND (r.replay_retain_until_seconds < ?1
                    OR (r.replay_retain_until_seconds = ?1
                        AND r.replay_retain_until_nanos <= ?2))
               AND (l.terminal_at_seconds < ?3
                    OR (l.terminal_at_seconds = ?3 AND l.terminal_at_nanos <= ?4))
               AND NOT EXISTS (
                    SELECT 1 FROM capacity_reservations c
                    WHERE c.lease_id = l.lease_id AND c.state <> 'RELEASED'
               )
               AND NOT EXISTS (
                    SELECT 1 FROM capacity_reservations c
                    WHERE c.lease_id = l.lease_id
                      AND (c.released_at_seconds > ?3
                           OR (c.released_at_seconds = ?3
                               AND c.released_at_nanos > ?4))
               )
               AND NOT EXISTS (
                    SELECT 1 FROM lease_processes p
                    WHERE p.lease_id = l.lease_id AND p.state <> 'EXITED'
               )
               AND NOT EXISTS (
                    SELECT 1 FROM lease_processes p
                    WHERE p.lease_id = l.lease_id
                      AND (p.ended_at_seconds > ?3
                           OR (p.ended_at_seconds = ?3 AND p.ended_at_nanos > ?4))
               )
               AND NOT EXISTS (
                    SELECT 1 FROM audit_events a
                    WHERE a.lease_id = l.lease_id
                      AND (a.event_at_seconds > ?3
                           OR (a.event_at_seconds = ?3 AND a.event_at_nanos > ?4))
               )
             ORDER BY l.lease_id",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let rows = statement
        .query_map(
            params![now.seconds, now.nanos, cutoff.seconds, cutoff.nanos],
            |row| {
                Ok(Candidate {
                    lease_id: row.get(0)?,
                    request_record_id: row.get(1)?,
                })
            },
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let unique = rows
        .iter()
        .map(|candidate| candidate.request_record_id.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() == rows.len() {
        Ok(rows)
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

fn delete_for_lease(
    transaction: &Transaction<'_>,
    table: &str,
    lease_id: &str,
) -> Result<usize, StoreError> {
    let sql = match table {
        "audit_events" => "DELETE FROM audit_events WHERE lease_id = ?1",
        "lease_processes" => "DELETE FROM lease_processes WHERE lease_id = ?1",
        "capacity_reservations" => "DELETE FROM capacity_reservations WHERE lease_id = ?1",
        _ => return Err(StoreError::IntegrityCheckFailed),
    };
    transaction
        .execute(sql, [lease_id])
        .map_err(|_| StoreError::DatabaseUnavailable)
}

fn event_range_for<P>(
    transaction: &Transaction<'_>,
    predicate: &str,
    parameters: P,
) -> Result<EventRange, StoreError>
where
    P: rusqlite::Params + Clone,
{
    let query = format!(
        "SELECT event_at_utc, event_at_seconds, event_at_nanos
         FROM audit_events WHERE {predicate}
         ORDER BY event_at_seconds, event_at_nanos, audit_event_id"
    );
    let mut statement = transaction
        .prepare(&query)
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let oldest = statement
        .query_row(parameters.clone(), event_time)
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let newest_query = format!(
        "SELECT event_at_utc, event_at_seconds, event_at_nanos
         FROM audit_events WHERE {predicate}
         ORDER BY event_at_seconds DESC, event_at_nanos DESC, audit_event_id DESC"
    );
    let newest = transaction
        .query_row(&newest_query, parameters, event_time)
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    Ok(EventRange { oldest, newest })
}

fn event_time(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventTime> {
    Ok(EventTime {
        wire: row.get(0)?,
        seconds: row.get(1)?,
        nanos: row.get(2)?,
    })
}

fn insert_pruned_audit(
    transaction: &Transaction<'_>,
    generation: i64,
    event_at: &StoredTimestamp<'_>,
    cutoff: &StoredTimestamp<'_>,
    result: PruneResult,
    range: &EventRange,
) -> Result<(), StoreError> {
    let audit_id = allocate_id(
        transaction,
        AUDIT_PREFIX,
        "SELECT EXISTS(SELECT 1 FROM audit_events WHERE audit_event_id = ?1)",
    )?;
    let changed = transaction
        .execute(
            "INSERT INTO audit_events (
                audit_event_id, service_generation, event_type, outcome,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                prune_cutoff_utc, prune_deleted_requests, prune_deleted_leases,
                prune_deleted_reservations, prune_deleted_processes,
                prune_deleted_events,
                prune_oldest_event_utc, prune_oldest_event_seconds,
                prune_oldest_event_nanos, prune_newest_event_utc,
                prune_newest_event_seconds, prune_newest_event_nanos
             ) VALUES (
                ?1, ?2, 'audit.pruned', 'succeeded', ?3, ?4, ?5, 'service',
                ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
             )",
            params![
                audit_id,
                generation,
                event_at.wire,
                event_at.seconds,
                event_at.nanos,
                cutoff.wire,
                as_i64(result.deleted_requests())?,
                as_i64(result.deleted_leases())?,
                as_i64(result.deleted_reservations())?,
                as_i64(result.deleted_processes())?,
                as_i64(result.deleted_events())?,
                range.oldest.as_ref().map(|value| value.wire.as_str()),
                range.oldest.as_ref().map(|value| value.seconds),
                range.oldest.as_ref().map(|value| value.nanos),
                range.newest.as_ref().map(|value| value.wire.as_str()),
                range.newest.as_ref().map(|value| value.seconds),
                range.newest.as_ref().map(|value| value.nanos),
            ],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

fn count(value: usize) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::IntegrityCheckFailed)
}

fn as_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::IntegrityCheckFailed)
}
