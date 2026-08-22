use rusqlite::{Row, Transaction};

use crate::automation::contracts::UtcTimestamp;

use crate::automation::store::{
    StoreError,
    load_parse::{
        OptionalRawTimestamp, RawTimestamp, optional_timestamp, parse_generation,
        required_timestamp,
    },
    records::audit_retention_cutoff,
};

use super::audit::valid_audit_id;

pub(super) fn validate(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT audit_event_id, service_generation, event_type, outcome,
                    event_at_utc, event_at_seconds, event_at_nanos, actor,
                    sequence IS NULL
                      AND lease_status IS NULL AND recovery_state IS NULL
                      AND quarantined IS NULL AND client_request_id IS NULL
                      AND tenant_id IS NULL AND work_order_id IS NULL
                      AND work_order_digest IS NULL AND run_id IS NULL
                      AND attempt_id IS NULL AND role IS NULL AND provider IS NULL
                      AND profile_uid IS NULL AND profile_ref IS NULL
                      AND repository_id IS NULL AND workspace_id IS NULL
                      AND environment IS NULL AND authenticated_caller IS NULL
                      AND host_identity IS NULL AND fencing_generation IS NULL
                      AND effective_policy_digest IS NULL AND refusal_code IS NULL
                      AND reason_code IS NULL,
                    prune_cutoff_utc, prune_deleted_requests, prune_deleted_leases,
                    prune_deleted_reservations, prune_deleted_processes,
                    prune_deleted_events, prune_oldest_event_utc,
                    prune_oldest_event_seconds, prune_oldest_event_nanos,
                    prune_newest_event_utc, prune_newest_event_seconds,
                    prune_newest_event_nanos
             FROM audit_events WHERE lease_id IS NULL ORDER BY audit_event_id",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let rows = statement
        .query_map([], RawGlobalAudit::from_row)
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    for row in rows {
        row.validate()?;
    }
    Ok(())
}

struct RawGlobalAudit {
    audit_event_id: String,
    service_generation: i64,
    event_type: String,
    outcome: String,
    event_at: RawTimestamp,
    actor: String,
    attribution_is_null: bool,
    prune_cutoff: Option<String>,
    prune_counts: [Option<i64>; 5],
    prune_oldest: OptionalRawTimestamp,
    prune_newest: OptionalRawTimestamp,
}

impl RawGlobalAudit {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            audit_event_id: row.get(0)?,
            service_generation: row.get(1)?,
            event_type: row.get(2)?,
            outcome: row.get(3)?,
            event_at: required_timestamp(row, 4)?,
            actor: row.get(7)?,
            attribution_is_null: row.get(8)?,
            prune_cutoff: row.get(9)?,
            prune_counts: [
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
            ],
            prune_oldest: optional_timestamp(row, 15)?,
            prune_newest: optional_timestamp(row, 18)?,
        })
    }

    fn validate(self) -> Result<(), StoreError> {
        if !valid_audit_id(&self.audit_event_id)
            || parse_generation(self.service_generation).is_err()
            || self.actor != "service"
            || !self.attribution_is_null
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let event_at = self.event_at.clone().validate()?;
        match self.event_type.as_str() {
            "caller.authentication-failed" if self.outcome == "failed" => {
                self.validate_authentication_failure()
            }
            "audit.pruned" if self.outcome == "succeeded" => self.validate_pruned(&event_at),
            _ => Err(StoreError::IntegrityCheckFailed),
        }
    }

    fn validate_authentication_failure(self) -> Result<(), StoreError> {
        if self.prune_cutoff.is_none()
            && self.prune_counts.iter().all(Option::is_none)
            && !self.prune_oldest.any_present()
            && !self.prune_newest.any_present()
        {
            Ok(())
        } else {
            Err(StoreError::IntegrityCheckFailed)
        }
    }

    fn validate_pruned(self, event_at: &UtcTimestamp) -> Result<(), StoreError> {
        let cutoff = self
            .prune_cutoff
            .ok_or(StoreError::IntegrityCheckFailed)
            .and_then(|value| {
                UtcTimestamp::parse(value).map_err(|_| StoreError::IntegrityCheckFailed)
            })?;
        let expected_cutoff =
            audit_retention_cutoff(event_at).map_err(|_| StoreError::IntegrityCheckFailed)?;
        let counts = self
            .prune_counts
            .into_iter()
            .map(|value| {
                value
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or(StoreError::IntegrityCheckFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let oldest = self
            .prune_oldest
            .validate()?
            .ok_or(StoreError::IntegrityCheckFailed)?;
        let newest = self
            .prune_newest
            .validate()?
            .ok_or(StoreError::IntegrityCheckFailed)?;
        let total = counts.iter().try_fold(0_u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or(StoreError::IntegrityCheckFailed)
        })?;
        let minimum_lease_events = counts[1]
            .checked_mul(2)
            .ok_or(StoreError::IntegrityCheckFailed)?;
        if cutoff == expected_cutoff
            && counts[0] == counts[1]
            && counts[4] > 0
            && counts[4] >= minimum_lease_events
            && (counts[1] > 0 || (counts[2] == 0 && counts[3] == 0))
            && total > 0
            && !oldest.is_after(&newest)
            && !newest.is_after(&cutoff)
        {
            Ok(())
        } else {
            Err(StoreError::IntegrityCheckFailed)
        }
    }
}
