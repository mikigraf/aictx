use rusqlite::{Row, Transaction};

use crate::automation::contracts::{LeaseReasonCode, LeaseStatus, Sha256Digest, UtcTimestamp};

use super::{LoadedRequest, RawLease};
use crate::automation::store::{
    StoreError,
    load_parse::{
        RawTimestamp, RecoveryState, parse_generation, parse_reason, parse_status,
        required_timestamp,
    },
    records::parse_refusal,
};

#[path = "audit/process.rs"]
mod process;
pub(crate) use process::ProcessAuditProjection;

pub(super) fn validate(
    transaction: &Transaction<'_>,
    lease: &RawLease,
    request: &LoadedRequest,
    status: LeaseStatus,
) -> Result<ProcessAuditProjection, StoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT audit_event_id, sequence, service_generation, event_type, outcome,
                    lease_status, recovery_state, quarantined,
                    event_at_utc, event_at_seconds, event_at_nanos, actor,
                    client_request_id, tenant_id, work_order_id, work_order_digest,
                    run_id, attempt_id, role, provider, profile_uid, profile_ref,
                    repository_id, workspace_id, environment, authenticated_caller,
                    host_identity, fencing_generation, effective_policy_digest,
                    refusal_code, reason_code
             FROM audit_events WHERE lease_id = ?1 ORDER BY sequence",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let events = statement
        .query_map([lease.lease_id.as_str()], RawAudit::from_row)
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if events.is_empty()
        || lease.next_audit_sequence
            != i64::try_from(events.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(StoreError::IntegrityCheckFailed)?
    {
        return Err(StoreError::IntegrityCheckFailed);
    }

    let issued_at = lease.issued_at.clone().validate()?;
    let mut projection = None;
    for (index, event) in events.iter().enumerate() {
        let sequence = i64::try_from(index + 1).map_err(|_| StoreError::IntegrityCheckFailed)?;
        event.validate_common(sequence, lease, request)?;
        if sequence == 1 {
            event.validate_initial(lease, request, &issued_at)?;
            projection = Some(AuditProjection {
                status: LeaseStatus::Requested,
                recovery_state: RecoveryState::None,
                quarantined: false,
                service_generation: parse_generation(event.service_generation)?.get(),
                origin_generation: parse_generation(event.service_generation)?.get(),
                fencing_generation: None,
                effective_policy_digest: None,
                refusal_code: None,
                reason_code: None,
                process: ProcessAuditProjection::None,
            });
        } else {
            projection = Some(
                event.validate_transition(
                    projection
                        .as_ref()
                        .ok_or(StoreError::IntegrityCheckFailed)?,
                    request,
                )?,
            );
        }
    }
    let latest = events.last().ok_or(StoreError::IntegrityCheckFailed)?;
    let projection = projection.ok_or(StoreError::IntegrityCheckFailed)?;
    if projection.status != status
        || projection.recovery_state != parse_recovery(lease.recovery_state.as_str())?
        || projection.quarantined != (lease.quarantined == 1)
        || projection.fencing_generation
            != lease
                .fencing_generation
                .and_then(|value| u64::try_from(value).ok())
        || projection.effective_policy_digest.as_deref() != lease.effective_policy_digest.as_deref()
        || projection.refusal_code.as_deref() != lease.refusal_code.as_deref()
        || projection.reason_code.as_deref() != lease.reason_code.as_deref()
    {
        return Err(StoreError::IntegrityCheckFailed);
    }
    latest.validate_latest(lease)?;
    validate_persisted_timestamps(&events, lease)?;
    Ok(projection.process)
}

#[derive(Clone)]
struct AuditProjection {
    status: LeaseStatus,
    recovery_state: RecoveryState,
    quarantined: bool,
    service_generation: u64,
    origin_generation: u64,
    fencing_generation: Option<u64>,
    effective_policy_digest: Option<String>,
    refusal_code: Option<String>,
    reason_code: Option<String>,
    process: ProcessAuditProjection,
}

struct RawAudit {
    audit_event_id: String,
    sequence: i64,
    service_generation: i64,
    event_type: String,
    outcome: String,
    lease_status: Option<String>,
    recovery_state: Option<String>,
    quarantined: Option<i64>,
    event_at: RawTimestamp,
    actor: String,
    client_request_id: Option<String>,
    tenant_id: Option<String>,
    work_order_id: Option<String>,
    work_order_digest: Option<String>,
    run_id: Option<String>,
    attempt_id: Option<String>,
    role: Option<String>,
    provider: Option<String>,
    profile_uid: Option<String>,
    profile_ref: Option<String>,
    repository_id: Option<String>,
    workspace_id: Option<String>,
    environment: Option<String>,
    authenticated_caller: Option<String>,
    host_identity: Option<String>,
    fencing_generation: Option<i64>,
    effective_policy_digest: Option<String>,
    refusal_code: Option<String>,
    reason_code: Option<String>,
}

impl RawAudit {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            audit_event_id: row.get(0)?,
            sequence: row.get(1)?,
            service_generation: row.get(2)?,
            event_type: row.get(3)?,
            outcome: row.get(4)?,
            lease_status: row.get(5)?,
            recovery_state: row.get(6)?,
            quarantined: row.get(7)?,
            event_at: required_timestamp(row, 8)?,
            actor: row.get(11)?,
            client_request_id: row.get(12)?,
            tenant_id: row.get(13)?,
            work_order_id: row.get(14)?,
            work_order_digest: row.get(15)?,
            run_id: row.get(16)?,
            attempt_id: row.get(17)?,
            role: row.get(18)?,
            provider: row.get(19)?,
            profile_uid: row.get(20)?,
            profile_ref: row.get(21)?,
            repository_id: row.get(22)?,
            workspace_id: row.get(23)?,
            environment: row.get(24)?,
            authenticated_caller: row.get(25)?,
            host_identity: row.get(26)?,
            fencing_generation: row.get(27)?,
            effective_policy_digest: row.get(28)?,
            refusal_code: row.get(29)?,
            reason_code: row.get(30)?,
        })
    }

    fn validate_common(
        &self,
        expected_sequence: i64,
        lease: &RawLease,
        request: &LoadedRequest,
    ) -> Result<(), StoreError> {
        if self.sequence != expected_sequence
            || !valid_audit_id(&self.audit_event_id)
            || parse_generation(self.service_generation)?.get()
                < parse_generation(lease.service_generation)?.get()
            || !matches!(
                self.outcome.as_str(),
                "recorded" | "succeeded" | "refused" | "failed"
            )
            || (self.actor != "service" && self.actor != request.caller.as_str())
            || !matches!(self.quarantined, Some(0 | 1))
            || !self.matches_attribution(lease, request)
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        self.event_at.clone().validate()?;
        parse_status(
            self.lease_status
                .as_deref()
                .ok_or(StoreError::IntegrityCheckFailed)?,
        )?;
        match self.recovery_state.as_deref() {
            Some("NONE" | "REQUIRED" | "RECONCILING") => {}
            _ => return Err(StoreError::IntegrityCheckFailed),
        }
        if let Some(value) = self.fencing_generation {
            crate::automation::contracts::FencingGeneration::from_value(
                u64::try_from(value).map_err(|_| StoreError::IntegrityCheckFailed)?,
            )
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        }
        if let Some(value) = &self.effective_policy_digest {
            value
                .parse::<Sha256Digest>()
                .map_err(|_| StoreError::IntegrityCheckFailed)?;
        }
        if self
            .refusal_code
            .as_deref()
            .is_some_and(|value| parse_refusal(value).is_none())
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        if let Some(value) = self.reason_code.as_deref() {
            parse_reason(value)?;
        }
        Ok(())
    }

    fn matches_attribution(&self, lease: &RawLease, request: &LoadedRequest) -> bool {
        self.client_request_id.as_deref() == Some(request.request.client_request_id.as_str())
            && self.tenant_id.as_deref() == Some(lease.tenant_id.as_str())
            && self.work_order_id.as_deref() == Some(lease.work_order_id.as_str())
            && self.work_order_digest.as_deref() == Some(lease.work_order_digest.as_str())
            && self.run_id.as_deref() == Some(lease.run_id.as_str())
            && self.attempt_id.as_deref() == Some(lease.attempt_id.as_str())
            && self.role.as_deref() == Some(lease.role.as_str())
            && self.provider.as_deref() == Some(lease.provider.as_str())
            && self.profile_uid.as_deref() == Some(lease.profile_uid.as_str())
            && self.profile_ref.as_deref() == Some(lease.profile_ref.as_str())
            && self.repository_id.as_deref() == Some(lease.repository_id.as_str())
            && self.workspace_id.as_deref() == Some(lease.workspace_id.as_str())
            && self.environment.as_deref() == Some(lease.environment.as_str())
            && self.authenticated_caller.as_deref() == Some(lease.caller.as_str())
            && self.host_identity.as_deref() == Some(lease.host.as_str())
    }

    fn validate_initial(
        &self,
        lease: &RawLease,
        request: &LoadedRequest,
        issued_at: &UtcTimestamp,
    ) -> Result<(), StoreError> {
        if self.event_type == "lease.requested"
            && self.outcome == "recorded"
            && self.lease_status.as_deref() == Some("REQUESTED")
            && self.recovery_state.as_deref() == Some("NONE")
            && self.quarantined == Some(0)
            && self.service_generation == lease.service_generation
            && self.actor == request.caller.as_str()
            && self.event_at.clone().validate()? == *issued_at
            && self.fencing_generation.is_none()
            && self.effective_policy_digest.is_none()
            && self.refusal_code.is_none()
            && self.reason_code.is_none()
        {
            Ok(())
        } else {
            Err(StoreError::IntegrityCheckFailed)
        }
    }

    fn validate_transition(
        &self,
        prior: &AuditProjection,
        request: &LoadedRequest,
    ) -> Result<AuditProjection, StoreError> {
        let status = parse_status(
            self.lease_status
                .as_deref()
                .ok_or(StoreError::IntegrityCheckFailed)?,
        )?;
        let recovery_state = parse_recovery(
            self.recovery_state
                .as_deref()
                .ok_or(StoreError::IntegrityCheckFailed)?,
        )?;
        let quarantined = self.quarantined.ok_or(StoreError::IntegrityCheckFailed)? == 1;
        let service_generation = parse_generation(self.service_generation)?.get();
        let fencing_generation = self
            .fencing_generation
            .map(|value| u64::try_from(value).map_err(|_| StoreError::IntegrityCheckFailed))
            .transpose()?;
        let effective_policy_digest = self.effective_policy_digest.clone();
        if !self.outcome_matches_event()
            || !self.actor_matches_event(request)
            || !self.generation_transition_is_valid(prior, service_generation)
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let next = match self.event_type.as_str() {
            "lease.refused" if prior.status == LeaseStatus::Requested => LeaseStatus::Refused,
            "lease.activated" if prior.status == LeaseStatus::Requested => LeaseStatus::Active,
            "lease.renewing" if prior.status == LeaseStatus::Active => LeaseStatus::Renewing,
            "lease.renewed" if prior.status == LeaseStatus::Renewing => LeaseStatus::Active,
            "lease.closed"
                if matches!(prior.status, LeaseStatus::Active | LeaseStatus::Renewing) =>
            {
                LeaseStatus::Closed
            }
            "lease.revoked"
                if matches!(
                    prior.status,
                    LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error
                ) =>
            {
                LeaseStatus::Revoked
            }
            "lease.expired"
                if matches!(
                    prior.status,
                    LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error
                ) =>
            {
                LeaseStatus::Expired
            }
            "lease.error"
                if matches!(prior.status, LeaseStatus::Active | LeaseStatus::Renewing) =>
            {
                LeaseStatus::Error
            }
            "lease.quarantined" | "lease.recovery-required"
                if status == prior.status && prior.status != LeaseStatus::Refused =>
            {
                prior.status
            }
            "process.launch-intent" | "process.started"
                if status == prior.status && prior.status == LeaseStatus::Active =>
            {
                prior.status
            }
            "process.exited"
                if status == prior.status
                    && matches!(
                        prior.status,
                        LeaseStatus::Active
                            | LeaseStatus::Renewing
                            | LeaseStatus::Error
                            | LeaseStatus::Closed
                            | LeaseStatus::Revoked
                            | LeaseStatus::Expired
                    ) =>
            {
                prior.status
            }
            _ => return Err(StoreError::IntegrityCheckFailed),
        };
        if status != next
            || !self.fields_match_status(status)
            || !self.authority_transition_is_valid(
                prior,
                fencing_generation,
                effective_policy_digest.as_deref(),
            )
            || !self.recovery_transition_is_valid(prior, recovery_state, quarantined)
            || !self.reason_transition_is_valid(prior)
            || !self.policy_expectation_is_valid(request, status)
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let process = prior.process.transition(
            self.event_type.as_str(),
            prior.status,
            &self.event_at.clone().validate()?,
            fencing_generation,
        )?;
        Ok(AuditProjection {
            status: next,
            recovery_state,
            quarantined,
            service_generation,
            origin_generation: prior.origin_generation,
            fencing_generation,
            effective_policy_digest,
            refusal_code: self.refusal_code.clone(),
            reason_code: self.reason_code.clone(),
            process,
        })
    }

    fn fields_match_status(&self, status: LeaseStatus) -> bool {
        match status {
            LeaseStatus::Requested => {
                self.refusal_code.is_none()
                    && self.reason_code.is_none()
                    && self.fencing_generation.is_none()
                    && self.effective_policy_digest.is_none()
            }
            LeaseStatus::Refused => {
                self.refusal_code.is_some()
                    && self.reason_code.is_none()
                    && self.fencing_generation.is_none()
                    && self.effective_policy_digest.is_none()
            }
            LeaseStatus::Active | LeaseStatus::Renewing => {
                self.refusal_code.is_none()
                    && self.reason_code.is_none()
                    && self.fencing_generation.is_some()
                    && self.effective_policy_digest.is_some()
            }
            LeaseStatus::Closed
            | LeaseStatus::Revoked
            | LeaseStatus::Expired
            | LeaseStatus::Error => {
                let reason = self
                    .reason_code
                    .as_deref()
                    .and_then(|value| parse_reason(value).ok());
                let valid_reason = match status {
                    LeaseStatus::Closed => matches!(
                        reason,
                        Some(LeaseReasonCode::Completed | LeaseReasonCode::WorkerFailed)
                    ),
                    LeaseStatus::Revoked => matches!(
                        reason,
                        Some(
                            LeaseReasonCode::OperatorRevoked
                                | LeaseReasonCode::PolicyRevoked
                                | LeaseReasonCode::PrincipalMismatch
                                | LeaseReasonCode::HeartbeatLost
                                | LeaseReasonCode::ProcessUnverifiable
                                | LeaseReasonCode::GenerationSuperseded
                                | LeaseReasonCode::RenewalAcknowledgementFailed
                                | LeaseReasonCode::ServiceRecovery
                        )
                    ),
                    LeaseStatus::Expired => matches!(
                        reason,
                        Some(
                            LeaseReasonCode::LeaseExpired | LeaseReasonCode::MaximumLifetimeReached
                        )
                    ),
                    LeaseStatus::Error => matches!(
                        reason,
                        Some(
                            LeaseReasonCode::ProcessUnverifiable
                                | LeaseReasonCode::ServiceRecovery
                                | LeaseReasonCode::InternalError
                        )
                    ),
                    _ => false,
                };
                self.refusal_code.is_none()
                    && valid_reason
                    && self.fencing_generation.is_some()
                    && self.effective_policy_digest.is_some()
            }
        }
    }

    fn outcome_matches_event(&self) -> bool {
        match self.event_type.as_str() {
            "lease.refused" => self.outcome == "refused",
            "lease.activated" | "lease.renewing" | "lease.renewed" | "lease.revoked"
            | "lease.expired" | "process.started" => self.outcome == "succeeded",
            "lease.closed" => match self.reason_code.as_deref() {
                Some("completed") => self.outcome == "succeeded",
                Some("worker-failed") => self.outcome == "failed",
                _ => false,
            },
            "process.exited" => matches!(self.outcome.as_str(), "succeeded" | "failed"),
            "process.launch-intent" => self.outcome == "recorded",
            "lease.error" | "lease.quarantined" | "lease.recovery-required" => {
                self.outcome == "failed"
            }
            _ => false,
        }
    }

    fn reason_transition_is_valid(&self, prior: &AuditProjection) -> bool {
        match self.event_type.as_str() {
            "lease.refused" | "lease.activated" | "lease.renewing" | "lease.renewed"
            | "lease.closed" | "lease.revoked" | "lease.expired" | "lease.error" => true,
            "lease.quarantined"
            | "lease.recovery-required"
            | "process.launch-intent"
            | "process.started"
            | "process.exited" => {
                self.refusal_code == prior.refusal_code && self.reason_code == prior.reason_code
            }
            _ => false,
        }
    }

    fn policy_expectation_is_valid(&self, request: &LoadedRequest, status: LeaseStatus) -> bool {
        match request.request.policy_digest {
            None => true,
            Some(_) if matches!(status, LeaseStatus::Requested | LeaseStatus::Refused) => true,
            Some(expected) => {
                self.effective_policy_digest
                    .as_deref()
                    .and_then(|value| value.parse::<Sha256Digest>().ok())
                    == Some(expected)
            }
        }
    }

    fn actor_matches_event(&self, request: &LoadedRequest) -> bool {
        match self.event_type.as_str() {
            "lease.closed" => self.actor == "service" || self.actor == request.caller.as_str(),
            "lease.revoked" if self.reason_code.as_deref() == Some("operator-revoked") => {
                self.actor == request.caller.as_str()
            }
            "lease.refused"
            | "lease.activated"
            | "lease.renewing"
            | "lease.renewed"
            | "lease.revoked"
            | "lease.expired"
            | "lease.error"
            | "lease.quarantined"
            | "lease.recovery-required"
            | "process.launch-intent"
            | "process.started"
            | "process.exited" => self.actor == "service",
            _ => false,
        }
    }

    fn generation_transition_is_valid(
        &self,
        prior: &AuditProjection,
        service_generation: u64,
    ) -> bool {
        if service_generation < prior.service_generation {
            return false;
        }
        match self.event_type.as_str() {
            "lease.activated"
            | "lease.renewing"
            | "lease.renewed"
            | "lease.closed"
            | "process.launch-intent"
            | "process.started" => service_generation == prior.origin_generation,
            "lease.refused"
            | "lease.revoked"
            | "lease.expired"
            | "lease.error"
            | "lease.quarantined"
            | "lease.recovery-required"
            | "process.exited" => true,
            _ => false,
        }
    }

    fn recovery_transition_is_valid(
        &self,
        prior: &AuditProjection,
        recovery_state: RecoveryState,
        quarantined: bool,
    ) -> bool {
        match self.event_type.as_str() {
            "lease.activated"
            | "lease.renewing"
            | "lease.renewed"
            | "process.launch-intent"
            | "process.started" => {
                prior.recovery_state == RecoveryState::None
                    && !prior.quarantined
                    && recovery_state == RecoveryState::None
                    && !quarantined
            }
            "lease.refused" | "lease.closed" | "lease.revoked" | "lease.expired"
            | "lease.error" => recovery_state == RecoveryState::None && !quarantined,
            "lease.recovery-required" => {
                quarantined == prior.quarantined
                    && matches!(
                        (prior.recovery_state, recovery_state),
                        (
                            RecoveryState::None | RecoveryState::Required,
                            RecoveryState::Required
                        ) | (
                            RecoveryState::Required | RecoveryState::Reconciling,
                            RecoveryState::Reconciling
                        )
                    )
            }
            "lease.quarantined" => {
                !prior.quarantined && quarantined && recovery_state == prior.recovery_state
            }
            "process.exited" => {
                recovery_did_not_escalate(prior.recovery_state, recovery_state)
                    && (!quarantined || prior.quarantined)
            }
            _ => false,
        }
    }

    fn authority_transition_is_valid(
        &self,
        prior: &AuditProjection,
        fencing_generation: Option<u64>,
        effective_policy_digest: Option<&str>,
    ) -> bool {
        let digest_matches = effective_policy_digest == prior.effective_policy_digest.as_deref();
        match self.event_type.as_str() {
            "lease.refused" => fencing_generation.is_none() && effective_policy_digest.is_none(),
            "lease.activated" => fencing_generation == Some(1) && effective_policy_digest.is_some(),
            "lease.renewing" => {
                prior
                    .fencing_generation
                    .and_then(|value| value.checked_add(1))
                    == fencing_generation
                    && effective_policy_digest.is_some()
            }
            "lease.renewed"
            | "lease.closed"
            | "lease.revoked"
            | "lease.expired"
            | "lease.error"
            | "lease.quarantined"
            | "lease.recovery-required"
            | "process.launch-intent"
            | "process.started"
            | "process.exited" => fencing_generation == prior.fencing_generation && digest_matches,
            _ => false,
        }
    }

    fn validate_latest(&self, lease: &RawLease) -> Result<(), StoreError> {
        if self.lease_status.as_deref() != Some(lease.status.as_str())
            || self.recovery_state.as_deref() != Some(lease.recovery_state.as_str())
            || self.quarantined != Some(lease.quarantined)
            || self.fencing_generation != lease.fencing_generation
            || self.effective_policy_digest != lease.effective_policy_digest
            || self.refusal_code != lease.refusal_code
            || self.reason_code != lease.reason_code
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let event_at = self.event_at.clone().validate()?;
        let expected = match self.event_type.as_str() {
            "lease.requested" => Some(lease.issued_at.clone().validate()?),
            "lease.refused" | "lease.closed" | "lease.revoked" | "lease.expired" => {
                lease.terminal_at.clone().validate()?
            }
            "lease.activated" => lease.activated_at.clone().validate()?,
            "lease.renewing" => lease.renewed_at.clone().validate()?,
            "lease.renewed" => lease.renewal_acknowledged_at.clone().validate()?,
            _ => None,
        };
        if expected
            .as_ref()
            .is_some_and(|expected| expected != &event_at)
        {
            Err(StoreError::IntegrityCheckFailed)
        } else {
            Ok(())
        }
    }
}

fn validate_persisted_timestamps(events: &[RawAudit], lease: &RawLease) -> Result<(), StoreError> {
    let final_fencing = lease.fencing_generation;
    let activated = unique_event_time(events, |event| event.event_type == "lease.activated")?;
    let renewed = unique_event_time(events, |event| {
        event.event_type == "lease.renewing" && event.fencing_generation == final_fencing
    })?;
    let acknowledged = unique_event_time(events, |event| {
        event.event_type == "lease.renewed" && event.fencing_generation == final_fencing
    })?;
    let terminal = unique_event_time(events, |event| {
        matches!(
            event.event_type.as_str(),
            "lease.refused" | "lease.closed" | "lease.revoked" | "lease.expired"
        )
    })?;
    if activated != lease.activated_at.clone().validate()?
        || renewed != lease.renewed_at.clone().validate()?
        || acknowledged != lease.renewal_acknowledged_at.clone().validate()?
        || terminal != lease.terminal_at.clone().validate()?
    {
        return Err(StoreError::IntegrityCheckFailed);
    }
    Ok(())
}

fn unique_event_time(
    events: &[RawAudit],
    predicate: impl Fn(&RawAudit) -> bool,
) -> Result<Option<UtcTimestamp>, StoreError> {
    let mut found = None;
    for event in events.iter().filter(|event| predicate(event)) {
        if found.is_some() {
            return Err(StoreError::IntegrityCheckFailed);
        }
        found = Some(event.event_at.clone().validate()?);
    }
    Ok(found)
}

fn parse_recovery(value: &str) -> Result<RecoveryState, StoreError> {
    match value {
        "NONE" => Ok(RecoveryState::None),
        "REQUIRED" => Ok(RecoveryState::Required),
        "RECONCILING" => Ok(RecoveryState::Reconciling),
        _ => Err(StoreError::IntegrityCheckFailed),
    }
}

const fn recovery_did_not_escalate(prior: RecoveryState, next: RecoveryState) -> bool {
    matches!(
        (prior, next),
        (RecoveryState::None, RecoveryState::None)
            | (
                RecoveryState::Required,
                RecoveryState::Required | RecoveryState::None
            )
            | (
                RecoveryState::Reconciling,
                RecoveryState::Reconciling | RecoveryState::None
            )
    )
}

fn valid_audit_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 32
        && bytes.starts_with(b"audit_")
        && matches!(bytes[6], b'0'..=b'7')
        && bytes[6..].iter().all(|byte| {
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
