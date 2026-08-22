use rusqlite::{Transaction, named_params};

use crate::automation::{
    contracts::{
        AutomationAuthMode, CallerSubject, IsolationClassification, LeaseReasonCode, LeaseStatus,
        RefusalCode, UtcTimestamp,
    },
    lease::{
        LeaseSnapshot, PersistedLeaseState, PersistedResolvedAuthority, ServiceClockGeneration,
    },
};

use super::super::{
    StoreError,
    ids::{AUDIT_PREFIX, allocate_id},
    load::LoadedLease,
    records::{StoredTimestamp, refusal_label},
};

#[derive(Clone, Copy)]
pub(in crate::automation::store) enum AuditActor<'a> {
    Service,
    Caller(&'a CallerSubject),
    AuthenticatedControl(&'a CallerSubject),
}

impl AuditActor<'_> {
    fn label(&self) -> &str {
        match self {
            Self::Service => "service",
            Self::Caller(caller) | Self::AuthenticatedControl(caller) => caller.as_str(),
        }
    }

    const fn is_service(&self) -> bool {
        matches!(self, Self::Service)
    }

    fn matches_caller(&self, caller: &CallerSubject) -> bool {
        matches!(self, Self::Caller(value) if *value == caller)
    }

    const fn resolve(self, event: TransitionEvent, reason: Option<LeaseReasonCode>) -> Self {
        match self {
            Self::AuthenticatedControl(caller)
                if matches!(event, TransitionEvent::Closed)
                    || matches!(
                        (event, reason),
                        (
                            TransitionEvent::Revoked,
                            Some(LeaseReasonCode::OperatorRevoked)
                        )
                    ) =>
            {
                Self::Caller(caller)
            }
            Self::AuthenticatedControl(_) => Self::Service,
            actor => actor,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TransitionEvent {
    Refused,
    Activated,
    Renewing,
    Renewed,
    Closed,
    Revoked,
    Expired,
    Error,
}

impl TransitionEvent {
    const fn event_type(self) -> &'static str {
        match self {
            Self::Refused => "lease.refused",
            Self::Activated => "lease.activated",
            Self::Renewing => "lease.renewing",
            Self::Renewed => "lease.renewed",
            Self::Closed => "lease.closed",
            Self::Revoked => "lease.revoked",
            Self::Expired => "lease.expired",
            Self::Error => "lease.error",
        }
    }

    const fn outcome(self, reason: Option<LeaseReasonCode>) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Error => "failed",
            Self::Closed if matches!(reason, Some(LeaseReasonCode::WorkerFailed)) => "failed",
            Self::Activated
            | Self::Renewing
            | Self::Renewed
            | Self::Closed
            | Self::Revoked
            | Self::Expired => "succeeded",
        }
    }
}

pub(in crate::automation::store) fn persist(
    transaction: &Transaction<'_>,
    loaded: &LoadedLease,
    after: &LeaseSnapshot,
    event_at: &UtcTimestamp,
    actor: AuditActor<'_>,
    current_generation: ServiceClockGeneration,
) -> Result<u64, StoreError> {
    let before = &loaded.snapshot;
    let event = transition_event(before, after)?;
    if event.is_none() && before.persisted_state() != after.persisted_state() {
        return Err(StoreError::IntegrityCheckFailed);
    }
    if event.is_none() && before == after {
        return Ok(loaded.row_version);
    }
    let now = StoredTimestamp::from_utc(event_at)?;
    let new_row_version = loaded
        .row_version
        .checked_add(1)
        .ok_or(StoreError::ConcurrentMutation)?;
    let event_delta = u64::from(event.is_some());
    let next_sequence = loaded
        .next_audit_sequence
        .checked_add(event_delta)
        .ok_or(StoreError::IntegrityCheckFailed)?;
    let projection = Projection::new(after)?;
    let actor = event.map_or(actor, |event| actor.resolve(event, projection.reason));
    if let Some(event) = event {
        validate_actor(event, projection.reason, &actor, before.caller_subject())?;
    }
    update_lease(
        transaction,
        loaded,
        &projection,
        event,
        &now,
        new_row_version,
        next_sequence,
    )?;
    if clock_changed(before, after) {
        update_clock(transaction, loaded, &projection, after)?;
    }
    if let Some(event) = event {
        insert_audit(
            transaction,
            loaded,
            &projection,
            event,
            &now,
            actor,
            current_generation,
            new_row_version,
        )?;
    }
    Ok(new_row_version)
}

fn validate_actor(
    event: TransitionEvent,
    reason: Option<LeaseReasonCode>,
    actor: &AuditActor<'_>,
    caller: &CallerSubject,
) -> Result<(), StoreError> {
    let valid = match (event, reason) {
        (TransitionEvent::Closed, _) => actor.is_service() || actor.matches_caller(caller),
        (TransitionEvent::Revoked, Some(LeaseReasonCode::OperatorRevoked)) => {
            actor.matches_caller(caller)
        }
        _ => actor.is_service(),
    };
    if valid {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

struct Projection<'a> {
    status: LeaseStatus,
    authority: Option<&'a PersistedResolvedAuthority>,
    acknowledgement_deadline: Option<&'a UtcTimestamp>,
    monotonic_acknowledgement_deadline: Option<u128>,
    refusal: Option<RefusalCode>,
    reason: Option<LeaseReasonCode>,
}

impl<'a> Projection<'a> {
    fn new(snapshot: &'a LeaseSnapshot) -> Result<Self, StoreError> {
        let (status, authority, acknowledgement_deadline, monotonic_ack, refusal, reason) =
            match snapshot.persisted_state() {
                PersistedLeaseState::Requested => {
                    (LeaseStatus::Requested, None, None, None, None, None)
                }
                PersistedLeaseState::Refused(code) => {
                    (LeaseStatus::Refused, None, None, None, Some(*code), None)
                }
                PersistedLeaseState::Active(authority) => {
                    (LeaseStatus::Active, Some(authority), None, None, None, None)
                }
                PersistedLeaseState::Renewing {
                    authority,
                    acknowledgement_deadline,
                    monotonic_acknowledgement_deadline,
                } => (
                    LeaseStatus::Renewing,
                    Some(authority),
                    Some(acknowledgement_deadline),
                    Some(monotonic_acknowledgement_deadline.as_nanoseconds()),
                    None,
                    None,
                ),
                PersistedLeaseState::Error { authority, reason } => (
                    LeaseStatus::Error,
                    Some(authority),
                    None,
                    None,
                    None,
                    Some(*reason),
                ),
                PersistedLeaseState::Closed { authority, reason } => (
                    LeaseStatus::Closed,
                    Some(authority),
                    None,
                    None,
                    None,
                    Some(*reason),
                ),
                PersistedLeaseState::Revoked { authority, reason } => (
                    LeaseStatus::Revoked,
                    Some(authority),
                    None,
                    None,
                    None,
                    Some(*reason),
                ),
                PersistedLeaseState::Expired { authority, reason } => (
                    LeaseStatus::Expired,
                    Some(authority),
                    None,
                    None,
                    None,
                    Some(*reason),
                ),
            };
        if snapshot.service_generation().get() == 0 {
            return Err(StoreError::IntegrityCheckFailed);
        }
        Ok(Self {
            status,
            authority,
            acknowledgement_deadline,
            monotonic_acknowledgement_deadline: monotonic_ack,
            refusal,
            reason,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn update_lease(
    transaction: &Transaction<'_>,
    loaded: &LoadedLease,
    projection: &Projection<'_>,
    event: Option<TransitionEvent>,
    now: &StoredTimestamp<'_>,
    new_row_version: u64,
    next_sequence: u64,
) -> Result<(), StoreError> {
    let authority = projection.authority;
    let resolution = authority.map(PersistedResolvedAuthority::resolution);
    let activated = i64::from(event == Some(TransitionEvent::Activated));
    let renewal_action = match event {
        Some(TransitionEvent::Renewing) => 1_i64,
        Some(TransitionEvent::Renewed) => 2_i64,
        _ => 0_i64,
    };
    let terminal = i64::from(matches!(
        event,
        Some(
            TransitionEvent::Refused
                | TransitionEvent::Closed
                | TransitionEvent::Revoked
                | TransitionEvent::Expired
        )
    ));
    let expires = authority
        .map(PersistedResolvedAuthority::expires_at)
        .map(stored)
        .transpose()?;
    let maximum = authority
        .map(PersistedResolvedAuthority::maximum_expires_at)
        .map(stored)
        .transpose()?;
    let acknowledgement = projection
        .acknowledgement_deadline
        .map(stored)
        .transpose()?;
    let changed = transaction
        .execute(
            "UPDATE leases SET
                status = :status,
                effective_policy_digest = :policy_digest,
                fencing_generation = :fencing_generation,
                clock_generation = :clock_generation,
                execution_handle = :execution_handle,
                worker_identity = :worker_identity,
                principal_ref = :principal_ref,
                workspace_ref = :workspace_ref,
                auth_mode = :auth_mode,
                isolation = :isolation,
                activated_at_utc = CASE WHEN :activated = 1 THEN :now_utc ELSE activated_at_utc END,
                activated_at_seconds = CASE WHEN :activated = 1 THEN :now_seconds ELSE activated_at_seconds END,
                activated_at_nanos = CASE WHEN :activated = 1 THEN :now_nanos ELSE activated_at_nanos END,
                renewed_at_utc = CASE WHEN :renewal_action = 1 THEN :now_utc ELSE renewed_at_utc END,
                renewed_at_seconds = CASE WHEN :renewal_action = 1 THEN :now_seconds ELSE renewed_at_seconds END,
                renewed_at_nanos = CASE WHEN :renewal_action = 1 THEN :now_nanos ELSE renewed_at_nanos END,
                renewal_acknowledged_at_utc = CASE
                    WHEN :renewal_action = 1 THEN NULL
                    WHEN :renewal_action = 2 THEN :now_utc
                    ELSE renewal_acknowledged_at_utc END,
                renewal_acknowledged_at_seconds = CASE
                    WHEN :renewal_action = 1 THEN NULL
                    WHEN :renewal_action = 2 THEN :now_seconds
                    ELSE renewal_acknowledged_at_seconds END,
                renewal_acknowledged_at_nanos = CASE
                    WHEN :renewal_action = 1 THEN NULL
                    WHEN :renewal_action = 2 THEN :now_nanos
                    ELSE renewal_acknowledged_at_nanos END,
                terminal_at_utc = CASE WHEN :terminal = 1 THEN :now_utc ELSE terminal_at_utc END,
                terminal_at_seconds = CASE WHEN :terminal = 1 THEN :now_seconds ELSE terminal_at_seconds END,
                terminal_at_nanos = CASE WHEN :terminal = 1 THEN :now_nanos ELSE terminal_at_nanos END,
                expires_at_utc = :expires_utc,
                expires_at_seconds = :expires_seconds,
                expires_at_nanos = :expires_nanos,
                expires_monotonic_nanos = :expires_monotonic,
                maximum_expires_at_utc = :maximum_utc,
                maximum_expires_at_seconds = :maximum_seconds,
                maximum_expires_at_nanos = :maximum_nanos,
                maximum_expires_monotonic_nanos = :maximum_monotonic,
                renewal_ack_deadline_utc = :ack_utc,
                renewal_ack_deadline_seconds = :ack_seconds,
                renewal_ack_deadline_nanos = :ack_nanos,
                renewal_ack_deadline_monotonic_nanos = :ack_monotonic,
                refusal_code = :refusal_code,
                reason_code = :reason_code,
                row_version = :new_row_version,
                next_audit_sequence = :next_sequence
             WHERE lease_id = :lease_id
               AND service_generation = :origin_generation
               AND row_version = :expected_row_version
               AND next_audit_sequence = :expected_sequence
               AND recovery_state = 'NONE' AND quarantined = 0",
            named_params! {
                ":status": status_label(projection.status),
                ":policy_digest": authority.map(|value| value.effective_policy_digest().to_string()),
                ":fencing_generation": authority.map(|value| i64::try_from(value.fencing_generation().get())).transpose().map_err(|_| StoreError::IntegrityCheckFailed)?,
                ":clock_generation": authority.map(|_| i64::try_from(loaded.origin_generation.get())).transpose().map_err(|_| StoreError::IntegrityCheckFailed)?,
                ":execution_handle": resolution.map(|value| value.execution_handle.as_str()),
                ":worker_identity": resolution.and_then(|value| value.worker_identity.as_ref()).map(crate::automation::contracts::WorkerIdentity::as_str),
                ":principal_ref": resolution.map(|value| value.principal_ref.as_str()),
                ":workspace_ref": resolution.map(|value| value.workspace_ref.as_str()),
                ":auth_mode": resolution.map(|value| auth_label(value.auth_mode)),
                ":isolation": resolution.map(|value| isolation_label(value.isolation)),
                ":activated": activated,
                ":renewal_action": renewal_action,
                ":terminal": terminal,
                ":now_utc": now.wire,
                ":now_seconds": now.seconds,
                ":now_nanos": now.nanos,
                ":expires_utc": expires.as_ref().map(|value| value.wire),
                ":expires_seconds": expires.as_ref().map(|value| value.seconds),
                ":expires_nanos": expires.as_ref().map(|value| value.nanos),
                ":expires_monotonic": authority.map(|value| value.monotonic_deadline().as_nanoseconds().to_be_bytes()),
                ":maximum_utc": maximum.as_ref().map(|value| value.wire),
                ":maximum_seconds": maximum.as_ref().map(|value| value.seconds),
                ":maximum_nanos": maximum.as_ref().map(|value| value.nanos),
                ":maximum_monotonic": authority.map(|value| value.monotonic_maximum_deadline().as_nanoseconds().to_be_bytes()),
                ":ack_utc": acknowledgement.as_ref().map(|value| value.wire),
                ":ack_seconds": acknowledgement.as_ref().map(|value| value.seconds),
                ":ack_nanos": acknowledgement.as_ref().map(|value| value.nanos),
                ":ack_monotonic": projection.monotonic_acknowledgement_deadline.map(u128::to_be_bytes),
                ":refusal_code": projection.refusal.map(refusal_label),
                ":reason_code": projection.reason.map(reason_label),
                ":new_row_version": i64::try_from(new_row_version).map_err(|_| StoreError::IntegrityCheckFailed)?,
                ":next_sequence": i64::try_from(next_sequence).map_err(|_| StoreError::IntegrityCheckFailed)?,
                ":lease_id": loaded.snapshot.lease_id().as_str(),
                ":origin_generation": i64::try_from(loaded.origin_generation.get()).map_err(|_| StoreError::IntegrityCheckFailed)?,
                ":expected_row_version": i64::try_from(loaded.row_version).map_err(|_| StoreError::IntegrityCheckFailed)?,
                ":expected_sequence": i64::try_from(loaded.next_audit_sequence).map_err(|_| StoreError::IntegrityCheckFailed)?,
            },
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::ConcurrentMutation)
    }
}

fn update_clock(
    transaction: &Transaction<'_>,
    loaded: &LoadedLease,
    projection: &Projection<'_>,
    after: &LeaseSnapshot,
) -> Result<(), StoreError> {
    let anchor = projection
        .authority
        .map(PersistedResolvedAuthority::interval_anchor_wall)
        .map(stored)
        .transpose()?;
    let changed = transaction
        .execute(
            "UPDATE lease_runtime_clocks SET
                monotonic_high_water_nanos = ?1,
                interval_anchor_at_utc = ?2,
                interval_anchor_at_seconds = ?3,
                interval_anchor_at_nanos = ?4,
                interval_anchor_monotonic_nanos = ?5,
                row_version = row_version + 1
             WHERE lease_id = ?6 AND service_generation = ?7 AND row_version = ?8",
            rusqlite::params![
                after
                    .monotonic_high_water()
                    .as_nanoseconds()
                    .to_be_bytes()
                    .as_slice(),
                anchor.as_ref().map(|value| value.wire),
                anchor.as_ref().map(|value| value.seconds),
                anchor.as_ref().map(|value| value.nanos),
                projection.authority.map(|value| value
                    .interval_anchor_monotonic()
                    .as_nanoseconds()
                    .to_be_bytes()),
                loaded.snapshot.lease_id().as_str(),
                i64::try_from(loaded.origin_generation.get())
                    .map_err(|_| StoreError::IntegrityCheckFailed)?,
                i64::try_from(loaded.clock_row_version)
                    .map_err(|_| StoreError::IntegrityCheckFailed)?,
            ],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::ConcurrentMutation)
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_audit(
    transaction: &Transaction<'_>,
    loaded: &LoadedLease,
    projection: &Projection<'_>,
    event: TransitionEvent,
    now: &StoredTimestamp<'_>,
    actor: AuditActor<'_>,
    current_generation: ServiceClockGeneration,
    new_row_version: u64,
) -> Result<(), StoreError> {
    let audit_id = allocate_id(
        transaction,
        AUDIT_PREFIX,
        "SELECT EXISTS(SELECT 1 FROM audit_events WHERE audit_event_id = ?1)",
    )?;
    let authority = projection.authority;
    let inserted = transaction
        .execute(
            "INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, fencing_generation, effective_policy_digest,
                refusal_code, reason_code
             ) SELECT
                ?1, l.lease_id, ?2, ?3, ?4, ?5, ?6, l.recovery_state, l.quarantined,
                ?7, ?8, ?9, ?10, r.client_request_id, l.tenant_id, l.work_order_id,
                l.work_order_digest, l.run_id, l.attempt_id, l.role, l.provider,
                l.profile_uid, l.profile_ref, l.repository_id, l.workspace_id,
                l.environment, l.authenticated_caller, l.host_identity, ?11, ?12, ?13, ?14
             FROM leases l JOIN lease_requests r ON r.request_record_id = l.request_record_id
             WHERE l.lease_id = ?15 AND l.row_version = ?16",
            rusqlite::params![
                audit_id,
                i64::try_from(loaded.next_audit_sequence)
                    .map_err(|_| StoreError::IntegrityCheckFailed)?,
                i64::try_from(current_generation.get())
                    .map_err(|_| StoreError::IntegrityCheckFailed)?,
                event.event_type(),
                event.outcome(projection.reason),
                status_label(projection.status),
                now.wire,
                now.seconds,
                now.nanos,
                actor.label(),
                authority
                    .map(|value| i64::try_from(value.fencing_generation().get()))
                    .transpose()
                    .map_err(|_| StoreError::IntegrityCheckFailed)?,
                authority.map(|value| value.effective_policy_digest().to_string()),
                projection.refusal.map(refusal_label),
                projection.reason.map(reason_label),
                loaded.snapshot.lease_id().as_str(),
                i64::try_from(new_row_version).map_err(|_| StoreError::IntegrityCheckFailed)?,
            ],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(StoreError::ConcurrentMutation)
    }
}

fn transition_event(
    before: &LeaseSnapshot,
    after: &LeaseSnapshot,
) -> Result<Option<TransitionEvent>, StoreError> {
    let prior = Projection::new(before)?.status;
    let next = Projection::new(after)?.status;
    let event = match (prior, next) {
        (left, right) if left == right => None,
        (LeaseStatus::Requested, LeaseStatus::Refused) => Some(TransitionEvent::Refused),
        (LeaseStatus::Requested, LeaseStatus::Active) => Some(TransitionEvent::Activated),
        (LeaseStatus::Active, LeaseStatus::Renewing) => Some(TransitionEvent::Renewing),
        (LeaseStatus::Renewing, LeaseStatus::Active) => Some(TransitionEvent::Renewed),
        (LeaseStatus::Active | LeaseStatus::Renewing, LeaseStatus::Closed) => {
            Some(TransitionEvent::Closed)
        }
        (
            LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error,
            LeaseStatus::Revoked,
        ) => Some(TransitionEvent::Revoked),
        (
            LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error,
            LeaseStatus::Expired,
        ) => Some(TransitionEvent::Expired),
        (LeaseStatus::Active | LeaseStatus::Renewing, LeaseStatus::Error) => {
            Some(TransitionEvent::Error)
        }
        _ => return Err(StoreError::IntegrityCheckFailed),
    };
    Ok(event)
}

fn clock_changed(before: &LeaseSnapshot, after: &LeaseSnapshot) -> bool {
    before.monotonic_high_water() != after.monotonic_high_water()
        || authority(before).map(anchor_projection) != authority(after).map(anchor_projection)
}

fn authority(snapshot: &LeaseSnapshot) -> Option<&PersistedResolvedAuthority> {
    match snapshot.persisted_state() {
        PersistedLeaseState::Active(authority)
        | PersistedLeaseState::Renewing { authority, .. }
        | PersistedLeaseState::Error { authority, .. }
        | PersistedLeaseState::Closed { authority, .. }
        | PersistedLeaseState::Revoked { authority, .. }
        | PersistedLeaseState::Expired { authority, .. } => Some(authority),
        PersistedLeaseState::Requested | PersistedLeaseState::Refused(_) => None,
    }
}

fn anchor_projection(authority: &PersistedResolvedAuthority) -> (&UtcTimestamp, u128) {
    (
        authority.interval_anchor_wall(),
        authority.interval_anchor_monotonic().as_nanoseconds(),
    )
}

fn stored(value: &UtcTimestamp) -> Result<StoredTimestamp<'_>, StoreError> {
    StoredTimestamp::from_utc(value).map_err(|_| StoreError::IntegrityCheckFailed)
}

const fn status_label(status: LeaseStatus) -> &'static str {
    match status {
        LeaseStatus::Requested => "REQUESTED",
        LeaseStatus::Active => "ACTIVE",
        LeaseStatus::Renewing => "RENEWING",
        LeaseStatus::Closed => "CLOSED",
        LeaseStatus::Revoked => "REVOKED",
        LeaseStatus::Expired => "EXPIRED",
        LeaseStatus::Refused => "REFUSED",
        LeaseStatus::Error => "ERROR",
    }
}

const fn auth_label(mode: AutomationAuthMode) -> &'static str {
    match mode {
        AutomationAuthMode::Wif => "wif",
        AutomationAuthMode::SubscriptionToken => "subscription-token",
        AutomationAuthMode::ApiKey => "api-key",
        AutomationAuthMode::ChatgptOauth => "chatgpt-oauth",
        AutomationAuthMode::AccessToken => "access-token",
    }
}

const fn isolation_label(value: IsolationClassification) -> &'static str {
    match value {
        IsolationClassification::CredentialIsolated => "credential-isolated",
        IsolationClassification::PerLeaseIsolated => "per-lease-isolated",
        IsolationClassification::CopiedCredentialDevelopment => "copied-credential-development",
        IsolationClassification::Unproven => "unproven",
    }
}

const fn reason_label(reason: LeaseReasonCode) -> &'static str {
    match reason {
        LeaseReasonCode::Completed => "completed",
        LeaseReasonCode::WorkerFailed => "worker-failed",
        LeaseReasonCode::OperatorRevoked => "operator-revoked",
        LeaseReasonCode::PolicyRevoked => "policy-revoked",
        LeaseReasonCode::PrincipalMismatch => "principal-mismatch",
        LeaseReasonCode::LeaseExpired => "lease-expired",
        LeaseReasonCode::MaximumLifetimeReached => "maximum-lifetime-reached",
        LeaseReasonCode::HeartbeatLost => "heartbeat-lost",
        LeaseReasonCode::ProcessUnverifiable => "process-unverifiable",
        LeaseReasonCode::GenerationSuperseded => "generation-superseded",
        LeaseReasonCode::RenewalAcknowledgementFailed => "renewal-acknowledgement-failed",
        LeaseReasonCode::ServiceRecovery => "service-recovery",
        LeaseReasonCode::InternalError => "internal-error",
    }
}
