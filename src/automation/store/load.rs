use rusqlite::{OptionalExtension, Row, Transaction};

use crate::automation::{
    contracts::{
        CallerSubject, HostIdentity, IdentityLeaseRequest, LeaseId, LeaseStatus, Sha256Digest,
        UtcTimestamp,
    },
    lease::{
        ClockSample, Lease, LeaseBinding, LeaseResolution, LeaseSnapshot, MonotonicMoment,
        PersistedLeaseState, PersistedResolvedAuthority, ServiceClockGeneration,
    },
};

use super::{
    StoreError,
    load_parse::{
        OptionalRawTimestamp, RawTimestamp, RecoveryState, optional_timestamp, parse_auth_mode,
        parse_fencing, parse_generation, parse_isolation, parse_optional, parse_optional_u128,
        parse_reason, parse_recovery_state, parse_required, parse_status, parse_u128,
        required_timestamp, role_label,
    },
    records::{PersistedIssuance, StoredTimestamp, parse_refusal, replay_retain_until},
};

#[path = "load/audit.rs"]
pub(super) mod audit;

pub(super) struct LoadedLease {
    pub(super) lease: Lease,
    pub(super) snapshot: LeaseSnapshot,
    pub(super) issuance: PersistedIssuance,
    pub(super) origin_generation: ServiceClockGeneration,
    pub(super) recovery_state: RecoveryState,
    pub(super) quarantined: bool,
    pub(super) row_version: u64,
    pub(super) clock_row_version: u64,
    pub(super) process_audit: audit::ProcessAuditProjection,
}

pub(super) struct LoadedReplay {
    pub(super) digest: Sha256Digest,
    pub(super) canonical: Vec<u8>,
    pub(super) caller: CallerSubject,
    pub(super) host: HostIdentity,
    pub(super) loaded: LoadedLease,
}

struct LoadedRequest {
    request_record_id: String,
    request: IdentityLeaseRequest,
    digest: Sha256Digest,
    canonical: Vec<u8>,
    caller: CallerSubject,
    host: HostIdentity,
    recorded_at: UtcTimestamp,
}

pub(super) fn replay_by_client_request(
    transaction: &Transaction<'_>,
    client_request_id: &str,
) -> Result<Option<LoadedReplay>, StoreError> {
    let Some(request) = request_by_client_id(transaction, client_request_id)? else {
        return Ok(None);
    };
    let loaded = lease_for_request(transaction, &request)?;
    Ok(Some(LoadedReplay {
        digest: request.digest,
        canonical: request.canonical,
        caller: request.caller,
        host: request.host,
        loaded,
    }))
}

pub(super) fn lease_by_id(
    transaction: &Transaction<'_>,
    lease_id: &str,
) -> Result<Option<LoadedLease>, StoreError> {
    let request_record_id = transaction
        .query_row(
            "SELECT request_record_id FROM leases WHERE lease_id = ?1",
            [lease_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let Some(request_record_id) = request_record_id else {
        return Ok(None);
    };
    let request = request_by_record_id(transaction, &request_record_id)?
        .ok_or(StoreError::IntegrityCheckFailed)?;
    lease_for_request(transaction, &request).map(Some)
}

pub(super) fn validate_all_leases(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let mut statement = transaction
        .prepare("SELECT client_request_id FROM lease_requests ORDER BY client_request_id")
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let client_request_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    drop(statement);
    for client_request_id in client_request_ids {
        let request = request_by_client_id(transaction, &client_request_id)?
            .ok_or(StoreError::IntegrityCheckFailed)?;
        lease_for_request(transaction, &request)?;
    }
    Ok(())
}

fn request_by_client_id(
    transaction: &Transaction<'_>,
    value: &str,
) -> Result<Option<LoadedRequest>, StoreError> {
    load_request(transaction, "client_request_id", value)
}

fn request_by_record_id(
    transaction: &Transaction<'_>,
    value: &str,
) -> Result<Option<LoadedRequest>, StoreError> {
    load_request(transaction, "request_record_id", value)
}

fn load_request(
    transaction: &Transaction<'_>,
    key: &str,
    value: &str,
) -> Result<Option<LoadedRequest>, StoreError> {
    let sql = format!(
        "SELECT request_record_id, client_request_id,
                canonical_authority_digest, canonical_request,
                authenticated_caller, host_identity,
                authorization_expires_at_utc, authorization_expires_at_seconds,
                authorization_expires_at_nanos,
                replay_retain_until_utc, replay_retain_until_seconds,
                replay_retain_until_nanos,
                recorded_at_utc, recorded_at_seconds, recorded_at_nanos
         FROM lease_requests WHERE {key} = ?1"
    );
    let raw = transaction
        .query_row(&sql, [value], |row| {
            Ok(RawRequest {
                request_record_id: row.get(0)?,
                client_request_id: row.get(1)?,
                digest: row.get(2)?,
                canonical: row.get(3)?,
                caller: row.get(4)?,
                host: row.get(5)?,
                authorization_expiry: required_timestamp(row, 6)?,
                replay_retention: required_timestamp(row, 9)?,
                recorded_at: required_timestamp(row, 12)?,
            })
        })
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    raw.map(RawRequest::validate).transpose()
}

struct RawRequest {
    request_record_id: String,
    client_request_id: String,
    digest: String,
    canonical: Vec<u8>,
    caller: String,
    host: String,
    authorization_expiry: RawTimestamp,
    replay_retention: RawTimestamp,
    recorded_at: RawTimestamp,
}

impl RawRequest {
    fn validate(self) -> Result<LoadedRequest, StoreError> {
        let request: IdentityLeaseRequest = serde_json::from_slice(&self.canonical)
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let canonical = request
            .canonical_authority_json()
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let digest = self
            .digest
            .parse::<Sha256Digest>()
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        if canonical != self.canonical || digest != Sha256Digest::hash(&canonical) {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let authorization_expiry = self.authorization_expiry.validate()?;
        let replay_retention = self.replay_retention.validate()?;
        let recorded_at = self.recorded_at.validate()?;
        let expected_retention = replay_retain_until(&recorded_at, &authorization_expiry)
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        if self.client_request_id != request.client_request_id.as_str()
            || authorization_expiry != request.work_order_authorization.expires_at
            || replay_retention != expected_retention
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        Ok(LoadedRequest {
            request_record_id: self.request_record_id,
            request,
            digest,
            canonical,
            caller: self
                .caller
                .parse()
                .map_err(|_| StoreError::IntegrityCheckFailed)?,
            host: self
                .host
                .parse()
                .map_err(|_| StoreError::IntegrityCheckFailed)?,
            recorded_at,
        })
    }
}

fn lease_for_request(
    transaction: &Transaction<'_>,
    request: &LoadedRequest,
) -> Result<LoadedLease, StoreError> {
    let raw = transaction
        .query_row(
            "SELECT
                l.lease_id, l.request_record_id, l.service_generation,
                l.row_version, l.next_audit_sequence, l.status, l.recovery_state,
                l.quarantined, l.tenant_id, l.work_order_id, l.work_order_digest,
                l.run_id, l.attempt_id, l.role, l.provider, l.profile_uid,
                l.profile_ref, l.repository_id, l.workspace_id, l.environment,
                l.authenticated_caller, l.host_identity, l.requested_ttl_seconds,
                l.requested_policy_digest, l.effective_policy_digest,
                l.fencing_generation, l.clock_generation, l.execution_handle,
                l.worker_identity, l.principal_ref, l.workspace_ref, l.auth_mode,
                l.isolation, l.issued_at_utc, l.issued_at_seconds, l.issued_at_nanos,
                l.issued_monotonic_nanos,
                l.activated_at_utc, l.activated_at_seconds, l.activated_at_nanos,
                l.renewed_at_utc, l.renewed_at_seconds, l.renewed_at_nanos,
                l.renewal_acknowledged_at_utc, l.renewal_acknowledged_at_seconds,
                l.renewal_acknowledged_at_nanos,
                l.terminal_at_utc, l.terminal_at_seconds, l.terminal_at_nanos,
                l.expires_at_utc, l.expires_at_seconds, l.expires_at_nanos,
                l.expires_monotonic_nanos,
                l.maximum_expires_at_utc, l.maximum_expires_at_seconds,
                l.maximum_expires_at_nanos, l.maximum_expires_monotonic_nanos,
                l.renewal_ack_deadline_utc, l.renewal_ack_deadline_seconds,
                l.renewal_ack_deadline_nanos,
                l.renewal_ack_deadline_monotonic_nanos,
                l.refusal_code, l.reason_code,
                c.service_generation, c.monotonic_high_water_nanos,
                c.interval_anchor_at_utc, c.interval_anchor_at_seconds,
                c.interval_anchor_at_nanos, c.interval_anchor_monotonic_nanos,
                c.row_version
             FROM leases l
             JOIN lease_runtime_clocks c
               ON c.lease_id = l.lease_id
              AND c.service_generation = l.service_generation
             WHERE l.request_record_id = ?1",
            [&request.request_record_id],
            RawLease::from_row,
        )
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .ok_or(StoreError::IntegrityCheckFailed)?;
    raw.validate(transaction, request)
}

struct RawLease {
    lease_id: String,
    request_record_id: String,
    service_generation: i64,
    row_version: i64,
    next_audit_sequence: i64,
    status: String,
    recovery_state: String,
    quarantined: i64,
    tenant_id: String,
    work_order_id: String,
    work_order_digest: String,
    run_id: String,
    attempt_id: String,
    role: String,
    provider: String,
    profile_uid: String,
    profile_ref: String,
    repository_id: String,
    workspace_id: String,
    environment: String,
    caller: String,
    host: String,
    requested_ttl: i64,
    requested_policy_digest: Option<String>,
    effective_policy_digest: Option<String>,
    fencing_generation: Option<i64>,
    clock_generation: Option<i64>,
    execution_handle: Option<String>,
    worker_identity: Option<String>,
    principal_ref: Option<String>,
    workspace_ref: Option<String>,
    auth_mode: Option<String>,
    isolation: Option<String>,
    issued_at: RawTimestamp,
    issued_monotonic: Vec<u8>,
    activated_at: OptionalRawTimestamp,
    renewed_at: OptionalRawTimestamp,
    renewal_acknowledged_at: OptionalRawTimestamp,
    terminal_at: OptionalRawTimestamp,
    expires_at: OptionalRawTimestamp,
    expires_monotonic: Option<Vec<u8>>,
    maximum_expires_at: OptionalRawTimestamp,
    maximum_expires_monotonic: Option<Vec<u8>>,
    renewal_ack_deadline: OptionalRawTimestamp,
    renewal_ack_monotonic: Option<Vec<u8>>,
    refusal_code: Option<String>,
    reason_code: Option<String>,
    clock_service_generation: i64,
    monotonic_high_water: Vec<u8>,
    interval_anchor_at: OptionalRawTimestamp,
    interval_anchor_monotonic: Option<Vec<u8>>,
    clock_row_version: i64,
}

impl RawLease {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            lease_id: row.get(0)?,
            request_record_id: row.get(1)?,
            service_generation: row.get(2)?,
            row_version: row.get(3)?,
            next_audit_sequence: row.get(4)?,
            status: row.get(5)?,
            recovery_state: row.get(6)?,
            quarantined: row.get(7)?,
            tenant_id: row.get(8)?,
            work_order_id: row.get(9)?,
            work_order_digest: row.get(10)?,
            run_id: row.get(11)?,
            attempt_id: row.get(12)?,
            role: row.get(13)?,
            provider: row.get(14)?,
            profile_uid: row.get(15)?,
            profile_ref: row.get(16)?,
            repository_id: row.get(17)?,
            workspace_id: row.get(18)?,
            environment: row.get(19)?,
            caller: row.get(20)?,
            host: row.get(21)?,
            requested_ttl: row.get(22)?,
            requested_policy_digest: row.get(23)?,
            effective_policy_digest: row.get(24)?,
            fencing_generation: row.get(25)?,
            clock_generation: row.get(26)?,
            execution_handle: row.get(27)?,
            worker_identity: row.get(28)?,
            principal_ref: row.get(29)?,
            workspace_ref: row.get(30)?,
            auth_mode: row.get(31)?,
            isolation: row.get(32)?,
            issued_at: required_timestamp(row, 33)?,
            issued_monotonic: row.get(36)?,
            activated_at: optional_timestamp(row, 37)?,
            renewed_at: optional_timestamp(row, 40)?,
            renewal_acknowledged_at: optional_timestamp(row, 43)?,
            terminal_at: optional_timestamp(row, 46)?,
            expires_at: optional_timestamp(row, 49)?,
            expires_monotonic: row.get(52)?,
            maximum_expires_at: optional_timestamp(row, 53)?,
            maximum_expires_monotonic: row.get(56)?,
            renewal_ack_deadline: optional_timestamp(row, 57)?,
            renewal_ack_monotonic: row.get(60)?,
            refusal_code: row.get(61)?,
            reason_code: row.get(62)?,
            clock_service_generation: row.get(63)?,
            monotonic_high_water: row.get(64)?,
            interval_anchor_at: optional_timestamp(row, 65)?,
            interval_anchor_monotonic: row.get(68)?,
            clock_row_version: row.get(69)?,
        })
    }

    fn validate(
        self,
        transaction: &Transaction<'_>,
        stored: &LoadedRequest,
    ) -> Result<LoadedLease, StoreError> {
        let status = parse_status(&self.status)?;
        let origin_generation = parse_generation(self.service_generation)?;
        if self.clock_service_generation != self.service_generation
            || self.request_record_id != stored.request_record_id
            || self.row_version <= 0
            || self.next_audit_sequence <= 0
            || self.clock_row_version <= 0
            || !matches!(self.quarantined, 0 | 1)
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        validate_binding_columns(&self, stored)?;
        let issued_at = self.issued_at.clone().validate()?;
        if issued_at != stored.recorded_at {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let issued_monotonic = parse_u128(&self.issued_monotonic)?;
        let high_water = parse_u128(&self.monotonic_high_water)?;
        if high_water < issued_monotonic {
            return Err(StoreError::IntegrityCheckFailed);
        }
        if parse_optional_u128(self.interval_anchor_monotonic.as_deref())?
            .is_some_and(|anchor| anchor > high_water)
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        validate_optional_audit_timestamps(&self, &issued_at, status)?;
        validate_terminal_evidence(&self, status, high_water)?;
        let process_audit = audit::validate(transaction, &self, stored, status)?;
        if !matches!(status, LeaseStatus::Requested | LeaseStatus::Refused) {
            stored
                .request
                .validate_authorization(&issued_at)
                .map_err(|_| StoreError::IntegrityCheckFailed)?;
        }

        let lease_id =
            LeaseId::parse(self.lease_id.clone()).map_err(|_| StoreError::IntegrityCheckFailed)?;
        let binding = LeaseBinding::from_request(
            lease_id,
            &stored.request,
            stored.caller.clone(),
            stored.host.clone(),
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let issuance_clock = ClockSample::new(
            issued_at.clone(),
            MonotonicMoment::from_nanoseconds(issued_monotonic),
            origin_generation,
        );
        let state = self.persisted_state(status, issued_monotonic)?;
        let snapshot = LeaseSnapshot::new(
            binding,
            issuance_clock.clone(),
            MonotonicMoment::from_nanoseconds(high_water),
            state,
        );
        if snapshot.service_generation() != origin_generation {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let expected_snapshot = snapshot.clone();
        let lease = Lease::restore(snapshot).map_err(|_| StoreError::IntegrityCheckFailed)?;
        if lease.snapshot() != expected_snapshot {
            return Err(StoreError::IntegrityCheckFailed);
        }
        super::recovery::validate_live_process_evidence(
            transaction,
            &LeaseId::parse(self.lease_id.clone()).map_err(|_| StoreError::IntegrityCheckFailed)?,
            &expected_snapshot,
            origin_generation,
            &process_audit,
        )?;
        if !matches!(status, LeaseStatus::Requested | LeaseStatus::Refused)
            && stored
                .request
                .policy_digest
                .is_some_and(|expected| lease.effective_policy_digest() != Some(expected))
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let recovery_state = parse_recovery_state(&self.recovery_state)?;
        Ok(LoadedLease {
            lease,
            snapshot: expected_snapshot,
            issuance: PersistedIssuance::new(
                issued_at,
                MonotonicMoment::from_nanoseconds(issued_monotonic),
                origin_generation,
            ),
            origin_generation,
            recovery_state,
            quarantined: self.quarantined == 1,
            row_version: u64::try_from(self.row_version)
                .map_err(|_| StoreError::IntegrityCheckFailed)?,
            clock_row_version: u64::try_from(self.clock_row_version)
                .map_err(|_| StoreError::IntegrityCheckFailed)?,
            process_audit,
        })
    }

    fn persisted_state(
        &self,
        status: LeaseStatus,
        issued_monotonic: u128,
    ) -> Result<PersistedLeaseState, StoreError> {
        let refusal = self
            .refusal_code
            .as_deref()
            .map(|value| parse_refusal(value).ok_or(StoreError::IntegrityCheckFailed))
            .transpose()?;
        let reason = self.reason_code.as_deref().map(parse_reason).transpose()?;
        if status == LeaseStatus::Requested {
            return match (refusal, reason, self.resolved_fields_present()) {
                (None, None, false) => Ok(PersistedLeaseState::Requested),
                _ => Err(StoreError::IntegrityCheckFailed),
            };
        }
        if status == LeaseStatus::Refused {
            return match (refusal, reason, self.resolved_fields_present()) {
                (Some(code), None, false) => Ok(PersistedLeaseState::Refused(code)),
                _ => Err(StoreError::IntegrityCheckFailed),
            };
        }
        if refusal.is_some() {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let authority = self.resolved_authority(issued_monotonic)?;
        match (status, reason) {
            (LeaseStatus::Active, None) => Ok(PersistedLeaseState::Active(authority)),
            (LeaseStatus::Renewing, None) => Ok(PersistedLeaseState::Renewing {
                authority,
                acknowledgement_deadline: self
                    .renewal_ack_deadline
                    .clone()
                    .validate()?
                    .ok_or(StoreError::IntegrityCheckFailed)?,
                monotonic_acknowledgement_deadline: MonotonicMoment::from_nanoseconds(
                    parse_optional_u128(self.renewal_ack_monotonic.as_deref())?
                        .ok_or(StoreError::IntegrityCheckFailed)?,
                ),
            }),
            (LeaseStatus::Error, Some(reason)) => {
                Ok(PersistedLeaseState::Error { authority, reason })
            }
            (LeaseStatus::Closed, Some(reason)) => {
                Ok(PersistedLeaseState::Closed { authority, reason })
            }
            (LeaseStatus::Revoked, Some(reason)) => {
                Ok(PersistedLeaseState::Revoked { authority, reason })
            }
            (LeaseStatus::Expired, Some(reason)) => {
                Ok(PersistedLeaseState::Expired { authority, reason })
            }
            _ => Err(StoreError::IntegrityCheckFailed),
        }
    }

    fn resolved_authority(
        &self,
        _issued_monotonic: u128,
    ) -> Result<PersistedResolvedAuthority, StoreError> {
        if self.clock_generation != Some(self.service_generation) {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let effective_policy_digest = parse_required(self.effective_policy_digest.as_deref())?;
        Ok(PersistedResolvedAuthority::new(
            LeaseResolution {
                execution_handle: parse_required(self.execution_handle.as_deref())?,
                worker_identity: parse_optional(self.worker_identity.as_deref())?,
                principal_ref: parse_required(self.principal_ref.as_deref())?,
                workspace_ref: parse_required(self.workspace_ref.as_deref())?,
                auth_mode: parse_auth_mode(
                    self.auth_mode
                        .as_deref()
                        .ok_or(StoreError::IntegrityCheckFailed)?,
                )?,
                isolation: parse_isolation(
                    self.isolation
                        .as_deref()
                        .ok_or(StoreError::IntegrityCheckFailed)?,
                )?,
            },
            effective_policy_digest,
            parse_fencing(self.fencing_generation)?,
            self.expires_at
                .clone()
                .validate()?
                .ok_or(StoreError::IntegrityCheckFailed)?,
            self.maximum_expires_at
                .clone()
                .validate()?
                .ok_or(StoreError::IntegrityCheckFailed)?,
            self.interval_anchor_at
                .clone()
                .validate()?
                .ok_or(StoreError::IntegrityCheckFailed)?,
            MonotonicMoment::from_nanoseconds(
                parse_optional_u128(self.interval_anchor_monotonic.as_deref())?
                    .ok_or(StoreError::IntegrityCheckFailed)?,
            ),
            MonotonicMoment::from_nanoseconds(
                parse_optional_u128(self.expires_monotonic.as_deref())?
                    .ok_or(StoreError::IntegrityCheckFailed)?,
            ),
            MonotonicMoment::from_nanoseconds(
                parse_optional_u128(self.maximum_expires_monotonic.as_deref())?
                    .ok_or(StoreError::IntegrityCheckFailed)?,
            ),
        ))
    }

    fn resolved_fields_present(&self) -> bool {
        [
            self.effective_policy_digest.is_some(),
            self.fencing_generation.is_some(),
            self.clock_generation.is_some(),
            self.execution_handle.is_some(),
            self.worker_identity.is_some(),
            self.principal_ref.is_some(),
            self.workspace_ref.is_some(),
            self.auth_mode.is_some(),
            self.isolation.is_some(),
            self.expires_monotonic.is_some(),
            self.maximum_expires_monotonic.is_some(),
            self.interval_anchor_monotonic.is_some(),
        ]
        .into_iter()
        .any(|value| value)
            || self.expires_at.any_present()
            || self.maximum_expires_at.any_present()
            || self.interval_anchor_at.any_present()
    }
}

fn validate_binding_columns(raw: &RawLease, stored: &LoadedRequest) -> Result<(), StoreError> {
    let request = &stored.request;
    let expected_policy = request.policy_digest.map(|value| value.to_string());
    let requested_ttl = i64::try_from(request.requested_ttl_seconds.get())
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let matches = raw.tenant_id == request.tenant_id.as_str()
        && raw.work_order_id == request.work_order_id.as_str()
        && raw.work_order_digest == request.work_order_digest.to_string()
        && raw.run_id == request.run_id.as_str()
        && raw.attempt_id == request.attempt_id.as_str()
        && raw.role == role_label(request.role)
        && raw.provider == request.provider.to_string()
        && raw.profile_uid == request.profile_uid.as_str()
        && raw.profile_ref == request.profile_ref.as_str()
        && raw.repository_id == request.repository.as_str()
        && raw.workspace_id == request.workspace_id.as_str()
        && raw.environment == request.environment.as_str()
        && raw.caller == stored.caller.as_str()
        && raw.host == stored.host.as_str()
        && raw.requested_ttl == requested_ttl
        && raw.requested_policy_digest == expected_policy;
    if matches {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

fn validate_optional_audit_timestamps(
    raw: &RawLease,
    issued_at: &UtcTimestamp,
    status: LeaseStatus,
) -> Result<(), StoreError> {
    // Runtime audit timestamps retain truthful wall observations. After
    // activation, wall rollback is valid, so only canonical tuple presence and
    // state/fence relations are checked; authority ordering remains monotonic.
    let activated = raw.activated_at.clone().validate()?;
    let renewed = raw.renewed_at.clone().validate()?;
    let acknowledged = raw.renewal_acknowledged_at.clone().validate()?;
    let terminal = raw.terminal_at.clone().validate()?;
    let resolved = !matches!(status, LeaseStatus::Requested | LeaseStatus::Refused);
    let terminal_expected = matches!(
        status,
        LeaseStatus::Closed | LeaseStatus::Revoked | LeaseStatus::Expired | LeaseStatus::Refused
    );
    if activated.is_some() != resolved || terminal.is_some() != terminal_expected {
        return Err(StoreError::IntegrityCheckFailed);
    }
    if !resolved && (renewed.is_some() || acknowledged.is_some()) {
        return Err(StoreError::IntegrityCheckFailed);
    }
    if let Some(activated) = &activated {
        let expires = raw
            .expires_at
            .clone()
            .validate()?
            .ok_or(StoreError::IntegrityCheckFailed)?;
        if activated.is_before(issued_at) || !activated.is_before(&expires) {
            return Err(StoreError::IntegrityCheckFailed);
        }
    }
    if acknowledged.is_some() && renewed.is_none() {
        return Err(StoreError::IntegrityCheckFailed);
    }
    let expires = raw.expires_at.clone().validate()?;
    if resolved {
        let fencing = parse_fencing(raw.fencing_generation)?;
        let anchor = raw
            .interval_anchor_at
            .clone()
            .validate()?
            .ok_or(StoreError::IntegrityCheckFailed)?;
        if fencing.get() == 1 {
            if renewed.is_some() || acknowledged.is_some() || &anchor != issued_at {
                return Err(StoreError::IntegrityCheckFailed);
            }
        } else if renewed.as_ref() != Some(&anchor) {
            return Err(StoreError::IntegrityCheckFailed);
        }
        if (status == LeaseStatus::Renewing && acknowledged.is_some())
            || (status == LeaseStatus::Active && fencing.get() > 1 && acknowledged.is_none())
            || (status == LeaseStatus::Renewing && fencing.get() == 1)
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
    } else if raw.interval_anchor_at.any_present() || raw.interval_anchor_monotonic.is_some() {
        return Err(StoreError::IntegrityCheckFailed);
    }
    if let Some(acknowledged) = &acknowledged {
        let anchor = raw
            .interval_anchor_at
            .clone()
            .validate()?
            .ok_or(StoreError::IntegrityCheckFailed)?;
        let expires = expires.as_ref().ok_or(StoreError::IntegrityCheckFailed)?;
        let anchor_nanos = timestamp_nanos(&anchor)?;
        let expires_nanos = timestamp_nanos(expires)?;
        let interval = expires_nanos
            .checked_sub(anchor_nanos)
            .filter(|value| *value > 0)
            .ok_or(StoreError::IntegrityCheckFailed)?;
        let ack_deadline = anchor_nanos
            .checked_add(interval.min(30_000_000_000))
            .ok_or(StoreError::IntegrityCheckFailed)?;
        if timestamp_nanos(acknowledged)? >= ack_deadline {
            return Err(StoreError::IntegrityCheckFailed);
        }
    }
    if status == LeaseStatus::Closed {
        let terminal = terminal.as_ref().ok_or(StoreError::IntegrityCheckFailed)?;
        let expires = expires.as_ref().ok_or(StoreError::IntegrityCheckFailed)?;
        if !terminal.is_before(expires) {
            return Err(StoreError::IntegrityCheckFailed);
        }
    }
    let ack_wall = raw.renewal_ack_deadline.clone().validate()?;
    let ack_monotonic = parse_optional_u128(raw.renewal_ack_monotonic.as_deref())?;
    if (status == LeaseStatus::Renewing) != ack_wall.is_some()
        || ack_wall.is_some() != ack_monotonic.is_some()
    {
        return Err(StoreError::IntegrityCheckFailed);
    }
    Ok(())
}

fn timestamp_nanos(value: &UtcTimestamp) -> Result<i128, StoreError> {
    let timestamp =
        StoredTimestamp::from_utc(value).map_err(|_| StoreError::IntegrityCheckFailed)?;
    i128::from(timestamp.seconds)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(i128::from(timestamp.nanos)))
        .ok_or(StoreError::IntegrityCheckFailed)
}

fn validate_terminal_evidence(
    raw: &RawLease,
    status: LeaseStatus,
    high_water: u128,
) -> Result<(), StoreError> {
    if status != LeaseStatus::Expired {
        return Ok(());
    }
    let terminal = raw
        .terminal_at
        .clone()
        .validate()?
        .ok_or(StoreError::IntegrityCheckFailed)?;
    let (wall_deadline, monotonic_deadline) = match raw.reason_code.as_deref() {
        Some("lease-expired") => (
            raw.expires_at
                .clone()
                .validate()?
                .ok_or(StoreError::IntegrityCheckFailed)?,
            parse_optional_u128(raw.expires_monotonic.as_deref())?
                .ok_or(StoreError::IntegrityCheckFailed)?,
        ),
        Some("maximum-lifetime-reached") => (
            raw.maximum_expires_at
                .clone()
                .validate()?
                .ok_or(StoreError::IntegrityCheckFailed)?,
            parse_optional_u128(raw.maximum_expires_monotonic.as_deref())?
                .ok_or(StoreError::IntegrityCheckFailed)?,
        ),
        _ => return Err(StoreError::IntegrityCheckFailed),
    };
    if !terminal.is_before(&wall_deadline) || high_water >= monotonic_deadline {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}
