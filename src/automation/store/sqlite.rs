use std::{
    fs::{self, File},
    io::ErrorKind,
};

use rusqlite::{
    Connection, MAIN_DB, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{
    automation::{
        contracts::{
            CallerSubject, HostIdentity, IdentityLeaseRequest, LeaseId, RefusalCode, Sha256Digest,
            UtcTimestamp,
        },
        lease::{ClockSample, MonotonicMoment, ServiceClockGeneration},
    },
    config::{AppPaths, ensure_secure_directory},
    model::InstallationUid,
};

use super::{
    BeginAcquireResult, PersistedAcquireOutcome, StoreError,
    ids::{AUDIT_PREFIX, COLLISION_RETRIES, LEASE_PREFIX, REQUEST_PREFIX, random_id},
    migrations,
    records::{
        PersistedIssuance, StoredTimestamp, parse_refusal, refusal_label, replay_retain_until,
        role_label,
    },
    security::{
        MAX_SERVICE_GENERATION, configure_connection, enable_wal, insert_service_generation,
        open_private_file, sync_directory, validate_existing_sidecars, validate_store_file,
        verify_connection_settings, verify_integrity,
    },
};

struct StoreCore {
    // Field order is deliberate: SQLite checkpoints/closes before the service lock is released.
    connection: Connection,
    _service_lock: File,
    service_generation: ServiceClockGeneration,
}

/// An opened store that has recorded a new, recovery-incomplete generation.
pub(crate) struct RecoveringStore {
    core: StoreCore,
}

/// A store whose current generation completed the conservative recovery gate.
pub(crate) struct ReadyStore {
    core: StoreCore,
}

impl RecoveringStore {
    pub(crate) fn open(
        paths: &AppPaths,
        installation_uid: &InstallationUid,
        now: &UtcTimestamp,
    ) -> Result<Self, StoreError> {
        let now = StoredTimestamp::from_utc(now)?;
        let automation_dir = paths.automation_state_dir();
        let automation_was_missing = matches!(
            fs::symlink_metadata(&automation_dir),
            Err(source) if source.kind() == ErrorKind::NotFound
        );
        ensure_secure_directory(&automation_dir).map_err(|_| StoreError::UnsafeStorage)?;
        if automation_was_missing {
            sync_directory(&automation_dir)?;
            if let Some(parent) = automation_dir.parent() {
                sync_directory(parent)?;
                if let Some(grandparent) = parent.parent() {
                    sync_directory(grandparent)?;
                }
            }
        }

        let (service_lock, _) = open_private_file(&paths.automation_service_lock())?;
        service_lock
            .try_lock()
            .map_err(|_| StoreError::ServiceBusy)?;

        let database_path = paths.automation_lease_store();
        validate_existing_sidecars(&database_path)?;
        let (database_file, _) = open_private_file(&database_path)?;
        drop(database_file);

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(&database_path, flags)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if connection
            .is_readonly(MAIN_DB)
            .map_err(|_| StoreError::DatabaseUnavailable)?
        {
            return Err(StoreError::DatabaseUnavailable);
        }
        validate_store_file(&database_path)?;
        configure_connection(&connection)?;
        migrations::migrate_and_bind(&mut connection, installation_uid, &now)?;
        verify_integrity(&connection)?;
        enable_wal(&connection)?;
        verify_connection_settings(&connection)?;
        validate_existing_sidecars(&database_path)?;

        let service_generation = insert_service_generation(&mut connection, &now)?;
        Ok(Self {
            core: StoreCore {
                connection,
                _service_lock: service_lock,
                service_generation,
            },
        })
    }

    #[must_use]
    pub(crate) const fn service_clock_generation(&self) -> ServiceClockGeneration {
        self.core.service_generation
    }

    pub(crate) fn into_ready(self, now: &UtcTimestamp) -> Result<ReadyStore, StoreError> {
        let now = StoredTimestamp::from_utc(now)?;
        let mut core = self.core;
        let generation = generation_i64(core.service_generation)?;
        let transaction = core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let recovery_required: bool = transaction
            .query_row(
                "SELECT
                    EXISTS(SELECT 1 FROM leases
                        WHERE status IN ('REQUESTED', 'ACTIVE', 'RENEWING', 'ERROR')
                           OR recovery_state <> 'NONE' OR quarantined = 1)
                    OR EXISTS(SELECT 1 FROM capacity_reservations WHERE state <> 'RELEASED')
                    OR EXISTS(SELECT 1 FROM lease_processes WHERE state <> 'EXITED')",
                [],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        if recovery_required {
            return Err(StoreError::RecoveryRequired);
        }

        // This is intentionally the final write in the readiness transaction.
        let changed = transaction
            .execute(
                "UPDATE service_generations
                 SET start_outcome = 'READY',
                     recovery_completed_at_utc = ?1,
                     recovery_completed_at_seconds = ?2,
                     recovery_completed_at_nanos = ?3
                 WHERE service_generation = ?4
                   AND start_outcome = 'RECOVERY_INCOMPLETE'
                   AND recovery_completed_at_utc IS NULL",
                params![now.wire, now.seconds, now.nanos, generation],
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if changed != 1 {
            return Err(StoreError::RecoveryRequired);
        }
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        Ok(ReadyStore { core })
    }
}

impl ReadyStore {
    #[must_use]
    pub(crate) const fn service_clock_generation(&self) -> ServiceClockGeneration {
        self.core.service_generation
    }

    pub(crate) fn begin_acquire(
        &mut self,
        request: &IdentityLeaseRequest,
        caller: &CallerSubject,
        host: &HostIdentity,
        issuance_clock: &ClockSample,
    ) -> Result<BeginAcquireResult, StoreError> {
        if issuance_clock.service_generation() != self.core.service_generation {
            return Err(StoreError::InvalidRequest);
        }
        let issued_at = StoredTimestamp::from_utc(issuance_clock.wall())?;
        let issued_monotonic = issuance_clock.monotonic().as_nanoseconds().to_be_bytes();
        let generation = generation_i64(self.core.service_generation)?;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;

        // This global replay lookup is deliberately the first statement after BEGIN IMMEDIATE.
        let replay = load_replay(&transaction, request.client_request_id.as_str())?;
        let canonical = request
            .canonical_authority_json()
            .map_err(|_| StoreError::InvalidRequest)?;
        if canonical.len() > 131_072 {
            return Err(StoreError::InvalidRequest);
        }
        let digest = Sha256Digest::hash(&canonical).to_string();
        if let Some(replay) = replay {
            if replay.digest != digest
                || replay.canonical != canonical
                || replay.caller != caller.as_str()
                || replay.host != host.as_str()
            {
                return Err(StoreError::IdempotencyConflict);
            }
            let outcome = replay.into_outcome()?;
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Ok(BeginAcquireResult::new(outcome, true));
        }

        let authorization_expiry =
            StoredTimestamp::from_utc(&request.work_order_authorization.expires_at)?;
        let replay_retain_until = replay_retain_until(
            issuance_clock.wall(),
            &request.work_order_authorization.expires_at,
        )?;
        let replay_retention = StoredTimestamp::from_utc(&replay_retain_until)?;
        let request_record_id = allocate_id(
            &transaction,
            REQUEST_PREFIX,
            "SELECT EXISTS(SELECT 1 FROM lease_requests WHERE request_record_id = ?1)",
        )?;
        let lease_text = allocate_id(
            &transaction,
            LEASE_PREFIX,
            "SELECT EXISTS(SELECT 1 FROM leases WHERE lease_id = ?1)",
        )?;
        let lease_id =
            LeaseId::parse(lease_text.clone()).map_err(|_| StoreError::IdentifierCollision)?;
        let audit_id = allocate_id(
            &transaction,
            AUDIT_PREFIX,
            "SELECT EXISTS(SELECT 1 FROM audit_events WHERE audit_event_id = ?1)",
        )?;

        insert_request(
            &transaction,
            request,
            caller,
            host,
            &request_record_id,
            &canonical,
            &digest,
            &authorization_expiry,
            &replay_retention,
            &issued_at,
        )?;
        insert_requested_lease(
            &transaction,
            request,
            caller,
            host,
            &request_record_id,
            &lease_text,
            generation,
            &issued_at,
            &issued_monotonic,
        )?;
        insert_requested_audit(
            &transaction,
            request,
            caller,
            host,
            &audit_id,
            &lease_text,
            generation,
            &issued_at,
        )?;
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;

        Ok(BeginAcquireResult::new(
            PersistedAcquireOutcome::Requested {
                lease_id,
                issuance: PersistedIssuance::new(
                    issuance_clock.wall().clone(),
                    issuance_clock.monotonic(),
                    self.core.service_generation,
                ),
            },
            false,
        ))
    }

    pub(crate) fn refuse_requested(
        &mut self,
        lease_id: &LeaseId,
        refusal_code: RefusalCode,
        now: &UtcTimestamp,
    ) -> Result<(), StoreError> {
        let now = StoredTimestamp::from_utc(now)?;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let attribution = load_attribution(&transaction, lease_id.as_str())?
            .ok_or(StoreError::InvalidTransition)?;
        if attribution.status != "REQUESTED" {
            return Err(StoreError::InvalidTransition);
        }
        let audit_id = allocate_id(
            &transaction,
            AUDIT_PREFIX,
            "SELECT EXISTS(SELECT 1 FROM audit_events WHERE audit_event_id = ?1)",
        )?;
        let changed = transaction
            .execute(
                "UPDATE leases
                 SET status = 'REFUSED', refusal_code = ?1,
                     terminal_at_utc = ?2, terminal_at_seconds = ?3, terminal_at_nanos = ?4,
                     row_version = row_version + 1,
                     next_audit_sequence = next_audit_sequence + 1
                 WHERE lease_id = ?5 AND status = 'REQUESTED'
                   AND recovery_state = 'NONE' AND quarantined = 0",
                params![
                    refusal_label(refusal_code),
                    now.wire,
                    now.seconds,
                    now.nanos,
                    lease_id.as_str()
                ],
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if changed != 1 {
            return Err(StoreError::InvalidTransition);
        }
        insert_refused_audit(
            &transaction,
            &audit_id,
            lease_id.as_str(),
            refusal_code,
            &attribution,
            &now,
        )?;
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)
    }

    #[cfg(test)]
    pub(super) const fn test_connection(&self) -> &Connection {
        &self.core.connection
    }
}

fn generation_i64(generation: ServiceClockGeneration) -> Result<i64, StoreError> {
    i64::try_from(generation.get()).map_err(|_| StoreError::IntegrityCheckFailed)
}

fn allocate_id(
    transaction: &Transaction<'_>,
    prefix: &str,
    exists_query: &str,
) -> Result<String, StoreError> {
    for _ in 0..COLLISION_RETRIES {
        let candidate = random_id(prefix).map_err(|()| StoreError::EntropyUnavailable)?;
        let exists: bool = transaction
            .query_row(exists_query, [&candidate], |row| row.get(0))
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(StoreError::IdentifierCollision)
}

struct ReplayRow {
    digest: String,
    canonical: Vec<u8>,
    caller: String,
    host: String,
    lease_id: String,
    status: String,
    refusal_code: Option<String>,
    issued_at: String,
    issued_seconds: i64,
    issued_nanos: i64,
    issued_monotonic: Vec<u8>,
    service_generation: i64,
}

impl ReplayRow {
    fn into_outcome(self) -> Result<PersistedAcquireOutcome, StoreError> {
        let lease_id =
            LeaseId::parse(self.lease_id).map_err(|_| StoreError::IntegrityCheckFailed)?;
        let issuance = persisted_issuance(
            self.issued_at,
            self.issued_seconds,
            self.issued_nanos,
            self.issued_monotonic,
            self.service_generation,
        )?;
        match (self.status.as_str(), self.refusal_code) {
            ("REQUESTED", None) => Ok(PersistedAcquireOutcome::Requested { lease_id, issuance }),
            ("REFUSED", Some(code)) => Ok(PersistedAcquireOutcome::Refused {
                lease_id,
                issuance,
                refusal_code: parse_refusal(&code).ok_or(StoreError::IntegrityCheckFailed)?,
            }),
            _ => Err(StoreError::IntegrityCheckFailed),
        }
    }
}

fn load_replay(
    transaction: &Transaction<'_>,
    client_request_id: &str,
) -> Result<Option<ReplayRow>, StoreError> {
    transaction
        .query_row(
            "SELECT r.canonical_authority_digest, r.canonical_request,
                    r.authenticated_caller, r.host_identity,
                    l.lease_id, l.status, l.refusal_code,
                    l.issued_at_utc, l.issued_at_seconds, l.issued_at_nanos,
                    l.issued_monotonic_nanos, l.service_generation
             FROM lease_requests r
             JOIN leases l ON l.request_record_id = r.request_record_id
             WHERE r.client_request_id = ?1",
            [client_request_id],
            |row| {
                Ok(ReplayRow {
                    digest: row.get(0)?,
                    canonical: row.get(1)?,
                    caller: row.get(2)?,
                    host: row.get(3)?,
                    lease_id: row.get(4)?,
                    status: row.get(5)?,
                    refusal_code: row.get(6)?,
                    issued_at: row.get(7)?,
                    issued_seconds: row.get(8)?,
                    issued_nanos: row.get(9)?,
                    issued_monotonic: row.get(10)?,
                    service_generation: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)
}

fn persisted_issuance(
    wire: String,
    seconds: i64,
    nanos: i64,
    monotonic: Vec<u8>,
    generation: i64,
) -> Result<PersistedIssuance, StoreError> {
    let issued_at = UtcTimestamp::parse(wire).map_err(|_| StoreError::IntegrityCheckFailed)?;
    let checked = StoredTimestamp::from_utc(&issued_at)?;
    if checked.seconds != seconds || checked.nanos != nanos {
        return Err(StoreError::IntegrityCheckFailed);
    }
    let monotonic: [u8; 16] = monotonic
        .try_into()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let generation = u64::try_from(generation)
        .ok()
        .filter(|value| (1..=MAX_SERVICE_GENERATION).contains(value))
        .ok_or(StoreError::IntegrityCheckFailed)?;
    Ok(PersistedIssuance::new(
        issued_at,
        MonotonicMoment::from_nanoseconds(u128::from_be_bytes(monotonic)),
        ServiceClockGeneration::from_value(generation),
    ))
}

#[allow(clippy::too_many_arguments)]
fn insert_request(
    transaction: &Transaction<'_>,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    request_record_id: &str,
    canonical: &[u8],
    digest: &str,
    authorization_expiry: &StoredTimestamp<'_>,
    replay_retention: &StoredTimestamp<'_>,
    recorded_at: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO lease_requests (
                request_record_id, client_request_id, canonical_authority_digest,
                canonical_request, authenticated_caller, host_identity,
                authorization_expires_at_utc, authorization_expires_at_seconds,
                authorization_expires_at_nanos, replay_retain_until_utc,
                replay_retain_until_seconds, replay_retain_until_nanos,
                recorded_at_utc, recorded_at_seconds, recorded_at_nanos
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
             )",
            params![
                request_record_id,
                request.client_request_id.as_str(),
                digest,
                canonical,
                caller.as_str(),
                host.as_str(),
                authorization_expiry.wire,
                authorization_expiry.seconds,
                authorization_expiry.nanos,
                replay_retention.wire,
                replay_retention.seconds,
                replay_retention.nanos,
                recorded_at.wire,
                recorded_at.seconds,
                recorded_at.nanos
            ],
        )
        .map(|_| ())
        .map_err(|_| StoreError::DatabaseUnavailable)
}

#[allow(clippy::too_many_arguments)]
fn insert_requested_lease(
    transaction: &Transaction<'_>,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    request_record_id: &str,
    lease_id: &str,
    service_generation: i64,
    issued_at: &StoredTimestamp<'_>,
    issued_monotonic: &[u8; 16],
) -> Result<(), StoreError> {
    let policy_digest = request.policy_digest.map(|value| value.to_string());
    let requested_ttl = i64::try_from(request.requested_ttl_seconds.get())
        .map_err(|_| StoreError::InvalidRequest)?;
    transaction
        .execute(
            "INSERT INTO leases (
                lease_id, request_record_id, service_generation, row_version,
                next_audit_sequence, status, recovery_state, quarantined,
                tenant_id, work_order_id, work_order_digest, run_id, attempt_id,
                role, provider, profile_uid, profile_ref, repository_id, workspace_id,
                environment, authenticated_caller, host_identity, requested_ttl_seconds,
                requested_policy_digest, issued_at_utc, issued_at_seconds, issued_at_nanos,
                issued_monotonic_nanos
             ) VALUES (
                ?1, ?2, ?3, 1, 2, 'REQUESTED', 'NONE', 0,
                ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
             )",
            params![
                lease_id,
                request_record_id,
                service_generation,
                request.tenant_id.as_str(),
                request.work_order_id.as_str(),
                request.work_order_digest.to_string(),
                request.run_id.as_str(),
                request.attempt_id.as_str(),
                role_label(request.role),
                request.provider.to_string(),
                request.profile_uid.as_str(),
                request.profile_ref.as_str(),
                request.repository.as_str(),
                request.workspace_id.as_str(),
                request.environment.as_str(),
                caller.as_str(),
                host.as_str(),
                requested_ttl,
                policy_digest,
                issued_at.wire,
                issued_at.seconds,
                issued_at.nanos,
                issued_monotonic.as_slice()
            ],
        )
        .map(|_| ())
        .map_err(|_| StoreError::DatabaseUnavailable)
}

#[allow(clippy::too_many_arguments)]
fn insert_requested_audit(
    transaction: &Transaction<'_>,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    audit_id: &str,
    lease_id: &str,
    service_generation: i64,
    now: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller, host_identity
             ) VALUES (
                ?1, ?2, 1, ?3, 'lease.requested', 'recorded', 'REQUESTED', 'NONE', 0,
                ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21, ?22
             )",
            params![
                audit_id,
                lease_id,
                service_generation,
                now.wire,
                now.seconds,
                now.nanos,
                caller.as_str(),
                request.client_request_id.as_str(),
                request.tenant_id.as_str(),
                request.work_order_id.as_str(),
                request.work_order_digest.to_string(),
                request.run_id.as_str(),
                request.attempt_id.as_str(),
                role_label(request.role),
                request.provider.to_string(),
                request.profile_uid.as_str(),
                request.profile_ref.as_str(),
                request.repository.as_str(),
                request.workspace_id.as_str(),
                request.environment.as_str(),
                caller.as_str(),
                host.as_str()
            ],
        )
        .map(|_| ())
        .map_err(|_| StoreError::DatabaseUnavailable)
}

struct LeaseAttribution {
    status: String,
    sequence: i64,
    service_generation: i64,
    client_request_id: String,
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
}

fn load_attribution(
    transaction: &Transaction<'_>,
    lease_id: &str,
) -> Result<Option<LeaseAttribution>, StoreError> {
    transaction
        .query_row(
            "SELECT l.status, l.next_audit_sequence, l.service_generation,
                    r.client_request_id, l.tenant_id, l.work_order_id, l.work_order_digest,
                    l.run_id, l.attempt_id, l.role, l.provider, l.profile_uid, l.profile_ref,
                    l.repository_id, l.workspace_id, l.environment,
                    l.authenticated_caller, l.host_identity
             FROM leases l JOIN lease_requests r ON r.request_record_id = l.request_record_id
             WHERE l.lease_id = ?1",
            [lease_id],
            |row| {
                Ok(LeaseAttribution {
                    status: row.get(0)?,
                    sequence: row.get(1)?,
                    service_generation: row.get(2)?,
                    client_request_id: row.get(3)?,
                    tenant_id: row.get(4)?,
                    work_order_id: row.get(5)?,
                    work_order_digest: row.get(6)?,
                    run_id: row.get(7)?,
                    attempt_id: row.get(8)?,
                    role: row.get(9)?,
                    provider: row.get(10)?,
                    profile_uid: row.get(11)?,
                    profile_ref: row.get(12)?,
                    repository_id: row.get(13)?,
                    workspace_id: row.get(14)?,
                    environment: row.get(15)?,
                    caller: row.get(16)?,
                    host: row.get(17)?,
                })
            },
        )
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)
}

fn insert_refused_audit(
    transaction: &Transaction<'_>,
    audit_id: &str,
    lease_id: &str,
    refusal_code: RefusalCode,
    value: &LeaseAttribution,
    now: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, lease_status, recovery_state, quarantined,
                event_at_utc, event_at_seconds, event_at_nanos, actor,
                client_request_id, tenant_id, work_order_id, work_order_digest,
                run_id, attempt_id, role, provider, profile_uid, profile_ref,
                repository_id, workspace_id, environment, authenticated_caller,
                host_identity, refusal_code
             ) VALUES (
                ?1, ?2, ?3, ?4, 'lease.refused', 'refused', 'REFUSED', 'NONE', 0,
                ?5, ?6, ?7, 'service', ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
             )",
            params![
                audit_id,
                lease_id,
                value.sequence,
                value.service_generation,
                now.wire,
                now.seconds,
                now.nanos,
                value.client_request_id,
                value.tenant_id,
                value.work_order_id,
                value.work_order_digest,
                value.run_id,
                value.attempt_id,
                value.role,
                value.provider,
                value.profile_uid,
                value.profile_ref,
                value.repository_id,
                value.workspace_id,
                value.environment,
                value.caller,
                value.host,
                refusal_label(refusal_code)
            ],
        )
        .map(|_| ())
        .map_err(|_| StoreError::DatabaseUnavailable)
}
