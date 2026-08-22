use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::ErrorKind,
};

use rusqlite::{Connection, MAIN_DB, OpenFlags, TransactionBehavior, params};

use crate::{
    automation::{
        contracts::{
            CallerSubject, HostIdentity, IdentityLeaseRequest, LeaseId, LeaseStatus, RefusalCode,
            Sha256Digest, UtcTimestamp,
        },
        lease::{ClockSample, ServiceClockGeneration},
    },
    config::{
        AppPaths, MetadataStore, ProfileAutomationDeferredFenceGuard,
        ProfileAutomationFenceBusyGuard, ProfileAutomationFenceGuard,
        ProfileAutomationFencePreparation, ProfileFenceRefusal, ensure_secure_directory,
        prepare_profile_automation_fence, recover_profile_automation_fences,
        validate_profile_automation_fence_profile,
    },
    model::{InstallationUid, ProfileId},
};

use super::{
    BeginAcquireResult, PersistedAcquireOutcome, StoreError,
    fence::fence_store_error,
    ids::{AUDIT_PREFIX, LEASE_PREFIX, REQUEST_PREFIX, allocate_id},
    load, migrations,
    records::{PersistedIssuance, StoredTimestamp, replay_retain_until},
    security::{
        configure_connection, enable_wal, insert_service_generation, open_private_file,
        sync_directory, validate_existing_sidecars, validate_store_file,
        verify_connection_settings, verify_integrity,
    },
};

#[path = "sqlite/insert.rs"]
mod insert;

pub(super) struct StoreCore {
    // Field order is deliberate: SQLite checkpoints/closes before the service lock is released.
    pub(super) connection: Connection,
    pub(super) profile_resources: BTreeMap<LeaseId, super::fence::HeldProfileResource>,
    pub(super) profile_fences: BTreeMap<crate::model::ProfileUid, ProfileAutomationFenceGuard>,
    pub(super) profile_fence_busy:
        BTreeMap<crate::model::ProfileUid, Vec<ProfileAutomationFenceBusyGuard>>,
    pub(super) profile_fence_deferred:
        BTreeMap<crate::model::ProfileUid, Vec<ProfileAutomationDeferredFenceGuard>>,
    pub(super) paths: AppPaths,
    pub(super) installation_uid: InstallationUid,
    pub(super) fence_cleanup_deferred: BTreeSet<crate::model::ProfileUid>,
    pub(super) retryable_cleanup_deferred: BTreeSet<crate::model::ProfileUid>,
    pub(super) durability_uncertain: bool,
    #[cfg(test)]
    pub(super) fail_next_post_terminal_cleanup: bool,
    #[cfg(test)]
    pub(super) fail_next_post_terminal_cleanup_integrity: bool,
    _service_lock: File,
    pub(super) service_generation: ServiceClockGeneration,
}

/// An opened store that has recorded a new, recovery-incomplete generation.
pub(crate) struct RecoveringStore {
    pub(super) core: StoreCore,
}

/// A store whose current generation completed the conservative recovery gate.
pub(crate) struct ReadyStore {
    pub(super) core: StoreCore,
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
        ensure_secure_directory(&paths.state_dir.join("profile-locks"))
            .map_err(|_| StoreError::UnsafeStorage)?;
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

        // Marker validation is read-only and precedes every database write so
        // an unsafe marker cannot append failed recovery generations.
        let profile_fences = recover_profile_automation_fences(paths, installation_uid)
            .map_err(fence_store_error)?;

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
        {
            // Existing v3 semantic corruption must fail before this open
            // appends another recovery generation. Qualified v1/v2 stores
            // are migrated first, then checked through the same loader.
            let validation = connection
                .unchecked_transaction()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            load::validate_all_leases(&validation)?;
            validation
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
        }
        enable_wal(&connection)?;
        verify_connection_settings(&connection)?;
        validate_existing_sidecars(&database_path)?;

        let service_generation = insert_service_generation(&mut connection, &now)?;
        Ok(Self {
            core: StoreCore {
                connection,
                profile_resources: BTreeMap::new(),
                profile_fences,
                profile_fence_busy: BTreeMap::new(),
                profile_fence_deferred: BTreeMap::new(),
                paths: paths.clone(),
                installation_uid: installation_uid.clone(),
                fence_cleanup_deferred: BTreeSet::new(),
                retryable_cleanup_deferred: BTreeSet::new(),
                durability_uncertain: false,
                #[cfg(test)]
                fail_next_post_terminal_cleanup: false,
                #[cfg(test)]
                fail_next_post_terminal_cleanup_integrity: false,
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
        load::validate_all_leases(&transaction)?;
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
        if recovery_required
            || !core.fence_cleanup_deferred.is_empty()
            || !core.retryable_cleanup_deferred.is_empty()
            || core.durability_uncertain
            || !core.profile_fences.is_empty()
            || !core.profile_fence_busy.is_empty()
            || !core.profile_fence_deferred.is_empty()
            || !core.profile_resources.is_empty()
        {
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

    pub(crate) fn recovery_candidates(
        &self,
        page: &super::RecoveryPageRequest,
    ) -> Result<super::RecoveryPage, StoreError> {
        let transaction = self
            .core
            .connection
            .unchecked_transaction()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let result = super::recovery::enumerate(&transaction, self.core.service_generation, page)?;
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        Ok(result)
    }

    #[cfg(test)]
    pub(super) const fn test_connection(&self) -> &Connection {
        &self.core.connection
    }

    #[cfg(test)]
    pub(super) const fn test_connection_mut(&mut self) -> &mut Connection {
        &mut self.core.connection
    }
}

impl ReadyStore {
    #[must_use]
    pub(crate) const fn service_clock_generation(&self) -> ServiceClockGeneration {
        self.core.service_generation
    }

    pub(in crate::automation::store) fn begin_acquire(
        &mut self,
        request: &IdentityLeaseRequest,
        caller: &CallerSubject,
        host: &HostIdentity,
        issuance_clock: &ClockSample,
    ) -> Result<BeginAcquireResult, StoreError> {
        // Reading the in-memory latch does not touch the profile filesystem or
        // database. Its effect is deliberately deferred until after the first
        // SQL statement and an exact replay binding match.
        let cleanup_deferred = self.core.has_cleanup_deferred();
        let first = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        // This global replay lookup is deliberately the first statement after BEGIN IMMEDIATE.
        let replay = load::replay_by_client_request(&first, request.client_request_id.as_str())?;
        if let Some(replay) = replay {
            let canonical = canonical_request(request)?;
            let digest = Sha256Digest::hash(&canonical).to_string();
            if replay.digest.to_string() != digest
                || replay.canonical != canonical
                || &replay.caller != caller
                || &replay.host != host
            {
                return Err(StoreError::IdempotencyConflict);
            }
            if cleanup_deferred {
                first
                    .commit()
                    .map_err(|_| StoreError::DatabaseUnavailable)?;
                return Err(StoreError::RecoveryRequired);
            }
            let row_version = replay.loaded.row_version;
            let status = replay.loaded.lease.status();
            let snapshot = replay.loaded.snapshot.clone();
            let outcome = outcome_from_loaded(replay.loaded)?;
            first
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            match status {
                LeaseStatus::Requested => self.core.validate_lease_fence(&snapshot)?,
                LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error => {
                    let _ = self
                        .core
                        .validate_lease_authority_guards(snapshot.lease_id(), &snapshot)?;
                }
                LeaseStatus::Refused
                | LeaseStatus::Closed
                | LeaseStatus::Revoked
                | LeaseStatus::Expired => {}
            }
            return Ok(BeginAcquireResult::new(outcome, true, row_version));
        }
        first
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;

        if self.core.has_cleanup_deferred() {
            return Err(StoreError::RecoveryRequired);
        }
        if issuance_clock.service_generation() != self.core.service_generation {
            return Err(StoreError::InvalidRequest);
        }
        let canonical = canonical_request(request)?;
        let digest = Sha256Digest::hash(&canonical).to_string();
        let profile_id = request
            .profile_ref
            .as_str()
            .parse::<ProfileId>()
            .map_err(|_| StoreError::InvalidRequest)?;
        let metadata = MetadataStore::new(self.core.paths.clone());
        let had_fence = self.core.profile_fences.contains_key(&request.profile_uid);
        let mut created_fence = false;
        let fence_refusal = if had_fence {
            let result = {
                let fence = match self.core.fence(&request.profile_uid) {
                    Ok(fence) => fence,
                    Err(error) => {
                        self.core.latch_profile_cleanup(request.profile_uid.clone());
                        return Err(error);
                    }
                };
                validate_profile_automation_fence_profile(
                    &metadata,
                    &self.core.installation_uid,
                    &profile_id,
                    request.provider,
                    &request.profile_uid,
                    fence,
                )
            };
            result.map_err(|error| {
                self.core.latch_profile_cleanup(request.profile_uid.clone());
                fence_store_error(error)
            })?
        } else {
            match prepare_profile_automation_fence(
                &metadata,
                &self.core.installation_uid,
                &profile_id,
                request.provider,
                &request.profile_uid,
            )
            .map_err(fence_store_error)?
            {
                ProfileAutomationFencePreparation::Prepared(guard) => {
                    if let Err(error) = self.core.retain_fence(request.profile_uid.clone(), guard) {
                        self.core.latch_profile_cleanup(request.profile_uid.clone());
                        return Err(error);
                    }
                    created_fence = true;
                    None
                }
                ProfileAutomationFencePreparation::Refused(refusal) => Some(refusal),
                ProfileAutomationFencePreparation::Busy => return Err(StoreError::ServiceBusy),
                ProfileAutomationFencePreparation::CleanupBusy(guard) => {
                    self.core
                        .retain_busy_fence(request.profile_uid.clone(), guard);
                    return Err(StoreError::ServiceBusy);
                }
                ProfileAutomationFencePreparation::CleanupDeferred(failure) => {
                    self.core
                        .retain_fence_failure(request.profile_uid.clone(), failure);
                    return Err(StoreError::UnsafeStorage);
                }
            }
        };

        let mut commit_attempted = false;
        let second = persist_acquire_second_phase(
            &mut self.core.connection,
            request,
            caller,
            host,
            issuance_clock,
            self.core.service_generation,
            &canonical,
            &digest,
            fence_refusal,
            &mut commit_attempted,
        );
        let second = match second {
            Ok(second) => second,
            Err(error) => {
                if commit_attempted {
                    self.core.latch_profile_cleanup(request.profile_uid.clone());
                } else if created_fence
                    && let Err(cleanup) = self.core.try_clear_profile_fence(&request.profile_uid)
                {
                    return Err(cleanup);
                }
                return Err(error);
            }
        };
        finish_acquire_second_phase(&mut self.core, request, created_fence, second)
    }

    #[cfg(test)]
    pub(super) const fn test_connection(&self) -> &Connection {
        &self.core.connection
    }

    #[cfg(test)]
    pub(super) const fn test_connection_mut(&mut self) -> &mut Connection {
        &mut self.core.connection
    }

    #[cfg(test)]
    pub(super) fn test_latch_durability_uncertain(&mut self) {
        self.core.durability_uncertain = true;
    }

    #[cfg(test)]
    pub(super) fn test_fail_next_post_terminal_cleanup(&mut self) {
        self.core.fail_next_post_terminal_cleanup = true;
    }

    #[cfg(test)]
    pub(super) fn test_fail_next_post_terminal_cleanup_integrity(&mut self) {
        self.core.fail_next_post_terminal_cleanup_integrity = true;
    }
}

pub(super) enum AcquireSecondPhase {
    Replay(BeginAcquireResult),
    Conflict,
    Inserted {
        result: BeginAcquireResult,
        lease_id: LeaseId,
    },
}

pub(super) fn finish_acquire_second_phase(
    core: &mut StoreCore,
    request: &IdentityLeaseRequest,
    created_fence: bool,
    second: AcquireSecondPhase,
) -> Result<BeginAcquireResult, StoreError> {
    match second {
        AcquireSecondPhase::Replay(result) => {
            if matches!(
                result.outcome().response().status,
                LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error
            ) {
                core.latch_profile_cleanup(request.profile_uid.clone());
                return Err(StoreError::RecoveryRequired);
            }
            if created_fence && core.try_clear_profile_fence(&request.profile_uid).is_err() {
                return Err(StoreError::RecoveryRequired);
            }
            Ok(result)
        }
        AcquireSecondPhase::Conflict => {
            if created_fence {
                // Cleanup state never replaces the stable replay conflict.
                let _ = core.try_clear_profile_fence(&request.profile_uid);
            }
            Err(StoreError::IdempotencyConflict)
        }
        AcquireSecondPhase::Inserted {
            mut result,
            lease_id,
        } => {
            if matches!(result.outcome(), PersistedAcquireOutcome::Refused { .. })
                && let Err(error) = core.post_terminal_cleanup(&lease_id, &request.profile_uid)
            {
                core.latch_cleanup_failure(request.profile_uid.clone(), error);
                result.mark_cleanup_deferred();
            }
            Ok(result)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_acquire_second_phase(
    connection: &mut Connection,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    issuance_clock: &ClockSample,
    service_generation: ServiceClockGeneration,
    canonical: &[u8],
    digest: &str,
    fence_refusal: Option<ProfileFenceRefusal>,
    commit_attempted: &mut bool,
) -> Result<AcquireSecondPhase, StoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    let replay = load::replay_by_client_request(&transaction, request.client_request_id.as_str())?;
    if let Some(replay) = replay {
        let exact = replay.digest.to_string() == digest
            && replay.canonical == canonical
            && &replay.caller == caller
            && &replay.host == host;
        let phase = if exact {
            let row_version = replay.loaded.row_version;
            let outcome = outcome_from_loaded(replay.loaded)?;
            AcquireSecondPhase::Replay(BeginAcquireResult::new(outcome, true, row_version))
        } else {
            AcquireSecondPhase::Conflict
        };
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        return Ok(phase);
    }
    load::validate_all_leases(&transaction)?;
    let issued_at = StoredTimestamp::from_utc(issuance_clock.wall())?;
    let issued_monotonic = issuance_clock.monotonic().as_nanoseconds().to_be_bytes();
    let generation = generation_i64(service_generation)?;
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
    insert::request(
        &transaction,
        request,
        caller,
        host,
        &request_record_id,
        canonical,
        digest,
        &authorization_expiry,
        &replay_retention,
        &issued_at,
    )?;
    insert::requested_lease(
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
    insert::requested_audit(
        &transaction,
        request,
        caller,
        host,
        &audit_id,
        &lease_text,
        generation,
        &issued_at,
    )?;
    let issuance = PersistedIssuance::new(
        issuance_clock.wall().clone(),
        issuance_clock.monotonic(),
        service_generation,
    );
    let (outcome, row_version) = if let Some(refusal) = fence_refusal {
        let refusal = fence_refusal_code(refusal);
        let mut loaded = load::lease_by_id(&transaction, lease_id.as_str())?
            .ok_or(StoreError::IntegrityCheckFailed)?;
        loaded
            .lease
            .refuse(refusal)
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let response = loaded
            .lease
            .identity_response()
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let after = loaded.lease.snapshot();
        let row_version = super::lifecycle::persist::persist(
            &transaction,
            &loaded,
            &after,
            issuance_clock.wall(),
            super::lifecycle::persist::AuditActor::Service,
            service_generation,
        )?;
        (
            PersistedAcquireOutcome::Refused {
                response,
                issuance,
                refusal_code: refusal,
            },
            row_version,
        )
    } else {
        let loaded = load::lease_by_id(&transaction, lease_id.as_str())?
            .ok_or(StoreError::IntegrityCheckFailed)?;
        let row_version = loaded.row_version;
        (outcome_from_loaded(loaded)?, row_version)
    };
    *commit_attempted = true;
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    Ok(AcquireSecondPhase::Inserted {
        result: BeginAcquireResult::new(outcome, false, row_version),
        lease_id,
    })
}

fn generation_i64(generation: ServiceClockGeneration) -> Result<i64, StoreError> {
    i64::try_from(generation.get()).map_err(|_| StoreError::IntegrityCheckFailed)
}

fn canonical_request(request: &IdentityLeaseRequest) -> Result<Vec<u8>, StoreError> {
    let canonical = request
        .canonical_authority_json()
        .map_err(|_| StoreError::InvalidRequest)?;
    if canonical.len() > 131_072 {
        Err(StoreError::InvalidRequest)
    } else {
        Ok(canonical)
    }
}

const fn fence_refusal_code(refusal: ProfileFenceRefusal) -> RefusalCode {
    match refusal {
        ProfileFenceRefusal::ProfileNotFound => RefusalCode::ProfileNotFound,
        ProfileFenceRefusal::ProviderMismatch => RefusalCode::ProviderMismatch,
    }
}

pub(super) fn outcome_from_loaded(
    loaded: load::LoadedLease,
) -> Result<PersistedAcquireOutcome, StoreError> {
    let status = loaded.lease.status();
    let response = loaded
        .lease
        .identity_response()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    Ok(match status {
        LeaseStatus::Requested => PersistedAcquireOutcome::Requested {
            response,
            issuance: loaded.issuance,
        },
        LeaseStatus::Refused => PersistedAcquireOutcome::Refused {
            refusal_code: response
                .refusal_code
                .ok_or(StoreError::IntegrityCheckFailed)?,
            response,
            issuance: loaded.issuance,
        },
        LeaseStatus::Active
        | LeaseStatus::Renewing
        | LeaseStatus::Closed
        | LeaseStatus::Revoked
        | LeaseStatus::Expired
        | LeaseStatus::Error => PersistedAcquireOutcome::Resolved {
            response,
            issuance: loaded.issuance,
        },
    })
}
