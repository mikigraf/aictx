use std::collections::BTreeMap;

use rusqlite::TransactionBehavior;

use crate::{
    automation::{
        contracts::{LeaseId, LeaseReasonCode, LeaseStatus, Provider, RefusalCode, UtcTimestamp},
        lease::LeaseDomainError,
    },
    config::{
        MetadataStore, ProfileAutomationFenceAliasExtension,
        ProfileAutomationRecoveryFencePreparation, extend_profile_automation_recovery_fence_alias,
        prepare_profile_automation_recovery_fence,
    },
    model::{ProfileId, ProfileUid},
};

use super::{
    RecoveringStore, RecoveryMutationResult, StoreError, capacity,
    fence::fence_store_error,
    lifecycle::persist::{self, AuditActor},
    load,
    load_parse::{RecoveryState, parse_recovery_state, parse_status},
};

#[derive(Clone, Eq, PartialEq)]
struct RecoveryIdentity {
    status: LeaseStatus,
    profile_ref: ProfileId,
    profile_uid: ProfileUid,
    provider: Provider,
}

#[derive(Clone, Eq, PartialEq)]
struct RecoveryBlocker {
    lease_id: LeaseId,
    status: LeaseStatus,
    profile_ref: ProfileId,
    provider: Provider,
    row_version: u64,
    recovery_state: RecoveryState,
    quarantined: bool,
    live_capacity: bool,
    live_process: bool,
}

struct RecoveryPreflight {
    identity: RecoveryIdentity,
    blockers: Vec<RecoveryBlocker>,
}

struct AliasRequirement {
    profile_ref: ProfileId,
    extensible: bool,
}

impl RecoveringStore {
    /// Terminalize one clean prior-generation lease without ever resuming its
    /// authority. A historical profile fence is held before BEGIN IMMEDIATE.
    pub(in crate::automation::store) fn terminalize_prior_generation(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        now: &UtcTimestamp,
    ) -> Result<RecoveryMutationResult, StoreError> {
        let preflight = self.recovery_preflight(lease_id, expected_row_version)?;
        let identity = &preflight.identity;
        let created_fence = self.ensure_recovery_fence(&preflight)?;

        let generation = self.core.service_generation;
        let mut commit_attempted = false;
        let mutation = (|| {
            let transaction = self
                .core
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            if recovery_blockers(&transaction, &identity.profile_uid)? != preflight.blockers {
                return Err(StoreError::ConcurrentMutation);
            }
            let mut loaded = load::lease_by_id(&transaction, lease_id.as_str())?
                .ok_or(StoreError::InvalidTransition)?;
            require_recovery_candidate(
                &transaction,
                &loaded,
                lease_id,
                expected_row_version,
                generation,
            )?;
            if loaded.lease.status() != identity.status
                || loaded.snapshot.profile_uid() != &identity.profile_uid
                || loaded.snapshot.profile_ref().as_str() != identity.profile_ref.to_string()
                || loaded.snapshot.provider() != identity.provider
            {
                return Err(StoreError::ConcurrentMutation);
            }

            let prior = loaded.lease.status();
            let mut row_version = match prior {
                LeaseStatus::Requested => {
                    loaded
                        .lease
                        .refuse(RefusalCode::ProfileNotReady)
                        .map_err(domain_integrity)?;
                    persist_recovery_transition(&transaction, &loaded, now, generation)?
                }
                LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error => {
                    loaded
                        .lease
                        .revoke(LeaseReasonCode::ServiceRecovery)
                        .map_err(domain_integrity)?;
                    persist_recovery_transition(&transaction, &loaded, now, generation)?
                }
                LeaseStatus::Closed
                | LeaseStatus::Revoked
                | LeaseStatus::Expired
                | LeaseStatus::Refused => loaded.row_version,
            };
            let released = capacity::release_recovery_if_resolved(&transaction, lease_id, now)?;
            if prior == loaded.lease.status() && released != 0 {
                row_version = bump_row_version(&transaction, lease_id, expected_row_version)?;
            }
            let status = loaded.lease.status();
            commit_attempted = true;
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            Ok((prior, status, row_version, released))
        })();
        let (prior, status, row_version, released) = match mutation {
            Ok(result) => result,
            Err(error) => {
                if commit_attempted {
                    self.core
                        .latch_profile_cleanup(identity.profile_uid.clone());
                } else if created_fence
                    && let Err(cleanup) = self.core.try_clear_profile_fence(&identity.profile_uid)
                {
                    return Err(cleanup);
                }
                return Err(error);
            }
        };

        let changed = status != prior || released != 0;
        let mut result = RecoveryMutationResult::new(status, row_version, released, changed);
        if let Err(error) = self
            .core
            .post_terminal_cleanup(lease_id, &identity.profile_uid)
        {
            self.core
                .latch_cleanup_failure(identity.profile_uid.clone(), error);
            result.mark_cleanup_deferred();
        }
        Ok(result)
    }

    fn recovery_preflight(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
    ) -> Result<RecoveryPreflight, StoreError> {
        let transaction = self
            .core
            .connection
            .unchecked_transaction()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let loaded = load::lease_by_id(&transaction, lease_id.as_str())?
            .ok_or(StoreError::InvalidTransition)?;
        require_recovery_candidate(
            &transaction,
            &loaded,
            lease_id,
            expected_row_version,
            self.core.service_generation,
        )?;
        let identity = RecoveryIdentity {
            status: loaded.lease.status(),
            profile_ref: loaded
                .snapshot
                .profile_ref()
                .as_str()
                .parse()
                .map_err(|_| StoreError::IntegrityCheckFailed)?,
            profile_uid: loaded.snapshot.profile_uid().clone(),
            provider: loaded.snapshot.provider(),
        };
        let blockers = recovery_blockers(&transaction, &identity.profile_uid)?;
        if blockers
            .iter()
            .any(|blocker| blocker.provider != identity.provider)
        {
            return Err(StoreError::IntegrityCheckFailed);
        }
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        Ok(RecoveryPreflight { identity, blockers })
    }

    fn ensure_recovery_fence(&mut self, preflight: &RecoveryPreflight) -> Result<bool, StoreError> {
        let identity = &preflight.identity;
        if self
            .core
            .profile_fence_busy
            .contains_key(&identity.profile_uid)
            && self.core.try_clear_profile_fence(&identity.profile_uid)?
        {
            self.core
                .latch_profile_cleanup(identity.profile_uid.clone());
            return Err(StoreError::IntegrityCheckFailed);
        }
        let created = if self.core.profile_fences.contains_key(&identity.profile_uid) {
            false
        } else {
            if !matches!(
                identity.status,
                LeaseStatus::Requested | LeaseStatus::Refused
            ) {
                self.core
                    .latch_profile_cleanup(identity.profile_uid.clone());
                return Err(StoreError::RecoveryRequired);
            }
            self.prepare_missing_recovery_fence(identity)?;
            true
        };
        self.extend_recovery_blocker_aliases(preflight)?;
        Ok(created)
    }

    fn prepare_missing_recovery_fence(
        &mut self,
        identity: &RecoveryIdentity,
    ) -> Result<(), StoreError> {
        let metadata = MetadataStore::new(self.core.paths.clone());
        match prepare_profile_automation_recovery_fence(
            &metadata,
            &self.core.installation_uid,
            &identity.profile_ref,
            identity.provider,
            &identity.profile_uid,
        )
        .map_err(fence_store_error)?
        {
            ProfileAutomationRecoveryFencePreparation::Prepared(guard) => {
                self.core.retain_fence(identity.profile_uid.clone(), guard)
            }
            ProfileAutomationRecoveryFencePreparation::Busy => Err(StoreError::ServiceBusy),
            ProfileAutomationRecoveryFencePreparation::CleanupBusy(guard) => {
                self.core
                    .retain_busy_fence(identity.profile_uid.clone(), guard);
                Err(StoreError::ServiceBusy)
            }
            ProfileAutomationRecoveryFencePreparation::CleanupDeferred(failure) => {
                self.core
                    .retain_fence_failure(identity.profile_uid.clone(), failure);
                Err(StoreError::UnsafeStorage)
            }
        }
    }

    fn extend_recovery_blocker_aliases(
        &mut self,
        preflight: &RecoveryPreflight,
    ) -> Result<(), StoreError> {
        let identity = &preflight.identity;
        let requirements = alias_requirements(preflight);
        for requirement in requirements.values() {
            let represented = self
                .core
                .profile_fences
                .get(&identity.profile_uid)
                .is_some_and(|fence| {
                    fence
                        .validate_recovery_binding(
                            &self.core.installation_uid,
                            &requirement.profile_ref,
                            identity.provider,
                            &identity.profile_uid,
                        )
                        .is_ok()
                });
            if represented {
                continue;
            }
            if !requirement.extensible {
                self.core
                    .latch_profile_cleanup(identity.profile_uid.clone());
                return Err(StoreError::UnsafeStorage);
            }
            self.extend_one_recovery_alias(identity, &requirement.profile_ref)?;
        }
        Ok(())
    }

    fn extend_one_recovery_alias(
        &mut self,
        identity: &RecoveryIdentity,
        profile_ref: &ProfileId,
    ) -> Result<(), StoreError> {
        let guard = self
            .core
            .profile_fences
            .remove(&identity.profile_uid)
            .ok_or(StoreError::IntegrityCheckFailed)?;
        let metadata = MetadataStore::new(self.core.paths.clone());
        match extend_profile_automation_recovery_fence_alias(
            &metadata,
            &self.core.installation_uid,
            profile_ref,
            identity.provider,
            &identity.profile_uid,
            guard,
        ) {
            Ok(ProfileAutomationFenceAliasExtension::Extended(guard)) => {
                self.core.retain_fence(identity.profile_uid.clone(), guard)
            }
            Ok(ProfileAutomationFenceAliasExtension::Busy(guard)) => {
                self.core
                    .retain_fence(identity.profile_uid.clone(), guard)?;
                Err(StoreError::ServiceBusy)
            }
            Ok(ProfileAutomationFenceAliasExtension::CleanupDeferred(failure)) => {
                self.core
                    .retain_fence_failure(identity.profile_uid.clone(), failure);
                Err(StoreError::UnsafeStorage)
            }
            Err(error) => {
                self.core
                    .latch_profile_cleanup(identity.profile_uid.clone());
                Err(fence_store_error(error))
            }
        }
    }
}

fn alias_requirements(preflight: &RecoveryPreflight) -> BTreeMap<String, AliasRequirement> {
    let mut requirements = BTreeMap::new();
    insert_alias_requirement(
        &mut requirements,
        &preflight.identity.profile_ref,
        preflight.identity.status,
    );
    for blocker in &preflight.blockers {
        insert_alias_requirement(&mut requirements, &blocker.profile_ref, blocker.status);
    }
    requirements
}

fn insert_alias_requirement(
    requirements: &mut BTreeMap<String, AliasRequirement>,
    profile_ref: &ProfileId,
    status: LeaseStatus,
) {
    let extensible = matches!(status, LeaseStatus::Requested | LeaseStatus::Refused);
    requirements
        .entry(profile_ref.to_string())
        .and_modify(|requirement| requirement.extensible &= extensible)
        .or_insert_with(|| AliasRequirement {
            profile_ref: profile_ref.clone(),
            extensible,
        });
}

fn recovery_blockers(
    transaction: &rusqlite::Transaction<'_>,
    profile_uid: &ProfileUid,
) -> Result<Vec<RecoveryBlocker>, StoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT l.lease_id, l.status, l.profile_ref, l.provider, l.row_version,
                    l.recovery_state, l.quarantined,
                    EXISTS(SELECT 1 FROM capacity_reservations c
                           WHERE c.lease_id = l.lease_id AND c.state <> 'RELEASED'),
                    EXISTS(SELECT 1 FROM lease_processes p
                           WHERE p.lease_id = l.lease_id AND p.state <> 'EXITED')
             FROM leases l
             WHERE l.profile_uid = ?1
               AND (l.status IN ('REQUESTED', 'ACTIVE', 'RENEWING', 'ERROR')
                    OR l.recovery_state <> 'NONE' OR l.quarantined = 1
                    OR EXISTS(SELECT 1 FROM capacity_reservations c
                              WHERE c.lease_id = l.lease_id AND c.state <> 'RELEASED')
                    OR EXISTS(SELECT 1 FROM lease_processes p
                              WHERE p.lease_id = l.lease_id AND p.state <> 'EXITED'))
             ORDER BY l.lease_id",
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let rows = statement
        .query_map([profile_uid.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, bool>(7)?,
                row.get::<_, bool>(8)?,
            ))
        })
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    drop(statement);
    rows.into_iter()
        .map(
            |(
                lease_id,
                status,
                profile_ref,
                provider,
                row_version,
                recovery_state,
                quarantined,
                live_capacity,
                live_process,
            )| {
                let profile_ref = profile_ref
                    .parse::<ProfileId>()
                    .map_err(|_| StoreError::IntegrityCheckFailed)?;
                let provider = parse_provider(&provider)?;
                if profile_ref.provider() != provider {
                    return Err(StoreError::IntegrityCheckFailed);
                }
                Ok(RecoveryBlocker {
                    lease_id: LeaseId::parse(lease_id)
                        .map_err(|_| StoreError::IntegrityCheckFailed)?,
                    status: parse_status(&status)?,
                    profile_ref,
                    provider,
                    row_version: u64::try_from(row_version)
                        .map_err(|_| StoreError::IntegrityCheckFailed)?,
                    recovery_state: parse_recovery_state(&recovery_state)?,
                    quarantined,
                    live_capacity,
                    live_process,
                })
            },
        )
        .collect()
}

fn parse_provider(value: &str) -> Result<Provider, StoreError> {
    match value {
        "claude" => Ok(Provider::Claude),
        "codex" => Ok(Provider::Codex),
        _ => Err(StoreError::IntegrityCheckFailed),
    }
}

fn require_recovery_candidate(
    transaction: &rusqlite::Transaction<'_>,
    loaded: &load::LoadedLease,
    lease_id: &LeaseId,
    expected_row_version: u64,
    generation: crate::automation::lease::ServiceClockGeneration,
) -> Result<(), StoreError> {
    if loaded.origin_generation.get() >= generation.get() {
        return Err(StoreError::InvalidTransition);
    }
    if expected_row_version == 0 || loaded.row_version != expected_row_version {
        return Err(StoreError::ConcurrentMutation);
    }
    if !matches!(loaded.recovery_state, RecoveryState::None) || loaded.quarantined {
        return Err(StoreError::RecoveryRequired);
    }
    let live_process: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM lease_processes
                WHERE lease_id = ?1 AND state <> 'EXITED')",
            [lease_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if live_process {
        Err(StoreError::RecoveryRequired)
    } else {
        Ok(())
    }
}

fn persist_recovery_transition(
    transaction: &rusqlite::Transaction<'_>,
    loaded: &load::LoadedLease,
    now: &UtcTimestamp,
    generation: crate::automation::lease::ServiceClockGeneration,
) -> Result<u64, StoreError> {
    loaded
        .lease
        .identity_response()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    persist::persist(
        transaction,
        loaded,
        &loaded.lease.snapshot(),
        now,
        AuditActor::Service,
        generation,
    )
}

fn bump_row_version(
    transaction: &rusqlite::Transaction<'_>,
    lease_id: &LeaseId,
    expected_row_version: u64,
) -> Result<u64, StoreError> {
    let next = expected_row_version
        .checked_add(1)
        .ok_or(StoreError::ConcurrentMutation)?;
    let changed = transaction
        .execute(
            "UPDATE leases SET row_version = ?1
             WHERE lease_id = ?2 AND row_version = ?3",
            rusqlite::params![
                i64::try_from(next).map_err(|_| StoreError::IntegrityCheckFailed)?,
                lease_id.as_str(),
                i64::try_from(expected_row_version)
                    .map_err(|_| StoreError::IntegrityCheckFailed)?,
            ],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    if changed == 1 {
        Ok(next)
    } else {
        Err(StoreError::ConcurrentMutation)
    }
}

// This `map_err` adapter owns and immediately redacts the domain error.
#[allow(clippy::needless_pass_by_value)]
fn domain_integrity(error: LeaseDomainError) -> StoreError {
    match error {
        LeaseDomainError::LeaseNotActive
        | LeaseDomainError::InvalidTransition { .. }
        | LeaseDomainError::TerminalImmutable(_) => StoreError::InvalidTransition,
        _ => StoreError::IntegrityCheckFailed,
    }
}
