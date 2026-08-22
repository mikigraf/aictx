use std::collections::{BTreeSet, btree_map::Entry};

use crate::{
    automation::contracts::{LeaseId, ProfileUid},
    config::{
        ProfileAutomationDeferredFenceGuard, ProfileAutomationFenceBusyGuard,
        ProfileAutomationFenceDowngrade, ProfileAutomationFenceFailure,
        ProfileAutomationFenceGuard, ProfileAutomationFenceUpgrade, ProfileAutomationResourceGuard,
        ProfileAutomationResourceMode, profile_automation_fence_presence,
    },
};

use super::{ReadyStore, RecoveringStore, StoreError, capacity, load, sqlite::StoreCore};

pub(super) struct HeldProfileResource {
    profile_uid: ProfileUid,
    mode: ProfileAutomationResourceMode,
    guard: ProfileAutomationResourceGuard,
}

impl HeldProfileResource {
    pub(super) fn new(
        profile_uid: ProfileUid,
        mode: ProfileAutomationResourceMode,
        guard: ProfileAutomationResourceGuard,
    ) -> Self {
        Self {
            profile_uid,
            mode,
            guard,
        }
    }

    pub(super) const fn profile_uid(&self) -> &ProfileUid {
        &self.profile_uid
    }

    pub(super) const fn guard(&self) -> &ProfileAutomationResourceGuard {
        &self.guard
    }

    pub(super) const fn mode(&self) -> ProfileAutomationResourceMode {
        self.mode
    }
}

impl StoreCore {
    pub(super) fn has_cleanup_deferred(&self) -> bool {
        self.durability_uncertain
            || !self.fence_cleanup_deferred.is_empty()
            || !self.retryable_cleanup_deferred.is_empty()
            || !self.profile_fence_busy.is_empty()
            || !self.profile_fence_deferred.is_empty()
    }

    pub(super) fn latch_profile_cleanup(&mut self, profile_uid: ProfileUid) {
        self.fence_cleanup_deferred.insert(profile_uid);
    }

    pub(super) fn latch_retryable_cleanup(&mut self, profile_uid: ProfileUid) {
        self.retryable_cleanup_deferred.insert(profile_uid);
    }

    pub(super) fn latch_cleanup_failure(&mut self, profile_uid: ProfileUid, error: StoreError) {
        match error {
            StoreError::DatabaseUnavailable | StoreError::ServiceBusy => {
                self.latch_retryable_cleanup(profile_uid);
            }
            _ => self.latch_profile_cleanup(profile_uid),
        }
    }

    pub(super) fn retain_busy_fence(
        &mut self,
        profile_uid: ProfileUid,
        guard: ProfileAutomationFenceBusyGuard,
    ) {
        let conflicted = self.profile_fences.contains_key(&profile_uid)
            || self.profile_fence_deferred.contains_key(&profile_uid)
            || self
                .profile_fence_busy
                .get(&profile_uid)
                .is_some_and(|guards| !guards.is_empty());
        self.profile_fence_busy
            .entry(profile_uid.clone())
            .or_default()
            .push(guard);
        if conflicted {
            self.latch_profile_cleanup(profile_uid);
        } else {
            self.latch_retryable_cleanup(profile_uid);
        }
    }

    pub(super) fn retain_deferred_fence(
        &mut self,
        profile_uid: ProfileUid,
        guard: ProfileAutomationDeferredFenceGuard,
    ) {
        self.profile_fence_deferred
            .entry(profile_uid.clone())
            .or_default()
            .push(guard);
        self.latch_profile_cleanup(profile_uid);
    }

    pub(super) fn retain_fence_failure(
        &mut self,
        profile_uid: ProfileUid,
        failure: ProfileAutomationFenceFailure,
    ) {
        let (error, guard) = failure.into_parts();
        let _ = error;
        self.retain_deferred_fence(profile_uid, guard);
    }

    pub(super) fn retain_fence(
        &mut self,
        profile_uid: ProfileUid,
        guard: ProfileAutomationFenceGuard,
    ) -> Result<(), StoreError> {
        if guard
            .validate_binding(&self.installation_uid, &profile_uid)
            .is_err()
        {
            self.retain_deferred_fence(profile_uid, guard.defer());
            return Err(StoreError::UnsafeStorage);
        }
        match self.profile_fences.entry(profile_uid.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(guard);
                Ok(())
            }
            Entry::Occupied(_) => {
                self.retain_deferred_fence(profile_uid, guard.defer());
                Err(StoreError::IntegrityCheckFailed)
            }
        }
    }

    pub(super) fn fence(
        &self,
        profile_uid: &ProfileUid,
    ) -> Result<&ProfileAutomationFenceGuard, StoreError> {
        if self.has_cleanup_deferred() {
            return Err(StoreError::RecoveryRequired);
        }
        let guard = self
            .profile_fences
            .get(profile_uid)
            .ok_or(StoreError::RecoveryRequired)?;
        guard
            .validate_binding(&self.installation_uid, profile_uid)
            .map_err(fence_store_error)?;
        Ok(guard)
    }

    pub(super) fn profile_resource_is_held(&self, profile_uid: &ProfileUid) -> bool {
        self.profile_resources
            .values()
            .any(|resource| resource.profile_uid() == profile_uid)
    }

    pub(super) fn retain_resource(
        &mut self,
        lease_id: LeaseId,
        profile_uid: ProfileUid,
        mode: ProfileAutomationResourceMode,
        guard: ProfileAutomationResourceGuard,
    ) -> Result<(), StoreError> {
        guard
            .validate_binding(&self.installation_uid, &profile_uid, mode)
            .map_err(fence_store_error)?;
        match self.profile_resources.entry(lease_id) {
            Entry::Vacant(entry) => {
                entry.insert(HeldProfileResource::new(profile_uid, mode, guard));
                Ok(())
            }
            Entry::Occupied(_) => Err(StoreError::IntegrityCheckFailed),
        }
    }

    pub(super) fn validate_lease_authority_guards(
        &mut self,
        lease_id: &LeaseId,
        snapshot: &crate::automation::lease::LeaseSnapshot,
    ) -> Result<ProfileAutomationResourceMode, StoreError> {
        let profile_uid = snapshot.profile_uid();
        self.validate_lease_fence(snapshot)?;
        let Some(resource) = self.profile_resources.get(lease_id) else {
            self.latch_profile_cleanup(profile_uid.clone());
            return Err(StoreError::RecoveryRequired);
        };
        if resource.profile_uid() != profile_uid
            || resource
                .guard()
                .validate_binding(&self.installation_uid, profile_uid, resource.mode())
                .is_err()
        {
            self.latch_profile_cleanup(profile_uid.clone());
            return Err(StoreError::UnsafeStorage);
        }
        Ok(resource.mode())
    }

    pub(super) fn validate_lease_fence(
        &mut self,
        snapshot: &crate::automation::lease::LeaseSnapshot,
    ) -> Result<(), StoreError> {
        let profile_uid = snapshot.profile_uid();
        if self.has_cleanup_deferred() {
            return Err(StoreError::RecoveryRequired);
        }
        let profile_ref = snapshot
            .profile_ref()
            .as_str()
            .parse::<crate::model::ProfileId>()
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let Some(fence) = self.profile_fences.get(profile_uid) else {
            self.latch_profile_cleanup(profile_uid.clone());
            return Err(StoreError::RecoveryRequired);
        };
        if fence
            .validate_recovery_binding(
                &self.installation_uid,
                &profile_ref,
                snapshot.provider(),
                profile_uid,
            )
            .is_err()
        {
            self.latch_profile_cleanup(profile_uid.clone());
            return Err(StoreError::UnsafeStorage);
        }
        Ok(())
    }

    pub(super) fn release_resource(&mut self, lease_id: &LeaseId) {
        self.profile_resources.remove(lease_id);
    }

    pub(super) fn post_terminal_cleanup(
        &mut self,
        lease_id: &LeaseId,
        profile_uid: &ProfileUid,
    ) -> Result<bool, StoreError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_post_terminal_cleanup) {
            return Err(StoreError::DatabaseUnavailable);
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_post_terminal_cleanup_integrity) {
            return Err(StoreError::IntegrityCheckFailed);
        }
        self.release_terminal_resource_if_resolved(lease_id, profile_uid)?;
        self.try_clear_profile_fence(profile_uid)
    }

    fn release_terminal_resource_if_resolved(
        &mut self,
        lease_id: &LeaseId,
        profile_uid: &ProfileUid,
    ) -> Result<bool, StoreError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let lease_blocked: bool = transaction
            .query_row(
                "SELECT status NOT IN ('CLOSED', 'REVOKED', 'EXPIRED', 'REFUSED')
                        OR recovery_state <> 'NONE' OR quarantined = 1
                        OR EXISTS(SELECT 1 FROM capacity_reservations
                            WHERE lease_id = leases.lease_id AND state <> 'RELEASED')
                        OR EXISTS(SELECT 1 FROM lease_processes
                            WHERE lease_id = leases.lease_id AND state <> 'EXITED')
                 FROM leases WHERE lease_id = ?1 AND profile_uid = ?2",
                rusqlite::params![lease_id.as_str(), profile_uid.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if self
            .profile_resources
            .get(lease_id)
            .is_some_and(|resource| resource.profile_uid() != profile_uid)
        {
            self.latch_profile_cleanup(profile_uid.clone());
            return Err(StoreError::IntegrityCheckFailed);
        }
        if !lease_blocked {
            self.release_resource(lease_id);
        }
        Ok(!lease_blocked)
    }

    /// Upgrade the UID lifecycle guard before opening the DB transaction. The
    /// transaction only proves blockers; it never waits on a filesystem lock.
    pub(super) fn try_clear_profile_fence(
        &mut self,
        profile_uid: &ProfileUid,
    ) -> Result<bool, StoreError> {
        if self.hard_cleanup_is_latched(profile_uid) {
            return Err(StoreError::RecoveryRequired);
        }
        if self.profile_resource_is_held(profile_uid) {
            if self.profile_fence_busy.contains_key(profile_uid) {
                self.latch_profile_cleanup(profile_uid.clone());
                return Err(StoreError::IntegrityCheckFailed);
            }
            let Some(fence) = self.profile_fences.get(profile_uid) else {
                self.latch_profile_cleanup(profile_uid.clone());
                return Err(StoreError::IntegrityCheckFailed);
            };
            if fence
                .validate_binding(&self.installation_uid, profile_uid)
                .is_err()
            {
                self.latch_profile_cleanup(profile_uid.clone());
                return Err(StoreError::UnsafeStorage);
            }
            let blocked = match self.validate_retained_profile_resources(profile_uid) {
                Ok(blocked) => blocked,
                Err(error) => {
                    if error == StoreError::DatabaseUnavailable {
                        self.latch_retryable_cleanup(profile_uid.clone());
                    } else {
                        self.latch_profile_cleanup(profile_uid.clone());
                    }
                    return Err(error);
                }
            };
            if !blocked {
                self.latch_profile_cleanup(profile_uid.clone());
                return Err(StoreError::IntegrityCheckFailed);
            }
            if self.fence_cleanup_deferred.contains(profile_uid) {
                return Err(StoreError::RecoveryRequired);
            }
            self.retryable_cleanup_deferred.remove(profile_uid);
            return Ok(false);
        }
        let upgrade = if let Some(mut busy) = self.profile_fence_busy.remove(profile_uid) {
            if busy.len() != 1 || self.profile_fences.contains_key(profile_uid) {
                self.profile_fence_busy.insert(profile_uid.clone(), busy);
                self.latch_profile_cleanup(profile_uid.clone());
                return Err(StoreError::IntegrityCheckFailed);
            }
            busy.pop()
                .ok_or(StoreError::IntegrityCheckFailed)?
                .try_upgrade_for_clear()
        } else if let Some(shared) = self.profile_fences.remove(profile_uid) {
            shared.try_upgrade_for_clear()
        } else {
            let blocked = match prove_profile_blockers(&mut self.connection, profile_uid) {
                Ok(blocked) => blocked,
                Err(error) => {
                    self.latch_profile_cleanup(profile_uid.clone());
                    return Err(error);
                }
            };
            if blocked {
                self.latch_profile_cleanup(profile_uid.clone());
                return Err(StoreError::RecoveryRequired);
            }
            return match profile_automation_fence_presence(&self.paths, profile_uid) {
                Ok(false) => {
                    self.fence_cleanup_deferred.remove(profile_uid);
                    self.retryable_cleanup_deferred.remove(profile_uid);
                    Ok(true)
                }
                Ok(true) => {
                    self.latch_profile_cleanup(profile_uid.clone());
                    Err(StoreError::RecoveryRequired)
                }
                Err(_) => {
                    self.latch_profile_cleanup(profile_uid.clone());
                    Err(StoreError::UnsafeStorage)
                }
            };
        };
        let exclusive = match upgrade {
            ProfileAutomationFenceUpgrade::Exclusive(guard) => guard,
            ProfileAutomationFenceUpgrade::Busy(guard) => {
                self.retain_busy_fence(profile_uid.clone(), guard);
                return Err(StoreError::ServiceBusy);
            }
            ProfileAutomationFenceUpgrade::CleanupDeferred(failure) => {
                self.retain_fence_failure(profile_uid.clone(), failure);
                return Err(StoreError::UnsafeStorage);
            }
        };
        let blocked = match prove_profile_blockers(&mut self.connection, profile_uid) {
            Ok(blocked) => blocked,
            Err(error) => {
                return Err(self.retain_after_blocker_read_failure(profile_uid, exclusive, error));
            }
        };
        if blocked {
            match exclusive.downgrade() {
                ProfileAutomationFenceDowngrade::Shared(shared) => {
                    self.retain_fence(profile_uid.clone(), shared)?;
                    self.retryable_cleanup_deferred.remove(profile_uid);
                    Ok(false)
                }
                ProfileAutomationFenceDowngrade::Busy(guard) => {
                    self.retain_busy_fence(profile_uid.clone(), guard);
                    Err(StoreError::ServiceBusy)
                }
                ProfileAutomationFenceDowngrade::CleanupDeferred(failure) => {
                    self.retain_fence_failure(profile_uid.clone(), failure);
                    Err(StoreError::UnsafeStorage)
                }
            }
        } else {
            if let Err(failure) = exclusive.clear() {
                self.retain_fence_failure(profile_uid.clone(), failure);
                return Err(StoreError::UnsafeStorage);
            }
            self.fence_cleanup_deferred.remove(profile_uid);
            self.retryable_cleanup_deferred.remove(profile_uid);
            Ok(true)
        }
    }

    fn hard_cleanup_is_latched(&self, profile_uid: &ProfileUid) -> bool {
        self.durability_uncertain
            || self.fence_cleanup_deferred.contains(profile_uid)
            || self
                .profile_fence_deferred
                .get(profile_uid)
                .is_some_and(|guards| !guards.is_empty())
    }

    fn retain_after_blocker_read_failure(
        &mut self,
        profile_uid: &ProfileUid,
        exclusive: crate::config::ProfileAutomationFenceClearGuard,
        error: StoreError,
    ) -> StoreError {
        if error != StoreError::DatabaseUnavailable {
            self.retain_deferred_fence(profile_uid.clone(), exclusive.defer());
            return error;
        }
        match exclusive.downgrade() {
            ProfileAutomationFenceDowngrade::Shared(shared) => {
                if self.retain_fence(profile_uid.clone(), shared).is_err() {
                    StoreError::UnsafeStorage
                } else {
                    self.latch_retryable_cleanup(profile_uid.clone());
                    error
                }
            }
            ProfileAutomationFenceDowngrade::Busy(guard) => {
                self.retain_busy_fence(profile_uid.clone(), guard);
                error
            }
            ProfileAutomationFenceDowngrade::CleanupDeferred(failure) => {
                self.retain_fence_failure(profile_uid.clone(), failure);
                StoreError::UnsafeStorage
            }
        }
    }

    fn validate_retained_profile_resources(
        &mut self,
        profile_uid: &ProfileUid,
    ) -> Result<bool, StoreError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        load::validate_all_leases(&transaction)?;
        let blocked = capacity::profile_has_blocking_state(&transaction, profile_uid)?;
        let mut statement = transaction
            .prepare(
                "SELECT lease_id FROM leases
                 WHERE profile_uid = ?1 AND (
                    status IN ('ACTIVE', 'RENEWING', 'ERROR')
                    OR EXISTS(SELECT 1 FROM capacity_reservations
                        WHERE lease_id = leases.lease_id AND state <> 'RELEASED')
                    OR EXISTS(SELECT 1 FROM lease_processes
                        WHERE lease_id = leases.lease_id AND state <> 'EXITED')
                    OR (execution_handle IS NOT NULL
                        AND (recovery_state <> 'NONE' OR quarantined = 1)))",
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let expected = statement
            .query_map(rusqlite::params![profile_uid.as_str()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|_| StoreError::DatabaseUnavailable)?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        drop(statement);
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let actual = self
            .profile_resources
            .iter()
            .filter(|(_, resource)| resource.profile_uid() == profile_uid)
            .map(|(lease_id, _)| lease_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(StoreError::IntegrityCheckFailed);
        }
        let bindings_valid = self
            .profile_resources
            .values()
            .filter(|resource| resource.profile_uid() == profile_uid)
            .all(|resource| {
                resource
                    .guard()
                    .validate_binding(&self.installation_uid, profile_uid, resource.mode())
                    .is_ok()
            });
        if !bindings_valid {
            return Err(StoreError::UnsafeStorage);
        }
        Ok(blocked)
    }
}

fn prove_profile_blockers(
    connection: &mut rusqlite::Connection,
    profile_uid: &ProfileUid,
) -> Result<bool, StoreError> {
    let transaction = connection
        .transaction()
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    let blocked = capacity::profile_has_blocking_state(&transaction, profile_uid)?;
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    Ok(blocked)
}

impl RecoveringStore {
    #[must_use]
    pub(crate) fn recovered_profile_fences(&self) -> Vec<ProfileUid> {
        self.core
            .profile_fences
            .keys()
            .chain(self.core.profile_fence_busy.keys())
            .chain(self.core.profile_fence_deferred.keys())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Clear only a marker whose same-profile durable blocker set is empty.
    pub(crate) fn clear_orphan_profile_fence(
        &mut self,
        profile_uid: &ProfileUid,
    ) -> Result<bool, StoreError> {
        self.core.try_clear_profile_fence(profile_uid)
    }
}

impl ReadyStore {
    pub(crate) fn retry_profile_fence_cleanup(
        &mut self,
        profile_uid: &ProfileUid,
    ) -> Result<bool, StoreError> {
        if self.core.hard_cleanup_is_latched(profile_uid) {
            return Err(StoreError::RecoveryRequired);
        }
        let lease_ids = self
            .core
            .profile_resources
            .iter()
            .filter(|(_, resource)| resource.profile_uid() == profile_uid)
            .map(|(lease_id, _)| lease_id.clone())
            .collect::<Vec<_>>();
        for lease_id in lease_ids {
            self.core
                .release_terminal_resource_if_resolved(&lease_id, profile_uid)?;
        }
        self.core.try_clear_profile_fence(profile_uid)
    }
}

// This `map_err` adapter owns and immediately redacts the configuration error.
#[allow(clippy::needless_pass_by_value)]
pub(super) fn fence_store_error(error: crate::Error) -> StoreError {
    if matches!(error, crate::Error::ConfigBusy) {
        StoreError::ServiceBusy
    } else {
        StoreError::UnsafeStorage
    }
}
