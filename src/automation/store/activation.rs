use rusqlite::TransactionBehavior;

use crate::{
    automation::{
        contracts::{AutomationOperation, IdentityLeaseResponse, LeaseStatus, RefusalCode},
        lease::{LeaseDomainError, LeaseResolution},
        policy::EffectivePolicy,
    },
    config::{
        MetadataStore, ProfileAutomationResourceAcquisition, ProfileAutomationResourceMode,
        acquire_profile_automation_resource, validate_profile_automation_fence_profile,
    },
    model::{AutomationConcurrencyMode, ProfileId},
};

use super::{
    AuthenticatedRequestControl, CommittedMutation, ReadyStore, StoreError, capacity,
    fence::fence_store_error,
    lifecycle::persist::{self, AuditActor},
    load, ownership,
};

impl ReadyStore {
    /// Resolve one fenced REQUESTED lease. Resource acquisition occurs before
    /// the IMMEDIATE transaction; capacity is always recounted inside it.
    // The sealed store boundary owns resolved evidence even when validation refuses it.
    #[allow(clippy::needless_pass_by_value)]
    pub(in crate::automation::store) fn activate_requested(
        &mut self,
        control: &AuthenticatedRequestControl<'_>,
        policy: &EffectivePolicy,
        resolution: LeaseResolution,
        now: &crate::automation::lease::ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        let identity = match self.preflight_activation_identity(control)? {
            ActivationPreflight::Ready(identity) => identity,
            ActivationPreflight::Domain(result) => return Ok(result),
        };
        self.validate_activation_fence(&identity)?;
        if !self.preflight_activation_authority(control, policy, &resolution, now)? {
            return self.persist_activation_preflight(control, policy, &resolution, now);
        }
        let profile_uid = identity.profile_uid;
        let resource_mode = policy_resource_mode(policy)?;
        let acquired = {
            let fence = match self.core.fence(&profile_uid) {
                Ok(fence) => fence,
                Err(error) => {
                    self.core.latch_profile_cleanup(profile_uid.clone());
                    return Err(error);
                }
            };
            acquire_profile_automation_resource(
                &self.core.paths,
                &self.core.installation_uid,
                &identity.profile_ref,
                &profile_uid,
                resource_mode,
                fence,
            )
            .map_err(fence_store_error)?
        };
        let resource = match acquired {
            ProfileAutomationResourceAcquisition::Acquired(guard) => Some(guard),
            ProfileAutomationResourceAcquisition::Busy => None,
        };
        let resource_registered = if let Some(guard) = resource {
            self.core.retain_resource(
                control.lease_id().clone(),
                profile_uid.clone(),
                resource_mode,
                guard,
            )?;
            true
        } else {
            false
        };

        // Registering the opaque resource guard before BEGIN makes ACTIVE
        // commit imply in-memory guard retention. Every non-ACTIVE/error path
        // below removes that exact registration.
        let mut commit_attempted = false;
        let mutation = (|| {
            let generation = self.core.service_generation;
            let transaction = self
                .core
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            if !ownership::caller_matches(
                &transaction,
                control.lease_id(),
                control.caller_subject(),
            )? {
                transaction
                    .commit()
                    .map_err(|_| StoreError::DatabaseUnavailable)?;
                return Ok((
                    CommittedMutation::authentication_denied(AutomationOperation::LeaseAcquire),
                    LeaseStatus::Requested,
                ));
            }
            let mut loaded = load::lease_by_id(&transaction, control.lease_id().as_str())?
                .ok_or(StoreError::LeaseNotFound)?;
            require_requested_control(&loaded, control, generation)?;
            let domain_result = match loaded.lease.prepare_activation(policy, &resolution, now) {
                Err(error) => Err(error),
                Ok(prepared) => {
                    let available = capacity::available(
                        &transaction,
                        control.lease_id(),
                        policy.capacity_claim(),
                    )?;
                    if !available {
                        loaded.lease.refuse(RefusalCode::CapacityExceeded)
                    } else if !resource_registered {
                        loaded.lease.refuse(RefusalCode::ProfileNotReady)
                    } else {
                        loaded.lease.activate_prepared(prepared)
                    }
                }
            };
            let response = validated_response(&loaded.lease)?;
            if domain_result.is_ok()
                && loaded.lease.status() == LeaseStatus::Active
                && !capacity::claim(
                    &transaction,
                    control.lease_id(),
                    policy.capacity_claim(),
                    now.wall(),
                )?
            {
                return Err(StoreError::IntegrityCheckFailed);
            }
            let status = loaded.lease.status();
            let after = loaded.lease.snapshot();
            let row_version = persist::persist(
                &transaction,
                &loaded,
                &after,
                now.wall(),
                AuditActor::Service,
                generation,
            )?;
            commit_attempted = true;
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            Ok((
                CommittedMutation::new(
                    AutomationOperation::LeaseAcquire,
                    response,
                    row_version,
                    domain_result,
                ),
                status,
            ))
        })();
        let (mut committed, status) = match mutation {
            Ok(result) => result,
            Err(error) => {
                if commit_attempted {
                    self.core.latch_profile_cleanup(profile_uid.clone());
                } else if resource_registered {
                    self.core.release_resource(control.lease_id());
                }
                return Err(error);
            }
        };
        if status != LeaseStatus::Active && resource_registered {
            self.core.release_resource(control.lease_id());
        }
        if status == LeaseStatus::Refused
            && let Err(error) = self
                .core
                .post_terminal_cleanup(control.lease_id(), &profile_uid)
        {
            self.core.latch_cleanup_failure(profile_uid.clone(), error);
            committed.mark_cleanup_deferred();
        }
        Ok(committed)
    }

    fn preflight_activation_identity(
        &mut self,
        control: &AuthenticatedRequestControl<'_>,
    ) -> Result<ActivationPreflight, StoreError> {
        let transaction = self
            .core
            .connection
            .unchecked_transaction()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if !ownership::caller_matches(&transaction, control.lease_id(), control.caller_subject())? {
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Ok(ActivationPreflight::Domain(
                CommittedMutation::authentication_denied(AutomationOperation::LeaseAcquire),
            ));
        }
        let Some(loaded) = load::lease_by_id(&transaction, control.lease_id().as_str())? else {
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Ok(ActivationPreflight::Domain(
                CommittedMutation::authentication_denied(AutomationOperation::LeaseAcquire),
            ));
        };
        if loaded.snapshot.caller_subject() != control.caller_subject() {
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Ok(ActivationPreflight::Domain(
                CommittedMutation::authentication_denied(AutomationOperation::LeaseAcquire),
            ));
        }
        if let Some(error) = requested_identity_error(&loaded, control) {
            let response = validated_response(&loaded.lease)?;
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            // Identity errors are returned without profile/fence access.
            return Ok(ActivationPreflight::Domain(CommittedMutation::new(
                AutomationOperation::LeaseAcquire,
                response,
                loaded.row_version,
                Err(error),
            )));
        }
        if self.core.has_cleanup_deferred() {
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Err(StoreError::RecoveryRequired);
        }
        require_requested_control(&loaded, control, self.core.service_generation)?;
        let profile_uid = loaded.snapshot.profile_uid().clone();
        let profile_ref = loaded
            .snapshot
            .profile_ref()
            .as_str()
            .parse::<ProfileId>()
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        Ok(ActivationPreflight::Ready(ActivationIdentity {
            profile_uid,
            profile_ref,
            provider: loaded.snapshot.provider(),
        }))
    }

    fn validate_activation_fence(
        &mut self,
        identity: &ActivationIdentity,
    ) -> Result<(), StoreError> {
        let metadata = MetadataStore::new(self.core.paths.clone());
        let validation = match self.core.fence(&identity.profile_uid) {
            Ok(fence) => validate_profile_automation_fence_profile(
                &metadata,
                &self.core.installation_uid,
                &identity.profile_ref,
                identity.provider,
                &identity.profile_uid,
                fence,
            ),
            Err(error) => {
                self.core
                    .latch_profile_cleanup(identity.profile_uid.clone());
                return Err(error);
            }
        };
        if matches!(validation, Ok(None)) {
            Ok(())
        } else {
            self.core
                .latch_profile_cleanup(identity.profile_uid.clone());
            Err(StoreError::UnsafeStorage)
        }
    }

    fn preflight_activation_authority(
        &mut self,
        control: &AuthenticatedRequestControl<'_>,
        policy: &EffectivePolicy,
        resolution: &LeaseResolution,
        now: &crate::automation::lease::ClockSample,
    ) -> Result<bool, StoreError> {
        let transaction = self
            .core
            .connection
            .unchecked_transaction()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if !ownership::caller_matches(&transaction, control.lease_id(), control.caller_subject())? {
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Ok(false);
        }
        let mut loaded = load::lease_by_id(&transaction, control.lease_id().as_str())?
            .ok_or(StoreError::LeaseNotFound)?;
        require_requested_control(&loaded, control, self.core.service_generation)?;
        let valid = loaded
            .lease
            .prepare_activation(policy, resolution, now)
            .is_ok();
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        Ok(valid)
    }

    fn persist_activation_preflight(
        &mut self,
        control: &AuthenticatedRequestControl<'_>,
        policy: &EffectivePolicy,
        resolution: &LeaseResolution,
        now: &crate::automation::lease::ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        let generation = self.core.service_generation;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if !ownership::caller_matches(&transaction, control.lease_id(), control.caller_subject())? {
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Ok(CommittedMutation::authentication_denied(
                AutomationOperation::LeaseAcquire,
            ));
        }
        let mut loaded = load::lease_by_id(&transaction, control.lease_id().as_str())?
            .ok_or(StoreError::LeaseNotFound)?;
        require_requested_control(&loaded, control, generation)?;
        let profile_uid = loaded.snapshot.profile_uid().clone();
        let domain_result = loaded
            .lease
            .prepare_activation(policy, resolution, now)
            .map(|_| ());
        if domain_result.is_ok() {
            return Err(StoreError::ConcurrentMutation);
        }
        let response = validated_response(&loaded.lease)?;
        let after = loaded.lease.snapshot();
        let row_version = persist::persist(
            &transaction,
            &loaded,
            &after,
            now.wall(),
            AuditActor::Service,
            generation,
        )?;
        if transaction.commit().is_err() {
            self.core.latch_profile_cleanup(profile_uid);
            return Err(StoreError::DatabaseUnavailable);
        }
        Ok(CommittedMutation::new(
            AutomationOperation::LeaseAcquire,
            response,
            row_version,
            domain_result,
        ))
    }
}

// Short-lived preflight values avoid heap allocation on every activation attempt.
#[allow(clippy::large_enum_variant)]
enum ActivationPreflight {
    Ready(ActivationIdentity),
    Domain(CommittedMutation<()>),
}

struct ActivationIdentity {
    profile_uid: crate::model::ProfileUid,
    profile_ref: ProfileId,
    provider: crate::model::Provider,
}

fn policy_resource_mode(
    policy: &EffectivePolicy,
) -> Result<ProfileAutomationResourceMode, StoreError> {
    if !policy.resource_isolation_is_consistent() {
        return Err(StoreError::IntegrityCheckFailed);
    }
    Ok(match policy.concurrency_mode() {
        AutomationConcurrencyMode::Exclusive => ProfileAutomationResourceMode::Exclusive,
        AutomationConcurrencyMode::Shared => ProfileAutomationResourceMode::Shared,
    })
}

fn require_requested_control(
    loaded: &load::LoadedLease,
    control: &AuthenticatedRequestControl<'_>,
    generation: crate::automation::lease::ServiceClockGeneration,
) -> Result<(), StoreError> {
    if loaded.lease.status() != LeaseStatus::Requested
        || loaded.origin_generation != generation
        || !matches!(
            loaded.recovery_state,
            super::load_parse::RecoveryState::None
        )
        || loaded.quarantined
    {
        return Err(StoreError::InvalidTransition);
    }
    if control.expected_row_version() == 0 || loaded.row_version != control.expected_row_version() {
        return Err(StoreError::ConcurrentMutation);
    }
    if requested_identity_error(loaded, control).is_some() {
        return Err(StoreError::IntegrityCheckFailed);
    }
    Ok(())
}

fn requested_identity_error(
    loaded: &load::LoadedLease,
    control: &AuthenticatedRequestControl<'_>,
) -> Option<LeaseDomainError> {
    if loaded.snapshot.caller_subject() != control.caller_subject() {
        Some(LeaseDomainError::CallerUnauthorized)
    } else if loaded.snapshot.host_identity() != control.host_identity() {
        Some(LeaseDomainError::HostMismatch)
    } else {
        None
    }
}

fn validated_response(
    lease: &crate::automation::lease::Lease,
) -> Result<IdentityLeaseResponse, StoreError> {
    lease
        .identity_response()
        .map_err(|_| StoreError::IntegrityCheckFailed)
}
