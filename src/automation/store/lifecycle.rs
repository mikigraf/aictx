use rusqlite::{Transaction, TransactionBehavior};

use crate::automation::{
    contracts::{
        AutomationOperation, CallerSubject, FencingGeneration, HostIdentity, IdentityLeaseResponse,
        LeaseId, LeaseReasonCode, LeaseStatus, UtcTimestamp,
    },
    lease::{ClockSample, Lease, LeaseControl, LeaseDomainError, LeaseSnapshot},
    policy::EffectivePolicy,
};
use crate::{config::ProfileAutomationResourceMode, model::AutomationConcurrencyMode};

use super::{
    AuthenticatedRequestControl, CommittedMutation, ReadyStore, StoreError, capacity,
    lifecycle_types::{NonCapacityRefusal, terminal_status},
    load, ownership,
};

#[path = "lifecycle/persist.rs"]
pub(super) mod persist;
use persist::AuditActor;

impl ReadyStore {
    pub(in crate::automation::store) fn refuse_requested(
        &mut self,
        control: &AuthenticatedRequestControl<'_>,
        refusal: NonCapacityRefusal,
        now: &UtcTimestamp,
    ) -> Result<CommittedMutation<()>, StoreError> {
        self.mutate_requested(control, now, AuditActor::Service, |lease| {
            lease.refuse(refusal.code())
        })
    }

    pub(in crate::automation::store) fn begin_renewal(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        control: &LeaseControl<'_>,
        current_policy: &EffectivePolicy,
        now: &ClockSample,
    ) -> Result<CommittedMutation<FencingGeneration>, StoreError> {
        match self.preflight_guarded_resolved::<FencingGeneration>(
            lease_id,
            expected_row_version,
            control,
            false,
            |lease| lease.begin_renewal(control, current_policy, now),
        )? {
            GuardedMutationPreflight::Domain(result) => return Ok(result),
            GuardedMutationPreflight::WithoutGuards => {}
            GuardedMutationPreflight::Guarded(snapshot) => {
                let held_mode = self
                    .core
                    .validate_lease_authority_guards(lease_id, &snapshot)?;
                if held_mode != policy_resource_mode(current_policy) {
                    return self.mutate_resolved(
                        lease_id,
                        expected_row_version,
                        control,
                        now.wall(),
                        AuditActor::Service,
                        AutomationOperation::LeaseRenew,
                        false,
                        |lease| {
                            let control_result = lease.validate_control_binding(control);
                            let deadline_result = lease.enforce_deadlines(now);
                            control_result?;
                            deadline_result?;
                            Err(LeaseDomainError::PolicyBindingMismatch)
                        },
                    );
                }
                return self.mutate_guarded_begin_renewal(
                    lease_id,
                    expected_row_version,
                    control,
                    current_policy,
                    now,
                );
            }
        }
        self.mutate_resolved(
            lease_id,
            expected_row_version,
            control,
            now.wall(),
            AuditActor::Service,
            AutomationOperation::LeaseRenew,
            false,
            |lease| lease.begin_renewal(control, current_policy, now),
        )
    }

    pub(in crate::automation::store) fn acknowledge_renewal(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        control: &LeaseControl<'_>,
        now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        match self.preflight_guarded_resolved::<()>(
            lease_id,
            expected_row_version,
            control,
            true,
            |lease| lease.acknowledge_renewal(control, now),
        )? {
            GuardedMutationPreflight::Domain(result) => return Ok(result),
            GuardedMutationPreflight::WithoutGuards => {}
            GuardedMutationPreflight::Guarded(snapshot) => {
                let _ = self
                    .core
                    .validate_lease_authority_guards(lease_id, &snapshot)?;
            }
        }
        self.mutate_resolved(
            lease_id,
            expected_row_version,
            control,
            now.wall(),
            AuditActor::Service,
            AutomationOperation::LeaseRenew,
            true,
            |lease| lease.acknowledge_renewal(control, now),
        )
    }

    fn preflight_guarded_resolved<T>(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        control: &LeaseControl<'_>,
        exact_caller_failure_mutates: bool,
        dry_run: impl FnOnce(&mut Lease) -> Result<T, LeaseDomainError>,
    ) -> Result<GuardedMutationPreflight<T>, StoreError> {
        let generation = self.core.service_generation;
        let transaction = self
            .core
            .connection
            .unchecked_transaction()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let owner = ownership::caller_matches(&transaction, lease_id, control.caller_subject)?;
        let foreign_ack = !owner
            && exact_caller_failure_mutates
            && ownership::foreign_exact_renewing_ack(
                &transaction,
                lease_id,
                expected_row_version,
                generation,
            )?;
        if !owner && !foreign_ack {
            return committed_authentication_denied(transaction, AutomationOperation::LeaseRenew)
                .map(GuardedMutationPreflight::Domain);
        }
        let loaded = match load::lease_by_id(&transaction, lease_id.as_str()) {
            Ok(Some(loaded)) => loaded,
            Ok(None) => {
                return committed_authentication_denied(
                    transaction,
                    AutomationOperation::LeaseRenew,
                )
                .map(GuardedMutationPreflight::Domain);
            }
            Err(_) if !owner => {
                return committed_authentication_denied(
                    transaction,
                    AutomationOperation::LeaseRenew,
                )
                .map(GuardedMutationPreflight::Domain);
            }
            Err(error) => return Err(error),
        };
        let exact = mutable_in_generation(&loaded, generation)
            && expected_row_version != 0
            && loaded.row_version == expected_row_version;
        if !owner && (!exact || loaded.lease.status() != LeaseStatus::Renewing) {
            return committed_authentication_denied(transaction, AutomationOperation::LeaseRenew)
                .map(GuardedMutationPreflight::Domain);
        }
        let binding_error = if owner {
            loaded.lease.validate_control_binding(control).err()
        } else {
            Some(LeaseDomainError::CallerUnauthorized)
        };
        let mut exact_renewing_ack_mismatch = false;
        if let Some(error) = binding_error.as_ref() {
            let exact_renewing_ack = exact
                && exact_caller_failure_mutates
                && loaded.lease.status() == LeaseStatus::Renewing;
            exact_renewing_ack_mismatch = exact_renewing_ack;
            if *error == LeaseDomainError::CallerUnauthorized && !exact_renewing_ack {
                return committed_authentication_denied(
                    transaction,
                    AutomationOperation::LeaseRenew,
                )
                .map(GuardedMutationPreflight::Domain);
            }
            if !exact {
                return committed_domain_error(
                    transaction,
                    &loaded,
                    AutomationOperation::LeaseRenew,
                    error.clone(),
                )
                .map(GuardedMutationPreflight::Domain);
            }
        }
        require_mutable_generation(&loaded, generation)?;
        require_expected_version(&loaded, expected_row_version)?;
        if self.core.has_cleanup_deferred() && !exact_renewing_ack_mismatch {
            if let Some(error) = binding_error {
                return committed_domain_error(
                    transaction,
                    &loaded,
                    AutomationOperation::LeaseRenew,
                    error,
                )
                .map(GuardedMutationPreflight::Domain);
            }
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Err(StoreError::RecoveryRequired);
        }
        let mut disposable = Lease::restore(loaded.snapshot.clone())
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let _ = dry_run(&mut disposable);
        let preflight = if matches!(
            disposable.status(),
            LeaseStatus::Active | LeaseStatus::Renewing | LeaseStatus::Error
        ) {
            GuardedMutationPreflight::Guarded(loaded.snapshot.clone())
        } else {
            GuardedMutationPreflight::WithoutGuards
        };
        transaction
            .commit()
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        Ok(preflight)
    }

    pub(in crate::automation::store) fn close_lease(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        control: &LeaseControl<'_>,
        reason: LeaseReasonCode,
        now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        self.mutate_resolved(
            lease_id,
            expected_row_version,
            control,
            now.wall(),
            AuditActor::AuthenticatedControl(control.caller_subject),
            AutomationOperation::LeaseClose,
            false,
            |lease| lease.close(control, reason, now),
        )
    }

    pub(in crate::automation::store) fn revoke_authenticated(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        control: &LeaseControl<'_>,
        now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        self.mutate_resolved(
            lease_id,
            expected_row_version,
            control,
            now.wall(),
            AuditActor::AuthenticatedControl(control.caller_subject),
            AutomationOperation::LeaseRevoke,
            false,
            |lease| lease.revoke_controlled(control, now),
        )
    }

    pub(in crate::automation::store) fn revoke_by_service(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        reason: LeaseReasonCode,
        now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        self.mutate_service(
            lease_id,
            expected_row_version,
            now.wall(),
            AutomationOperation::LeaseRevoke,
            |lease| {
                let reason_error = (!service_revocation_reason(reason)).then_some(
                    LeaseDomainError::InvalidReason {
                        status: LeaseStatus::Revoked,
                        reason,
                    },
                );
                let deadline_result = enforce_before(lease, now);
                if let Some(error) = reason_error {
                    return Err(error);
                }
                deadline_result?;
                lease.revoke(reason)
            },
        )
    }

    pub(in crate::automation::store) fn mark_error(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        reason: LeaseReasonCode,
        now: &ClockSample,
    ) -> Result<CommittedMutation<()>, StoreError> {
        self.mutate_service(
            lease_id,
            expected_row_version,
            now.wall(),
            AutomationOperation::LeaseRevoke,
            |lease| {
                let reason_error =
                    (!error_reason(reason)).then_some(LeaseDomainError::InvalidReason {
                        status: LeaseStatus::Error,
                        reason,
                    });
                let deadline_result = enforce_before(lease, now);
                if let Some(error) = reason_error {
                    return Err(error);
                }
                deadline_result?;
                lease.mark_error(reason)
            },
        )
    }

    pub(in crate::automation::store) fn enforce_expiration(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        now: &ClockSample,
    ) -> Result<CommittedMutation<bool>, StoreError> {
        self.mutate_service(
            lease_id,
            expected_row_version,
            now.wall(),
            AutomationOperation::LeaseRenew,
            |lease| lease.enforce_deadlines(now),
        )
    }

    fn mutate_requested<T>(
        &mut self,
        control: &AuthenticatedRequestControl<'_>,
        event_at: &UtcTimestamp,
        actor: AuditActor<'_>,
        mutation: impl FnOnce(&mut Lease) -> Result<T, LeaseDomainError>,
    ) -> Result<CommittedMutation<T>, StoreError> {
        let generation = self.core.service_generation;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if !ownership::caller_matches(&transaction, control.lease_id(), control.caller_subject())? {
            return committed_authentication_denied(transaction, AutomationOperation::LeaseAcquire);
        }
        let Some(mut loaded) = load::lease_by_id(&transaction, control.lease_id().as_str())? else {
            return committed_authentication_denied(transaction, AutomationOperation::LeaseAcquire);
        };
        let identity_error =
            requested_identity_error(&loaded, control.caller_subject(), control.host_identity());
        if let Some(error) = identity_error {
            let response = validated_response(&loaded.lease)?;
            transaction
                .commit()
                .map_err(|_| StoreError::DatabaseUnavailable)?;
            return Ok(CommittedMutation::new(
                AutomationOperation::LeaseAcquire,
                response,
                loaded.row_version,
                Err(error),
            ));
        }
        require_mutable_generation(&loaded, generation)?;
        require_expected_version(&loaded, control.expected_row_version())?;
        let profile_uid = loaded.snapshot.profile_uid().clone();
        let mut commit_attempted = false;
        let finished = finish_mutation(
            transaction,
            &mut loaded,
            event_at,
            actor,
            generation,
            AutomationOperation::LeaseAcquire,
            &mut commit_attempted,
            mutation,
        );
        let finished = match finished {
            Ok(finished) => finished,
            Err(error) => {
                if commit_attempted {
                    self.core.latch_profile_cleanup(profile_uid);
                }
                return Err(error);
            }
        };
        Ok(complete_mutation(&mut self.core, finished))
    }

    #[allow(clippy::too_many_arguments)]
    fn mutate_resolved<T>(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        control: &LeaseControl<'_>,
        event_at: &UtcTimestamp,
        actor: AuditActor<'_>,
        operation: AutomationOperation,
        allow_foreign_renewing_ack: bool,
        mutation: impl FnOnce(&mut Lease) -> Result<T, LeaseDomainError>,
    ) -> Result<CommittedMutation<T>, StoreError> {
        let generation = self.core.service_generation;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let owner = ownership::caller_matches(&transaction, lease_id, control.caller_subject)?;
        let foreign_ack = !owner
            && allow_foreign_renewing_ack
            && ownership::foreign_exact_renewing_ack(
                &transaction,
                lease_id,
                expected_row_version,
                generation,
            )?;
        if !owner && !foreign_ack {
            return committed_authentication_denied(transaction, operation);
        }
        let mut loaded = match load::lease_by_id(&transaction, lease_id.as_str()) {
            Ok(Some(loaded)) => loaded,
            Ok(None) => return committed_authentication_denied(transaction, operation),
            Err(_) if !owner => return committed_authentication_denied(transaction, operation),
            Err(error) => return Err(error),
        };
        if !owner
            && (!mutable_in_generation(&loaded, generation)
                || loaded.row_version != expected_row_version
                || expected_row_version == 0
                || loaded.lease.status() != LeaseStatus::Renewing)
        {
            return committed_authentication_denied(transaction, operation);
        }
        if (!mutable_in_generation(&loaded, generation)
            || loaded.row_version != expected_row_version
            || expected_row_version == 0)
            && let Err(error) = loaded.lease.validate_control_binding(control)
        {
            return committed_domain_error(transaction, &loaded, operation, error);
        }
        require_mutable_generation(&loaded, generation)?;
        require_expected_version(&loaded, expected_row_version)?;
        let profile_uid = loaded.snapshot.profile_uid().clone();
        let mut commit_attempted = false;
        let finished = finish_mutation(
            transaction,
            &mut loaded,
            event_at,
            actor,
            generation,
            operation,
            &mut commit_attempted,
            mutation,
        );
        let finished = match finished {
            Ok(finished) => finished,
            Err(error) => {
                if commit_attempted {
                    self.core.latch_profile_cleanup(profile_uid);
                }
                return Err(error);
            }
        };
        Ok(complete_mutation(&mut self.core, finished))
    }

    fn mutate_guarded_begin_renewal(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        control: &LeaseControl<'_>,
        current_policy: &EffectivePolicy,
        now: &ClockSample,
    ) -> Result<CommittedMutation<FencingGeneration>, StoreError> {
        let generation = self.core.service_generation;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if !ownership::caller_matches(&transaction, lease_id, control.caller_subject)? {
            return committed_authentication_denied(transaction, AutomationOperation::LeaseRenew);
        }
        let Some(mut loaded) = load::lease_by_id(&transaction, lease_id.as_str())? else {
            return committed_authentication_denied(transaction, AutomationOperation::LeaseRenew);
        };
        if (!mutable_in_generation(&loaded, generation)
            || loaded.row_version != expected_row_version
            || expected_row_version == 0)
            && let Err(error) = loaded.lease.validate_control_binding(control)
        {
            return committed_domain_error(
                transaction,
                &loaded,
                AutomationOperation::LeaseRenew,
                error,
            );
        }
        require_mutable_generation(&loaded, generation)?;
        require_expected_version(&loaded, expected_row_version)?;
        let mut disposable = Lease::restore(loaded.snapshot.clone())
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        let would_renew = disposable
            .begin_renewal(control, current_policy, now)
            .is_ok()
            && disposable.status() == LeaseStatus::Renewing;
        let claim_matches = !would_renew
            || capacity::held_claim_matches(
                &transaction,
                lease_id,
                current_policy.capacity_claim(),
            )?;
        let profile_uid = loaded.snapshot.profile_uid().clone();
        let mut commit_attempted = false;
        let finished = finish_mutation(
            transaction,
            &mut loaded,
            now.wall(),
            AuditActor::Service,
            generation,
            AutomationOperation::LeaseRenew,
            &mut commit_attempted,
            |lease| {
                if claim_matches {
                    lease.begin_renewal(control, current_policy, now)
                } else {
                    lease.validate_control_binding(control)?;
                    if lease.enforce_deadlines(now)? {
                        return Err(match lease.status() {
                            LeaseStatus::Expired => LeaseDomainError::LeaseExpired,
                            LeaseStatus::Revoked => LeaseDomainError::LeaseRevoked,
                            _ => LeaseDomainError::LeaseNotActive,
                        });
                    }
                    Err(LeaseDomainError::PolicyBindingMismatch)
                }
            },
        );
        let finished = match finished {
            Ok(finished) => finished,
            Err(error) => {
                if commit_attempted {
                    self.core.latch_profile_cleanup(profile_uid);
                }
                return Err(error);
            }
        };
        Ok(complete_mutation(&mut self.core, finished))
    }

    fn mutate_service<T>(
        &mut self,
        lease_id: &LeaseId,
        expected_row_version: u64,
        event_at: &UtcTimestamp,
        operation: AutomationOperation,
        mutation: impl FnOnce(&mut Lease) -> Result<T, LeaseDomainError>,
    ) -> Result<CommittedMutation<T>, StoreError> {
        let generation = self.core.service_generation;
        let transaction = self
            .core
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        let mut loaded = load_lease(&transaction, lease_id)?;
        require_mutable_generation(&loaded, generation)?;
        require_expected_version(&loaded, expected_row_version)?;
        let profile_uid = loaded.snapshot.profile_uid().clone();
        let mut commit_attempted = false;
        let finished = finish_mutation(
            transaction,
            &mut loaded,
            event_at,
            AuditActor::Service,
            generation,
            operation,
            &mut commit_attempted,
            mutation,
        );
        let finished = match finished {
            Ok(finished) => finished,
            Err(error) => {
                if commit_attempted {
                    self.core.latch_profile_cleanup(profile_uid);
                }
                return Err(error);
            }
        };
        Ok(complete_mutation(&mut self.core, finished))
    }
}

// Short-lived preflight values avoid heap allocation on every authority mutation.
#[allow(clippy::large_enum_variant)]
enum GuardedMutationPreflight<T> {
    Domain(CommittedMutation<T>),
    WithoutGuards,
    Guarded(LeaseSnapshot),
}

fn committed_domain_error<T>(
    transaction: Transaction<'_>,
    loaded: &load::LoadedLease,
    operation: AutomationOperation,
    error: LeaseDomainError,
) -> Result<CommittedMutation<T>, StoreError> {
    let response = validated_response(&loaded.lease)?;
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    Ok(CommittedMutation::new(
        operation,
        response,
        loaded.row_version,
        Err(error),
    ))
}

fn committed_authentication_denied<T>(
    transaction: Transaction<'_>,
    operation: AutomationOperation,
) -> Result<CommittedMutation<T>, StoreError> {
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    Ok(CommittedMutation::authentication_denied(operation))
}

struct FinishedMutation<T> {
    committed: CommittedMutation<T>,
    terminal: Option<(LeaseId, crate::model::ProfileUid)>,
}

// Keep the transaction, CAS projection, audit context, and mutation in one atomic helper.
#[allow(clippy::too_many_arguments)]
fn finish_mutation<T>(
    transaction: Transaction<'_>,
    loaded: &mut load::LoadedLease,
    event_at: &UtcTimestamp,
    actor: AuditActor<'_>,
    generation: crate::automation::lease::ServiceClockGeneration,
    operation: AutomationOperation,
    commit_attempted: &mut bool,
    mutation: impl FnOnce(&mut Lease) -> Result<T, LeaseDomainError>,
) -> Result<FinishedMutation<T>, StoreError> {
    let prior_status = loaded.lease.status();
    let domain_result = mutation(&mut loaded.lease);
    let response = validated_response(&loaded.lease)?;
    let after = loaded.lease.snapshot();
    let row_version = persist::persist(&transaction, loaded, &after, event_at, actor, generation)?;
    let became_terminal = !terminal_status(prior_status) && terminal_status(loaded.lease.status());
    if became_terminal {
        capacity::release_if_resolved(&transaction, after.lease_id(), event_at)?;
    }
    *commit_attempted = true;
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    let terminal = became_terminal.then(|| (after.lease_id().clone(), after.profile_uid().clone()));
    Ok(FinishedMutation {
        committed: CommittedMutation::new(operation, response, row_version, domain_result),
        terminal,
    })
}

fn complete_mutation<T>(
    core: &mut super::sqlite::StoreCore,
    mut finished: FinishedMutation<T>,
) -> CommittedMutation<T> {
    if let Some((lease_id, profile_uid)) = &finished.terminal
        && let Err(error) = core.post_terminal_cleanup(lease_id, profile_uid)
    {
        core.latch_cleanup_failure(profile_uid.clone(), error);
        finished.committed.mark_cleanup_deferred();
    }
    finished.committed
}

fn load_lease(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
) -> Result<load::LoadedLease, StoreError> {
    load::lease_by_id(transaction, lease_id.as_str())?.ok_or(StoreError::LeaseNotFound)
}

fn require_mutable_generation(
    loaded: &load::LoadedLease,
    generation: crate::automation::lease::ServiceClockGeneration,
) -> Result<(), StoreError> {
    if mutable_in_generation(loaded, generation) {
        Ok(())
    } else {
        Err(StoreError::InvalidTransition)
    }
}

fn mutable_in_generation(
    loaded: &load::LoadedLease,
    generation: crate::automation::lease::ServiceClockGeneration,
) -> bool {
    loaded.origin_generation == generation
        && matches!(
            loaded.recovery_state,
            super::load_parse::RecoveryState::None
        )
        && !loaded.quarantined
}

fn require_expected_version(loaded: &load::LoadedLease, expected: u64) -> Result<(), StoreError> {
    if expected == 0 || loaded.row_version != expected {
        Err(StoreError::ConcurrentMutation)
    } else {
        Ok(())
    }
}

fn requested_identity_error(
    loaded: &load::LoadedLease,
    caller: &CallerSubject,
    host: &HostIdentity,
) -> Option<LeaseDomainError> {
    if loaded.snapshot.caller_subject() != caller {
        Some(LeaseDomainError::CallerUnauthorized)
    } else if loaded.snapshot.host_identity() != host {
        Some(LeaseDomainError::HostMismatch)
    } else {
        None
    }
}

fn validated_response(lease: &Lease) -> Result<IdentityLeaseResponse, StoreError> {
    lease
        .identity_response()
        .map_err(|_| StoreError::IntegrityCheckFailed)
}

fn enforce_before(lease: &mut Lease, now: &ClockSample) -> Result<(), LeaseDomainError> {
    if !lease.enforce_deadlines(now)? {
        return Ok(());
    }
    match lease.status() {
        LeaseStatus::Expired => Err(LeaseDomainError::LeaseExpired),
        LeaseStatus::Revoked => Err(LeaseDomainError::LeaseRevoked),
        _ => Err(LeaseDomainError::LeaseNotActive),
    }
}

const fn service_revocation_reason(reason: LeaseReasonCode) -> bool {
    matches!(
        reason,
        LeaseReasonCode::PolicyRevoked
            | LeaseReasonCode::PrincipalMismatch
            | LeaseReasonCode::HeartbeatLost
            | LeaseReasonCode::ProcessUnverifiable
            | LeaseReasonCode::GenerationSuperseded
            | LeaseReasonCode::RenewalAcknowledgementFailed
            | LeaseReasonCode::ServiceRecovery
    )
}

const fn error_reason(reason: LeaseReasonCode) -> bool {
    matches!(
        reason,
        LeaseReasonCode::ProcessUnverifiable
            | LeaseReasonCode::ServiceRecovery
            | LeaseReasonCode::InternalError
    )
}

const fn policy_resource_mode(policy: &EffectivePolicy) -> ProfileAutomationResourceMode {
    match policy.concurrency_mode() {
        AutomationConcurrencyMode::Exclusive => ProfileAutomationResourceMode::Exclusive,
        AutomationConcurrencyMode::Shared => ProfileAutomationResourceMode::Shared,
    }
}
