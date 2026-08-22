use std::{
    fmt,
    num::{NonZeroU32, NonZeroU64},
};

use crate::automation::{
    contracts::{
        ExecutionHandle, FencingGeneration, LeaseId, LeaseStatus, UtcTimestamp, WorkerIdentity,
    },
    lease::{LeaseSnapshot, ServiceClockGeneration},
};

use super::StoreError;

const MAX_PAGE_SIZE: u16 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryMutationResult {
    status: LeaseStatus,
    row_version: u64,
    released_reservations: u64,
    changed: bool,
    cleanup_deferred: bool,
}

impl RecoveryMutationResult {
    pub(super) const fn new(
        status: LeaseStatus,
        row_version: u64,
        released_reservations: u64,
        changed: bool,
    ) -> Self {
        Self {
            status,
            row_version,
            released_reservations,
            changed,
            cleanup_deferred: false,
        }
    }

    #[must_use]
    pub(crate) const fn status(self) -> LeaseStatus {
        self.status
    }

    #[must_use]
    pub(crate) const fn row_version(self) -> u64 {
        self.row_version
    }

    #[must_use]
    pub(crate) const fn released_reservations(self) -> u64 {
        self.released_reservations
    }

    #[must_use]
    pub(crate) const fn changed(self) -> bool {
        self.changed
    }

    #[must_use]
    pub(crate) const fn cleanup_deferred(self) -> bool {
        self.cleanup_deferred
    }

    pub(super) fn mark_cleanup_deferred(&mut self) {
        self.cleanup_deferred = true;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryCursor(pub(super) LeaseId);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryPageRequest {
    pub(super) after: Option<RecoveryCursor>,
    pub(super) limit: u16,
}

impl RecoveryPageRequest {
    pub(crate) fn first(limit: u16) -> Result<Self, StoreError> {
        Self::new(None, limit)
    }

    pub(crate) fn after(cursor: RecoveryCursor, limit: u16) -> Result<Self, StoreError> {
        Self::new(Some(cursor), limit)
    }

    fn new(after: Option<RecoveryCursor>, limit: u16) -> Result<Self, StoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(StoreError::InvalidRequest);
        }
        Ok(Self { after, limit })
    }
}

#[derive(Clone)]
pub(crate) struct RecoveryPage {
    pub(super) candidates: Vec<RecoveryCandidate>,
    pub(super) next_cursor: Option<RecoveryCursor>,
}

impl RecoveryPage {
    #[must_use]
    pub(crate) fn candidates(&self) -> &[RecoveryCandidate] {
        &self.candidates
    }

    #[must_use]
    pub(crate) const fn next_cursor(&self) -> Option<&RecoveryCursor> {
        self.next_cursor.as_ref()
    }
}

impl fmt::Debug for RecoveryPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryPage")
            .field("candidates", &self.candidates)
            .field("has_next_cursor", &self.next_cursor.is_some())
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct RecoveryCandidate {
    pub(super) lease_id: LeaseId,
    pub(super) status: LeaseStatus,
    pub(super) recovery_state: RecoveryLeaseState,
    pub(super) quarantined: bool,
    pub(super) origin_generation: ServiceClockGeneration,
    pub(super) current_generation: ServiceClockGeneration,
    pub(super) lease_row_version: u64,
    pub(super) clock_row_version: u64,
    pub(super) capacity: Vec<CapacityEvidence>,
    pub(super) processes: Vec<ProcessEvidence>,
    pub(super) snapshot: LeaseSnapshot,
}

impl RecoveryCandidate {
    #[must_use]
    pub(crate) const fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }

    #[must_use]
    pub(crate) const fn status(&self) -> LeaseStatus {
        self.status
    }

    #[must_use]
    pub(crate) const fn recovery_state(&self) -> RecoveryLeaseState {
        self.recovery_state
    }

    #[must_use]
    pub(crate) const fn quarantined(&self) -> bool {
        self.quarantined
    }

    #[must_use]
    pub(crate) const fn origin_generation(&self) -> ServiceClockGeneration {
        self.origin_generation
    }

    #[must_use]
    pub(crate) const fn current_generation(&self) -> ServiceClockGeneration {
        self.current_generation
    }

    #[must_use]
    pub(crate) const fn lease_row_version(&self) -> u64 {
        self.lease_row_version
    }

    #[must_use]
    pub(crate) const fn clock_row_version(&self) -> u64 {
        self.clock_row_version
    }

    #[must_use]
    pub(crate) fn capacity_evidence(&self) -> &[CapacityEvidence] {
        &self.capacity
    }

    #[must_use]
    pub(crate) fn process_evidence(&self) -> &[ProcessEvidence] {
        &self.processes
    }

    #[must_use]
    // Recovery is deliberately terminal-only in this checkpoint. Keeping the
    // query on the candidate makes the prohibition explicit at call sites.
    #[allow(clippy::unused_self)]
    pub(crate) const fn resume_permitted(&self) -> bool {
        false
    }

    /// Store-private evidence for a future terminal-only reconciler. There is
    /// deliberately no public or crate-facing launch/resume authority accessor.
    #[allow(dead_code)]
    pub(super) fn into_private_evidence(self) -> (LeaseSnapshot, Vec<ProcessEvidence>) {
        (self.snapshot, self.processes)
    }
}

impl fmt::Debug for RecoveryCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryCandidate")
            .field("lease_id", &self.lease_id)
            .field("status", &self.status)
            .field("recovery_state", &self.recovery_state)
            .field("quarantined", &self.quarantined)
            .field("origin_generation", &self.origin_generation)
            .field("current_generation", &self.current_generation)
            .field("lease_row_version", &self.lease_row_version)
            .field("clock_row_version", &self.clock_row_version)
            .field("capacity", &self.capacity)
            .field("processes", &self.processes)
            .field("resume_permitted", &false)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryLeaseState {
    None,
    Required,
    Reconciling,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapacityState {
    Held,
    Quarantined,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapacityDimension {
    Provider,
    Profile,
    Caller,
    Host,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapacityEvidence {
    pub(super) state: CapacityState,
    pub(super) dimension: CapacityDimension,
    pub(super) limit: NonZeroU32,
    pub(super) slot: NonZeroU64,
}

impl CapacityEvidence {
    #[must_use]
    pub(crate) const fn state(&self) -> CapacityState {
        self.state
    }

    #[must_use]
    pub(crate) const fn dimension(&self) -> CapacityDimension {
        self.dimension
    }

    #[must_use]
    pub(crate) const fn limit(&self) -> u32 {
        self.limit.get()
    }

    #[must_use]
    pub(crate) const fn slot(&self) -> u64 {
        self.slot.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessState {
    LaunchIntent,
    Starting,
    Running,
    Stopping,
    Quarantined,
    RecoveryRequired,
}

#[derive(Clone)]
pub(crate) struct ProcessEvidence {
    pub(super) process_record_id: String,
    pub(super) state: ProcessState,
    pub(super) origin_generation: ServiceClockGeneration,
    pub(super) process_id_number: Option<NonZeroU64>,
    pub(super) process_identity: Option<String>,
    pub(super) execution_handle: ExecutionHandle,
    pub(super) worker_identity: Option<WorkerIdentity>,
    pub(super) observed_fencing_generation: FencingGeneration,
    pub(super) launch_intent_at: UtcTimestamp,
    pub(super) started_at: Option<UtcTimestamp>,
    pub(super) stop_requested_at: Option<UtcTimestamp>,
    pub(super) ended_at: Option<UtcTimestamp>,
    pub(super) exit_code: Option<i64>,
}

impl ProcessEvidence {
    #[must_use]
    pub(crate) const fn state(&self) -> ProcessState {
        self.state
    }

    #[must_use]
    pub(crate) const fn origin_generation(&self) -> ServiceClockGeneration {
        self.origin_generation
    }

    #[must_use]
    pub(crate) const fn has_process_id(&self) -> bool {
        self.process_id_number.is_some()
    }

    #[must_use]
    pub(crate) const fn has_process_identity(&self) -> bool {
        self.process_identity.is_some()
    }

    #[must_use]
    pub(crate) const fn observed_fencing_generation(&self) -> FencingGeneration {
        self.observed_fencing_generation
    }
}

impl fmt::Debug for ProcessEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessEvidence")
            .field("state", &self.state)
            .field("origin_generation", &self.origin_generation)
            .field("has_process_id", &self.process_id_number.is_some())
            .field("has_process_identity", &self.process_identity.is_some())
            .field(
                "observed_fencing_generation",
                &self.observed_fencing_generation,
            )
            .field("has_started_at", &self.started_at.is_some())
            .field("has_stop_requested_at", &self.stop_requested_at.is_some())
            .finish_non_exhaustive()
    }
}
